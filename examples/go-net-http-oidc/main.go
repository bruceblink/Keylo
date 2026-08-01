package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/alexedwards/scs/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	issuer       = requiredEnv("KEYLO_ISSUER")
	clientID     = requiredEnv("OIDC_CLIENT_ID")
	clientSecret = os.Getenv("OIDC_CLIENT_SECRET")
	redirectURI  = envOr("OIDC_REDIRECT_URI", "http://127.0.0.1:3000/oidc/callback")
	port         = envOr("PORT", "3000")
	sessions     = scs.New()
)

type profile struct {
	Subject       string `json:"sub"`
	Name          string `json:"name,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
}

// requiredEnv reads identity-boundary configuration without providing unsafe defaults.
func requiredEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("%s must be configured", name)
	}
	return value
}

// envOr returns a local development default only for values that are not secrets.
func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// callbackIssuerMatches binds Keylo's authorization response to the issuer discovered at startup.
func callbackIssuerMatches(values url.Values) bool {
	return values.Get("iss") == issuer
}

// callbackHandler validates one browser login transaction before accepting its authorization code.
func callbackHandler(oauthConfig oauth2.Config, verifier *oidc.IDTokenVerifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		expectedState := sessions.PopString(r.Context(), "oidc_state")
		codeVerifier := sessions.PopString(r.Context(), "oidc_code_verifier")
		expectedNonce := sessions.PopString(r.Context(), "oidc_nonce")
		if expectedState == "" || codeVerifier == "" || expectedNonce == "" {
			http.Error(w, "OIDC login transaction is missing or expired", http.StatusBadRequest)
			return
		}
		if query.Get("state") != expectedState {
			http.Error(w, "OIDC callback state is invalid", http.StatusBadRequest)
			return
		}
		if !callbackIssuerMatches(query) {
			http.Error(w, "OIDC callback issuer is missing or invalid", http.StatusBadRequest)
			return
		}
		if query.Get("error") != "" {
			http.Error(w, "OIDC login was denied", http.StatusForbidden)
			return
		}

		token, err := oauthConfig.Exchange(r.Context(), query.Get("code"), oauth2.VerifierOption(codeVerifier))
		if err != nil {
			http.Error(w, "OIDC authorization code exchange failed", http.StatusBadGateway)
			return
		}
		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "OIDC response does not contain an ID token", http.StatusBadGateway)
			return
		}
		idToken, err := verifier.Verify(r.Context(), rawIDToken)
		if err != nil || idToken.Nonce != expectedNonce {
			http.Error(w, "OIDC ID token is invalid", http.StatusUnauthorized)
			return
		}

		var user profile
		if err := idToken.Claims(&user); err != nil || user.Subject == "" {
			http.Error(w, "OIDC ID token claims are invalid", http.StatusUnauthorized)
			return
		}
		if err := sessions.RenewToken(r.Context()); err != nil {
			http.Error(w, "OIDC session renewal failed", http.StatusInternalServerError)
			return
		}
		sessions.Put(r.Context(), "user", user)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func main() {
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		log.Fatal(err)
	}
	sessions.Cookie.HttpOnly = true
	sessions.Cookie.SameSite = http.SameSiteLaxMode
	sessions.Cookie.Secure = redirectURL.Scheme == "https"
	sessions.Cookie.Name = "keylo_rp_session"

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Fatalf("OIDC discovery failed: %v", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	oauthConfig := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURI,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		state := oauth2.GenerateVerifier()
		nonce := oauth2.GenerateVerifier()
		codeVerifier := oauth2.GenerateVerifier()
		sessions.Put(r.Context(), "oidc_state", state)
		sessions.Put(r.Context(), "oidc_nonce", nonce)
		sessions.Put(r.Context(), "oidc_code_verifier", codeVerifier)
		http.Redirect(w, r, oauthConfig.AuthCodeURL(
			state,
			oauth2.S256ChallengeOption(codeVerifier),
			oauth2.SetAuthURLParam("nonce", nonce),
		), http.StatusFound)
	})
	mux.Handle("/oidc/callback", callbackHandler(oauthConfig, verifier))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		user, ok := sessions.Get(r.Context(), "user").(profile)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(user)
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if err := sessions.Destroy(r.Context()); err != nil {
			http.Error(w, "OIDC logout failed", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})

	log.Printf("Open http://127.0.0.1:%s", port)
	if err := http.ListenAndServe("127.0.0.1:"+port, sessions.LoadAndSave(mux)); err != nil {
		log.Fatal(err)
	}
}
