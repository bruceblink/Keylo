use std::{env, net::SocketAddr, sync::Arc};

use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    RedirectUrl, Scope,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    reqwest,
};
use serde::Deserialize;
use tower_sessions::{MemoryStore, Session, SessionManagerLayer};

#[derive(Clone)]
struct AppState {
    issuer: String,
    client_id: String,
    client_secret: Option<String>,
    redirect_uri: String,
    metadata: CoreProviderMetadata,
    http_client: reqwest::Client,
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    iss: Option<String>,
    error: Option<String>,
}

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} must be configured"))
}

fn env_or(name: &str, fallback: String) -> String {
    env::var(name).unwrap_or(fallback)
}

/// Start one browser login by persisting the values that must bind the callback to this request.
async fn login(State(state): State<Arc<AppState>>, session: Session) -> Response {
    let client = CoreClient::from_provider_metadata(
        state.metadata.clone(),
        ClientId::new(state.client_id.clone()),
        state.client_secret.clone().map(ClientSecret::new),
    )
    .set_redirect_uri(RedirectUrl::new(state.redirect_uri.clone()).expect("redirect URI is valid"));
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (authorization_url, csrf_state, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("profile".to_owned()))
        .add_scope(Scope::new("email".to_owned()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    if session
        .insert("oidc_state", csrf_state.secret())
        .await
        .is_err()
        || session.insert("oidc_nonce", nonce.secret()).await.is_err()
        || session
            .insert("oidc_pkce", pkce_verifier.secret())
            .await
            .is_err()
    {
        return server_error();
    }

    Redirect::to(authorization_url.as_ref()).into_response()
}

/// Consume and validate a callback once before converting the verified ID token into an app session.
async fn callback(
    State(state): State<Arc<AppState>>,
    session: Session,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let expected_state: Option<String> = session.remove("oidc_state").await.unwrap_or(None);
    let expected_nonce: Option<String> = session.remove("oidc_nonce").await.unwrap_or(None);
    let pkce_verifier: Option<String> = session.remove("oidc_pkce").await.unwrap_or(None);

    let (Some(expected_state), Some(expected_nonce), Some(pkce_verifier)) =
        (expected_state, expected_nonce, pkce_verifier)
    else {
        return client_error("OIDC login transaction is missing or expired");
    };
    if query.state.as_deref() != Some(expected_state.as_str()) {
        return client_error("OIDC callback state is invalid");
    }
    if query.iss.as_deref() != Some(state.issuer.as_str()) {
        return client_error("OIDC callback issuer is missing or invalid");
    }
    if query.error.is_some() {
        return (StatusCode::FORBIDDEN, "OIDC login was denied").into_response();
    }
    let Some(code) = query.code else {
        return client_error("OIDC callback code is missing");
    };

    let client = CoreClient::from_provider_metadata(
        state.metadata.clone(),
        ClientId::new(state.client_id.clone()),
        state.client_secret.clone().map(ClientSecret::new),
    )
    .set_redirect_uri(RedirectUrl::new(state.redirect_uri.clone()).expect("redirect URI is valid"));
    let token_response = match client
        .exchange_code(AuthorizationCode::new(code))
        .expect("discovered client has a token endpoint")
        .set_pkce_verifier(openidconnect::PkceCodeVerifier::new(pkce_verifier))
        .request_async(&state.http_client)
        .await
    {
        Ok(response) => response,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                "OIDC authorization code exchange failed",
            )
                .into_response();
        }
    };
    let Some(id_token) = token_response.extra_fields().id_token() else {
        return (
            StatusCode::BAD_GATEWAY,
            "OIDC response does not contain an ID token",
        )
            .into_response();
    };
    let claims = match id_token.claims(&client.id_token_verifier(), &Nonce::new(expected_nonce)) {
        Ok(claims) => claims,
        Err(_) => return (StatusCode::UNAUTHORIZED, "OIDC ID token is invalid").into_response(),
    };

    if session.cycle_id().await.is_err()
        || session
            .insert("user_sub", claims.subject().as_str())
            .await
            .is_err()
        || session
            .insert("user_email", claims.email().map(|email| email.as_str()))
            .await
            .is_err()
    {
        return server_error();
    }
    Redirect::to("/").into_response()
}

async fn home(session: Session) -> Response {
    let subject: Option<String> = session.get("user_sub").await.unwrap_or(None);
    match subject {
        Some(subject) => (StatusCode::OK, format!("Signed in as {subject}")).into_response(),
        None => Redirect::to("/login").into_response(),
    }
}

async fn logout(session: Session) -> Response {
    if session.flush().await.is_err() {
        return server_error();
    }
    Redirect::to("/").into_response()
}

fn client_error(message: &'static str) -> Response {
    (StatusCode::BAD_REQUEST, message).into_response()
}

fn server_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "OIDC session operation failed",
    )
        .into_response()
}

#[tokio::main]
async fn main() {
    let port = env_or("PORT", "3000".to_owned());
    let issuer = required_env("KEYLO_ISSUER");
    let client_id = required_env("OIDC_CLIENT_ID");
    let redirect_uri = env_or(
        "OIDC_REDIRECT_URI",
        format!("http://127.0.0.1:{port}/oidc/callback"),
    );
    // Discovery and token requests share a redirect-free client to avoid following an IdP-provided URL.
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("HTTP client builds");
    let metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new(issuer.clone()).expect("KEYLO_ISSUER is a valid URL"),
        &http_client,
    )
    .await
    .expect("OIDC discovery succeeds");

    let state = Arc::new(AppState {
        issuer,
        client_id,
        client_secret: env::var("OIDC_CLIENT_SECRET").ok(),
        redirect_uri: redirect_uri.clone(),
        metadata,
        http_client,
    });
    let session_layer = SessionManagerLayer::new(MemoryStore::default())
        .with_name("keylo_rp_session")
        .with_http_only(true)
        .with_same_site(tower_sessions::cookie::SameSite::Lax)
        .with_secure(redirect_uri.starts_with("https://"));
    let app = Router::new()
        .route("/", get(home))
        .route("/login", get(login))
        .route("/oidc/callback", get(callback))
        .route("/logout", get(logout))
        .with_state(state)
        .layer(session_layer);

    let address: SocketAddr = format!("127.0.0.1:{port}").parse().expect("port is valid");
    println!("Open http://{address}");
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("listener binds");
    axum::serve(listener, app).await.expect("server runs");
}
