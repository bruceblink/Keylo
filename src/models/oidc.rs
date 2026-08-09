use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::FromRow;
use url::Url;

pub const OIDC_CLIENT_SCOPE_PLATFORM: &str = "platform";
pub const OIDC_CLIENT_SCOPE_ORGANIZATION: &str = "organization";

/// A registered relying party that will later use Keylo's OIDC authorization endpoints.
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct OidcClient {
    pub id: String,
    pub client_id: String,
    pub name: String,
    pub description: Option<String>,
    pub client_type: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    pub active: bool,
    pub scope_kind: String,
    pub organization_id: Option<String>,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateOidcClientRequest {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub client_type: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateOidcClientRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub grant_types: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub active: Option<bool>,
}

/// Bounds administrative OIDC client listings without changing the default response shape.
#[derive(Debug, Deserialize)]
pub struct OidcClientListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Authorization data retained until the token endpoint atomically consumes the one-time code.
#[derive(Debug, Clone)]
pub struct OidcAuthorizationCode {
    pub client_id: String,
    pub organization_id: Option<String>,
    pub user_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub expires_at: i64,
}

/// Authenticated browser state used only by the OIDC authorization UI, never as an API token.
#[derive(Debug, Clone)]
pub struct OidcBrowserSession {
    pub user_id: String,
    pub expires_at: i64,
}

/// Query parameters accepted by the future browser-facing authorization endpoint.
#[derive(Debug, Deserialize)]
pub struct OidcAuthorizeRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

/// Form posted by Keylo's browser login page; it carries the original authorization request.
#[derive(Debug, Deserialize)]
pub struct OidcLoginRequest {
    #[serde(flatten)]
    pub authorization: OidcAuthorizeRequest,
    pub username: String,
    pub password: String,
}

/// Same-site confirmation submitted after Keylo displays the requested client and scopes.
#[derive(Debug, Deserialize)]
pub struct OidcConsentRequest {
    #[serde(flatten)]
    pub authorization: OidcAuthorizeRequest,
    pub decision: String,
}

/// OAuth 2.0 token endpoint form for the authorization-code grant.
#[derive(Debug, Deserialize)]
pub struct OidcTokenRequest {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: String,
}

#[derive(Debug, Serialize)]
pub struct OidcTokenResponse {
    pub access_token: String,
    pub id_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: String,
}

#[derive(Debug, Serialize)]
pub struct OidcIdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcAccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub scope: String,
    pub token_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
}

/// Validate an authorization request against the registered client before any login UI is shown.
pub fn validate_authorization_request(
    client: &OidcClient,
    request: &OidcAuthorizeRequest,
) -> Result<Vec<String>, String> {
    if !client.active || client.client_id != request.client_id {
        return Err("OIDC client is not active".to_string());
    }
    if request.response_type != "code"
        || !client
            .grant_types
            .iter()
            .any(|grant| grant == "authorization_code")
    {
        return Err("only response_type=code is supported".to_string());
    }
    if !client
        .redirect_uris
        .iter()
        .any(|uri| uri == &request.redirect_uri)
    {
        return Err("redirect_uri must exactly match a registered URI".to_string());
    }
    if request.nonce.as_deref().is_none_or(str::is_empty) {
        return Err("nonce is required for OIDC authorization requests".to_string());
    }
    if request
        .state
        .as_deref()
        .is_some_and(|state| state.len() > 1024)
    {
        return Err("state must not exceed 1024 characters".to_string());
    }
    validate_pkce_challenge(&request.code_challenge, &request.code_challenge_method)?;
    let scopes: Vec<String> = request
        .scope
        .split_ascii_whitespace()
        .map(str::to_string)
        .collect();
    if scopes.is_empty() || !scopes.iter().any(|scope| scope == "openid") {
        return Err("scope must include openid".to_string());
    }
    if scopes
        .iter()
        .any(|scope| !client.scopes.iter().any(|allowed| allowed == scope))
    {
        return Err("requested scope is not registered for this client".to_string());
    }
    Ok(scopes)
}

/// Check the S256 PKCE challenge before issuing an authorization code.
pub fn validate_pkce_challenge(challenge: &str, method: &str) -> Result<(), String> {
    if method != "S256" {
        return Err("only S256 code_challenge_method is supported".to_string());
    }
    validate_pkce_value("code_challenge", challenge)
}

/// Verify the verifier sent to the token endpoint against the challenge bound to the code.
pub fn verify_pkce_s256(verifier: &str, challenge: &str) -> bool {
    if validate_pkce_value("code_verifier", verifier).is_err() {
        return false;
    }
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest) == challenge
}

/// Hash an opaque authorization code so database disclosure cannot mint access tokens.
pub fn authorization_code_hash(code: &str) -> String {
    hex::encode(Sha256::digest(code.as_bytes()))
}

/// Hash the opaque browser-session cookie before it reaches persistent storage.
pub fn browser_session_hash(session: &str) -> String {
    hex::encode(Sha256::digest(session.as_bytes()))
}

fn validate_pkce_value(label: &str, value: &str) -> Result<(), String> {
    if !(43..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(format!("{label} must be 43-128 PKCE unreserved characters"));
    }
    Ok(())
}

/// Validate static registration data before it can become an OAuth redirect target.
pub fn validate_oidc_client_registration(request: &CreateOidcClientRequest) -> Result<(), String> {
    if request.client_id.len() < 3
        || request.client_id.len() > 128
        || !request
            .client_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("client_id must be 3-128 ASCII letters, digits, '.', '_' or '-'".to_string());
    }
    if request.name.trim().is_empty() {
        return Err("name must not be empty".to_string());
    }
    if !matches!(request.client_type.as_str(), "public" | "confidential") {
        return Err("client_type must be public or confidential".to_string());
    }
    if request.client_type == "public" && request.client_secret.is_some() {
        return Err("public clients must not register a client_secret".to_string());
    }
    if request.client_type == "confidential"
        && request
            .client_secret
            .as_deref()
            .is_none_or(|secret| secret.trim().len() < 16)
    {
        return Err(
            "confidential clients require a client_secret of at least 16 characters".to_string(),
        );
    }
    validate_redirect_uris(&request.redirect_uris)?;
    validate_grant_types(
        request
            .grant_types
            .as_deref()
            .unwrap_or(&["authorization_code".to_string()]),
    )?;
    validate_oidc_scopes(request.scopes.as_deref().unwrap_or(&[
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
    ]))?;
    Ok(())
}

/// Keep registered scopes aligned with claims Keylo can actually issue today.
pub fn validate_oidc_scopes(scopes: &[String]) -> Result<(), String> {
    if scopes.is_empty() || !scopes.iter().any(|scope| scope == "openid") {
        return Err("OIDC client scopes must include openid".to_string());
    }
    if scopes
        .iter()
        .any(|scope| !matches!(scope.as_str(), "openid" | "profile" | "email"))
    {
        return Err("OIDC client scopes may only include openid, profile, and email".to_string());
    }
    let mut unique = scopes.to_vec();
    unique.sort();
    unique.dedup();
    if unique.len() != scopes.len() {
        return Err("OIDC client scopes must not contain duplicates".to_string());
    }
    Ok(())
}

pub fn validate_redirect_uris(redirect_uris: &[String]) -> Result<(), String> {
    if redirect_uris.is_empty() {
        return Err("at least one redirect_uri is required".to_string());
    }
    for uri in redirect_uris {
        let parsed =
            Url::parse(uri).map_err(|_| format!("redirect_uri must be an absolute URL: {uri}"))?;
        let loopback_http = parsed.scheme() == "http"
            && matches!(parsed.host_str(), Some("127.0.0.1") | Some("::1"));
        let safe_https = parsed.scheme() == "https" && parsed.host_str().is_some();
        if (!safe_https && !loopback_http)
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(format!(
                "redirect_uri must use HTTPS (or an exact loopback IP over HTTP) without credentials or a fragment: {uri}"
            ));
        }
    }
    Ok(())
}

pub fn validate_grant_types(grant_types: &[String]) -> Result<(), String> {
    if grant_types.is_empty()
        || grant_types
            .iter()
            .any(|grant| grant != "authorization_code")
    {
        return Err("only authorization_code is supported for OIDC clients".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_client(uri: &str) -> CreateOidcClientRequest {
        CreateOidcClientRequest {
            client_id: "portal-web".to_string(),
            client_secret: None,
            name: "Portal".to_string(),
            description: None,
            client_type: "public".to_string(),
            redirect_uris: vec![uri.to_string()],
            grant_types: None,
            scopes: None,
        }
    }

    #[test]
    fn registration_allows_https_and_loopback_redirects() {
        assert!(validate_oidc_client_registration(&public_client(
            "https://portal.example.com/callback"
        ))
        .is_ok());
        assert!(validate_oidc_client_registration(&public_client(
            "http://127.0.0.1:4567/callback"
        ))
        .is_ok());
    }

    #[test]
    fn registration_rejects_insecure_or_fragment_redirects() {
        assert!(validate_oidc_client_registration(&public_client(
            "http://portal.example.com/callback"
        ))
        .is_err());
        assert!(validate_oidc_client_registration(&public_client(
            "https://portal.example.com/callback#token"
        ))
        .is_err());
        assert!(validate_oidc_client_registration(&public_client(
            "http://127.0.0.1.evil.example/callback"
        ))
        .is_err());
        assert!(validate_oidc_client_registration(&public_client(
            "http://[::1].evil.example/callback"
        ))
        .is_err());
        assert!(validate_oidc_client_registration(&public_client(
            "https://attacker@portal.example.com/callback"
        ))
        .is_err());
    }

    #[test]
    fn registration_rejects_unsupported_or_missing_oidc_scopes() {
        assert!(validate_oidc_scopes(&["openid".to_string(), "admin".to_string()]).is_err());
        assert!(validate_oidc_scopes(&["profile".to_string()]).is_err());
        assert!(validate_oidc_scopes(&["openid".to_string(), "openid".to_string()]).is_err());
    }

    #[test]
    fn pkce_s256_matches_the_rfc_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(validate_pkce_challenge(challenge, "S256").is_ok());
        assert!(verify_pkce_s256(verifier, challenge));
        assert!(!verify_pkce_s256(
            "this-verifier-is-definitely-not-the-original-value-123",
            challenge
        ));
    }

    #[test]
    fn pkce_rejects_plain_or_invalid_challenges() {
        assert!(validate_pkce_challenge("short", "S256").is_err());
        assert!(validate_pkce_challenge("a".repeat(43).as_str(), "plain").is_err());
    }

    #[test]
    fn authorization_request_requires_exact_client_binding() {
        let client = OidcClient {
            id: "id".to_string(),
            client_id: "portal-web".to_string(),
            name: "Portal".to_string(),
            description: None,
            client_type: "public".to_string(),
            redirect_uris: vec!["https://portal.example.com/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            scopes: vec!["openid".to_string(), "profile".to_string()],
            active: true,
            scope_kind: OIDC_CLIENT_SCOPE_PLATFORM.to_string(),
            organization_id: None,
            created_at: chrono::Utc::now().naive_utc(),
            updated_at: chrono::Utc::now().naive_utc(),
        };
        let request = OidcAuthorizeRequest {
            response_type: "code".to_string(),
            client_id: "portal-web".to_string(),
            redirect_uri: "https://portal.example.com/callback".to_string(),
            scope: "openid profile".to_string(),
            state: Some("client-csrf-value".to_string()),
            nonce: Some("browser-nonce".to_string()),
            code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string(),
            code_challenge_method: "S256".to_string(),
        };
        assert_eq!(
            validate_authorization_request(&client, &request).unwrap(),
            vec!["openid", "profile"]
        );
        let invalid_redirect = OidcAuthorizeRequest {
            redirect_uri: "https://portal.example.com/other".to_string(),
            ..request
        };
        assert!(validate_authorization_request(&client, &invalid_redirect).is_err());
    }

    #[test]
    fn browser_session_hash_is_stable_and_does_not_echo_cookie() {
        let cookie = "opaque-browser-cookie";
        let hash = browser_session_hash(cookie);
        assert_eq!(hash, browser_session_hash(cookie));
        assert_ne!(hash, cookie);
        assert_eq!(hash.len(), 64);
    }
}
