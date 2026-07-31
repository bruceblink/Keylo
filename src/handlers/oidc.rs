use axum::{
    extract::{Form, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bcrypt::verify;
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::{
    errors::{is_unique_violation, AuthError},
    models::{
        validate_authorization_request, validate_grant_types, validate_oidc_client_registration,
        validate_oidc_scopes, validate_redirect_uris, verify_pkce_s256, CreateOidcClientRequest,
        OidcAccessTokenClaims, OidcAuthorizationCode, OidcAuthorizeRequest, OidcBrowserSession,
        OidcConsentRequest, OidcIdTokenClaims, OidcLoginRequest, OidcTokenRequest,
        OidcTokenResponse, RotateClientSecretRequest, UpdateOidcClientRequest,
    },
    state::AppState,
};

#[derive(serde::Serialize)]
struct OidcErrorBody {
    error: &'static str,
    error_description: String,
}

/// OAuth 2.0-compliant error format for the public token endpoint.
#[derive(Debug)]
pub struct OidcProtocolError {
    status: StatusCode,
    error: &'static str,
    description: String,
}

impl OidcProtocolError {
    fn invalid_grant(description: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_grant",
            description: description.into(),
        }
    }
}

impl From<AuthError> for OidcProtocolError {
    fn from(error: AuthError) -> Self {
        let (status, code, description) = match error {
            AuthError::Unauthorized
            | AuthError::WrongCredentials
            | AuthError::MissingCredentials => (
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "client authentication failed".to_string(),
            ),
            AuthError::InvalidRequest(message) => {
                (StatusCode::BAD_REQUEST, "invalid_request", message)
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "the authorization server could not complete the request".to_string(),
            ),
        };
        Self {
            status,
            error: code,
            description,
        }
    }
}

impl IntoResponse for OidcProtocolError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(OidcErrorBody {
                error: self.error,
                error_description: self.description,
            }),
        )
            .into_response();
        if self.error == "invalid_client" {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"oidc-token\""),
            );
        }
        response
    }
}

/// Extract one token-endpoint client authentication method without allowing ambiguous credentials.
fn token_client_credentials(
    headers: &HeaderMap,
    request: &OidcTokenRequest,
) -> Result<(String, Option<String>), OidcProtocolError> {
    let form_client_id = request
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty());
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(basic) = basic {
        if form_client_id.is_some() || request.client_secret.is_some() {
            return Err(AuthError::InvalidRequest(
                "OIDC token request must use exactly one client authentication method".to_string(),
            )
            .into());
        }
        let (scheme, encoded) = basic
            .split_once(char::is_whitespace)
            .ok_or(AuthError::Unauthorized)?;
        if !scheme.eq_ignore_ascii_case("Basic") || encoded.trim().is_empty() {
            return Err(AuthError::Unauthorized.into());
        }
        let encoded = encoded.trim();
        let decoded = STANDARD
            .decode(encoded)
            .map_err(|_| AuthError::Unauthorized)?;
        let decoded = std::str::from_utf8(&decoded).map_err(|_| AuthError::Unauthorized)?;
        let (encoded_client_id, encoded_client_secret) =
            decoded.split_once(':').ok_or(AuthError::Unauthorized)?;
        let decode_form_component = |value: &str| {
            urlencoding::decode(&value.replace('+', " "))
                .map(|value| value.into_owned())
                .map_err(|_| AuthError::Unauthorized)
        };
        let client_id = decode_form_component(encoded_client_id)?;
        let client_secret = decode_form_component(encoded_client_secret)?;
        if client_id.trim().is_empty() || client_secret.is_empty() {
            return Err(AuthError::Unauthorized.into());
        }
        return Ok((client_id, Some(client_secret)));
    }
    let client_id = form_client_id.ok_or_else(|| {
        OidcProtocolError::from(AuthError::InvalidRequest(
            "OIDC token request is missing client_id".to_string(),
        ))
    })?;
    Ok((client_id.to_string(), request.client_secret.clone()))
}

fn database(state: &AppState) -> Result<&sqlx::PgPool, AuthError> {
    state
        .db
        .as_deref()
        .ok_or_else(|| AuthError::DatabaseError("Database not available".to_string()))
}

/// Register an OIDC relying party after applying redirect URI and client-type security rules.
pub async fn create_client(
    State(state): State<AppState>,
    Json(request): Json<CreateOidcClientRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    validate_oidc_client_registration(&request).map_err(AuthError::InvalidRequest)?;
    match crate::db::create_oidc_client(database(&state)?, &request).await {
        Ok(client) => Ok(Json(json!({"success": true, "data": client}))),
        Err(error) if is_unique_violation(error.as_ref()) => Err(AuthError::Conflict(
            "OIDC client_id already exists".to_string(),
        )),
        Err(error) => Err(AuthError::DatabaseError(error.to_string())),
    }
}

pub async fn list_clients(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let clients = crate::db::list_oidc_clients(database(&state)?)
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))?;
    Ok(Json(json!({"success": true, "data": clients})))
}

/// Update metadata only; client type and secrets remain immutable until explicit rotation is added.
pub async fn update_client(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    Json(request): Json<UpdateOidcClientRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    if let Some(redirect_uris) = &request.redirect_uris {
        validate_redirect_uris(redirect_uris).map_err(AuthError::InvalidRequest)?;
    }
    if let Some(grant_types) = &request.grant_types {
        validate_grant_types(grant_types).map_err(AuthError::InvalidRequest)?;
    }
    if let Some(scopes) = &request.scopes {
        validate_oidc_scopes(scopes).map_err(AuthError::InvalidRequest)?;
    }
    let client = crate::db::update_oidc_client(database(&state)?, &client_id, &request)
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))?;
    client
        .map(|value| Json(json!({"success": true, "data": value})))
        .ok_or(AuthError::NotFound)
}

/// Rotate a confidential OIDC client secret without exposing any stored credential material.
pub async fn rotate_client_secret(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
    Json(request): Json<RotateClientSecretRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let new_secret = request
        .new_secret
        .as_deref()
        .filter(|secret| secret.trim().len() >= 16)
        .ok_or_else(|| {
            AuthError::InvalidRequest("new_secret must contain at least 16 characters".to_string())
        })?;
    let rotated = crate::db::rotate_oidc_client_secret(database(&state)?, &client_id, new_secret)
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))?;
    if !rotated {
        return Err(AuthError::NotFound);
    }
    Ok(Json(
        json!({"success": true, "message": "OIDC client secret rotated"}),
    ))
}

/// Publish only OIDC capabilities that relying parties can use today.
pub async fn discovery(State(state): State<AppState>) -> Json<serde_json::Value> {
    let base_url = state.config.oidc_issuer();
    Json(json!({
        "issuer": base_url,
        "authorization_endpoint": format!("{base_url}/v1/oidc/authorize"),
        "token_endpoint": format!("{base_url}/v1/oidc/token"),
        "userinfo_endpoint": format!("{base_url}/v1/oidc/userinfo"),
        "jwks_uri": format!("{base_url}/.well-known/jwks.json"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid", "profile", "email"]
    }))
}

/// Return only profile claims allowed by the OIDC scopes embedded in a signed access token.
pub async fn userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AuthError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(AuthError::MissingCredentials)?;
    let claims = state
        .jwt_keys
        .decode_oidc_access_token(token, &state.config.oidc_issuer())?;
    if claims.token_type != "Bearer"
        || !claims
            .scope
            .split_ascii_whitespace()
            .any(|scope| scope == "openid")
    {
        return Err(AuthError::InvalidToken);
    }
    let user = crate::db::user::get_user_by_id(database(&state)?, &claims.sub)
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))?
        .filter(|user| user.active)
        .ok_or(AuthError::InvalidToken)?;
    let has_scope = |scope: &str| {
        claims
            .scope
            .split_ascii_whitespace()
            .any(|value| value == scope)
    };
    let mut response = json!({"sub": user.id});
    if has_scope("profile") {
        response["name"] = json!(user.username);
    }
    if has_scope("email") {
        response["email"] = json!(user.email);
    }
    Ok(Json(response))
}

fn browser_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| part.trim().strip_prefix("keylo_oidc_session="))
}

fn redirect_with_code(request: &OidcAuthorizeRequest, code: &str) -> Redirect {
    let separator = if request.redirect_uri.contains('?') {
        '&'
    } else {
        '?'
    };
    let mut location = format!(
        "{}{}code={}",
        request.redirect_uri,
        separator,
        urlencoding::encode(code)
    );
    if let Some(state) = &request.state {
        location.push_str("&state=");
        location.push_str(&urlencoding::encode(state));
    }
    Redirect::to(&location)
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn consent_page(request: &OidcAuthorizeRequest, client_name: &str) -> Response {
    let optional = |name: &str, value: Option<&String>| {
        value
            .map(|value| {
                format!(
                    "<input type=\"hidden\" name=\"{name}\" value=\"{}\">",
                    html_escape(value)
                )
            })
            .unwrap_or_default()
    };
    let body = format!("<!doctype html><html><body><main><h1>Authorize {}</h1><p>Requested scopes: {}</p><form method=\"post\" action=\"/v1/oidc/consent\"><input type=\"hidden\" name=\"response_type\" value=\"{}\"><input type=\"hidden\" name=\"client_id\" value=\"{}\"><input type=\"hidden\" name=\"redirect_uri\" value=\"{}\"><input type=\"hidden\" name=\"scope\" value=\"{}\"><input type=\"hidden\" name=\"code_challenge\" value=\"{}\"><input type=\"hidden\" name=\"code_challenge_method\" value=\"{}\">{}{}<button name=\"decision\" value=\"approve\" type=\"submit\">Approve</button><button name=\"decision\" value=\"deny\" type=\"submit\">Deny</button></form></main></body></html>", html_escape(client_name), html_escape(&request.scope), html_escape(&request.response_type), html_escape(&request.client_id), html_escape(&request.redirect_uri), html_escape(&request.scope), html_escape(&request.code_challenge), html_escape(&request.code_challenge_method), optional("state", request.state.as_ref()), optional("nonce", request.nonce.as_ref()));
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

async fn consent_for_session(
    state: &AppState,
    request: &OidcAuthorizeRequest,
    user_id: String,
) -> Result<Response, AuthError> {
    let client = crate::db::get_oidc_client(database(state)?, &request.client_id)
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))?
        .ok_or(AuthError::NotFound)?;
    validate_authorization_request(&client, request).map_err(AuthError::InvalidRequest)?;
    let _ = user_id;
    Ok(consent_page(request, &client.name))
}

async fn authorize_for_user(
    state: &AppState,
    request: &OidcAuthorizeRequest,
    user_id: String,
) -> Result<Redirect, AuthError> {
    let db = database(state)?;
    let client = crate::db::get_oidc_client(db, &request.client_id)
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))?
        .ok_or(AuthError::NotFound)?;
    let scopes =
        validate_authorization_request(&client, request).map_err(AuthError::InvalidRequest)?;
    let code = Uuid::new_v4().simple().to_string();
    crate::db::create_authorization_code(
        db,
        &code,
        &OidcAuthorizationCode {
            client_id: request.client_id.clone(),
            user_id,
            redirect_uri: request.redirect_uri.clone(),
            scopes,
            nonce: request.nonce.clone(),
            code_challenge: request.code_challenge.clone(),
            expires_at: Utc::now().timestamp() + 300,
        },
    )
    .await
    .map_err(|error| AuthError::DatabaseError(error.to_string()))?;
    Ok(redirect_with_code(request, &code))
}

/// Start an authorization-code flow. Existing browser sessions can immediately continue to the client redirect URI.
pub async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(request): Query<OidcAuthorizeRequest>,
) -> Result<Response, AuthError> {
    let Some(cookie) = browser_cookie(&headers) else {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"login_required","login_endpoint":"/v1/oidc/login"})),
        )
            .into_response());
    };
    let session = crate::db::resolve_browser_session(database(&state)?, cookie)
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))?
        .ok_or(AuthError::Unauthorized)?;
    consent_for_session(&state, &request, session.user_id).await
}

/// Authenticate a local user for an OIDC browser flow, then issue a short-lived code and HttpOnly session cookie.
pub async fn login(
    State(state): State<AppState>,
    Form(request): Form<OidcLoginRequest>,
) -> Result<Response, AuthError> {
    let db = database(&state)?;
    let user = crate::db::user::get_user_by_username(db, &request.username)
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))?
        .filter(|user| user.active)
        .ok_or(AuthError::WrongCredentials)?;
    let password_hash = user
        .password_hash
        .as_deref()
        .ok_or(AuthError::WrongCredentials)?;
    if !verify(&request.password, password_hash).unwrap_or(false) {
        return Err(AuthError::WrongCredentials);
    }
    let raw_session = Uuid::new_v4().simple().to_string();
    crate::db::create_browser_session(
        db,
        &raw_session,
        &OidcBrowserSession {
            user_id: user.id.clone(),
            expires_at: Utc::now().timestamp() + 28_800,
        },
    )
    .await
    .map_err(|error| AuthError::DatabaseError(error.to_string()))?;
    let mut response = consent_for_session(&state, &request.authorization, user.id).await?;
    let cookie = format!("keylo_oidc_session={raw_session}; Path=/v1/oidc; Max-Age=28800; HttpOnly; Secure; SameSite=Lax");
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(|_| {
            AuthError::InternalServerError("Failed to construct session cookie".to_string())
        })?,
    );
    Ok(response)
}

/// Approve or deny a validated authorization request from Keylo's same-site consent form.
pub async fn consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(request): Form<OidcConsentRequest>,
) -> Result<Response, AuthError> {
    let cookie = browser_cookie(&headers).ok_or(AuthError::Unauthorized)?;
    let session = crate::db::resolve_browser_session(database(&state)?, cookie)
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))?
        .ok_or(AuthError::Unauthorized)?;
    let event_type = match request.decision.as_str() {
        "approve" => "oidc.authorization.approved",
        "deny" => "oidc.authorization.denied",
        _ => {
            return Err(AuthError::InvalidRequest(
                "decision must be approve or deny".to_string(),
            ))
        }
    };
    let detail = format!(
        "client_id={}, scopes={}",
        request.authorization.client_id, request.authorization.scope
    );
    if let Err(error) = crate::db::create_audit_log(
        database(&state)?,
        event_type,
        Some(&session.user_id),
        Some(&detail),
    )
    .await
    {
        tracing::warn!("Failed to record OIDC consent audit event: {error}");
    }
    if request.decision == "approve" {
        return Ok(
            authorize_for_user(&state, &request.authorization, session.user_id)
                .await?
                .into_response(),
        );
    }
    if request.decision == "deny" {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(json!({"error":"access_denied"})),
        )
            .into_response());
    }
    unreachable!("validated OIDC consent decision")
}

/// End the browser-only OIDC session and expire its cookie without affecting API refresh sessions.
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AuthError> {
    if let Some(cookie) = browser_cookie(&headers) {
        crate::db::revoke_browser_session(database(&state)?, cookie)
            .await
            .map_err(|error| AuthError::DatabaseError(error.to_string()))?;
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "keylo_oidc_session=; Path=/v1/oidc; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
        ),
    );
    Ok(response)
}

/// Exchange one authorization code exactly once after validating its client, redirect URI, and PKCE verifier.
pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(request): Form<OidcTokenRequest>,
) -> Result<Json<OidcTokenResponse>, OidcProtocolError> {
    if request.grant_type != "authorization_code" {
        return Err(AuthError::InvalidRequest(
            "only grant_type=authorization_code is supported".to_string(),
        )
        .into());
    }
    let (client_id, client_secret) = token_client_credentials(&headers, &request)?;
    let db = database(&state)?;
    let Some((client_type, secret_hash, active)) =
        crate::db::get_oidc_client_secret_hash(db, &client_id)
            .await
            .map_err(|error| AuthError::DatabaseError(error.to_string()))?
    else {
        return Err(AuthError::Unauthorized.into());
    };
    if !active
        || (client_type == "confidential"
            && !client_secret.as_deref().is_some_and(|secret| {
                secret_hash
                    .as_deref()
                    .is_some_and(|hash| verify(secret, hash).unwrap_or(false))
            }))
        || (client_type == "public" && client_secret.is_some())
    {
        return Err(AuthError::Unauthorized.into());
    }
    let authorization = crate::db::get_active_authorization_code(db, &request.code)
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))?
        .ok_or_else(|| {
            OidcProtocolError::invalid_grant("authorization code is invalid or expired")
        })?;
    if authorization.client_id != client_id
        || authorization.redirect_uri != request.redirect_uri
        || !verify_pkce_s256(&request.code_verifier, &authorization.code_challenge)
    {
        return Err(OidcProtocolError::invalid_grant(
            "authorization code binding or PKCE verification failed",
        ));
    }
    if crate::db::consume_authorization_code(db, &request.code)
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))?
        .is_none()
    {
        return Err(OidcProtocolError::invalid_grant(
            "authorization code has already been consumed",
        ));
    }
    let user = crate::db::user::get_user_by_id(db, &authorization.user_id)
        .await
        .map_err(|error| AuthError::DatabaseError(error.to_string()))?
        .filter(|user| user.active)
        .ok_or(AuthError::InvalidToken)?;
    let now = Utc::now().timestamp();
    let expires_at = now + state.config.token_expiry_seconds;
    let scope = authorization.scopes.join(" ");
    let access_token = state.jwt_keys.sign_token(&OidcAccessTokenClaims {
        iss: state.config.oidc_issuer(),
        sub: user.id.clone(),
        aud: client_id.clone(),
        exp: expires_at,
        iat: now,
        jti: Uuid::new_v4().to_string(),
        scope: scope.clone(),
        token_type: "Bearer".to_string(),
    })?;
    let id_token = state.jwt_keys.sign_token(&OidcIdTokenClaims {
        iss: state.config.oidc_issuer(),
        sub: user.id,
        aud: client_id,
        exp: expires_at,
        iat: now,
        nonce: authorization.nonce.ok_or(AuthError::InvalidToken)?,
        name: authorization
            .scopes
            .iter()
            .any(|scope| scope == "profile")
            .then_some(user.username),
        email: authorization
            .scopes
            .iter()
            .any(|scope| scope == "email")
            .then_some(user.email),
        // Keylo has no verified-email state yet, so it must not claim verification to relying parties.
        email_verified: None,
    })?;
    Ok(Json(OidcTokenResponse {
        access_token,
        id_token,
        token_type: "Bearer".to_string(),
        expires_in: state.config.token_expiry_seconds,
        scope,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token_request(client_id: Option<&str>, client_secret: Option<&str>) -> OidcTokenRequest {
        OidcTokenRequest {
            grant_type: "authorization_code".to_string(),
            code: "code".to_string(),
            redirect_uri: "https://client.example/callback".to_string(),
            client_id: client_id.map(str::to_string),
            client_secret: client_secret.map(str::to_string),
            code_verifier: "a".repeat(43),
        }
    }

    #[test]
    fn token_client_credentials_accepts_standard_basic_authentication() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic Y2xpZW50OnNlY3JldA=="),
        );

        let credentials = token_client_credentials(&headers, &token_request(None, None)).unwrap();

        assert_eq!(credentials.0, "client");
        assert_eq!(credentials.1.as_deref(), Some("secret"));
    }

    #[test]
    fn token_client_credentials_rejects_mixed_client_authentication_methods() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic Y2xpZW50OnNlY3JldA=="),
        );

        assert!(token_client_credentials(&headers, &token_request(Some("client"), None)).is_err());
    }

    #[test]
    fn token_client_credentials_decodes_standard_basic_form_encoding() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic Y2xpZW50JTJEaWQ6c2VjcmV0JTNBd2l0aCUyQnN5bWJvbHM="),
        );

        let credentials = token_client_credentials(&headers, &token_request(None, None)).unwrap();

        assert_eq!(credentials.0, "client-id");
        assert_eq!(credentials.1.as_deref(), Some("secret:with+symbols"));
    }

    #[test]
    fn token_client_credentials_accepts_case_insensitive_basic_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("basic Y2xpZW50OnNlY3JldA=="),
        );

        let credentials = token_client_credentials(&headers, &token_request(None, None)).unwrap();

        assert_eq!(credentials.0, "client");
        assert_eq!(credentials.1.as_deref(), Some("secret"));
    }
}
