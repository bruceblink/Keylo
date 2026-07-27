use serde::{Deserialize, Serialize};
use sqlx::FromRow;

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
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[derive(Debug, Deserialize)]
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
pub struct UpdateOidcClientRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub grant_types: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub active: Option<bool>,
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
    Ok(())
}

pub fn validate_redirect_uris(redirect_uris: &[String]) -> Result<(), String> {
    if redirect_uris.is_empty() {
        return Err("at least one redirect_uri is required".to_string());
    }
    for uri in redirect_uris {
        let is_loopback = uri.starts_with("http://127.0.0.1") || uri.starts_with("http://[::1]");
        if (!uri.starts_with("https://") && !is_loopback) || uri.contains('#') {
            return Err(format!("redirect_uri must use https (or a loopback IP) and cannot contain a fragment: {uri}"));
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
    }
}
