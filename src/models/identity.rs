use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct IdentitySource {
    pub id: String,
    pub name: String,
    pub source_type: String,
    pub display_name: String,
    pub description: Option<String>,
    pub config: Value,
    pub claim_mapping: Value,
    pub jit_enabled: bool,
    pub auto_link_enabled: bool,
    pub active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl IdentitySource {
    /// Return metadata safe for API responses by redacting credential-bearing config values.
    pub fn redacted_for_response(mut self) -> Self {
        redact_sensitive_values(&mut self.config);
        self
    }
}

fn redact_sensitive_values(value: &mut Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    for (key, value) in object.iter_mut() {
        let normalized = key.to_ascii_lowercase();
        if normalized.contains("secret") || normalized.contains("password") || normalized == "token"
        {
            *value = Value::String("[REDACTED]".to_string());
        } else {
            redact_sensitive_values(value);
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateIdentitySourceRequest {
    pub name: String,
    pub source_type: String,
    pub display_name: String,
    pub description: Option<String>,
    pub config: Option<Value>,
    pub claim_mapping: Option<Value>,
    pub jit_enabled: Option<bool>,
    pub auto_link_enabled: Option<bool>,
    pub active: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateIdentitySourceRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub config: Option<Value>,
    pub claim_mapping: Option<Value>,
    pub jit_enabled: Option<bool>,
    pub auto_link_enabled: Option<bool>,
    pub active: Option<bool>,
}

/// Validated configuration required to use an upstream OpenID Connect provider.
#[derive(Debug, Deserialize)]
pub struct OidcUpstreamConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
}

fn default_oidc_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
    ]
}

/// Parse and validate an OIDC upstream configuration before it can be persisted.
pub fn parse_oidc_upstream_config(config: &Value) -> Result<OidcUpstreamConfig, String> {
    let parsed: OidcUpstreamConfig = serde_json::from_value(config.clone()).map_err(|_| {
        "oidc_upstream config requires issuer, client_id, client_secret, and redirect_uri"
            .to_string()
    })?;
    let issuer = parsed.issuer.trim().to_string();
    let redirect_uri = parsed.redirect_uri.trim().to_string();
    if !issuer.starts_with("https://") || issuer.contains('?') || issuer.contains('#') {
        return Err(
            "oidc_upstream issuer must be an HTTPS URL without query or fragment".to_string(),
        );
    }
    if parsed.client_id.trim().is_empty() || parsed.client_secret.trim().is_empty() {
        return Err("oidc_upstream client_id and client_secret must not be empty".to_string());
    }
    let local_http = redirect_uri.starts_with("http://localhost")
        || redirect_uri.starts_with("http://127.0.0.1")
        || redirect_uri.starts_with("http://[::1]");
    if (!redirect_uri.starts_with("https://") && !local_http) || redirect_uri.contains('#') {
        return Err(
            "oidc_upstream redirect_uri must be HTTPS or a loopback HTTP URL without fragment"
                .to_string(),
        );
    }
    let scopes = parsed
        .scopes
        .iter()
        .map(|scope| scope.trim().to_string())
        .collect::<Vec<_>>();
    let unique = scopes.iter().collect::<HashSet<_>>();
    if scopes.iter().any(|scope| scope.is_empty())
        || unique.len() != scopes.len()
        || !scopes.iter().any(|scope| scope == "openid")
    {
        return Err("oidc_upstream scopes must be unique and include openid".to_string());
    }

    Ok(OidcUpstreamConfig {
        issuer,
        redirect_uri,
        scopes,
        ..parsed
    })
}

#[cfg(test)]
mod tests {
    use super::redact_sensitive_values;
    use serde_json::json;

    #[test]
    fn identity_source_response_redacts_nested_credentials() {
        let mut config = json!({
            "client_secret": "top-secret",
            "nested": { "bind_password": "directory-secret", "issuer": "https://idp.example" }
        });

        redact_sensitive_values(&mut config);

        assert_eq!(config["client_secret"], "[REDACTED]");
        assert_eq!(config["nested"]["bind_password"], "[REDACTED]");
        assert_eq!(config["nested"]["issuer"], "https://idp.example");
    }

    #[test]
    fn oidc_upstream_config_requires_safe_endpoints_and_openid() {
        let config = json!({
            "issuer": "https://idp.example/realms/acme",
            "client_id": "keylo",
            "client_secret": "secret",
            "redirect_uri": "https://identity.example/v1/upstream/oidc/callback/acme"
        });
        assert!(super::parse_oidc_upstream_config(&config).is_ok());

        let invalid = json!({
            "issuer": "http://idp.example",
            "client_id": "keylo",
            "client_secret": "secret",
            "redirect_uri": "https://identity.example/callback",
            "scopes": ["profile"]
        });
        assert!(super::parse_oidc_upstream_config(&invalid).is_err());
    }
}
