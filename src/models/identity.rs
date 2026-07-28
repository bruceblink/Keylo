use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;

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
}
