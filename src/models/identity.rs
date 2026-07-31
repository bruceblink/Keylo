use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use sqlx::FromRow;
use std::collections::{BTreeMap, HashSet};
use uuid::Uuid;

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

/// A user-visible upstream source currently associated with the caller's Keylo account.
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct LinkedOidcIdentitySource {
    pub source_id: String,
    pub name: String,
    pub display_name: String,
    pub linked_at: chrono::NaiveDateTime,
}

/// A safe administrator view of local users linked to one upstream OIDC source.
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct OidcIdentitySourceLink {
    pub user_id: String,
    pub username: String,
    pub email: String,
    pub linked_at: chrono::NaiveDateTime,
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

/// Minimal OIDC Discovery document required for authorization-code login.
#[derive(Debug, Serialize, Deserialize)]
pub struct OidcUpstreamDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub userinfo_endpoint: Option<String>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Option<Vec<String>>,
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

/// Opaque state retained only for one upstream authorization-code round trip.
#[derive(Debug, Clone)]
pub struct OidcUpstreamAuthorizationState {
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
    pub code_challenge: String,
}

/// Claims required from a signed upstream ID Token after JWKS signature verification.
#[derive(Debug, Deserialize)]
pub struct OidcUpstreamIdTokenClaims {
    pub iss: String,
    pub sub: String,
    #[serde(default)]
    pub aud: Value,
    pub exp: i64,
    pub nonce: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub preferred_username: Option<String>,
    #[serde(flatten)]
    pub additional_claims: Map<String, Value>,
}

/// Normalized local profile fields derived from a verified upstream identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcUpstreamProfile {
    pub external_subject: String,
    pub username: String,
    pub email: String,
    pub email_verified: bool,
}

/// Merge UserInfo fields only after its subject has been bound to a verified ID Token subject.
pub fn merge_oidc_upstream_userinfo(
    mut id_token_claims: OidcUpstreamIdTokenClaims,
    userinfo: &Value,
) -> Result<OidcUpstreamIdTokenClaims, String> {
    let claims = userinfo
        .as_object()
        .ok_or_else(|| "OIDC UserInfo response must be a JSON object".to_string())?;
    let subject = claims
        .get("sub")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "OIDC UserInfo response is missing subject".to_string())?;
    if subject != id_token_claims.sub {
        return Err("OIDC UserInfo subject does not match the ID Token".to_string());
    }

    if id_token_claims.email.is_none() {
        id_token_claims.email = claims
            .get("email")
            .and_then(Value::as_str)
            .map(str::to_string);
    }
    if id_token_claims.preferred_username.is_none() {
        id_token_claims.preferred_username = claims
            .get("preferred_username")
            .and_then(Value::as_str)
            .map(str::to_string);
    }
    if id_token_claims.email_verified.is_none() {
        id_token_claims.email_verified = claims.get("email_verified").and_then(Value::as_bool);
    }
    for (name, value) in claims {
        if !matches!(
            name.as_str(),
            "sub" | "email" | "preferred_username" | "email_verified"
        ) {
            id_token_claims
                .additional_claims
                .entry(name.clone())
                .or_insert_with(|| value.clone());
        }
    }
    Ok(id_token_claims)
}

/// Map verified standard OIDC claims into safe local user fields for linking or JIT creation.
pub fn oidc_upstream_profile(
    claims: &OidcUpstreamIdTokenClaims,
) -> Result<OidcUpstreamProfile, String> {
    oidc_upstream_profile_with_mapping(claims, &Value::Object(Map::new()))
}

/// Apply an administrator-defined OIDC claim mapping after the ID Token has been verified.
pub fn oidc_upstream_profile_with_mapping(
    claims: &OidcUpstreamIdTokenClaims,
    claim_mapping: &Value,
) -> Result<OidcUpstreamProfile, String> {
    let mapping = parse_oidc_upstream_claim_mapping(claim_mapping)?;
    let external_subject = oidc_string_claim(claims, mapping.get("external_subject"), "sub")?;
    let email = oidc_string_claim(claims, mapping.get("email"), "email")?
        .trim()
        .to_ascii_lowercase();
    if !email.contains('@') {
        return Err("Upstream ID Token must contain a valid email for account mapping".to_string());
    }
    let candidate = mapping
        .get("username")
        .map(|claim_name| oidc_string_claim(claims, Some(claim_name), "preferred_username"))
        .transpose()?
        .or_else(|| claims.preferred_username.clone())
        .unwrap_or_else(|| email.split('@').next().unwrap_or("user").to_string());
    let username = candidate
        .chars()
        .filter_map(|character| {
            (character.is_ascii_alphanumeric()
                || character == '_'
                || character == '-'
                || character == '.')
                .then_some(character.to_ascii_lowercase())
        })
        .collect::<String>();
    if username.is_empty() {
        return Err("Upstream identity does not provide a usable username".to_string());
    }
    Ok(OidcUpstreamProfile {
        external_subject,
        username,
        email,
        email_verified: oidc_bool_claim(claims, mapping.get("email_verified"), "email_verified")?
            .unwrap_or(false),
    })
}

/// Validate the small, fixed mapping contract instead of accepting arbitrary local profile fields.
pub fn parse_oidc_upstream_claim_mapping(
    mapping: &Value,
) -> Result<BTreeMap<String, String>, String> {
    let object = mapping
        .as_object()
        .ok_or_else(|| "OIDC claim_mapping must be a JSON object".to_string())?;
    let mut parsed = BTreeMap::new();
    for (target, value) in object {
        if !matches!(
            target.as_str(),
            "external_subject" | "email" | "username" | "email_verified"
        ) {
            return Err(format!("OIDC claim_mapping does not support '{}'", target));
        }
        let source = value
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty() && !value.chars().any(char::is_whitespace))
            .ok_or_else(|| format!("OIDC claim_mapping '{}' must name one claim", target))?;
        parsed.insert(target.clone(), source.to_string());
    }
    Ok(parsed)
}

/// Read a string claim from the standard OIDC fields or from signed custom claims.
fn oidc_string_claim(
    claims: &OidcUpstreamIdTokenClaims,
    mapped_name: Option<&String>,
    default_name: &str,
) -> Result<String, String> {
    let name = mapped_name.map(String::as_str).unwrap_or(default_name);
    let value = match name {
        "sub" => Some(claims.sub.clone()),
        "email" => claims.email.clone(),
        "preferred_username" => claims.preferred_username.clone(),
        _ => claims
            .additional_claims
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_string),
    };
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("Upstream ID Token is missing mapped '{}' claim", name))
}

/// Read an optional boolean verification claim without coercing strings such as "true".
fn oidc_bool_claim(
    claims: &OidcUpstreamIdTokenClaims,
    mapped_name: Option<&String>,
    default_name: &str,
) -> Result<Option<bool>, String> {
    let name = mapped_name.map(String::as_str).unwrap_or(default_name);
    let value = match name {
        "email_verified" => claims.email_verified,
        _ => claims.additional_claims.get(name).and_then(Value::as_bool),
    };
    if mapped_name.is_some() && value.is_none() {
        return Err(format!(
            "Upstream ID Token is missing mapped '{}' boolean claim",
            name
        ));
    }
    Ok(value)
}

#[derive(Debug, Deserialize)]
pub struct OidcUpstreamJwks {
    pub keys: Vec<OidcUpstreamJwk>,
}

#[derive(Debug, Deserialize)]
pub struct OidcUpstreamJwk {
    pub kid: Option<String>,
    pub kty: String,
    pub n: Option<String>,
    pub e: Option<String>,
}

/// Verify an RS256 upstream ID Token using the JWK selected by its required key id.
pub fn verify_oidc_upstream_id_token(
    id_token: &str,
    jwks: &OidcUpstreamJwks,
) -> Result<OidcUpstreamIdTokenClaims, String> {
    let header =
        decode_header(id_token).map_err(|_| "Upstream ID Token header is invalid".to_string())?;
    if header.alg != Algorithm::RS256 {
        return Err("Upstream ID Token must use RS256".to_string());
    }
    let kid = header
        .kid
        .ok_or_else(|| "Upstream ID Token is missing kid".to_string())?;
    let jwk = jwks
        .keys
        .iter()
        .find(|jwk| jwk.kid.as_deref() == Some(kid.as_str()) && jwk.kty == "RSA")
        .ok_or_else(|| "Upstream ID Token signing key is unavailable".to_string())?;
    let key = DecodingKey::from_rsa_components(
        jwk.n
            .as_deref()
            .ok_or_else(|| "Upstream RSA JWK is missing modulus".to_string())?,
        jwk.e
            .as_deref()
            .ok_or_else(|| "Upstream RSA JWK is missing exponent".to_string())?,
    )
    .map_err(|_| "Upstream RSA JWK is invalid".to_string())?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    decode::<OidcUpstreamIdTokenClaims>(id_token, &key, &validation)
        .map(|data| data.claims)
        .map_err(|_| "Upstream ID Token signature or expiry is invalid".to_string())
}

/// Validate issuer, audience, expiry, and nonce after cryptographic signature validation.
pub fn validate_oidc_upstream_id_token_claims(
    claims: &OidcUpstreamIdTokenClaims,
    issuer: &str,
    client_id: &str,
    nonce_hash: &str,
    now: i64,
) -> Result<(), String> {
    if claims.iss != issuer || claims.sub.trim().is_empty() {
        return Err("Upstream ID Token issuer or subject is invalid".to_string());
    }
    let audience_matches = claims.aud.as_str() == Some(client_id)
        || claims
            .aud
            .as_array()
            .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(client_id)));
    if !audience_matches || claims.exp <= now {
        return Err("Upstream ID Token audience or expiry is invalid".to_string());
    }
    let nonce = claims
        .nonce
        .as_deref()
        .ok_or_else(|| "Upstream ID Token nonce is missing".to_string())?;
    if hex::encode(Sha256::digest(nonce.as_bytes())) != nonce_hash {
        return Err(
            "Upstream ID Token nonce does not match the authorization transaction".to_string(),
        );
    }
    Ok(())
}

/// Generate independent state, nonce, and PKCE S256 material for an upstream login.
pub fn new_oidc_upstream_authorization_state() -> OidcUpstreamAuthorizationState {
    let state = Uuid::new_v4().simple().to_string();
    let nonce = Uuid::new_v4().simple().to_string();
    let code_verifier = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    OidcUpstreamAuthorizationState {
        state,
        nonce,
        code_verifier,
        code_challenge,
    }
}

/// Build the standard Discovery address from the previously validated issuer.
pub fn oidc_discovery_url(issuer: &str) -> String {
    format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    )
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

/// Validate Discovery metadata against the registered issuer before it drives redirects or token calls.
pub fn parse_oidc_upstream_discovery(
    registered_issuer: &str,
    discovery: &Value,
) -> Result<OidcUpstreamDiscovery, String> {
    let parsed: OidcUpstreamDiscovery = serde_json::from_value(discovery.clone())
        .map_err(|_| "OIDC Discovery document is missing required endpoints".to_string())?;
    if parsed.issuer != registered_issuer {
        return Err("OIDC Discovery issuer does not match the registered issuer".to_string());
    }
    for (label, endpoint) in [
        ("authorization_endpoint", &parsed.authorization_endpoint),
        ("token_endpoint", &parsed.token_endpoint),
        ("jwks_uri", &parsed.jwks_uri),
    ] {
        if !endpoint.starts_with("https://") || endpoint.contains('#') {
            return Err(format!(
                "OIDC Discovery {label} must be an HTTPS URL without fragment"
            ));
        }
    }
    if let Some(endpoint) = &parsed.userinfo_endpoint {
        if !endpoint.starts_with("https://") || endpoint.contains('#') {
            return Err(
                "OIDC Discovery userinfo_endpoint must be an HTTPS URL without fragment"
                    .to_string(),
            );
        }
    }
    if !parsed
        .response_types_supported
        .iter()
        .any(|response_type| response_type == "code")
    {
        return Err("OIDC Discovery must support response_type code".to_string());
    }
    if parsed
        .grant_types_supported
        .as_ref()
        .is_some_and(|grant_types| {
            !grant_types
                .iter()
                .any(|grant_type| grant_type == "authorization_code")
        })
    {
        return Err("OIDC Discovery must support authorization_code".to_string());
    }
    if parsed
        .token_endpoint_auth_methods_supported
        .as_ref()
        .is_some_and(|methods| !methods.iter().any(|method| method == "client_secret_basic"))
    {
        return Err(
            "OIDC Discovery must support token_endpoint_auth_method client_secret_basic"
                .to_string(),
        );
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::redact_sensitive_values;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use serde_json::json;
    use sha2::{Digest, Sha256};

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

    #[test]
    fn oidc_discovery_requires_matching_issuer_and_code_flow() {
        let document = json!({
            "issuer": "https://idp.example/realms/acme",
            "authorization_endpoint": "https://idp.example/realms/acme/protocol/openid-connect/auth",
            "token_endpoint": "https://idp.example/realms/acme/protocol/openid-connect/token",
            "jwks_uri": "https://idp.example/realms/acme/protocol/openid-connect/certs",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"]
        });
        assert!(
            super::parse_oidc_upstream_discovery("https://idp.example/realms/acme", &document)
                .is_ok()
        );

        let invalid = json!({
            "issuer": "https://other.example",
            "authorization_endpoint": "https://idp.example/auth",
            "token_endpoint": "https://idp.example/token",
            "jwks_uri": "https://idp.example/jwks",
            "response_types_supported": ["token"]
        });
        assert!(
            super::parse_oidc_upstream_discovery("https://idp.example/realms/acme", &invalid)
                .is_err()
        );
    }

    #[test]
    fn oidc_discovery_rejects_an_incompatible_token_client_authentication_method() {
        let discovery = json!({
            "issuer": "https://idp.example/realms/acme",
            "authorization_endpoint": "https://idp.example/realms/acme/protocol/openid-connect/auth",
            "token_endpoint": "https://idp.example/realms/acme/protocol/openid-connect/token",
            "jwks_uri": "https://idp.example/realms/acme/protocol/openid-connect/certs",
            "response_types_supported": ["code"],
            "token_endpoint_auth_methods_supported": ["private_key_jwt"]
        });

        let error =
            super::parse_oidc_upstream_discovery("https://idp.example/realms/acme", &discovery)
                .unwrap_err();

        assert!(error.contains("client_secret_basic"));
    }

    #[test]
    fn upstream_authorization_state_uses_distinct_pkce_material() {
        let first = super::new_oidc_upstream_authorization_state();
        let second = super::new_oidc_upstream_authorization_state();

        assert_ne!(first.state, second.state);
        assert_ne!(first.nonce, first.state);
        assert_eq!(first.code_verifier.len(), 64);
        assert_eq!(
            first.code_challenge,
            URL_SAFE_NO_PAD.encode(Sha256::digest(first.code_verifier.as_bytes()))
        );
    }

    #[test]
    fn upstream_id_token_claims_require_matching_nonce_and_audience() {
        let nonce = "nonce-1";
        let claims = super::OidcUpstreamIdTokenClaims {
            iss: "https://idp.example".to_string(),
            sub: "user-1".to_string(),
            aud: json!(["keylo-client"]),
            exp: 2_000,
            nonce: Some(nonce.to_string()),
            email: None,
            email_verified: None,
            preferred_username: None,
            additional_claims: serde_json::Map::new(),
        };
        let nonce_hash = hex::encode(Sha256::digest(nonce.as_bytes()));

        assert!(super::validate_oidc_upstream_id_token_claims(
            &claims,
            "https://idp.example",
            "keylo-client",
            &nonce_hash,
            1_000,
        )
        .is_ok());
        assert!(super::validate_oidc_upstream_id_token_claims(
            &claims,
            "https://idp.example",
            "wrong-client",
            &nonce_hash,
            1_000,
        )
        .is_err());
    }

    #[test]
    fn upstream_profile_normalizes_email_and_username() {
        let claims = super::OidcUpstreamIdTokenClaims {
            iss: "https://idp.example".to_string(),
            sub: "external-1".to_string(),
            aud: json!("keylo"),
            exp: 2_000,
            nonce: None,
            email: Some(" Alice@Example.COM ".to_string()),
            email_verified: Some(true),
            preferred_username: Some("Alice Smith!".to_string()),
            additional_claims: serde_json::Map::new(),
        };
        let profile = super::oidc_upstream_profile(&claims).unwrap();
        assert_eq!(profile.email, "alice@example.com");
        assert_eq!(profile.username, "alicesmith");
        assert!(profile.email_verified);
    }

    #[test]
    fn upstream_profile_uses_signed_custom_claim_mapping() {
        let claims = super::OidcUpstreamIdTokenClaims {
            iss: "https://idp.example".to_string(),
            sub: "ignored-subject".to_string(),
            aud: json!("keylo"),
            exp: 2_000,
            nonce: None,
            email: None,
            email_verified: None,
            preferred_username: None,
            additional_claims: serde_json::from_value(json!({
                "employee_id": "E-17",
                "work_email": "SAM@EXAMPLE.COM",
                "login_name": "Sam Example",
                "work_email_verified": true
            }))
            .unwrap(),
        };
        let mapping = json!({
            "external_subject": "employee_id",
            "email": "work_email",
            "username": "login_name",
            "email_verified": "work_email_verified"
        });

        let profile = super::oidc_upstream_profile_with_mapping(&claims, &mapping).unwrap();

        assert_eq!(profile.external_subject, "E-17");
        assert_eq!(profile.email, "sam@example.com");
        assert_eq!(profile.username, "samexample");
        assert!(profile.email_verified);
    }

    #[test]
    fn upstream_claim_mapping_rejects_unknown_local_fields() {
        let error =
            super::parse_oidc_upstream_claim_mapping(&json!({"role": "groups"})).unwrap_err();

        assert!(error.contains("does not support"));
    }

    #[test]
    fn userinfo_fills_missing_profile_claims_after_subject_binding() {
        let claims = super::OidcUpstreamIdTokenClaims {
            iss: "https://idp.example".to_string(),
            sub: "external-1".to_string(),
            aud: json!("keylo"),
            exp: 2_000,
            nonce: None,
            email: None,
            email_verified: None,
            preferred_username: None,
            additional_claims: serde_json::Map::new(),
        };
        let userinfo = json!({
            "sub": "external-1",
            "email": "alice@example.com",
            "email_verified": true,
            "preferred_username": "alice",
            "employee_id": "E-17"
        });

        let merged = super::merge_oidc_upstream_userinfo(claims, &userinfo).unwrap();

        assert_eq!(merged.email.as_deref(), Some("alice@example.com"));
        assert_eq!(merged.additional_claims["employee_id"], "E-17");
        assert_eq!(merged.email_verified, Some(true));
    }

    #[test]
    fn userinfo_rejects_a_different_subject() {
        let claims = super::OidcUpstreamIdTokenClaims {
            iss: "https://idp.example".to_string(),
            sub: "external-1".to_string(),
            aud: json!("keylo"),
            exp: 2_000,
            nonce: None,
            email: None,
            email_verified: None,
            preferred_username: None,
            additional_claims: serde_json::Map::new(),
        };

        let error =
            super::merge_oidc_upstream_userinfo(claims, &json!({"sub": "external-2"})).unwrap_err();

        assert!(error.contains("does not match"));
    }
}
