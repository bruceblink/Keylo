use serde::{Deserialize, Serialize};
use sqlx::FromRow;

pub const MAX_AUTHORIZE_BATCH_CHECKS: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Principal {
    pub id: String,
    pub principal_type: String,
    pub subject: String,
    pub ref_id: String,
    pub display_name: String,
    pub active: bool,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[derive(Debug, Deserialize)]
pub struct PrincipalListQuery {
    pub principal_type: Option<String>,
    pub active: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct PrincipalEffectivePermissionsResponse {
    pub principal: Principal,
    pub roles: Vec<crate::models::Role>,
    pub permissions: Vec<crate::models::Permission>,
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeCheckRequest {
    pub permission: Option<String>,
    pub app: Option<String>,
    pub resource_type: Option<String>,
    pub resource_code: Option<String>,
}

impl AuthorizeCheckRequest {
    /// Require exactly one unambiguous authorization target before it reaches the database.
    pub fn validate(&self) -> Result<(), String> {
        let permission = self.permission.as_deref().map(str::trim);
        if permission.is_some_and(str::is_empty) {
            return Err("permission must not be empty when provided".to_string());
        }
        let resource_fields = [
            self.app.as_deref(),
            self.resource_type.as_deref(),
            self.resource_code.as_deref(),
        ];
        let supplied_resource_fields = resource_fields
            .iter()
            .filter(|value| value.is_some())
            .count();
        if permission.is_some() && supplied_resource_fields > 0 {
            return Err("provide either permission or resource coordinates, not both".to_string());
        }
        if permission.is_none()
            && (supplied_resource_fields != resource_fields.len()
                || resource_fields
                    .iter()
                    .flatten()
                    .any(|value| value.trim().is_empty()))
        {
            return Err(
                "provide permission or non-empty app, resource_type, and resource_code".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeBatchCheckRequest {
    pub checks: Vec<AuthorizeCheckRequest>,
}

impl AuthorizeBatchCheckRequest {
    /// Keep one authorization request bounded so it cannot amplify database work without limits.
    pub fn validate(&self) -> Result<(), String> {
        if self.checks.is_empty() {
            return Err("checks must contain at least one authorization request".to_string());
        }
        if self.checks.len() > MAX_AUTHORIZE_BATCH_CHECKS {
            return Err(format!(
                "checks must not contain more than {MAX_AUTHORIZE_BATCH_CHECKS} authorization requests"
            ));
        }
        for check in &self.checks {
            check.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct AuthorizeCheckResponse {
    pub allowed: bool,
    pub decision: String,
    pub reason: String,
    pub principal_id: String,
    pub matched_permission: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthorizeBatchCheckResponse {
    pub results: Vec<AuthorizeCheckResponse>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check() -> AuthorizeCheckRequest {
        AuthorizeCheckRequest {
            permission: Some("system:read".to_string()),
            app: None,
            resource_type: None,
            resource_code: None,
        }
    }

    #[test]
    fn batch_authorization_validation_rejects_empty_and_oversized_requests() {
        assert!(AuthorizeBatchCheckRequest { checks: vec![] }
            .validate()
            .is_err());
        assert!(AuthorizeBatchCheckRequest {
            checks: (0..=MAX_AUTHORIZE_BATCH_CHECKS).map(|_| check()).collect(),
        }
        .validate()
        .is_err());
        assert!(AuthorizeBatchCheckRequest {
            checks: (0..MAX_AUTHORIZE_BATCH_CHECKS).map(|_| check()).collect(),
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn authorization_check_validation_requires_one_complete_target() {
        assert!(AuthorizeCheckRequest {
            permission: Some(" ".to_string()),
            app: None,
            resource_type: None,
            resource_code: None,
        }
        .validate()
        .is_err());
        assert!(AuthorizeCheckRequest {
            permission: Some("system:read".to_string()),
            app: Some("app".to_string()),
            resource_type: None,
            resource_code: None,
        }
        .validate()
        .is_err());
        assert!(AuthorizeCheckRequest {
            permission: None,
            app: Some("app".to_string()),
            resource_type: Some("service".to_string()),
            resource_code: None,
        }
        .validate()
        .is_err());
        assert!(AuthorizeCheckRequest {
            permission: None,
            app: Some("app".to_string()),
            resource_type: Some("service".to_string()),
            resource_code: Some("sync".to_string()),
        }
        .validate()
        .is_ok());
    }
}
