use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

pub const CUSTOMER_SUPPORT_ROLE_NAME: &str = "customer_support";
pub const CUSTOMER_SUPPORT_MAX_REASON_LENGTH: usize = 1000;
pub const CUSTOMER_SUPPORT_MAX_DENIAL_REASON_LENGTH: usize = 200;
pub const CUSTOMER_SUPPORT_UNKNOWN_REASON_SNAPSHOT: &str = "unavailable";

pub const CUSTOMER_SUPPORT_OPERATION_ORGANIZATION_READ: &str = "organization.read";
pub const CUSTOMER_SUPPORT_OPERATION_MEMBERSHIP_READ: &str = "membership.read";
pub const CUSTOMER_SUPPORT_OPERATION_AUTHORIZATION_AUDIT_READ: &str = "authorization_audit.read";
pub const CUSTOMER_SUPPORT_OPERATION_REFRESH_SESSION_READ: &str = "refresh_session.read";
pub const CUSTOMER_SUPPORT_OPERATION_RESOURCE_READ: &str = "resource.read";
pub const CUSTOMER_SUPPORT_SUPPORTED_OPERATIONS: [&str; 5] = [
    CUSTOMER_SUPPORT_OPERATION_ORGANIZATION_READ,
    CUSTOMER_SUPPORT_OPERATION_MEMBERSHIP_READ,
    CUSTOMER_SUPPORT_OPERATION_AUTHORIZATION_AUDIT_READ,
    CUSTOMER_SUPPORT_OPERATION_REFRESH_SESSION_READ,
    CUSTOMER_SUPPORT_OPERATION_RESOURCE_READ,
];

pub const CUSTOMER_SUPPORT_AUDIT_OPERATION_GRANT_CREATED: &str = "grant.created";
pub const CUSTOMER_SUPPORT_AUDIT_OPERATION_GRANT_REVOKED: &str = "grant.revoked";
pub const CUSTOMER_SUPPORT_AUDIT_OPERATION_CONTEXT_ISSUED: &str = "context.issued";
pub const CUSTOMER_SUPPORT_AUDIT_OUTCOME_ALLOW: &str = "allow";
pub const CUSTOMER_SUPPORT_AUDIT_OUTCOME_DENY: &str = "deny";

pub const CUSTOMER_SUPPORT_TARGET_TYPE_ORGANIZATION: &str = "organization";
pub const CUSTOMER_SUPPORT_TARGET_TYPE_MEMBERSHIP: &str = "membership";
pub const CUSTOMER_SUPPORT_TARGET_TYPE_AUTHORIZATION_AUDIT_LOG: &str = "authorization_audit_log";
pub const CUSTOMER_SUPPORT_TARGET_TYPE_REFRESH_SESSION: &str = "refresh_session";
pub const CUSTOMER_SUPPORT_TARGET_TYPE_RESOURCE: &str = "resource";
pub const CUSTOMER_SUPPORT_TARGET_TYPE_ACCESS_GRANT: &str = "customer_support_access_grant";

pub const CUSTOMER_SUPPORT_DENIAL_GRANT_NOT_FOUND: &str = "customer_support_grant_not_found";
pub const CUSTOMER_SUPPORT_DENIAL_PRINCIPAL_MISMATCH: &str = "customer_support_principal_mismatch";
pub const CUSTOMER_SUPPORT_DENIAL_ORGANIZATION_MISMATCH: &str =
    "customer_support_organization_mismatch";
pub const CUSTOMER_SUPPORT_DENIAL_GRANT_REVOKED: &str = "customer_support_grant_revoked";
pub const CUSTOMER_SUPPORT_DENIAL_GRANT_EXPIRED: &str = "customer_support_grant_expired";
pub const CUSTOMER_SUPPORT_DENIAL_ORGANIZATION_NOT_FOUND: &str =
    "customer_support_organization_not_found";
pub const CUSTOMER_SUPPORT_DENIAL_ORGANIZATION_NOT_CUSTOMER: &str =
    "customer_support_organization_not_customer";
pub const CUSTOMER_SUPPORT_DENIAL_ORGANIZATION_NOT_ACTIVE: &str =
    "customer_support_organization_not_active";
pub const CUSTOMER_SUPPORT_DENIAL_PRINCIPAL_NOT_FOUND: &str =
    "customer_support_principal_not_found";
pub const CUSTOMER_SUPPORT_DENIAL_PRINCIPAL_NOT_HUMAN: &str =
    "customer_support_principal_requires_user";
pub const CUSTOMER_SUPPORT_DENIAL_PRINCIPAL_NOT_ACTIVE: &str =
    "customer_support_principal_not_active";
pub const CUSTOMER_SUPPORT_DENIAL_PRINCIPAL_NOT_INTERNAL: &str =
    "customer_support_principal_requires_internal_employee";
pub const CUSTOMER_SUPPORT_DENIAL_ROLE_REQUIRED: &str = "customer_support_role_required";
pub const CUSTOMER_SUPPORT_DENIAL_OPERATION_NOT_ALLOWED: &str =
    "customer_support_operation_not_allowed";

/// Accept only the operations explicitly designed for customer support reads.
///
/// The grant table has the same closed database constraint; callers use this
/// helper before beginning a transaction so malformed requests fail early.
pub fn is_valid_customer_support_operation(operation: &str) -> bool {
    CUSTOMER_SUPPORT_SUPPORTED_OPERATIONS.contains(&operation)
}

/// Normalize, de-duplicate, and validate a requested support operation set.
///
/// A grant without an operation authorizes nothing, so empty and unknown sets
/// are rejected rather than being silently broadened or stored as inert data.
pub fn normalize_customer_support_operations(operations: &[String]) -> Result<Vec<String>, String> {
    if operations.is_empty() {
        return Err("customer_support_operations_required".to_string());
    }

    let mut normalized = Vec::with_capacity(operations.len());
    for operation in operations {
        let operation = operation.trim();
        if !is_valid_customer_support_operation(operation) {
            return Err("invalid_customer_support_operation".to_string());
        }
        if normalized.iter().any(|existing| existing == operation) {
            return Err("duplicate_customer_support_operation".to_string());
        }
        normalized.push(operation.to_string());
    }

    normalized.sort();
    Ok(normalized)
}

/// Normalize a human audit reason without allowing blank or unbounded entries.
pub fn normalize_customer_support_reason(reason: &str) -> Result<String, String> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err("customer_support_reason_required".to_string());
    }
    if reason.chars().count() > CUSTOMER_SUPPORT_MAX_REASON_LENGTH {
        return Err("customer_support_reason_too_long".to_string());
    }
    Ok(reason.to_string())
}

/// Tests whether an audit event is one of the bounded support event names.
pub fn is_valid_customer_support_audit_operation(operation: &str) -> bool {
    is_valid_customer_support_operation(operation)
        || matches!(
            operation,
            CUSTOMER_SUPPORT_AUDIT_OPERATION_GRANT_CREATED
                | CUSTOMER_SUPPORT_AUDIT_OPERATION_GRANT_REVOKED
                | CUSTOMER_SUPPORT_AUDIT_OPERATION_CONTEXT_ISSUED
        )
}

/// Maps each auditable support action to its only valid target category.
pub fn customer_support_target_type_for_operation(operation: &str) -> Option<&'static str> {
    match operation {
        CUSTOMER_SUPPORT_OPERATION_ORGANIZATION_READ => {
            Some(CUSTOMER_SUPPORT_TARGET_TYPE_ORGANIZATION)
        }
        CUSTOMER_SUPPORT_OPERATION_MEMBERSHIP_READ => Some(CUSTOMER_SUPPORT_TARGET_TYPE_MEMBERSHIP),
        CUSTOMER_SUPPORT_OPERATION_AUTHORIZATION_AUDIT_READ => {
            Some(CUSTOMER_SUPPORT_TARGET_TYPE_AUTHORIZATION_AUDIT_LOG)
        }
        CUSTOMER_SUPPORT_OPERATION_REFRESH_SESSION_READ => {
            Some(CUSTOMER_SUPPORT_TARGET_TYPE_REFRESH_SESSION)
        }
        CUSTOMER_SUPPORT_OPERATION_RESOURCE_READ => Some(CUSTOMER_SUPPORT_TARGET_TYPE_RESOURCE),
        CUSTOMER_SUPPORT_AUDIT_OPERATION_GRANT_CREATED
        | CUSTOMER_SUPPORT_AUDIT_OPERATION_GRANT_REVOKED
        | CUSTOMER_SUPPORT_AUDIT_OPERATION_CONTEXT_ISSUED => {
            Some(CUSTOMER_SUPPORT_TARGET_TYPE_ACCESS_GRANT)
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CustomerSupportAccessGrant {
    pub id: String,
    pub support_principal_id: String,
    pub organization_id: String,
    pub reason: String,
    pub granted_by_principal_id: String,
    pub granted_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
    pub revoked_at: Option<NaiveDateTime>,
    pub revoked_by_principal_id: Option<String>,
    pub revoke_reason: Option<String>,
}

/// A grant plus its normalized, closed operation list for API responses.
#[derive(Debug, Clone, Serialize)]
pub struct CustomerSupportAccessGrantDetail {
    #[serde(flatten)]
    pub grant: CustomerSupportAccessGrant,
    pub operations: Vec<String>,
}

/// Query parameters for an exact, bounded support-grant listing.
#[derive(Debug, Deserialize)]
pub struct CustomerSupportAccessGrantListQuery {
    pub organization_id: Option<String>,
    pub support_principal_id: Option<String>,
    pub granted_by_principal_id: Option<String>,
    pub include_revoked: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Request body for granting a support user narrow, temporary organization access.
#[derive(Debug, Deserialize)]
pub struct CreateCustomerSupportAccessGrantRequest {
    pub support_principal_id: String,
    pub organization_id: String,
    pub reason: String,
    pub operations: Vec<String>,
    pub expires_at: NaiveDateTime,
}

/// Request body for an idempotent support-grant revocation.
#[derive(Debug, Deserialize)]
pub struct RevokeCustomerSupportAccessGrantRequest {
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CustomerSupportAuditLog {
    pub id: String,
    pub grant_id: Option<String>,
    pub actor_principal_id: Option<String>,
    pub organization_id: String,
    pub operation: String,
    pub reason_snapshot: String,
    pub target_type: String,
    pub target_id: Option<String>,
    pub outcome: String,
    pub denial_reason: Option<String>,
    pub created_at: NaiveDateTime,
}

/// Query parameters for an exact, bounded customer-support audit listing.
#[derive(Debug, Deserialize)]
pub struct CustomerSupportAuditLogListQuery {
    pub organization_id: Option<String>,
    pub actor_principal_id: Option<String>,
    pub grant_id: Option<String>,
    pub operation: Option<String>,
    pub outcome: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// The live facts that make one support grant usable without tenant membership.
#[derive(Debug, Clone)]
pub struct CustomerSupportAccessContext {
    pub grant_id: String,
    pub support_principal_id: String,
    pub organization_id: String,
    pub reason: String,
    pub expires_at: NaiveDateTime,
    pub operations: Vec<String>,
}

/// A fail-closed result that gives route code a stable audit reason for every decision.
#[derive(Debug, Clone)]
pub struct CustomerSupportAccessDecision {
    pub allowed: bool,
    pub denial_reason: Option<String>,
    pub reason_snapshot: String,
    pub context: Option<CustomerSupportAccessContext>,
}

/// Input for a structured audit write. Callers must return an error when this write fails.
pub struct CreateCustomerSupportAuditLogParams<'a> {
    pub grant_id: Option<&'a str>,
    pub actor_principal_id: Option<&'a str>,
    pub organization_id: &'a str,
    pub operation: &'a str,
    pub reason_snapshot: &'a str,
    pub target_type: &'a str,
    pub target_id: Option<&'a str>,
    pub outcome: &'a str,
    pub denial_reason: Option<&'a str>,
}

/// Input for the transactional creation path; it intentionally contains no membership or session fields.
pub struct CreateCustomerSupportAccessGrantParams<'a> {
    pub support_principal_id: &'a str,
    pub organization_id: &'a str,
    pub reason: &'a str,
    pub granted_by_principal_id: &'a str,
    pub expires_at: NaiveDateTime,
    pub operations: &'a [String],
}
