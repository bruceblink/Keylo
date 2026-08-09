use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

pub const ORGANIZATION_KIND_CUSTOMER: &str = "customer";
pub const ORGANIZATION_KIND_INTERNAL: &str = "internal";
pub const ORGANIZATION_STATUS_ACTIVE: &str = "active";
pub const ORGANIZATION_STATUS_DISABLED: &str = "disabled";
pub const ORGANIZATION_STATUS_ARCHIVED: &str = "archived";

/// Human account classes stay separate from machine Principal types.
pub const USER_CLASS_INTERNAL_EMPLOYEE: &str = "internal_employee";
pub const USER_CLASS_EXTERNAL_CUSTOMER: &str = "external_customer";
pub const ROLE_SCOPE_PLATFORM: &str = "platform";
pub const ROLE_SCOPE_ORGANIZATION: &str = "organization";
pub const ORGANIZATION_MANAGEMENT_ROLE_MEMBER: &str = "member";
pub const ORGANIZATION_MANAGEMENT_ROLE_ADMIN: &str = "admin";
pub const ORGANIZATION_MANAGEMENT_ROLE_OWNER: &str = "owner";

#[derive(Debug, Deserialize)]
pub struct OrganizationListQuery {
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct CreateOrganizationRequest {
    pub slug: String,
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateOrganizationStatusRequest {
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct UpsertOrganizationMembershipRequest {
    pub status: String,
    #[serde(default)]
    pub management_role: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct InviteOrganizationMemberRequest {
    pub principal_id: String,
    #[serde(default)]
    pub management_role: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateOrganizationMembershipRequest {
    pub status: String,
    #[serde(default)]
    pub management_role: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OrganizationRoleBindingRequest {
    pub role_id: String,
}

#[derive(Debug, Deserialize)]
pub struct OrganizationContextRequest {
    pub organization_id: String,
}

pub fn is_valid_organization_kind(kind: &str) -> bool {
    matches!(
        kind,
        ORGANIZATION_KIND_CUSTOMER | ORGANIZATION_KIND_INTERNAL
    )
}

pub fn is_valid_organization_status(status: &str) -> bool {
    matches!(
        status,
        ORGANIZATION_STATUS_ACTIVE | ORGANIZATION_STATUS_DISABLED | ORGANIZATION_STATUS_ARCHIVED
    )
}

pub fn is_valid_user_class(user_class: &str) -> bool {
    matches!(
        user_class,
        USER_CLASS_INTERNAL_EMPLOYEE | USER_CLASS_EXTERNAL_CUSTOMER
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Organization {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub kind: String,
    pub status: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct OrganizationMembership {
    pub organization_id: String,
    pub principal_id: String,
    pub status: String,
    pub joined_at: NaiveDateTime,
    pub invited_by: Option<String>,
    pub management_role: String,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct OrganizationRoleBinding {
    pub organization_id: String,
    pub principal_id: String,
    pub role_id: String,
    pub scope: String,
    pub assigned_at: NaiveDateTime,
    pub assigned_by: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organization_and_user_class_values_are_closed_sets() {
        assert!(is_valid_organization_kind(ORGANIZATION_KIND_CUSTOMER));
        assert!(is_valid_organization_kind(ORGANIZATION_KIND_INTERNAL));
        assert!(!is_valid_organization_kind("partner"));

        assert!(is_valid_organization_status(ORGANIZATION_STATUS_ACTIVE));
        assert!(is_valid_organization_status(ORGANIZATION_STATUS_DISABLED));
        assert!(is_valid_organization_status(ORGANIZATION_STATUS_ARCHIVED));
        assert!(!is_valid_organization_status("deleted"));

        assert!(is_valid_user_class(USER_CLASS_INTERNAL_EMPLOYEE));
        assert!(is_valid_user_class(USER_CLASS_EXTERNAL_CUSTOMER));
        assert!(!is_valid_user_class("device"));
    }
}
