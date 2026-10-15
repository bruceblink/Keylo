//! Real PostgreSQL regressions for the forced password-change authorization boundary.
//!
//! These tests deliberately require TEST_DATABASE_URL. Connection, migration,
//! bootstrap, or fixture errors must fail the test rather than select an
//! in-memory router or report a skipped test as successful.

use axum::http::StatusCode;
use axum_test::{TestResponse, TestServer};
use keylo::{config::Config, db, models, startup};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::LazyLock;

const INITIAL_PASSWORD: &str = "InitialPassword#123";
const TEMPORARY_PASSWORD: &str = "TemporaryPassword#123";
const FINAL_PASSWORD: &str = "FinalPassword#123";
const ADMIN_SECRET: &str = "AuthorizationRegressionAdmin#123";
const SERVICE_SECRET: &str = "AuthorizationRegressionService#123";

static JWT_KEYS: LazyLock<(String, String)> = LazyLock::new(|| {
    let private = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)
        .expect("Synthetic regression JWT key generation must succeed");
    let public = rsa::RsaPublicKey::from(&private);
    (
        private
            .to_pkcs8_pem(LineEnding::LF)
            .expect("Synthetic JWT private key encoding must succeed")
            .to_string(),
        public
            .to_public_key_pem(LineEnding::LF)
            .expect("Synthetic JWT public key encoding must succeed"),
    )
});

struct TestContext {
    pool: PgPool,
    server: TestServer,
    admin_id: String,
    suffix: String,
}

impl TestContext {
    async fn new() -> Self {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL must explicitly name an isolated PostgreSQL test database");
        assert!(
            !database_url.trim().is_empty(),
            "TEST_DATABASE_URL must not be empty"
        );
        let pool = db::init_db_pool(&database_url)
            .await
            .expect("The explicitly configured PostgreSQL test database must be reachable");
        db::run_migrations(&pool)
            .await
            .expect("PostgreSQL test database migrations must succeed");
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let admin_id = format!("password-auth-admin-{suffix}");
        let config = Config {
            jwt_private_key_pem: JWT_KEYS.0.clone(),
            jwt_public_key_pem: JWT_KEYS.1.clone(),
            jwt_keys_generated: false,
            environment: "test".to_string(),
            redis_url: None,
            enable_setup_wizard: false,
            enable_super_admin_bootstrap: false,
            auth_rate_limit_max_requests: 1000,
            auth_global_rate_limit_max_requests: 10_000,
            ..Default::default()
        };
        let app = startup::init_app_router_with_db_and_admin(
            config,
            &database_url,
            &admin_id,
            ADMIN_SECRET,
        )
        .await
        .expect("Database-backed HTTP router initialization must succeed");
        Self {
            pool,
            server: TestServer::new(app),
            admin_id,
            suffix,
        }
    }

    async fn employee(&self) -> models::User {
        let username = format!("password-auth-user-{}", self.suffix);
        let user = db::create_user(
            &self.pool,
            &username,
            &format!("{username}@example.test"),
            Some(INITIAL_PASSWORD),
        )
        .await
        .expect("Synthetic employee creation must succeed");
        db::promote_user_to_internal_employee(&self.pool, &user.id, Some(&self.admin_id))
            .await
            .expect("Synthetic employee promotion must succeed")
            .expect("Synthetic employee must exist")
    }

    async fn login(&self, username: &str, password: &str) -> Value {
        let response = self
            .server
            .post("/v1/auth/token")
            .json(&json!({"client_id": username, "client_secret": password}))
            .await;
        response.assert_status_ok();
        response.json()
    }

    async fn admin_token(&self) -> String {
        let response = self
            .server
            .post("/v1/admin/token")
            .json(&json!({"client_id": self.admin_id, "client_secret": ADMIN_SECRET}))
            .await;
        response.assert_status_ok();
        access_token(&response.json())
    }

    async fn permission(&self, label: &str) -> models::Permission {
        db::create_permission(
            &self.pool,
            &format!("regression:{label}:{}", self.suffix),
            Some("Synthetic password-change authorization regression"),
        )
        .await
        .expect("Regression permission creation must succeed")
    }

    async fn resource(
        &self,
        organization_id: Option<&str>,
        code: &str,
        permission: &models::Permission,
    ) -> models::Resource {
        db::create_resource_in_organization(
            &self.pool,
            organization_id,
            db::CreateResourceParams {
                app: &format!("password-auth-{}", self.suffix),
                resource_type: "menu",
                code,
                name: "Synthetic protected business resource",
                parent_id: None,
                display_order: 0,
                description: None,
                metadata: None,
                permission_ids: std::slice::from_ref(&permission.id),
            },
        )
        .await
        .expect("Regression resource creation and permission assignment must succeed")
    }

    async fn platform_role(&self, permission: &models::Permission) -> models::Role {
        let role = db::create_role(
            &self.pool,
            &format!("password-auth-role-{}", self.suffix),
            Some("Synthetic platform business reader"),
        )
        .await
        .expect("Regression role creation must succeed");
        db::assign_permission_to_role(&self.pool, &role.id, &permission.id)
            .await
            .expect("Regression role permission assignment must succeed");
        role
    }
}

fn access_token(body: &Value) -> String {
    body["access_token"]
        .as_str()
        .expect("Successful authentication must return an access token")
        .to_string()
}

fn assert_password_change_required(response: TestResponse) {
    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
    let body: Value = response.json();
    assert_eq!(body["error"], "password_change_required");
    assert_eq!(body["code"], 1022);
    for unexpected in ["success", "data", "allowed"] {
        assert!(body.get(unexpected).is_none());
    }
}

/// Every unified authorization entry point must reject a restricted human token,
/// even when its real Principal has a role that grants the requested resource.
async fn assert_restricted_authorization(
    server: &TestServer,
    token: &str,
    permission: &models::Permission,
    resource: &models::Resource,
) {
    let bearer = format!("Bearer {token}");
    assert_password_change_required(
        server
            .post("/v1/authorize/check")
            .add_header("Authorization", bearer.as_str())
            .json(&json!({"permission": permission.name}))
            .await,
    );
    assert_password_change_required(
        server
            .post("/v1/authorize/batch-check")
            .add_header("Authorization", bearer.as_str())
            .json(&json!({"checks": [{
                "app": resource.app,
                "resource_type": resource.resource_type,
                "resource_code": resource.code
            }]}))
            .await,
    );
    assert_password_change_required(
        server
            .get("/v1/principals/me/effective-permissions")
            .add_header("Authorization", bearer.as_str())
            .await,
    );
    assert_password_change_required(
        server
            .get(&format!(
                "/v1/principals/me/resource-tree?app={}&type=menu",
                resource.app
            ))
            .add_header("Authorization", bearer.as_str())
            .await,
    );
}

/// Normal bearer identities must retain granted and denied decisions, effective
/// permissions, and resource visibility across all four entry points.
async fn assert_normal_authorization(
    server: &TestServer,
    token: &str,
    granted: &models::Permission,
    denied: &models::Permission,
    resource: &models::Resource,
) {
    let bearer = format!("Bearer {token}");
    for (permission, expected) in [(granted, true), (denied, false)] {
        let response = server
            .post("/v1/authorize/check")
            .add_header("Authorization", bearer.as_str())
            .json(&json!({"permission": permission.name}))
            .await;
        response.assert_status_ok();
        assert_eq!(response.json::<Value>()["data"]["allowed"], expected);
    }
    let batch = server
        .post("/v1/authorize/batch-check")
        .add_header("Authorization", bearer.as_str())
        .json(&json!({"checks": [
            {"app": resource.app, "resource_type": resource.resource_type, "resource_code": resource.code},
            {"permission": denied.name}
        ]}))
        .await;
    batch.assert_status_ok();
    let batch: Value = batch.json();
    assert_eq!(batch["data"]["results"][0]["allowed"], true);
    assert_eq!(batch["data"]["results"][1]["allowed"], false);

    let effective = server
        .get("/v1/principals/me/effective-permissions")
        .add_header("Authorization", bearer.as_str())
        .await;
    effective.assert_status_ok();
    let effective: Value = effective.json();
    let permissions = effective["data"]["permissions"]
        .as_array()
        .expect("Effective permissions must be an array");
    assert!(permissions.iter().any(|item| item["id"] == granted.id));
    assert!(!permissions.iter().any(|item| item["id"] == denied.id));

    let tree = server
        .get(&format!(
            "/v1/principals/me/resource-tree?app={}&type=menu",
            resource.app
        ))
        .add_header("Authorization", bearer.as_str())
        .await;
    tree.assert_status_ok();
    let tree: Value = tree.json();
    let nodes = tree["data"]
        .as_array()
        .expect("Resource tree must be an array");
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0]["resource"]["id"], resource.id);
}

#[tokio::test]
async fn password_change_required_blocks_all_authorization_endpoints_until_password_changed() {
    let context = TestContext::new().await;
    let employee = context.employee().await;
    let granted = context.permission("business-read").await;
    let denied = context.permission("business-write").await;
    let role = context.platform_role(&granted).await;
    db::assign_role_to_user(&context.pool, &employee.id, &role.id)
        .await
        .expect("Synthetic employee business role assignment must succeed");
    let resource = context.resource(None, "dashboard", &granted).await;
    context.resource(None, "forbidden", &denied).await;

    let normal_login = context.login(&employee.username, INITIAL_PASSWORD).await;
    assert_ne!(normal_login["password_change_required"], true);
    assert_normal_authorization(
        &context.server,
        &access_token(&normal_login),
        &granted,
        &denied,
        &resource,
    )
    .await;

    let admin_token = context.admin_token().await;
    let reset = context
        .server
        .post(&format!("/v1/admin/users/{}/reset-password", employee.id))
        .add_header("Authorization", format!("Bearer {admin_token}"))
        .json(&json!({"password": TEMPORARY_PASSWORD}))
        .await;
    reset.assert_status_ok();
    let restricted_login = context.login(&employee.username, TEMPORARY_PASSWORD).await;
    assert_eq!(restricted_login["password_change_required"], true);
    let restricted_token = access_token(&restricted_login);
    assert_restricted_authorization(&context.server, &restricted_token, &granted, &resource).await;

    let change = context
        .server
        .post("/v1/user/change-password")
        .add_header("Authorization", format!("Bearer {restricted_token}"))
        .json(&json!({
            "current_password": TEMPORARY_PASSWORD,
            "new_password": FINAL_PASSWORD
        }))
        .await;
    change.assert_status_ok();
    let changed_employee = db::get_user_by_id(&context.pool, &employee.id)
        .await
        .expect("Updated employee lookup must succeed")
        .expect("Updated employee must exist");
    assert!(!changed_employee.password_change_required);

    // The signed restriction survives the database flag being cleared. The
    // caller must obtain a new unrestricted access token by authenticating.
    assert_restricted_authorization(&context.server, &restricted_token, &granted, &resource).await;
    let final_login = context.login(&employee.username, FINAL_PASSWORD).await;
    assert_ne!(final_login["password_change_required"], true);
    assert_normal_authorization(
        &context.server,
        &access_token(&final_login),
        &granted,
        &denied,
        &resource,
    )
    .await;
}

#[tokio::test]
async fn ordinary_human_authorization_preserves_organization_boundaries() {
    let context = TestContext::new().await;
    let employee = context.employee().await;
    let principal = db::get_principal_by_ref(&context.pool, "user", &employee.id)
        .await
        .expect("Employee principal lookup must succeed")
        .expect("Employee principal must exist");
    let mut organizations = Vec::new();
    for label in ["a", "b"] {
        organizations.push(
            db::create_organization(
                &context.pool,
                &format!("password-auth-{label}-{}", context.suffix),
                "Synthetic authorization tenant",
                models::ORGANIZATION_KIND_CUSTOMER,
            )
            .await
            .expect("Synthetic organization creation must succeed"),
        );
    }
    let organization = &organizations[0];
    db::upsert_organization_membership(
        &context.pool,
        &organization.id,
        &principal.id,
        "active",
        None,
        None,
    )
    .await
    .expect("Employee tenant membership must succeed");
    let granted = context.permission("tenant-read").await;
    let denied = context.permission("tenant-write").await;
    let role = db::create_organization_role(
        &context.pool,
        &format!("password-auth-tenant-reader-{}", context.suffix),
        None,
        "user",
    )
    .await
    .expect("Tenant role creation must succeed");
    db::assign_permission_to_role(&context.pool, &role.id, &granted.id)
        .await
        .expect("Tenant role permission assignment must succeed");
    db::assign_organization_role(
        &context.pool,
        &organization.id,
        &principal.id,
        &role.id,
        Some(&context.admin_id),
    )
    .await
    .expect("Employee tenant role assignment must succeed");
    let resource = context
        .resource(Some(&organization.id), "tenant-dashboard", &granted)
        .await;
    context
        .resource(Some(&organization.id), "tenant-forbidden", &denied)
        .await;
    let foreign = context
        .resource(Some(&organizations[1].id), "foreign-dashboard", &granted)
        .await;
    let login = context.login(&employee.username, INITIAL_PASSWORD).await;
    let platform_token = access_token(&login);
    let platform_check = context
        .server
        .post("/v1/authorize/check")
        .add_header("Authorization", format!("Bearer {platform_token}"))
        .json(&json!({"permission": granted.name}))
        .await;
    platform_check.assert_status_ok();
    assert_eq!(platform_check.json::<Value>()["data"]["allowed"], false);
    let organization_login = context
        .server
        .post("/v1/auth/organization-context")
        .add_header("Authorization", format!("Bearer {platform_token}"))
        .json(&json!({"organization_id": organization.id}))
        .await;
    organization_login.assert_status_ok();
    let token = access_token(&organization_login.json());
    assert_normal_authorization(&context.server, &token, &granted, &denied, &resource).await;
    let cross_tenant = context
        .server
        .post("/v1/authorize/check")
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "app": foreign.app,
            "resource_type": foreign.resource_type,
            "resource_code": foreign.code
        }))
        .await;
    cross_tenant.assert_status_ok();
    assert_eq!(cross_tenant.json::<Value>()["data"]["allowed"], false);
}

#[tokio::test]
async fn service_and_machine_authorization_preserve_existing_permission_decisions() {
    let context = TestContext::new().await;
    let granted = context.permission("machine-read").await;
    let denied = context.permission("machine-write").await;
    let role = context.platform_role(&granted).await;
    let resource = context.resource(None, "machine-dashboard", &granted).await;
    context.resource(None, "machine-forbidden", &denied).await;
    let service_id = format!("password-auth-service-{}", context.suffix);
    db::create_service_client(
        &context.pool,
        db::CreateServiceClientParams {
            service_id: &service_id,
            service_secret: SERVICE_SECRET,
            name: "Synthetic authorization service",
            description: None,
            organization_id: None,
            allowed_scopes: &["read".to_string()],
            allowed_audiences: &["admin-backend".to_string()],
            integration_type: "custom",
            introspection_allowed: false,
            token_ttl_seconds: None,
            owner: None,
            contact: None,
        },
    )
    .await
    .expect("Synthetic service creation must succeed");
    let principal = db::get_principal_by_ref(&context.pool, "service", &service_id)
        .await
        .expect("Service principal lookup must succeed")
        .expect("Service principal must exist");
    db::assign_role_to_principal(&context.pool, &principal.id, &role.id)
        .await
        .expect("Service business role assignment must succeed");
    let service_login = context
        .server
        .post("/v1/service/token")
        .json(&json!({
            "service_id": service_id,
            "service_secret": SERVICE_SECRET,
            "audience": "admin-backend",
            "scope": "read"
        }))
        .await;
    service_login.assert_status_ok();
    let service_token = access_token(&service_login.json());
    assert_normal_authorization(
        &context.server,
        &service_token,
        &granted,
        &denied,
        &resource,
    )
    .await;

    let device = db::create_device(
        &context.pool,
        db::CreateDeviceParams {
            device_id: &format!("password-auth-device-{}", context.suffix),
            display_name: "Synthetic authorization machine",
            organization_id: None,
        },
    )
    .await
    .expect("Synthetic machine creation must succeed");
    db::assign_role_to_principal(&context.pool, &device.principal_id, &role.id)
        .await
        .expect("Machine business role assignment must succeed");
    let credential = db::create_machine_credential(
        &context.pool,
        db::CreateMachineCredentialParams {
            principal_id: &device.principal_id,
            organization_id: None,
            created_by_principal_id: None,
            expires_at: None,
            allowed_scopes: &[models::MACHINE_AUTHORIZATION_SCOPE.to_string()],
            allowed_audiences: &[models::MACHINE_AUTHORIZATION_AUDIENCE.to_string()],
        },
    )
    .await
    .expect("Synthetic machine credential creation must succeed");
    for (permission, expected) in [(&granted, true), (&denied, false)] {
        let response = context
            .server
            .post("/v1/authorize/check")
            .add_header("x-api-key", credential.api_key.as_str())
            .json(&json!({"permission": permission.name}))
            .await;
        response.assert_status_ok();
        assert_eq!(response.json::<Value>()["data"]["allowed"], expected);
    }
    let batch = context
        .server
        .post("/v1/authorize/batch-check")
        .add_header("x-api-key", credential.api_key.as_str())
        .json(&json!({"checks": [
            {"app": resource.app, "resource_type": resource.resource_type, "resource_code": resource.code},
            {"permission": denied.name}
        ]}))
        .await;
    batch.assert_status_ok();
    let batch: Value = batch.json();
    assert_eq!(batch["data"]["results"][0]["allowed"], true);
    assert_eq!(batch["data"]["results"][1]["allowed"], false);
}
