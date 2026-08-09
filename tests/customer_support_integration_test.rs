#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use axum_test::TestServer;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use chrono::{Duration, Utc};
    use keylo::{config::Config, db, startup};
    use serde_json::{json, Value};
    use sqlx::PgPool;

    const SUPPORT_TEST_ADMIN_CLIENT_ID: &str = "customer-support-integration-client";
    const SUPPORT_TEST_ADMIN_CLIENT_SECRET: &str = "CustomerSupportIntegration#123";
    const SUPPORT_USER_PASSWORD: &str = "CustomerSupportUser#123";

    /// Open the Docker-backed test database and apply the current migration set.
    ///
    /// Customer-support behavior depends on PostgreSQL constraints and live queries,
    /// so this test deliberately skips when TEST_DATABASE_URL is not configured
    /// instead of accidentally exercising the in-memory application fallback.
    async fn setup_support_test_pool() -> Option<PgPool> {
        let database_url = match std::env::var("TEST_DATABASE_URL") {
            Ok(database_url) => database_url,
            Err(_) => {
                eprintln!(
                    "Skipping customer-support integration test: TEST_DATABASE_URL is required"
                );
                return None;
            }
        };
        let pool = db::init_db_pool(&database_url)
            .await
            .expect("TEST_DATABASE_URL must reach the local Docker PostgreSQL database");
        db::run_migrations(&pool)
            .await
            .expect("Customer-support migrations must apply on the test database");
        Some(pool)
    }

    /// Configure one isolated human platform administrator for this test run.
    fn support_test_config(username: String, email: String) -> Config {
        Config {
            environment: "test".to_string(),
            redis_url: None,
            auth_rate_limit_max_requests: 1_000,
            auth_global_rate_limit_max_requests: 10_000,
            enable_setup_wizard: false,
            enable_super_admin_bootstrap: true,
            super_admin_username: Some(username),
            super_admin_email: Some(email),
            super_admin_password: Some("CustomerSupportAdmin#123".to_string()),
            ..Default::default()
        }
    }

    /// Decode only the signed JWT payload so the test can bind an MFA proof to its JTI.
    fn jwt_payload(token: &str) -> Value {
        let encoded_payload = token
            .split('.')
            .nth(1)
            .expect("JWT must contain a payload segment");
        let payload = URL_SAFE_NO_PAD
            .decode(encoded_payload)
            .expect("JWT payload must use URL-safe base64 without padding");
        serde_json::from_slice(&payload).expect("JWT payload must be JSON")
    }

    /// Persist a test-only recent MFA proof after the normal MFA checks are covered elsewhere.
    async fn enable_recent_mfa_for_token(pool: &PgPool, user_id: &str, token_jti: &str) {
        db::save_pending_totp_credential(pool, user_id, "customer-support-test-seed")
            .await
            .expect("Test administrator MFA enrollment should be saved");
        assert!(db::enable_totp_credential(pool, user_id, 0)
            .await
            .expect("Test administrator MFA enrollment should be enabled"));
        sqlx::query(
            "INSERT INTO mfa_recent_verifications (user_id, token_jti, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '10 minutes')
             ON CONFLICT (user_id, token_jti) DO UPDATE
             SET verified_at = NOW(), expires_at = EXCLUDED.expires_at",
        )
        .bind(user_id)
        .bind(token_jti)
        .execute(pool)
        .await
        .expect("Test administrator MFA proof should be recorded");
    }

    #[tokio::test]
    async fn customer_support_grant_is_live_tenant_bound_and_audited() {
        let Some(pool) = setup_support_test_pool().await else {
            return;
        };
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let admin_username = format!("customer-support-admin-{suffix}");
        let admin_email = format!("{admin_username}@example.test");
        let config = support_test_config(admin_username.clone(), admin_email);
        let database_url = std::env::var("TEST_DATABASE_URL").expect("test database URL exists");
        let server = TestServer::new(
            startup::init_app_router_with_db_and_admin(
                config,
                &database_url,
                SUPPORT_TEST_ADMIN_CLIENT_ID,
                SUPPORT_TEST_ADMIN_CLIENT_SECRET,
            )
            .await
            .expect("Docker-backed application router should start"),
        );

        let admin_login = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": admin_username,
                "client_secret": "CustomerSupportAdmin#123"
            }))
            .await;
        admin_login.assert_status_ok();
        let admin_token = admin_login.json::<Value>()["access_token"]
            .as_str()
            .expect("human administrator login must return an access token")
            .to_string();
        let admin_user = db::get_user_by_username(&pool, &admin_username)
            .await
            .expect("bootstrap administrator should be queryable")
            .expect("bootstrap administrator should exist");
        let admin_jti = jwt_payload(&admin_token)["jti"]
            .as_str()
            .expect("administrator access token should contain jti")
            .to_string();
        enable_recent_mfa_for_token(&pool, &admin_user.id, &admin_jti).await;

        let introspection_service_id = format!("customer-support-introspection-{suffix}");
        let service_scopes = vec!["read".to_string()];
        let service_audiences = vec!["admin-backend".to_string()];
        db::create_service_client(
            &pool,
            db::CreateServiceClientParams {
                service_id: &introspection_service_id,
                service_secret: "CustomerSupportIntrospection#123",
                name: "Customer support introspection service",
                description: None,
                organization_id: None,
                allowed_scopes: &service_scopes,
                allowed_audiences: &service_audiences,
                integration_type: "third_party",
                introspection_allowed: true,
                token_ttl_seconds: None,
                owner: None,
                contact: None,
            },
        )
        .await
        .expect("platform introspection service should be created");
        let service_login = server
            .post("/v1/service/token")
            .json(&json!({
                "service_id": introspection_service_id,
                "service_secret": "CustomerSupportIntrospection#123",
                "audience": "admin-backend",
                "scope": "read"
            }))
            .await;
        service_login.assert_status_ok();
        let introspection_service_token = service_login.json::<Value>()["access_token"]
            .as_str()
            .expect("introspection service token endpoint should return an access token")
            .to_string();

        let support_user = db::create_user(
            &pool,
            &format!("customer-support-user-{suffix}"),
            &format!("customer-support-user-{suffix}@example.test"),
            Some(SUPPORT_USER_PASSWORD),
        )
        .await
        .expect("support user should be created");
        let support_user = db::set_user_class(
            &pool,
            &support_user.id,
            keylo::models::USER_CLASS_INTERNAL_EMPLOYEE,
            Some("customer-support-integration-test"),
        )
        .await
        .expect("support user should be promoted to an internal employee")
        .expect("support user should still exist");
        let support_principal = db::get_principal_by_ref(&pool, "user", &support_user.id)
            .await
            .expect("support user principal should be queryable")
            .expect("support user principal should exist");
        let customer_support_role = db::get_role_by_name(&pool, "customer_support")
            .await
            .expect("customer_support role should be queryable")
            .expect("customer_support role should be installed by migration");
        db::assign_role_to_user(&pool, &support_user.id, &customer_support_role.id)
            .await
            .expect("internal support user should receive the fixed support role");

        let organization_a = db::create_organization(
            &pool,
            &format!("customer-support-a-{suffix}"),
            "Customer support organization A",
            keylo::models::ORGANIZATION_KIND_CUSTOMER,
        )
        .await
        .expect("first customer organization should be created");
        let organization_b = db::create_organization(
            &pool,
            &format!("customer-support-b-{suffix}"),
            "Customer support organization B",
            keylo::models::ORGANIZATION_KIND_CUSTOMER,
        )
        .await
        .expect("second customer organization should be created");
        assert!(
            db::get_active_organization_membership(
                &pool,
                &organization_a.id,
                &support_principal.id
            )
            .await
            .expect("support membership lookup should succeed")
            .is_none(),
            "customer support access must not be represented as customer membership"
        );

        let grant_response = server
            .post("/v1/admin/customer-support-grants")
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({
                "support_principal_id": support_principal.id,
                "organization_id": organization_a.id,
                "reason": "Investigate a customer-reported sign-in failure",
                "operations": ["organization.read"],
                "expires_at": (Utc::now() + Duration::minutes(10)).to_rfc3339()
            }))
            .await;
        grant_response.assert_status_ok();
        let grant_body = grant_response.json::<Value>();
        let grant_id = grant_body["data"]["id"]
            .as_str()
            .expect("grant creation should return its identifier")
            .to_string();
        assert_eq!(
            grant_body["data"]["operations"],
            json!(["organization.read"])
        );

        let grant_list_response = server
            .get(&format!(
                "/v1/admin/customer-support-grants?organization_id={}&limit=1&offset=0",
                organization_a.id
            ))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .await;
        grant_list_response.assert_status_ok();
        let grant_list_body = grant_list_response.json::<Value>();
        assert_eq!(grant_list_body["pagination"]["limit"], 1);
        assert_eq!(grant_list_body["pagination"]["offset"], 0);
        assert_eq!(grant_list_body["pagination"]["has_more"], false);

        let support_login = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": support_user.username,
                "client_secret": SUPPORT_USER_PASSWORD
            }))
            .await;
        support_login.assert_status_ok();
        let support_access_token = support_login.json::<Value>()["access_token"]
            .as_str()
            .expect("support user login should return an access token")
            .to_string();
        let context_response = server
            .post("/v1/customer-support/context")
            .add_header("Authorization", format!("Bearer {support_access_token}"))
            .json(&json!({ "grant_id": grant_id }))
            .await;
        context_response.assert_status_ok();
        let context_body = context_response.json::<Value>();
        assert!(
            context_body.get("refresh_token").is_none(),
            "the support context exchange must never mint a refresh token"
        );
        let context_token = context_body["access_token"]
            .as_str()
            .expect("context exchange should return a dedicated access token")
            .to_string();
        let context_claims = jwt_payload(&context_token);
        assert_eq!(context_claims["token_type"], "customer_support_access");
        assert_eq!(context_claims["organization_id"], organization_a.id);
        assert_eq!(context_claims["customer_support_grant_id"], grant_id);
        assert_eq!(context_claims["scope"], json!(["organization.read"]));

        let active_introspection = server
            .post("/v1/auth/introspect")
            .add_header(
                "Authorization",
                format!("Bearer {introspection_service_token}"),
            )
            .json(&json!({ "token": context_token }))
            .await;
        active_introspection.assert_status_ok();
        assert_eq!(active_introspection.json::<Value>()["active"], true);

        let allowed_read = server
            .get(&format!(
                "/v1/customer-support/organizations/{}",
                organization_a.id
            ))
            .add_header("Authorization", format!("Bearer {context_token}"))
            .await;
        allowed_read.assert_status_ok();
        assert_eq!(
            allowed_read.json::<Value>()["data"]["id"],
            organization_a.id
        );

        let cross_organization_read = server
            .get(&format!(
                "/v1/customer-support/organizations/{}",
                organization_b.id
            ))
            .add_header("Authorization", format!("Bearer {context_token}"))
            .await;
        assert_eq!(cross_organization_read.status_code(), StatusCode::FORBIDDEN);

        let revoke_response = server
            .delete(&format!("/v1/admin/customer-support-grants/{grant_id}"))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({ "reason": "Customer investigation is complete" }))
            .await;
        revoke_response.assert_status_ok();
        assert!(revoke_response.json::<Value>()["data"]["revoked_at"].is_string());

        let revoked_read = server
            .get(&format!(
                "/v1/customer-support/organizations/{}",
                organization_a.id
            ))
            .add_header("Authorization", format!("Bearer {context_token}"))
            .await;
        assert_eq!(revoked_read.status_code(), StatusCode::FORBIDDEN);

        let revoked_introspection = server
            .post("/v1/auth/introspect")
            .add_header(
                "Authorization",
                format!("Bearer {introspection_service_token}"),
            )
            .json(&json!({ "token": context_token }))
            .await;
        revoked_introspection.assert_status_ok();
        assert_eq!(revoked_introspection.json::<Value>()["active"], false);

        let audit_list_response = server
            .get(&format!(
                "/v1/admin/customer-support-audit-logs?grant_id={grant_id}"
            ))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .await;
        audit_list_response.assert_status_ok();
        let audit_list_body = audit_list_response.json::<Value>();
        assert!(audit_list_body["data"]
            .as_array()
            .is_some_and(|entries| entries.len() >= 5));
        assert_eq!(audit_list_body["pagination"]["limit"], 50);
        assert_eq!(audit_list_body["pagination"]["offset"], 0);
        assert_eq!(audit_list_body["pagination"]["has_more"], false);

        let audit_logs = db::list_customer_support_audit_logs(
            &pool,
            None,
            None,
            Some(&grant_id),
            None,
            None,
            100,
            0,
        )
        .await
        .expect("support audit logs should be queryable");
        assert!(audit_logs.iter().any(|entry| {
            entry.operation == "grant.created"
                && entry.outcome == "allow"
                && entry.target_id.as_deref() == Some(grant_id.as_str())
        }));
        assert!(audit_logs.iter().any(|entry| {
            entry.operation == "context.issued"
                && entry.outcome == "allow"
                && entry.actor_principal_id.as_deref() == Some(support_principal.id.as_str())
        }));
        assert!(audit_logs.iter().any(|entry| {
            entry.operation == "organization.read"
                && entry.outcome == "allow"
                && entry.organization_id == organization_a.id
        }));
        assert!(audit_logs.iter().any(|entry| {
            entry.operation == "organization.read"
                && entry.outcome == "deny"
                && entry.organization_id == organization_b.id
                && entry.denial_reason.as_deref() == Some("customer_support_organization_mismatch")
        }));
        assert!(audit_logs.iter().any(|entry| {
            entry.operation == "grant.revoked"
                && entry.outcome == "allow"
                && entry.target_id.as_deref() == Some(grant_id.as_str())
        }));
    }
}
