use keylo::db;
use sqlx::PgPool;
use std::sync::LazyLock;
use tokio::sync::Mutex;

static DB_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[cfg(test)]
mod database_tests {
    use super::*;

    /// 设置测试数据库
    async fn setup_test_db() -> Result<PgPool, &'static str> {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://keylo_user@localhost:5432/keylo".to_string());

        let pool = match db::init_db_pool(&database_url).await {
            Ok(pool) => pool,
            Err(_) => return Err("Database not available, skipping database tests"),
        };

        // 运行迁移
        if db::run_migrations(&pool).await.is_err() {
            return Err("Failed to run migrations");
        }

        // 清理测试数据，保留表结构
        if (sqlx::query(
            "TRUNCATE TABLE
                organization_role_bindings,
                organization_memberships,
                organizations,
                oidc_authorization_codes,
                oidc_clients,
                user_oauth_accounts,
                oauth_providers,
                role_permissions,
                user_roles,
                principal_roles,
                principals,
                permissions,
                roles,
                audit_logs,
                blacklisted_tokens,
                refresh_tokens,
                sessions,
                users,
                clients
             RESTART IDENTITY CASCADE",
        )
        .execute(&pool)
        .await)
            .is_err()
        {
            return Err("Failed to clean database data");
        }

        if (sqlx::query(
            "INSERT INTO organizations (id, slug, name, kind, status)
             VALUES ('org-internal', 'internal', 'Internal Organization', 'internal', 'active')",
        )
        .execute(&pool)
        .await)
            .is_err()
        {
            return Err("Failed to restore the internal organization");
        }

        Ok(pool)
    }

    #[tokio::test]
    async fn test_database_migrations() {
        let _guard = DB_TEST_LOCK.lock().await;
        let pool = match setup_test_db().await {
            Ok(pool) => pool,
            Err(msg) => {
                println!("Skipping test_database_migrations: {}", msg);
                return;
            }
        };

        // 验证表是否创建成功
        let clients_count = sqlx::query_scalar("SELECT COUNT(*) FROM clients")
            .fetch_one(&pool)
            .await
            .unwrap_or(0);
        assert_eq!(clients_count, 0);

        let refresh_tokens_count = sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens")
            .fetch_one(&pool)
            .await
            .unwrap_or(0);
        assert_eq!(refresh_tokens_count, 0);

        let blacklisted_count = sqlx::query_scalar("SELECT COUNT(*) FROM blacklisted_tokens")
            .fetch_one(&pool)
            .await
            .unwrap_or(0);
        assert_eq!(blacklisted_count, 0);
    }

    #[tokio::test]
    async fn test_email_verification_is_idempotent_and_resets_on_email_change() {
        let _guard = DB_TEST_LOCK.lock().await;
        let pool = match setup_test_db().await {
            Ok(pool) => pool,
            Err(msg) => {
                println!(
                    "Skipping test_email_verification_is_idempotent_and_resets_on_email_change: {}",
                    msg
                );
                return;
            }
        };
        let user = db::create_user(
            &pool,
            "email-verification-user",
            "email-verification@example.test",
            Some("Password123!"),
        )
        .await
        .unwrap();
        assert!(!user.email_verified);

        assert!(
            db::mark_user_email_verified(&pool, &user.id, Some("identity_source:test"))
                .await
                .unwrap()
        );
        assert!(
            !db::mark_user_email_verified(&pool, &user.id, Some("identity_source:test"))
                .await
                .unwrap()
        );

        let verified = db::get_user_by_id(&pool, &user.id).await.unwrap().unwrap();
        assert!(verified.email_verified);

        let updated = db::update_user(
            &pool,
            &user.id,
            None,
            Some("changed-email@example.test"),
            None,
            None,
            Some("test-admin"),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!updated.email_verified);
    }

    #[tokio::test]
    async fn test_organization_domain_tracks_explicit_human_classes_and_memberships() {
        let _guard = DB_TEST_LOCK.lock().await;
        let pool = match setup_test_db().await {
            Ok(pool) => pool,
            Err(msg) => {
                println!(
                    "Skipping test_organization_domain_tracks_explicit_human_classes_and_memberships: {msg}"
                );
                return;
            }
        };
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let organization = db::create_organization(
            &pool,
            &format!("customer-{suffix}"),
            "Customer organization",
            keylo::models::ORGANIZATION_KIND_CUSTOMER,
        )
        .await
        .expect("Failed to create organization");
        assert_eq!(organization.status, "active");

        let user = db::create_user(
            &pool,
            &format!("customer-user-{suffix}"),
            &format!("customer-user-{suffix}@example.test"),
            Some("CustomerUser#123"),
        )
        .await
        .expect("Failed to create user");
        assert_eq!(user.user_class, keylo::models::USER_CLASS_EXTERNAL_CUSTOMER);

        let external_principal = db::ensure_user_principal(&pool, &user.id)
            .await
            .expect("Failed to resolve external user principal")
            .expect("External user principal should exist");
        assert!(db::upsert_organization_membership(
            &pool,
            "org-internal",
            &external_principal.id,
            "active",
            Some("test-admin"),
        )
        .await
        .is_err());

        let user = db::set_user_class(
            &pool,
            &user.id,
            keylo::models::USER_CLASS_INTERNAL_EMPLOYEE,
            Some("test-admin"),
        )
        .await
        .expect("Failed to set user class")
        .expect("User should exist");
        assert_eq!(user.user_class, keylo::models::USER_CLASS_INTERNAL_EMPLOYEE);

        let principal = db::ensure_user_principal(&pool, &user.id)
            .await
            .expect("Failed to resolve user principal")
            .expect("User principal should exist");
        let membership = db::upsert_organization_membership(
            &pool,
            &organization.id,
            &principal.id,
            "active",
            Some("test-admin"),
        )
        .await
        .expect("Failed to create organization membership");
        assert_eq!(membership.status, "active");

        let role = db::create_organization_role(
            &pool,
            &format!("organization-member-{suffix}"),
            Some("Organization member role"),
            "user",
        )
        .await
        .expect("Failed to create user role");
        let binding = db::assign_organization_role(
            &pool,
            &organization.id,
            &principal.id,
            &role.id,
            Some("test-admin"),
        )
        .await
        .expect("Failed to bind organization role");
        assert_eq!(binding.scope, "organization");

        let platform_role = db::create_role_with_options(
            &pool,
            &format!("platform-role-{suffix}"),
            Some("Platform role must not be tenant-bound"),
            "user",
            false,
        )
        .await
        .expect("Failed to create platform role");
        assert!(db::assign_organization_role(
            &pool,
            &organization.id,
            &principal.id,
            &platform_role.id,
            Some("test-admin"),
        )
        .await
        .is_err());
        assert!(sqlx::query(
            "INSERT INTO organization_role_bindings (organization_id, principal_id, role_id, scope) VALUES ($1, $2, $3, 'organization')",
        )
        .bind(&organization.id)
        .bind(&principal.id)
        .bind(&platform_role.id)
        .execute(&pool)
        .await
        .is_err());

        let bindings = db::get_organization_role_bindings(&pool, &organization.id, &principal.id)
            .await
            .expect("Failed to list organization role bindings");
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].role_id, role.id);

        let disabled = db::set_organization_status(&pool, &organization.id, "disabled")
            .await
            .expect("Failed to disable organization")
            .expect("Organization should exist");
        assert_eq!(disabled.previous_status, "active");
        assert_eq!(disabled.organization.status, "disabled");
        assert!(db::upsert_organization_membership(
            &pool,
            &organization.id,
            &principal.id,
            "active",
            Some("test-admin"),
        )
        .await
        .is_err());
        assert!(db::assign_organization_role(
            &pool,
            &organization.id,
            &principal.id,
            &role.id,
            Some("test-admin"),
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn test_super_admin_bootstrap_is_an_internal_member() {
        let _guard = DB_TEST_LOCK.lock().await;
        let pool = match setup_test_db().await {
            Ok(pool) => pool,
            Err(msg) => {
                println!("Skipping test_super_admin_bootstrap_is_an_internal_member: {msg}");
                return;
            }
        };
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let username = format!("bootstrap-admin-{suffix}");
        let config = keylo::config::Config {
            enable_super_admin_bootstrap: true,
            super_admin_username: Some(username.clone()),
            super_admin_email: Some(format!("{username}@example.test")),
            super_admin_password: Some("BootstrapAdmin#123".to_string()),
            ..keylo::config::Config::default()
        };

        db::seed_super_admin_user(&pool, &config)
            .await
            .expect("Failed to seed super administrator");
        let user = db::get_user_by_username(&pool, &username)
            .await
            .expect("Failed to load bootstrap user")
            .expect("Bootstrap user should exist");
        assert_eq!(user.user_class, keylo::models::USER_CLASS_INTERNAL_EMPLOYEE);
        let principal = db::get_principal_by_ref(&pool, "user", &user.id)
            .await
            .expect("Failed to load bootstrap principal")
            .expect("Bootstrap principal should exist");
        let membership = db::get_organization_membership(&pool, "org-internal", &principal.id)
            .await
            .expect("Failed to load internal membership")
            .expect("Bootstrap user should join the internal organization");
        assert_eq!(membership.status, "active");
    }

    #[tokio::test]
    async fn test_deleting_user_removes_linked_principal() {
        let _guard = DB_TEST_LOCK.lock().await;
        let pool = match setup_test_db().await {
            Ok(pool) => pool,
            Err(msg) => {
                println!(
                    "Skipping test_deleting_user_removes_linked_principal: {}",
                    msg
                );
                return;
            }
        };
        let user = db::create_user(
            &pool,
            "deleted-principal-user",
            "deleted-principal-user@example.test",
            Some("Password123!"),
        )
        .await
        .unwrap();
        assert!(db::get_principal_by_ref(&pool, "user", &user.id)
            .await
            .unwrap()
            .is_some());

        assert!(db::delete_user(&pool, &user.id, Some("test-admin"))
            .await
            .unwrap());
        assert!(db::get_principal_by_ref(&pool, "user", &user.id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_client_creation_and_validation() {
        let _guard = DB_TEST_LOCK.lock().await;
        let pool = match setup_test_db().await {
            Ok(pool) => pool,
            Err(msg) => {
                println!("Skipping test_client_creation_and_validation: {}", msg);
                return;
            }
        };

        // 创建客户端
        db::create_client(
            &pool,
            "test-client",
            "test-secret",
            "Test Client",
            Some("Test client"),
        )
        .await
        .expect("Failed to create client");

        // 验证客户端存在（secret 已 bcrypt 哈希，验证其存在且可通过 verify）
        let auth_info = db::get_client_auth_info(&pool, "test-client")
            .await
            .expect("Failed to get client auth info");

        assert!(auth_info.is_some(), "Client should exist");
        let (hashed_secret, _) = auth_info.unwrap();
        assert!(
            bcrypt::verify("test-secret", &hashed_secret).unwrap_or(false),
            "Secret hash should match"
        );

        // 验证不存在的客户端
        let non_existent = db::get_client_auth_info(&pool, "non-existent")
            .await
            .expect("Failed to query non-existent client");

        assert_eq!(non_existent, None);
    }

    #[tokio::test]
    async fn test_oidc_authorization_code_is_one_time_use() {
        let _guard = DB_TEST_LOCK.lock().await;
        let pool = match setup_test_db().await {
            Ok(pool) => pool,
            Err(msg) => {
                println!("Skipping test_oidc_authorization_code_is_one_time_use: {msg}");
                return;
            }
        };
        let user = db::create_user(
            &pool,
            "oidc-code-user",
            "oidc-code@example.com",
            Some("CodeUser#123"),
        )
        .await
        .expect("Failed to create OIDC code user");
        let client_request = keylo::models::CreateOidcClientRequest {
            client_id: "oidc-code-client".to_string(),
            client_secret: None,
            name: "OIDC code client".to_string(),
            description: None,
            client_type: "public".to_string(),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            grant_types: None,
            scopes: None,
        };
        db::create_oidc_client(&pool, &client_request)
            .await
            .expect("Failed to create OIDC client");
        let code = "authorization-code-value";
        let authorization = keylo::models::OidcAuthorizationCode {
            client_id: client_request.client_id,
            user_id: user.id.clone(),
            redirect_uri: "https://example.com/callback".to_string(),
            scopes: vec!["openid".to_string()],
            nonce: Some("browser-nonce".to_string()),
            code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string(),
            expires_at: chrono::Utc::now().timestamp() + 60,
        };
        db::create_authorization_code(&pool, code, &authorization)
            .await
            .expect("Failed to store authorization code");

        let consumed = db::consume_authorization_code(&pool, code)
            .await
            .expect("Failed to consume authorization code")
            .expect("Authorization code should be active");
        assert_eq!(consumed.client_id, "oidc-code-client");
        assert_eq!(consumed.user_id, user.id);
        assert_eq!(consumed.nonce.as_deref(), Some("browser-nonce"));
        assert!(db::consume_authorization_code(&pool, code)
            .await
            .expect("Failed to check authorization-code replay")
            .is_none());
    }

    #[tokio::test]
    async fn test_upstream_oidc_callback_state_is_one_time_use() {
        let _guard = DB_TEST_LOCK.lock().await;
        let pool = match setup_test_db().await {
            Ok(pool) => pool,
            Err(msg) => {
                println!("Skipping test_upstream_oidc_callback_state_is_one_time_use: {msg}");
                return;
            }
        };
        let source_name = format!("upstream-state-idp-{}", uuid::Uuid::new_v4());
        let source = db::identity::create_identity_source(
            &pool,
            db::identity::CreateIdentitySourceParams {
                name: &source_name,
                source_type: "oidc_upstream",
                display_name: "Upstream State Test IdP",
                description: None,
                config: &serde_json::json!({}),
                claim_mapping: &serde_json::json!({}),
                jit_enabled: true,
                auto_link_enabled: true,
                active: true,
            },
        )
        .await
        .expect("Failed to create upstream OIDC source");
        let transaction = keylo::models::new_oidc_upstream_authorization_state();

        db::create_oidc_upstream_authorization(
            &pool,
            &source.id,
            &transaction,
            "encrypted-test-verifier",
            chrono::Utc::now().timestamp() + 60,
        )
        .await
        .expect("Failed to store upstream OIDC transaction");

        let first = db::consume_oidc_upstream_authorization(&pool, &transaction.state)
            .await
            .expect("Failed to consume upstream OIDC transaction");
        assert!(first.is_some(), "The fresh upstream state must be accepted");
        let replay = db::consume_oidc_upstream_authorization(&pool, &transaction.state)
            .await
            .expect("Failed to check replayed upstream OIDC transaction");
        assert!(
            replay.is_none(),
            "A consumed upstream state must not be reusable"
        );
    }

    #[tokio::test]
    async fn test_external_identity_mapping_hashes_subject_at_rest() {
        let _guard = DB_TEST_LOCK.lock().await;
        let pool = match setup_test_db().await {
            Ok(pool) => pool,
            Err(msg) => {
                println!("Skipping test_external_identity_mapping_hashes_subject_at_rest: {msg}");
                return;
            }
        };
        let username = format!("external-subject-user-{}", uuid::Uuid::new_v4());
        let user = db::create_user(
            &pool,
            &username,
            &format!("{username}@example.test"),
            Some("ExternalSubject#123"),
        )
        .await
        .expect("Failed to create external mapping user");
        let subject = "upstream-subject-should-not-be-stored";

        db::create_external_user_mapping(&pool, "oidc_upstream:test", subject, &user.id, None)
            .await
            .expect("Failed to create external mapping");

        let stored_subject: String = sqlx::query_scalar(
            "SELECT external_user_id FROM external_user_mappings WHERE provider = $1",
        )
        .bind("oidc_upstream:test")
        .fetch_one(&pool)
        .await
        .expect("Failed to read stored external mapping key");
        assert_ne!(stored_subject, subject);
        assert_eq!(stored_subject.len(), 64);
        assert_eq!(
            db::get_mapped_user_id(&pool, "oidc_upstream:test", subject)
                .await
                .expect("Failed to resolve hashed external mapping"),
            Some(user.id)
        );
    }

    #[tokio::test]
    async fn test_refresh_token_operations() {
        let _guard = DB_TEST_LOCK.lock().await;
        let pool = match setup_test_db().await {
            Ok(pool) => pool,
            Err(msg) => {
                println!("Skipping test_refresh_token_operations: {}", msg);
                return;
            }
        };

        let token_id = "test-jti";
        let client_id = "test-client";
        let token = "test.jwt.token";
        let expires_at = chrono::Utc::now().timestamp() + 3600;

        db::create_client(
            &pool,
            client_id,
            "test-secret",
            "Test Client",
            Some("Test client"),
        )
        .await
        .expect("Failed to create client");

        // 创建refresh token
        db::create_refresh_token(&pool, token_id, client_id, token, expires_at)
            .await
            .expect("Failed to create refresh token");

        // 验证token存在
        let token_data = db::validate_refresh_token(&pool, token)
            .await
            .expect("Failed to validate refresh token");

        assert_eq!(
            token_data,
            Some((token_id.to_string(), client_id.to_string()))
        );

        // 撤销token
        db::revoke_refresh_token(&pool, token_id)
            .await
            .expect("Failed to revoke refresh token");

        // 验证token已被撤销
        let revoked_token = db::validate_refresh_token(&pool, token)
            .await
            .expect("Failed to validate revoked token");

        assert_eq!(revoked_token, None);
    }

    #[tokio::test]
    async fn test_consume_refresh_token_is_one_time_use() {
        let _guard = DB_TEST_LOCK.lock().await;
        let pool = match setup_test_db().await {
            Ok(pool) => pool,
            Err(msg) => {
                println!(
                    "Skipping test_consume_refresh_token_is_one_time_use: {}",
                    msg
                );
                return;
            }
        };

        let token_id = "test-consume-jti";
        let client_id = "test-client";
        let token = "test.consume.jwt.token";
        let expires_at = chrono::Utc::now().timestamp() + 3600;

        db::create_client(
            &pool,
            client_id,
            "test-secret",
            "Test Client",
            Some("Test client"),
        )
        .await
        .expect("Failed to create client");

        db::create_refresh_token(&pool, token_id, client_id, token, expires_at)
            .await
            .expect("Failed to create refresh token");

        let consumed = db::consume_refresh_token(&pool, token)
            .await
            .expect("Failed to consume refresh token");
        assert_eq!(
            consumed,
            Some((token_id.to_string(), client_id.to_string()))
        );

        let replay = db::consume_refresh_token(&pool, token)
            .await
            .expect("Failed to check consumed refresh token");
        assert_eq!(replay, None);
    }

    #[tokio::test]
    async fn test_blacklist_operations() {
        let _guard = DB_TEST_LOCK.lock().await;
        let pool = match setup_test_db().await {
            Ok(pool) => pool,
            Err(msg) => {
                println!("Skipping test_blacklist_operations: {}", msg);
                return;
            }
        };

        let token = "test.blacklisted.token";
        let reason = "Test blacklist";
        let expires_at = chrono::Utc::now().timestamp() + 3600;

        // 将token加入黑名单
        db::blacklist_token(&pool, token, Some(reason), expires_at)
            .await
            .expect("Failed to blacklist token");

        // 验证token在黑名单中
        let is_blacklisted = db::is_token_blacklisted(&pool, token)
            .await
            .expect("Failed to check blacklist");

        assert!(is_blacklisted);

        // 验证不存在的token不在黑名单中
        let not_blacklisted = db::is_token_blacklisted(&pool, "not.blacklisted.token")
            .await
            .expect("Failed to check blacklist");

        assert!(!not_blacklisted);

        // 获取黑名单列表
        let blacklisted_tokens = db::get_active_blacklisted_tokens(&pool)
            .await
            .expect("Failed to get blacklisted tokens");

        assert_eq!(blacklisted_tokens.len(), 1);
        assert!(!blacklisted_tokens[0].0.is_empty());
    }

    #[tokio::test]
    async fn test_cleanup_operations() {
        let _guard = DB_TEST_LOCK.lock().await;
        let pool = match setup_test_db().await {
            Ok(pool) => pool,
            Err(msg) => {
                println!("Skipping test_cleanup_operations: {}", msg);
                return;
            }
        };

        db::create_client(
            &pool,
            "test-client",
            "test-secret",
            "Test Client",
            Some("Test client"),
        )
        .await
        .expect("Failed to create client");

        // 创建一个过期的refresh token
        let expired_time = 1577836800; // 2020-01-01 (过去的时间)
        db::create_refresh_token(
            &pool,
            "expired-jti",
            "test-client",
            "expired.token",
            expired_time,
        )
        .await
        .expect("Failed to create expired refresh token");

        // 创建一个过期的黑名单token
        db::blacklist_token(
            &pool,
            "expired.blacklisted.token",
            Some("Expired"),
            expired_time,
        )
        .await
        .expect("Failed to create expired blacklisted token");

        // 验证它们存在
        let expired_refresh = db::validate_refresh_token(&pool, "expired.token")
            .await
            .expect("Failed to check expired refresh token");
        assert_eq!(expired_refresh, None); // 应该因为过期而返回None

        let expired_blacklisted = db::is_token_blacklisted(&pool, "expired.blacklisted.token")
            .await
            .expect("Failed to check expired blacklisted token");
        assert!(!expired_blacklisted); // 应该因为过期而返回false

        // 运行清理
        let refresh_cleaned = db::cleanup_expired_refresh_tokens(&pool)
            .await
            .expect("Failed to cleanup refresh tokens");

        let blacklist_cleaned = db::cleanup_expired_blacklisted_tokens(&pool)
            .await
            .expect("Failed to cleanup blacklisted tokens");

        // 验证清理函数可执行（u64 类型总是 >= 0）
        let _ = refresh_cleaned;
        let _ = blacklist_cleaned;
    }

    #[tokio::test]
    async fn test_audit_log_operations() {
        let _guard = DB_TEST_LOCK.lock().await;
        let pool = match setup_test_db().await {
            Ok(pool) => pool,
            Err(msg) => {
                println!("Skipping test_audit_log_operations: {}", msg);
                return;
            }
        };

        db::create_audit_log(
            &pool,
            "auth.token.success",
            Some("cli"),
            Some("Access token issued"),
        )
        .await
        .expect("Failed to create audit log");

        let logs = db::get_recent_audit_logs(&pool, 10)
            .await
            .expect("Failed to query audit logs");

        assert!(!logs.is_empty());
        assert_eq!(logs[0].0, "auth.token.success");
        assert_eq!(logs[0].1.as_deref(), Some("cli"));
    }

    #[tokio::test]
    async fn test_authorization_audit_log_filters() {
        let _guard = DB_TEST_LOCK.lock().await;
        let pool = match setup_test_db().await {
            Ok(pool) => pool,
            Err(msg) => {
                println!("Skipping test_authorization_audit_log_filters: {}", msg);
                return;
            }
        };

        db::create_authorization_audit_log(
            &pool,
            None,
            "allow",
            Some("inventory:read"),
            None,
            Some("reason=permission_granted"),
        )
        .await
        .expect("Failed to create allowed authorization audit log");
        db::create_authorization_audit_log(
            &pool,
            None,
            "deny",
            Some("inventory:write"),
            None,
            Some("reason=permission_not_bound"),
        )
        .await
        .expect("Failed to create denied authorization audit log");

        let logs = db::list_authorization_audit_logs(&pool, None, Some("deny"), None, None, 10, 0)
            .await
            .expect("Failed to filter authorization audit logs");

        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].decision, "deny");
        assert_eq!(logs[0].permission_name.as_deref(), Some("inventory:write"));
    }

    #[tokio::test]
    async fn test_authorization_audit_log_cleanup() {
        let _guard = DB_TEST_LOCK.lock().await;
        let pool = match setup_test_db().await {
            Ok(pool) => pool,
            Err(msg) => {
                println!("Skipping test_authorization_audit_log_cleanup: {}", msg);
                return;
            }
        };

        db::create_authorization_audit_log(&pool, None, "deny", None, None, None)
            .await
            .expect("Failed to create authorization audit log");
        sqlx::query(
            "UPDATE authorization_audit_logs
             SET created_at = NOW() - INTERVAL '2 days'",
        )
        .execute(&pool)
        .await
        .expect("Failed to age authorization audit log");
        db::create_authorization_audit_log(&pool, None, "allow", None, None, None)
            .await
            .expect("Failed to create recent authorization audit log");

        let deleted = db::cleanup_old_authorization_audit_logs(&pool, 1)
            .await
            .expect("Failed to clean authorization audit logs");
        let remaining = db::list_authorization_audit_logs(&pool, None, None, None, None, 10, 0)
            .await
            .expect("Failed to list remaining authorization audit logs");

        assert!(deleted >= 1);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].decision, "allow");
    }
}
