use axum::body::Bytes;
use axum::http::StatusCode;
use axum_test::TestServer;
use keylo::config::Config;
use keylo::startup;
use serde_json::json;

const INTEGRATION_ADMIN_CLIENT_ID: &str = "cli-admin-root";
const INTEGRATION_ADMIN_CLIENT_SECRET: &str = "CliAdminRoot#123";

const TEST_JWT_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCsrVdCePdLh6/8
Xazk597DtrPS2rRHG/T8M9kfIequXrlRaYhwQkHLoGLK0Pn2wBmW5Ep81M3CRHCJ
Jzosqs6MYLfk2fr0Iwra0iBkNQx2vwEWmSZ3KZ4wGGRrlQI45vXOOAA2J6a1I6Ik
t8bV9N21jQ/pYDpI9SyHLvvHutZmyZHp0PGHNainUEddHsUqPUgwNpDsBl+v9fLV
OChsB382RTfX5tSd9s7IqhFROlOoWqdZm6+jRzIpusCYoKda6fxeBPC00E5eZNsV
PDBKbASFOrLTPvInucys4NiXY23e3U+OiZ6hSpWwMSy95HQOkVo34KGFWV0ZgaBv
K79AgyvDAgMBAAECggEAHEvljj+LasWn+aeSIwq6LwE8E5QCUdrLeR63+EmTDxL3
tFciZB7/cDJurgSzyZMuPlNXv4AR3cFgXaFff51X7poU2Hw+Cw7JAxXG+BTXX4gq
Uf0z1/gqc4AzyItpC1ERu8Liif1SbMGTmwfAniQbxtoAXwKFWppOuzJgURkVdE9T
WNd+waklRNBNO7abQBfP/qptyfRgaiGWT8ZNAWvlrwEY3MPcONfb9cvrIj4Oo4wK
MANT/vQOjMkvovtgkDH31WVAWdHWFZc7Weoo0b1edgwgc/pjMUVBXiPj0Ui9YH12
xPFOd3b9jTXmKmt5neXNLHJI9AaRtFXSG88fIGax6QKBgQDuCMhZxElQIgY9HRrz
Un5oQIxJ2AtMDuqW44zyBBwMxVRDaWDj6i2JN8H39KGPqMRNEzTzSYGPxaSRLRpB
1eWtAFpaVIkf02ruCbo9rdsFLaMoJY1SmIwk1AKTZ7GIqB00hlEr83H2Vy/JrWmq
zxYqAVKTakL1TFxokAxzs7th2wKBgQC5tb+4VM835n7r/QMkJeHv7naTZU85qUSn
P8fewEljF6PndKThm8StBBRCW6B0uaUE1ESsEClPRjaFtPF/BhIlmCkxaWpI0DEr
jfr/4SE1OmzNMZznl3aI4pNmBJiHWWneQuTgdHue/0uPOifbAn7elqfcfjzrxD3X
7HEYGMHGOQKBgF7YDwR9inysYfH949wp9YYSmhNeSvoOQ3jFyEYyTv7jrXSCy4Fk
sKopFld3GNzF8RmI2qNJmZ8wsCbMYtbypGYvatDtOAn/Um7wX03uNQO2MHlxpQLR
F54g/7m+KmX6HlDsZ/FsOe9exALG3wCZLQqlpkJop69XssZTBzMe3T3bAoGAJDym
sF08IfhEA+BW4JLTx3GMia5XCzVQRCJZ6ckziLZwMRW9ppgyhGArY9dlM+GVpZ+V
1s1Agkt9EBICnXqdx+AtCYs8RgD51znZJFzVkgFYgaGQsFAJvSQZBusWqDJ2Sfxb
lMCl7px6LfR3GnEeOGjFUG0Bji+4sY1ddApApWECgYBVjoNyfgQ/1vvJB3ZDXRrV
OdInx2dqATy+v1XXzSmHSkkE59SpDBex0mgDpBKfn1GJDCXeb5U9MAB7oAtGi8iJ
jwC3vnjXgXp6i1O/s7YjI4kfHYFZvKrYnDmjc2Ns/G2LgQF8LlRj+MJ4PVOqCIjr
RNDrJSwOaC4JLXavN61F6g==
-----END PRIVATE KEY-----"#;

const TEST_JWT_PUBLIC_KEY_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArK1XQnj3S4ev/F2s5Ofe
w7az0tq0Rxv0/DPZHyHqrl65UWmIcEJBy6BiytD59sAZluRKfNTNwkRwiSc6LKrO
jGC35Nn69CMK2tIgZDUMdr8BFpkmdymeMBhka5UCOOb1zjgANiemtSOiJLfG1fTd
tY0P6WA6SPUshy77x7rWZsmR6dDxhzWop1BHXR7FKj1IMDaQ7AZfr/Xy1TgobAd/
NkU31+bUnfbOyKoRUTpTqFqnWZuvo0cyKbrAmKCnWun8XgTwtNBOXmTbFTwwSmwE
hTqy0z7yJ7nMrODYl2Nt3t1PjomeoUqVsDEsveR0DpFaN+ChhVldGYGgbyu/QIMr
wwIDAQAB
-----END PUBLIC KEY-----"#;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::time::sleep;

    static TEST_PREFIX_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_config() -> Config {
        Config {
            jwt_private_key_pem: TEST_JWT_PRIVATE_KEY_PEM.to_string(),
            jwt_public_key_pem: TEST_JWT_PUBLIC_KEY_PEM.to_string(),
            environment: "test".to_string(),
            redis_url: None,
            auth_rate_limit_max_requests: 1000,
            auth_global_rate_limit_max_requests: 10_000,
            ..Default::default()
        }
    }

    /// 设置测试服务器（带数据库）
    async fn setup_test_server() -> TestServer {
        setup_test_server_with_config(test_config()).await
    }

    async fn setup_test_server_with_config(mut config: Config) -> TestServer {
        config.jwt_private_key_pem = TEST_JWT_PRIVATE_KEY_PEM.to_string();
        config.jwt_public_key_pem = TEST_JWT_PUBLIC_KEY_PEM.to_string();
        config.environment = "test".to_string();
        config.redis_url = None;
        config.redis_key_prefix = format!(
            "keylo-test-{}-{}",
            std::process::id(),
            TEST_PREFIX_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let database_url = std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
            "postgres://keylo_user:keylo_password@localhost:5432/keylo".to_string()
        });

        match startup::init_app_router_with_db_and_admin(
            config.clone(),
            &database_url,
            INTEGRATION_ADMIN_CLIENT_ID,
            INTEGRATION_ADMIN_CLIENT_SECRET,
        )
        .await
        {
            Ok(app) => TestServer::new(app),
            Err(_) => {
                let app = startup::init_app_router_with_config(config);
                TestServer::new(app)
            }
        }
    }

    #[tokio::test]
    async fn test_health_check() {
        let server = setup_test_server().await;

        let response = server.get("/").await;

        response.assert_status_ok();
        let body = response.text();
        assert_eq!(body, "Welcome to the keylo :)");
    }

    #[tokio::test]
    async fn test_liveness_endpoint() {
        let server = setup_test_server().await;

        let response = server.get("/healthz").await;

        response.assert_status_ok();
        let body: serde_json::Value = response.json();
        assert_eq!(body["status"], "ok");
        assert_eq!(body["service"], "keylo");
    }

    #[tokio::test]
    async fn test_readiness_endpoint() {
        let server = setup_test_server().await;

        let response = server.get("/readyz").await;
        let body: serde_json::Value = response.json();
        let status = response.status_code();
        assert!(status == StatusCode::OK || status == StatusCode::SERVICE_UNAVAILABLE);
        assert!(body["status"] == "ok" || body["status"] == "error");
        assert_eq!(body["service"], "keylo");
        assert!(body["checks"]["database"].is_string());
        assert!(body["checks"]["redis"].is_string());
    }

    #[tokio::test]
    async fn test_jwks_endpoint() {
        let server = setup_test_server().await;

        let response = server.get("/.well-known/jwks.json").await;

        response.assert_status_ok();
        let body: serde_json::Value = response.json();
        let keys = body["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "RSA");
        assert_eq!(keys[0]["alg"], "RS256");
        assert!(keys[0]["kid"].as_str().is_some());
        assert!(keys[0]["n"].as_str().is_some());
        assert!(keys[0]["e"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_invalid_auth_request() {
        let server = setup_test_server().await;

        let auth_payload = json!({
            "client_id": "invalid",
            "client_secret": "invalid"
        });

        let response = server.post("/v1/auth/token").json(&auth_payload).await;

        // 如果数据库不可用，返回500；否则返回401（错误凭据）
        let status = response.status_code();
        assert!(status == StatusCode::INTERNAL_SERVER_ERROR || status == StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_access_protected_without_token() {
        let server = setup_test_server().await;

        let response = server.get("/protected").await;

        // 兼容缺少 header 时的框架级 400 或统一鉴权返回的 401
        let status = response.status_code();
        assert!(status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_missing_credentials() {
        let server = setup_test_server().await;

        let empty_payload = json!({
            "client_id": "",
            "client_secret": ""
        });

        let response = server.post("/v1/auth/token").json(&empty_payload).await;

        response.assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_invalid_json_payload() {
        let server = setup_test_server().await;

        let response = server
            .post("/v1/auth/token")
            .bytes(Bytes::from("invalid json"))
            .add_header("content-type", "application/json")
            .await;

        // 无效的JSON应该返回400 Bad Request
        response.assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_invalid_refresh_token() {
        let server = setup_test_server().await;

        let refresh_payload = json!({
            "refresh_token": "invalid.jwt.token"
        });

        let response = server.post("/v1/auth/refresh").json(&refresh_payload).await;

        // 无效令牌应返回401（无效令牌）；数据库不可用时返回500
        let status = response.status_code();
        assert!(
            status == StatusCode::UNAUTHORIZED
                || status == StatusCode::BAD_REQUEST
                || status == StatusCode::INTERNAL_SERVER_ERROR,
            "Expected 401/400/500, got {}",
            status
        );
    }

    #[tokio::test]
    async fn test_login_lockout_after_repeated_failures() {
        let server = setup_test_server().await;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let principal = format!("invalid-lockout-{}", ts);

        let auth_payload = json!({
            "client_id": principal,
            "client_secret": "wrong-password"
        });

        // 数据库不可用场景下，接口会返回500，跳过此测试
        let first = server.post("/v1/auth/token").json(&auth_payload).await;
        if first.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        assert_eq!(first.status_code(), StatusCode::UNAUTHORIZED);

        for _ in 0..4 {
            let response = server.post("/v1/auth/token").json(&auth_payload).await;
            assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
        }

        let locked = server.post("/v1/auth/token").json(&auth_payload).await;
        assert_eq!(locked.status_code(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_auth_token_rate_limit() {
        let config = Config {
            max_failed_login_attempts: 100, // 避免锁定逻辑先触发
            auth_rate_limit_max_requests: 3,
            auth_global_rate_limit_max_requests: 100,
            auth_rate_limit_window_seconds: 60,
            ..test_config()
        };
        let server = setup_test_server_with_config(config).await;

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let principal = format!("invalid-ratelimit-{}", ts);

        let auth_payload = json!({
            "client_id": principal,
            "client_secret": "wrong-password"
        });

        for _ in 0..3 {
            let response = server.post("/v1/auth/token").json(&auth_payload).await;
            if response.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
                return;
            }
            assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
        }

        let limited = server.post("/v1/auth/token").json(&auth_payload).await;
        assert_eq!(limited.status_code(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_admin_endpoints_require_auth() {
        let server = setup_test_server().await;

        // 测试黑名单管理端点
        let blacklist_response = server
            .post("/v1/admin/blacklist")
            .json(&json!({"token": "test"}))
            .await;

        // 应该返回400（缺少Authorization header）或401（无权限）
        assert!(
            blacklist_response.status_code() == StatusCode::BAD_REQUEST
                || blacklist_response.status_code() == StatusCode::NOT_FOUND
                || blacklist_response.status_code() == StatusCode::UNAUTHORIZED
        );

        // 测试获取黑名单端点
        let list_response = server.get("/v1/admin/blacklisted-tokens").await;

        assert!(
            list_response.status_code() == StatusCode::BAD_REQUEST
                || list_response.status_code() == StatusCode::NOT_FOUND
                || list_response.status_code() == StatusCode::UNAUTHORIZED
        );

        // 测试获取审计日志端点
        let audit_response = server.get("/v1/admin/audit-logs").await;
        assert!(
            audit_response.status_code() == StatusCode::BAD_REQUEST
                || audit_response.status_code() == StatusCode::NOT_FOUND
                || audit_response.status_code() == StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn test_admin_rotate_client_secret_revokes_refresh_tokens() {
        // Use a UNIQUE admin client for this test to avoid polluting the shared
        // cli-admin-root client (rotation leaves the secret changed in the DB and
        // ON CONFLICT DO NOTHING prevents subsequent seed calls from restoring it,
        // which would break other parallel tests that rely on cli-admin-root).
        //
        // Since is_admin_client is now stored in the DB (not from ADMIN_CLIENT_ID
        // env var at request time), seeding a unique client via setup_test_server
        // gives it admin privileges independently without affecting cli-admin-root.
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let rotate_client_id = format!("cli-rotate-test-{}", ts);
        let rotate_client_secret = "RotateTest123!";

        let database_url = std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
            "postgres://keylo_user:keylo_password@localhost:5432/keylo".to_string()
        });
        let mut config = test_config();
        config.redis_key_prefix = format!(
            "keylo-test-{}-rotate-{}",
            std::process::id(),
            TEST_PREFIX_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let router = match startup::init_app_router_with_db_and_admin(
            config,
            &database_url,
            &rotate_client_id,
            rotate_client_secret,
        )
        .await
        {
            Ok(r) => r,
            Err(_) => return,
        };
        let server = TestServer::new(router);
        let admin_login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": rotate_client_id,
                "client_secret": rotate_client_secret
            }))
            .await;

        if admin_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        admin_login_resp.assert_status_ok();
        let admin_login_body: serde_json::Value = admin_login_resp.json();
        let admin_access_token = admin_login_body["access_token"].as_str().unwrap();
        let admin_refresh_token = admin_login_body["refresh_token"].as_str().unwrap();

        let rotate_resp = server
            .post(&format!(
                "/v1/admin/clients/{}/rotate-secret",
                rotate_client_id
            ))
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({}))
            .await;
        rotate_resp.assert_status_ok();
        let rotate_body: serde_json::Value = rotate_resp.json();
        assert_eq!(rotate_body["secret_generated"], true);
        let new_secret = rotate_body["new_secret"].as_str().unwrap();
        assert_ne!(new_secret, rotate_client_secret);

        let old_login = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": rotate_client_id,
                "client_secret": rotate_client_secret
            }))
            .await;
        assert_eq!(old_login.status_code(), StatusCode::UNAUTHORIZED);

        let new_login = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": rotate_client_id,
                "client_secret": new_secret
            }))
            .await;
        new_login.assert_status_ok();

        let refresh_resp = server
            .post("/v1/auth/refresh")
            .json(&json!({
                "refresh_token": admin_refresh_token
            }))
            .await;
        assert_eq!(refresh_resp.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_admin_rotate_client_secret_with_supplied_secret_does_not_echo_secret() {
        let server = setup_test_server().await;
        let login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        login_resp.assert_status_ok();
        let login_body: serde_json::Value = login_resp.json();
        let access_token = login_body["access_token"].as_str().unwrap();

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let client_id = format!("managed-rotate-{}", ts);
        let supplied_secret = format!("ManagedRotate#{}!", ts);

        let create_resp = server
            .post("/v1/admin/clients")
            .add_header("Authorization", format!("Bearer {}", access_token))
            .json(&json!({
                "client_id": client_id,
                "client_secret": "ManagedRotate#Old1",
                "name": "Managed Rotate Client"
            }))
            .await;
        create_resp.assert_status_ok();

        let rotate_resp = server
            .post(&format!("/v1/admin/clients/{}/rotate-secret", client_id))
            .add_header("Authorization", format!("Bearer {}", access_token))
            .json(&json!({
                "new_secret": supplied_secret
            }))
            .await;
        rotate_resp.assert_status_ok();
        let rotate_body: serde_json::Value = rotate_resp.json();
        assert_eq!(rotate_body["secret_generated"], false);
        assert!(rotate_body.get("new_secret").is_none());
    }

    #[tokio::test]
    async fn test_admin_client_management_api() {
        let server = setup_test_server().await;
        let login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        login_resp.assert_status_ok();
        let login_body: serde_json::Value = login_resp.json();
        let access_token = login_body["access_token"].as_str().unwrap();

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let managed_client = format!("managed-{}", ts);

        let create_resp = server
            .post("/v1/admin/clients")
            .add_header("Authorization", format!("Bearer {}", access_token))
            .json(&json!({
                "client_id": managed_client,
                "client_secret": "managed-secret",
                "name": "Managed Client",
                "description": "created by admin api"
            }))
            .await;
        create_resp.assert_status_ok();

        let list_resp = server
            .get("/v1/admin/clients")
            .add_header("Authorization", format!("Bearer {}", access_token))
            .await;
        list_resp.assert_status_ok();
        let list_body: serde_json::Value = list_resp.json();
        let found = list_body["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == managed_client);
        assert!(found);

        let disable_resp = server
            .put(&format!("/v1/admin/clients/{}", managed_client))
            .add_header("Authorization", format!("Bearer {}", access_token))
            .json(&json!({
                "active": false
            }))
            .await;
        disable_resp.assert_status_ok();

        let disabled_login = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": managed_client,
                "client_secret": "managed-secret"
            }))
            .await;
        assert_eq!(disabled_login.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_non_admin_cannot_access_admin_user_routes() {
        let server = setup_test_server().await;

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let username = format!("plain-user-{}", ts);
        let email = format!("{}@example.com", username);

        let register_resp = server
            .post("/v1/auth/register")
            .json(&json!({
                "username": username,
                "email": email,
                "password": "Password123!"
            }))
            .await;

        if register_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        register_resp.assert_status_ok();

        let login_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "Password123!"
            }))
            .await;
        login_resp.assert_status_ok();
        let login_body: serde_json::Value = login_resp.json();
        let access_token = login_body["access_token"].as_str().unwrap();

        let list_users_resp = server
            .get("/v1/admin/users")
            .add_header("Authorization", format!("Bearer {}", access_token))
            .await;
        assert_eq!(list_users_resp.status_code(), StatusCode::FORBIDDEN);

        let list_clients_resp = server
            .get("/v1/admin/clients")
            .add_header("Authorization", format!("Bearer {}", access_token))
            .await;
        assert_eq!(list_clients_resp.status_code(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_inactive_user_cannot_get_auth_token() {
        let server = setup_test_server().await;

        let admin_login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if admin_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        admin_login_resp.assert_status_ok();
        let admin_body: serde_json::Value = admin_login_resp.json();
        let admin_access_token = admin_body["access_token"].as_str().unwrap();

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let username = format!("inactive-user-{}", ts);
        let email = format!("{}@example.com", username);

        let register_resp = server
            .post("/v1/auth/register")
            .json(&json!({
                "username": username,
                "email": email,
                "password": "Password123!"
            }))
            .await;
        register_resp.assert_status_ok();
        let register_body: serde_json::Value = register_resp.json();
        let user_id = register_body["data"]["id"].as_str().unwrap();

        let disable_resp = server
            .put(&format!("/v1/admin/users/{}", user_id))
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "active": false
            }))
            .await;
        disable_resp.assert_status_ok();

        let login_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "Password123!"
            }))
            .await;
        assert_eq!(login_resp.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_service_can_introspect_user_access_token() {
        let server = setup_test_server().await;

        let admin_login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if admin_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        admin_login_resp.assert_status_ok();
        let admin_body: serde_json::Value = admin_login_resp.json();
        let admin_access_token = admin_body["access_token"].as_str().unwrap();

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let service_id = format!("agileboot-admin-{}", ts);
        let username = format!("introspect-user-{}", ts);
        let email = format!("{}@example.com", username);

        let create_service_resp = server
            .post("/v1/admin/services")
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "service_id": service_id,
                "service_secret": "service-secret",
                "name": "AgileBoot Admin",
                "description": "integration test service",
                "allowed_scopes": ["read"],
                "allowed_audiences": ["admin-backend"]
            }))
            .await;
        create_service_resp.assert_status_ok();

        let service_login_resp = server
            .post("/v1/service/token")
            .json(&json!({
                "service_id": service_id,
                "service_secret": "service-secret",
                "audience": "admin-backend",
                "scope": "read"
            }))
            .await;
        service_login_resp.assert_status_ok();
        let service_login_body: serde_json::Value = service_login_resp.json();
        let service_access_token = service_login_body["access_token"].as_str().unwrap();

        let register_resp = server
            .post("/v1/auth/register")
            .json(&json!({
                "username": username,
                "email": email,
                "password": "Password123!"
            }))
            .await;
        register_resp.assert_status_ok();

        let user_login_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "Password123!"
            }))
            .await;
        user_login_resp.assert_status_ok();
        let user_login_body: serde_json::Value = user_login_resp.json();
        let user_access_token = user_login_body["access_token"].as_str().unwrap();

        let introspect_resp = server
            .post("/v1/auth/introspect")
            .add_header("Authorization", format!("Bearer {}", service_access_token))
            .json(&json!({
                "token": user_access_token
            }))
            .await;
        introspect_resp.assert_status_ok();
        let introspect_body: serde_json::Value = introspect_resp.json();

        assert_eq!(introspect_body["active"], true);
        assert_eq!(introspect_body["sub"], format!("user:{}", username));
        assert_eq!(introspect_body["aud"], "admin-backend");
        assert_eq!(introspect_body["role"], json!(["user"]));
        assert_eq!(introspect_body["token_type"], "access");
    }

    #[tokio::test]
    async fn test_service_rotate_secret_with_supplied_secret_does_not_echo_secret() {
        let server = setup_test_server().await;

        let admin_login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if admin_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        admin_login_resp.assert_status_ok();
        let admin_body: serde_json::Value = admin_login_resp.json();
        let admin_access_token = admin_body["access_token"].as_str().unwrap();

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let service_id = format!("rotate-service-{}", ts);
        let supplied_secret = format!("RotateSvc#{}!", ts);

        let create_service_resp = server
            .post("/v1/admin/services")
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "service_id": service_id,
                "service_secret": "RotateSvc#Old1",
                "name": "Rotate Service",
                "allowed_scopes": ["read"],
                "allowed_audiences": ["admin-backend"]
            }))
            .await;
        create_service_resp.assert_status_ok();

        let rotate_resp = server
            .post(&format!("/v1/admin/services/{}/rotate-secret", service_id))
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "new_secret": supplied_secret
            }))
            .await;
        rotate_resp.assert_status_ok();
        let rotate_body: serde_json::Value = rotate_resp.json();
        assert_eq!(rotate_body["secret_generated"], false);
        assert!(rotate_body.get("new_secret").is_none());
    }

    #[tokio::test]
    async fn test_untrusted_management_client_cannot_use_user_or_admin_token_flow() {
        let server = setup_test_server().await;
        let admin_login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;

        if admin_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }

        admin_login_resp.assert_status_ok();
        let admin_login_body: serde_json::Value = admin_login_resp.json();
        let admin_access_token = admin_login_body["access_token"].as_str().unwrap();

        let client_id = format!(
            "untrusted-client-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );

        let create_resp = server
            .post("/v1/admin/clients")
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "client_id": client_id,
                "client_secret": "client-secret",
                "name": "Untrusted Client",
                "description": "should not authenticate as user or admin"
            }))
            .await;
        create_resp.assert_status_ok();

        let user_flow_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": client_id,
                "client_secret": "client-secret"
            }))
            .await;
        assert_eq!(user_flow_resp.status_code(), StatusCode::UNAUTHORIZED);
        let user_flow_body: serde_json::Value = user_flow_resp.json();
        assert_eq!(user_flow_body["error"], "wrong_credentials");

        let admin_flow_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": client_id,
                "client_secret": "client-secret"
            }))
            .await;
        assert_eq!(admin_flow_resp.status_code(), StatusCode::FORBIDDEN);
        let admin_flow_body: serde_json::Value = admin_flow_resp.json();
        assert_eq!(admin_flow_body["error"], "insufficient_role");
    }

    #[tokio::test]
    async fn test_service_token_requires_registered_service_client() {
        let server = setup_test_server().await;

        let response = server
            .post("/v1/service/token")
            .json(&json!({
                "service_id": "missing-agileboot-client",
                "service_secret": "missing-secret",
                "audience": "admin-backend",
                "scope": "read"
            }))
            .await;

        if response.status_code() == StatusCode::INTERNAL_SERVER_ERROR
            || response.status_code() == StatusCode::NOT_FOUND
        {
            return;
        }

        assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
        let body: serde_json::Value = response.json();
        assert_eq!(body["error"], "service_client_not_authorized");
    }

    #[tokio::test]
    async fn test_super_admin_bootstrap_can_access_admin_routes() {
        let config = Config {
            enable_super_admin_bootstrap: true,
            super_admin_username: Some("root_bootstrap".to_string()),
            super_admin_email: Some("root_bootstrap@example.com".to_string()),
            super_admin_password: Some("RootBootstrap#123".to_string()),
            ..test_config()
        };

        let server = setup_test_server_with_config(config).await;

        let login_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": "root_bootstrap",
                "client_secret": "RootBootstrap#123"
            }))
            .await;

        if login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }

        login_resp.assert_status_ok();
        let login_body: serde_json::Value = login_resp.json();
        assert_eq!(login_body["refresh_token"], serde_json::Value::Null);
        let access_token = login_body["access_token"].as_str().unwrap();

        let admin_users_resp = server
            .get("/v1/admin/users")
            .add_header("Authorization", format!("Bearer {}", access_token))
            .await;
        assert_eq!(admin_users_resp.status_code(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_third_party_user_migration_import_is_idempotent() {
        let server = setup_test_server().await;
        let admin_login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;

        if admin_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }

        admin_login_resp.assert_status_ok();
        let admin_body: serde_json::Value = admin_login_resp.json();
        let admin_access_token = admin_body["access_token"].as_str().unwrap();

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let username = format!("agileboot-migrated-{}", ts);
        let updated_username = format!("agileboot-migrated-updated-{}", ts);
        let email = format!("{}@example.com", username);
        let updated_email = format!("updated-{}", email);
        let external_user_id = format!("ab-{}", ts);

        let import_resp = server
            .post("/v1/admin/users/migrations/import")
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "provider": "agileboot",
                "users": [{
                    "external_user_id": external_user_id.clone(),
                    "username": username.clone(),
                    "email": email.clone(),
                    "password": "MigratedPass#123",
                    "active": true
                }]
            }))
            .await;
        import_resp.assert_status_ok();
        let import_body: serde_json::Value = import_resp.json();
        assert_eq!(import_body["summary"]["failed"], 0);

        let migrated_login_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "MigratedPass#123"
            }))
            .await;
        migrated_login_resp.assert_status_ok();

        let second_import_resp = server
            .post("/v1/admin/users/migrations/import")
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "provider": "agileboot",
                "users": [{
                    "external_user_id": external_user_id.clone(),
                    "username": updated_username.clone(),
                    "email": updated_email.clone(),
                    "password": "MigratedPass#123",
                    "active": true
                }]
            }))
            .await;
        second_import_resp.assert_status_ok();
        let second_body: serde_json::Value = second_import_resp.json();
        assert_eq!(second_body["summary"]["failed"], 0);

        let updated_login_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": updated_username,
                "client_secret": "MigratedPass#123"
            }))
            .await;
        updated_login_resp.assert_status_ok();
    }

    #[tokio::test]
    async fn test_jit_migration_register_can_issue_access_token() {
        let server = setup_test_server().await;

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let username = format!("jit-user-{}", ts);
        let email = format!("{}@example.com", username);

        let response = server
            .post("/v1/auth/migrations/jit-register")
            .json(&json!({
                "provider": "agileboot",
                "external_user_id": format!("jit-ext-{}", ts),
                "username": username,
                "email": email,
                "password": "JitMigrated#123",
                "active": true
            }))
            .await;

        if response.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }

        response.assert_status_ok();
        let body: serde_json::Value = response.json();
        assert_eq!(body["success"], true);
        assert!(body["access_token"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_async_migration_job_submit_and_query_status() {
        let server = setup_test_server().await;
        let admin_login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;

        if admin_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }

        admin_login_resp.assert_status_ok();
        let admin_body: serde_json::Value = admin_login_resp.json();
        let admin_access_token = admin_body["access_token"].as_str().unwrap();

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        let create_job_resp = server
            .post("/v1/admin/users/migrations/jobs")
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "provider": "agileboot",
                "dry_run": true,
                "users": [{
                    "external_user_id": format!("job-ext-{}", ts),
                    "username": format!("job-user-{}", ts),
                    "email": format!("job-user-{}@example.com", ts),
                    "password": "JobMigrated#123",
                    "active": true
                }]
            }))
            .await;
        create_job_resp.assert_status_ok();
        let create_job_body: serde_json::Value = create_job_resp.json();
        let job_id = create_job_body["job_id"].as_str().unwrap().to_string();

        let mut final_status = String::new();
        for _ in 0..20 {
            let status_resp = server
                .get(&format!("/v1/admin/users/migrations/jobs/{}", job_id))
                .add_header("Authorization", format!("Bearer {}", admin_access_token))
                .await;
            status_resp.assert_status_ok();
            let status_body: serde_json::Value = status_resp.json();
            final_status = status_body["job"]["status"]
                .as_str()
                .unwrap_or_default()
                .to_string();

            if final_status == "completed" || final_status == "failed" {
                break;
            }

            sleep(Duration::from_millis(100)).await;
        }

        assert!(final_status == "completed" || final_status == "failed");
    }
}
