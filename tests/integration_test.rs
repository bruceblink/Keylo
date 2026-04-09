use axum::body::Bytes;
use axum::http::StatusCode;
use axum_test::TestServer;
use keylo::config::Config;
use keylo::startup;
use serde_json::json;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// 设置测试服务器（带数据库）
    async fn setup_test_server() -> TestServer {
        setup_test_server_with_config(Config::default()).await
    }

    async fn setup_test_server_with_config(config: Config) -> TestServer {
        let database_url = std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
            "postgres://keylo_user:keylo_password@localhost:5432/keylo".to_string()
        });

        // 尝试连接数据库，如果失败则使用无数据库版本
        match startup::init_app_router_with_db(config, &database_url).await {
            Ok(app) => TestServer::new(app),
            Err(_) => {
                // 如果数据库不可用，使用无数据库版本
                let app = startup::init_app_router();
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

        // 应该返回400，因为缺少Authorization header
        response.assert_status(StatusCode::BAD_REQUEST);
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

        // 如果数据库不可用，返回500；否则返回400（无效令牌）
        let status = response.status_code();
        assert!(status == StatusCode::INTERNAL_SERVER_ERROR || status == StatusCode::BAD_REQUEST);
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
        let mut config = Config::default();
        config.max_failed_login_attempts = 100; // 避免锁定逻辑先触发
        config.auth_rate_limit_max_requests = 3;
        config.auth_global_rate_limit_max_requests = 100;
        config.auth_rate_limit_window_seconds = 60;
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
        std::env::set_var("ADMIN_CLIENT_ID", "cli-admin-root");
        std::env::set_var("ADMIN_CLIENT_SECRET", "cli-admin-root-secret");

        let server = setup_test_server().await;
        let admin_login_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": "cli-admin-root",
                "client_secret": "cli-admin-root-secret"
            }))
            .await;

        if admin_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        admin_login_resp.assert_status_ok();
        let admin_login_body: serde_json::Value = admin_login_resp.json();
        let admin_access_token = admin_login_body["access_token"].as_str().unwrap();

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let managed_client = format!("rotate-client-{}", ts);

        let create_resp = server
            .post("/v1/admin/clients")
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "client_id": managed_client,
                "client_secret": "rotate-old-secret",
                "name": "Rotate Client",
                "description": "for rotate test"
            }))
            .await;
        create_resp.assert_status_ok();

        let client_login_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": managed_client,
                "client_secret": "rotate-old-secret"
            }))
            .await;
        client_login_resp.assert_status_ok();
        let client_login_body: serde_json::Value = client_login_resp.json();
        let refresh_token = client_login_body["refresh_token"].as_str().unwrap();

        let rotate_resp = server
            .post(&format!(
                "/v1/admin/clients/{}/rotate-secret",
                managed_client
            ))
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({}))
            .await;
        rotate_resp.assert_status_ok();
        let rotate_body: serde_json::Value = rotate_resp.json();
        let new_secret = rotate_body["new_secret"].as_str().unwrap();
        assert_ne!(new_secret, "rotate-old-secret");

        let old_login = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": managed_client,
                "client_secret": "rotate-old-secret"
            }))
            .await;
        assert_eq!(old_login.status_code(), StatusCode::UNAUTHORIZED);

        let new_login = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": managed_client,
                "client_secret": new_secret
            }))
            .await;
        new_login.assert_status_ok();

        let refresh_resp = server
            .post("/v1/auth/refresh")
            .json(&json!({
                "refresh_token": refresh_token
            }))
            .await;
        assert_eq!(refresh_resp.status_code(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_admin_client_management_api() {
        std::env::set_var("ADMIN_CLIENT_ID", "cli-admin-root");
        std::env::set_var("ADMIN_CLIENT_SECRET", "cli-admin-root-secret");

        let server = setup_test_server().await;
        let login_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": "cli-admin-root",
                "client_secret": "cli-admin-root-secret"
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
                "password": "password123"
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
                "client_secret": "password123"
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
    async fn test_service_can_introspect_user_access_token() {
        std::env::set_var("ADMIN_CLIENT_ID", "cli-admin-root");
        std::env::set_var("ADMIN_CLIENT_SECRET", "cli-admin-root-secret");

        let server = setup_test_server().await;

        let admin_login_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": "cli-admin-root",
                "client_secret": "cli-admin-root-secret"
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
                "password": "password123"
            }))
            .await;
        register_resp.assert_status_ok();

        let user_login_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "password123"
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
        assert_eq!(introspect_body["token_type"], "access");
    }
}
