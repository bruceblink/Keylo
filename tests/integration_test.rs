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
                || blacklist_response.status_code() == StatusCode::UNAUTHORIZED
        );

        // 测试获取黑名单端点
        let list_response = server.get("/v1/admin/blacklisted-tokens").await;

        assert!(
            list_response.status_code() == StatusCode::BAD_REQUEST
                || list_response.status_code() == StatusCode::UNAUTHORIZED
        );

        // 测试获取审计日志端点
        let audit_response = server.get("/v1/admin/audit-logs").await;
        assert!(
            audit_response.status_code() == StatusCode::BAD_REQUEST
                || audit_response.status_code() == StatusCode::UNAUTHORIZED
        );
    }
}
