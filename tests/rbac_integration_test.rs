#[cfg(test)]
mod tests {
    use axum_test::TestServer;
    use keylo::config::Config;
    use keylo::startup::init_app_router_with_db;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    async fn setup_test_server() -> TestServer {
        let config = Config::default();
        let db_url = std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
            "postgres://keylo_user:keylo_password@localhost:5432/keylo".to_string()
        });

        let router = init_app_router_with_db(config, &db_url)
            .await
            .expect("Failed to initialize test server");
        TestServer::new(router)
    }

    async fn get_access_token(server: &TestServer) -> String {
        let login_response = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": "cli",
                "client_secret": "cli-secret"
            }))
            .await;

        login_response.assert_status_ok();
        let body: serde_json::Value = login_response.json();
        body["access_token"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn test_create_role() {
        let server = setup_test_server().await;
        let token = get_access_token(&server).await;
        let role_name = format!(
            "admin-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );

        let response = server
            .post("/api/rbac/roles")
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "name": role_name,
                "description": "Administrator role"
            }))
            .await;

        assert_eq!(response.status_code(), 200);

        let body: serde_json::Value = response.json();
        assert!(body["success"].as_bool().unwrap());
        assert_eq!(body["data"]["name"], role_name);
    }

    #[tokio::test]
    async fn test_get_roles() {
        let server = setup_test_server().await;
        let token = get_access_token(&server).await;

        let response = server
            .get("/api/rbac/roles")
            .add_header("Authorization", format!("Bearer {}", token))
            .await;

        assert_eq!(response.status_code(), 200);

        let body: serde_json::Value = response.json();
        assert!(body["success"].as_bool().unwrap());
        assert!(body["data"].is_array());
    }

    #[tokio::test]
    async fn test_create_permission() {
        let server = setup_test_server().await;
        let token = get_access_token(&server).await;
        let permission_name = format!(
            "user.manage.{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );

        let response = server
            .post("/api/rbac/permissions")
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "name": permission_name,
                "description": "Manage users permission"
            }))
            .await;

        assert_eq!(response.status_code(), 200);

        let body: serde_json::Value = response.json();
        assert!(body["success"].as_bool().unwrap());
        assert_eq!(body["data"]["name"], permission_name);
    }

    #[tokio::test]
    async fn test_get_permissions() {
        let server = setup_test_server().await;
        let token = get_access_token(&server).await;

        let response = server
            .get("/api/rbac/permissions")
            .add_header("Authorization", format!("Bearer {}", token))
            .await;

        assert_eq!(response.status_code(), 200);

        let body: serde_json::Value = response.json();
        assert!(body["success"].as_bool().unwrap());
        assert!(body["data"].is_array());
    }
}
