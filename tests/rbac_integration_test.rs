#[cfg(test)]
mod tests {
    use axum_test::TestServer;
    use serde_json::json;
    use keylo::startup::init_app_router_with_db;
    use keylo::config::Config;

    async fn setup_test_server() -> TestServer {
        let config = Config::default();
        let db_url = "postgres://postgres:password@localhost:5432/keylo_test".to_string();
        
        let router = init_app_router_with_db(config, &db_url)
            .await
            .expect("Failed to initialize test server");
        TestServer::new(router)
    }

    #[tokio::test]
    async fn test_create_role() {
        let server = setup_test_server().await;

        let response = server
            .post("/api/rbac/roles")
            .json(&json!({
                "name": "admin",
                "description": "Administrator role"
            }))
            .await;

        assert_eq!(response.status_code(), 201);

        let body: serde_json::Value = response.json();
        assert!(body["success"].as_bool().unwrap());
        assert_eq!(body["data"]["name"], "admin");
    }

    #[tokio::test]
    async fn test_get_roles() {
        let server = setup_test_server().await;

        let response = server.get("/api/rbac/roles").await;

        assert_eq!(response.status_code(), 200);

        let body: serde_json::Value = response.json();
        assert!(body["success"].as_bool().unwrap());
        assert!(body["data"].is_array());
    }

    #[tokio::test]
    async fn test_create_permission() {
        let server = setup_test_server().await;

        let response = server
            .post("/api/rbac/permissions")
            .json(&json!({
                "name": "user.manage",
                "description": "Manage users permission"
            }))
            .await;

        assert_eq!(response.status_code(), 201);

        let body: serde_json::Value = response.json();
        assert!(body["success"].as_bool().unwrap());
        assert_eq!(body["data"]["name"], "user.manage");
    }

    #[tokio::test]
    async fn test_get_permissions() {
        let server = setup_test_server().await;

        let response = server.get("/api/rbac/permissions").await;

        assert_eq!(response.status_code(), 200);

        let body: serde_json::Value = response.json();
        assert!(body["success"].as_bool().unwrap());
        assert!(body["data"].is_array());
    }
}