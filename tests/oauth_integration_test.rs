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
    async fn test_create_oauth_provider() {
        let server = setup_test_server().await;

        let response = server
            .post("/api/oauth/providers")
            .json(&json!({
                "name": "github",
                "client_id": "test_client_id",
                "client_secret": "test_client_secret",
                "authorization_url": "https://github.com/login/oauth/authorize",
                "token_url": "https://github.com/login/oauth/access_token",
                "user_info_url": "https://api.github.com/user",
                "scope": "read:user",
                "redirect_url": "http://localhost:3000/callback/github"
            }))
            .await;

        assert_eq!(response.status_code(), 201);

        let body: serde_json::Value = response.json();
        assert!(body["success"].as_bool().unwrap());
        assert_eq!(body["data"]["name"], "github");
    }

    #[tokio::test]
    async fn test_get_oauth_providers() {
        let server = setup_test_server().await;

        let response = server.get("/api/oauth/providers").await;

        assert_eq!(response.status_code(), 200);

        let body: serde_json::Value = response.json();
        assert!(body["success"].as_bool().unwrap());
        assert!(body["data"].is_array());
    }

    #[tokio::test]
    async fn test_oauth_login_redirect() {
        // First create a provider
        let server = setup_test_server().await;

        let _ = server
            .post("/api/oauth/providers")
            .json(&json!({
                "name": "github",
                "client_id": "test_client_id",
                "client_secret": "test_client_secret",
                "authorization_url": "https://github.com/login/oauth/authorize",
                "token_url": "https://github.com/login/oauth/access_token",
                "user_info_url": "https://api.github.com/user",
                "scope": "read:user",
                "redirect_url": "http://localhost:3000/callback/github"
            }))
            .await;

        // Test OAuth login redirect
        let response = server
            .get("/v1/auth/oauth/login/github")
            .await;

        assert_eq!(response.status_code(), 302); // Redirect

        let location = response.headers().get("location").unwrap();
        assert!(location.to_str().unwrap().contains("github.com/login/oauth/authorize"));
    }
}