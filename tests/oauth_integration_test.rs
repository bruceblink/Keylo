#[cfg(test)]
mod tests {
    use axum_test::TestServer;
    use keylo::config::Config;
    use keylo::startup::init_app_router_with_db;
    use serde_json::json;
    use uuid::Uuid;

    async fn setup_test_server() -> Option<TestServer> {
        std::env::set_var("ADMIN_CLIENT_ID", "cli");
        std::env::set_var("ADMIN_CLIENT_SECRET", "cli-secret");

        let config = Config::default();
        let db_url = std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
            "postgres://keylo_user:keylo_password@localhost:5432/keylo".to_string()
        });

        match init_app_router_with_db(config, &db_url).await {
            Ok(router) => Some(TestServer::new(router)),
            Err(e) => {
                println!("Skipping test: failed to initialize test server: {}", e);
                None
            }
        }
    }

    async fn get_access_token(server: &TestServer) -> String {
        let login_response = server
            .post("/v1/admin/token")
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
    async fn test_create_oauth_provider() {
        let Some(server) = setup_test_server().await else {
            return;
        };
        let token = get_access_token(&server).await;
        let provider_name = format!("github-{}", Uuid::new_v4().simple());

        let response = server
            .post("/api/oauth/providers")
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "name": provider_name,
                "client_id": "test_client_id",
                "client_secret": "test_client_secret",
                "authorization_url": "https://github.com/login/oauth/authorize",
                "token_url": "https://github.com/login/oauth/access_token",
                "user_info_url": "https://api.github.com/user",
                "scope": "read:user",
                "redirect_url": "http://localhost:3000/callback/github"
            }))
            .await;

        assert_eq!(response.status_code(), 200);

        let body: serde_json::Value = response.json();
        assert!(body["success"].as_bool().unwrap());
        assert_eq!(body["data"]["name"], provider_name);
    }

    #[tokio::test]
    async fn test_get_oauth_providers() {
        let Some(server) = setup_test_server().await else {
            return;
        };
        let token = get_access_token(&server).await;

        let response = server
            .get("/api/oauth/providers")
            .add_header("Authorization", format!("Bearer {}", token))
            .await;

        assert_eq!(response.status_code(), 200);

        let body: serde_json::Value = response.json();
        assert!(body["success"].as_bool().unwrap());
        assert!(body["data"].is_array());
    }

    #[tokio::test]
    async fn test_oauth_login_redirect() {
        // First create a provider
        let Some(server) = setup_test_server().await else {
            return;
        };
        let token = get_access_token(&server).await;
        let provider_name = format!("github-{}", Uuid::new_v4().simple());

        let _ = server
            .post("/api/oauth/providers")
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "name": provider_name,
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
            .get(&format!("/v1/auth/oauth/login/{}", provider_name))
            .await;

        let status = response.status_code();
        assert!(status == 302 || status == 303); // Redirect

        let location = response.headers().get("location").unwrap();
        assert!(location
            .to_str()
            .unwrap()
            .contains("github.com/login/oauth/authorize"));
    }
}
