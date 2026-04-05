#[cfg(test)]
mod tests {
    use axum_test::TestServer;
    use serde_json::json;
    use keylo::startup::init_app_router_with_db;
    use keylo::config::Config;
    use keylo::db;

    async fn setup_test_server() -> TestServer {
        let config = Config::default();
        let db_url = "postgres://postgres:password@localhost:5432/keylo_test".to_string();

        let router = init_app_router_with_db(config, &db_url)
            .await
            .expect("Failed to initialize test server");
        TestServer::new(router)
    }

    #[tokio::test]
    async fn test_change_password_success() {
        let server = setup_test_server().await;

        // 首先创建用户
        let create_user_response = server
            .post("/v1/admin/users")
            .json(&json!({
                "username": "testuser",
                "email": "test@example.com",
                "password": "oldpassword123"
            }))
            .await;

        assert_eq!(create_user_response.status_code(), 200);

        let create_response: serde_json::Value = create_user_response.json().await;
        let user_id = create_response["data"]["id"].as_str().unwrap();

        // 登录获取token
        let login_response = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": "testuser",
                "client_secret": "oldpassword123"
            }))
            .await;

        assert_eq!(login_response.status_code(), 200);

        let login_data: serde_json::Value = login_response.json().await;
        let access_token = login_data["access_token"].as_str().unwrap();

        // 更改密码
        let change_response = server
            .post("/v1/user/change-password")
            .add_header("Authorization", format!("Bearer {}", access_token))
            .json(&json!({
                "current_password": "oldpassword123",
                "new_password": "newpassword123"
            }))
            .await;

        assert_eq!(change_response.status_code(), 200);

        let change_data: serde_json::Value = change_response.json().await;
        assert_eq!(change_data["success"], true);
        assert_eq!(change_data["message"], "Password changed successfully");

        // 验证新密码可以登录
        let new_login_response = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": "testuser",
                "client_secret": "newpassword123"
            }))
            .await;

        assert_eq!(new_login_response.status_code(), 200);

        // 验证旧密码不能登录
        let old_login_response = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": "testuser",
                "client_secret": "oldpassword123"
            }))
            .await;

        assert_eq!(old_login_response.status_code(), 401);
    }

    #[tokio::test]
    async fn test_change_password_wrong_current() {
        let server = setup_test_server().await;

        // 首先创建用户
        let create_user_response = server
            .post("/v1/admin/users")
            .json(&json!({
                "username": "testuser2",
                "email": "test2@example.com",
                "password": "correctpassword123"
            }))
            .await;

        assert_eq!(create_user_response.status_code(), 200);

        // 登录获取token
        let login_response = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": "testuser2",
                "client_secret": "correctpassword123"
            }))
            .await;

        assert_eq!(login_response.status_code(), 200);

        let login_data: serde_json::Value = login_response.json().await;
        let access_token = login_data["access_token"].as_str().unwrap();

        // 尝试用错误的当前密码更改密码
        let change_response = server
            .post("/v1/user/change-password")
            .add_header("Authorization", format!("Bearer {}", access_token))
            .json(&json!({
                "current_password": "wrongpassword123",
                "new_password": "newpassword123"
            }))
            .await;

        assert_eq!(change_response.status_code(), 400);

        let change_data: serde_json::Value = change_response.json().await;
        assert_eq!(change_data["success"], false);
        assert!(change_data["error"].as_str().unwrap().contains("Current password is incorrect"));
    }

    #[tokio::test]
    async fn test_change_password_too_short() {
        let server = setup_test_server().await;

        // 首先创建用户
        let create_user_response = server
            .post("/v1/admin/users")
            .json(&json!({
                "username": "testuser3",
                "email": "test3@example.com",
                "password": "oldpassword123"
            }))
            .await;

        assert_eq!(create_user_response.status_code(), 200);

        // 登录获取token
        let login_response = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": "testuser3",
                "client_secret": "oldpassword123"
            }))
            .await;

        assert_eq!(login_response.status_code(), 200);

        let login_data: serde_json::Value = login_response.json().await;
        let access_token = login_data["access_token"].as_str().unwrap();

        // 尝试更改为太短的密码
        let change_response = server
            .post("/v1/user/change-password")
            .add_header("Authorization", format!("Bearer {}", access_token))
            .json(&json!({
                "current_password": "oldpassword123",
                "new_password": "short"
            }))
            .await;

        assert_eq!(change_response.status_code(), 400);

        let change_data: serde_json::Value = change_response.json().await;
        assert_eq!(change_data["success"], false);
        assert!(change_data["error"].as_str().unwrap().contains("must be at least 8 characters"));
    }

    #[tokio::test]
    async fn test_change_password_unauthorized() {
        let server = setup_test_server().await;

        // 不带token尝试更改密码
        let change_response = server
            .post("/v1/user/change-password")
            .json(&json!({
                "current_password": "somepassword",
                "new_password": "newpassword123"
            }))
            .await;

        assert_eq!(change_response.status_code(), 400); // 缺少Authorization header
    }
}