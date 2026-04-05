#[cfg(test)]
mod tests {
    use axum_test::TestServer;
    use serde_json::json;
    use keylo::startup::init_app_router_with_db;
    use keylo::config::Config;

    async fn setup_test_server() -> TestServer {
        println!("Setting up test server...");
        let config = Config::default();
        let db_url = "postgres://keylo_user:keylo_password@localhost:5432/keylo".to_string();
        
        let router = init_app_router_with_db(config, &db_url)
            .await
            .expect("Failed to initialize test server");
        println!("Test server initialized successfully");
        TestServer::new(router)
    }

    #[tokio::test]
    async fn test_change_password_success() {
        let server = setup_test_server().await;

        // 使用时间戳生成唯一用户名
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let username = format!("testuser_{}", timestamp);
        let email = format!("test_{}@example.com", timestamp);

        // 首先创建用户
        let create_user_response = server
            .post("/v1/auth/register")
            .json(&json!({
                "username": username,
                "email": email,
                "password": "oldpassword123"
            }))
            .await;

        let create_status = create_user_response.status_code();
        println!("Create user status: {}", create_status);
        
        if create_status != 200 {
            let error_data: serde_json::Value = create_user_response.json::<serde_json::Value>();
            println!("Create user error: {:?}", error_data);
        }
        
        assert_eq!(create_status, 200);

        let create_response: serde_json::Value = create_user_response.json::<serde_json::Value>();
        let _user_id = create_response["data"]["id"].as_str().unwrap();

        // 登录获取token
        let login_response = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username.clone(),
                "client_secret": "oldpassword123"
            }))
            .await;

        let login_status = login_response.status_code();
        println!("Login status: {}", login_status);
        
        if login_status != 200 {
            let error_data: serde_json::Value = login_response.json::<serde_json::Value>();
            println!("Login error: {:?}", error_data);
        }
        
        assert_eq!(login_status, 200);

        let login_data: serde_json::Value = login_response.json::<serde_json::Value>();
        let access_token = login_data["access_token"].as_str().unwrap();
        println!("Access token: {}", access_token);

        // 更改密码
        let change_response = server
            .post("/v1/user/change-password")
            .add_header("Authorization", format!("Bearer {}", access_token))
            .json(&json!({
                "current_password": "oldpassword123",
                "new_password": "newpassword123"
            }))
            .await;

        let status_code = change_response.status_code();
        let error_body: serde_json::Value = change_response.json::<serde_json::Value>();
        println!("Status code: {}, Error response: {:?}", status_code, error_body);

        assert_eq!(status_code, 200);

        let change_data: serde_json::Value = change_response.json::<serde_json::Value>();
        assert_eq!(change_data["success"], true);
        assert_eq!(change_data["message"], "Password changed successfully");

        // 验证新密码可以登录
        let new_login_response = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "newpassword123"
            }))
            .await;

        assert_eq!(new_login_response.status_code(), 200);

        // 验证旧密码不能登录
        let old_login_response = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "oldpassword123"
            }))
            .await;

        assert_eq!(old_login_response.status_code(), 401);
    }

    #[tokio::test]
    async fn test_change_password_wrong_current() {
        let server = setup_test_server().await;

        // 使用时间戳生成唯一用户名
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let username = format!("testuser2_{}", timestamp);
        let email = format!("test2_{}@example.com", timestamp);

        // 首先创建用户
        let create_user_response = server
            .post("/v1/auth/register")
            .json(&json!({
                "username": username,
                "email": email,
                "password": "correctpassword123"
            }))
            .await;

        assert_eq!(create_user_response.status_code(), 200);

        // 登录获取token
        let login_response = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username.clone(),
                "client_secret": "correctpassword123"
            }))
            .await;

        assert_eq!(login_response.status_code(), 200);

        let login_data: serde_json::Value = login_response.json::<serde_json::Value>();
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

        let change_data: serde_json::Value = change_response.json::<serde_json::Value>();
        assert_eq!(change_data["success"], false);
        assert!(change_data["error"].as_str().unwrap().contains("Current password is incorrect"));
    }

    #[tokio::test]
    async fn test_change_password_too_short() {
        let server = setup_test_server().await;

        // 使用时间戳生成唯一用户名
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let username = format!("testuser3_{}", timestamp);
        let email = format!("test3_{}@example.com", timestamp);

        // 首先创建用户
        let create_user_response = server
            .post("/v1/auth/register")
            .json(&json!({
                "username": username.clone(),
                "email": email,
                "password": "oldpassword123"
            }))
            .await;

        assert_eq!(create_user_response.status_code(), 200);

        // 登录获取token
        let login_response = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "oldpassword123"
            }))
            .await;

        assert_eq!(login_response.status_code(), 200);

        let login_data: serde_json::Value = login_response.json::<serde_json::Value>();
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

        let change_data: serde_json::Value = change_response.json::<serde_json::Value>();
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