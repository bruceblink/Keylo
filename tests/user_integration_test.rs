#[cfg(test)]
mod tests {
    use axum_test::TestServer;
    use keylo::config::Config;
    use keylo::db;
    use keylo::mail::{MailDeliveryError, MailDeliveryFuture, MailMessage, MailProvider};
    use keylo::startup::{
        init_app_router_with_db_and_admin, init_app_router_with_db_and_admin_and_mail_provider,
    };
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    use totp_rs::{Algorithm, Secret, TOTP};

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

    fn test_config() -> Config {
        Config {
            jwt_private_key_pem: TEST_JWT_PRIVATE_KEY_PEM.to_string(),
            jwt_public_key_pem: TEST_JWT_PUBLIC_KEY_PEM.to_string(),
            jwt_keys_generated: false,
            admin_client_id: Some("user-test-admin".to_string()),
            admin_client_secret: Some("UserTestAdmin#123".to_string()),
            mfa_secret_key: Some("01234567890123456789012345678901".to_string()),
            environment: "test".to_string(),
            ..Default::default()
        }
    }

    #[derive(Clone, Default)]
    struct RecordingMailProvider {
        deliveries: Arc<Mutex<Vec<MailMessage>>>,
        failure: Arc<Mutex<Option<MailDeliveryError>>>,
    }

    impl RecordingMailProvider {
        fn set_failure(&self, failure: Option<MailDeliveryError>) {
            *self.failure.lock().unwrap() = failure;
        }

        fn deliveries(&self) -> Vec<MailMessage> {
            self.deliveries.lock().unwrap().clone()
        }
    }

    impl MailProvider for RecordingMailProvider {
        fn send<'a>(&'a self, message: MailMessage) -> MailDeliveryFuture<'a> {
            let deliveries = Arc::clone(&self.deliveries);
            let failure = *self.failure.lock().unwrap();
            Box::pin(async move {
                message.validate()?;
                if let Some(failure) = failure {
                    return Err(failure);
                }
                deliveries.lock().unwrap().push(message);
                Ok(())
            })
        }
    }

    async fn setup_email_verification_test_server() -> Option<(TestServer, RecordingMailProvider)> {
        let config = test_config();
        let db_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://keylo_user@localhost:5432/keylo".to_string());
        let provider = RecordingMailProvider::default();
        match init_app_router_with_db_and_admin_and_mail_provider(
            config,
            &db_url,
            "user-test-admin",
            "UserTestAdmin#123",
            Arc::new(provider.clone()),
        )
        .await
        {
            Ok(router) => Some((TestServer::new(router), provider)),
            Err(error) => {
                println!(
                    "Skipping email verification test: DB unavailable ({})",
                    error
                );
                None
            }
        }
    }

    #[tokio::test]
    async fn test_email_verification_request_and_confirmation_are_single_use() {
        let Some((server, provider)) = setup_email_verification_test_server().await else {
            return;
        };
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let username = format!("email-verify-{suffix}");
        let email = format!("email-verify-{suffix}@example.test");

        let registration = server
            .post("/v1/auth/register")
            .json(&json!({
                "username": username,
                "email": email,
                "password": "Password123!"
            }))
            .await;
        assert_eq!(registration.status_code(), 200);

        let login = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "Password123!"
            }))
            .await;
        assert_eq!(login.status_code(), 200);
        let login_data: serde_json::Value = login.json::<serde_json::Value>();
        let access_token = login_data["access_token"].as_str().unwrap();

        let request = server
            .post("/v1/user/email-verification/request")
            .add_header("Authorization", format!("Bearer {access_token}"))
            .await;
        assert_eq!(request.status_code(), 200);
        let request_data: serde_json::Value = request.json::<serde_json::Value>();
        assert_eq!(request_data["data"]["status"], "sent");

        let deliveries = provider.deliveries();
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].recipient, email);
        let token = deliveries[0]
            .text_body
            .strip_prefix("Use this one-time Keylo email verification token: ")
            .unwrap()
            .to_string();

        let confirmation = server
            .post("/v1/auth/email-verification/confirm")
            .json(&json!({ "token": token.clone() }))
            .await;
        assert_eq!(confirmation.status_code(), 200);
        let confirmation_data: serde_json::Value = confirmation.json::<serde_json::Value>();
        assert_eq!(confirmation_data["data"]["email_verified"], true);

        let replay = server
            .post("/v1/auth/email-verification/confirm")
            .json(&json!({ "token": token }))
            .await;
        assert_eq!(replay.status_code(), 400);
    }

    #[tokio::test]
    async fn test_email_verification_delivery_failure_returns_unavailable_and_revokes_token() {
        let Some((server, provider)) = setup_email_verification_test_server().await else {
            return;
        };
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let username = format!("email-failure-{suffix}");
        let email = format!("email-failure-{suffix}@example.test");

        let registration = server
            .post("/v1/auth/register")
            .json(&json!({
                "username": username,
                "email": email,
                "password": "Password123!"
            }))
            .await;
        assert_eq!(registration.status_code(), 200);
        let registration_data: serde_json::Value = registration.json::<serde_json::Value>();
        let user_id = registration_data["data"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        let login = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "Password123!"
            }))
            .await;
        let login_data: serde_json::Value = login.json::<serde_json::Value>();
        let access_token = login_data["access_token"].as_str().unwrap();

        provider.set_failure(Some(MailDeliveryError::Timeout));
        let failed_request = server
            .post("/v1/user/email-verification/request")
            .add_header("Authorization", format!("Bearer {access_token}"))
            .await;
        assert_eq!(failed_request.status_code(), 503);
        assert!(provider.deliveries().is_empty());

        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://keylo_user@localhost:5432/keylo".to_string());
        let pool = db::init_db_pool(&database_url).await.unwrap();
        let revoked_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM email_verification_tokens
             WHERE user_id = $1 AND revoked_at IS NOT NULL",
        )
        .bind(&user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(revoked_count, 1);
        pool.close().await;
    }

    /// Generate the code expected by the enrollment endpoint using the same fixed RFC 6238 profile.
    fn current_totp_code(seed: &str) -> String {
        let secret = Secret::Encoded(seed.to_string()).to_bytes().unwrap();
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            0,
            30,
            secret,
            Some("Keylo".to_string()),
            "verification".to_string(),
        )
        .unwrap();
        totp.generate(chrono::Utc::now().timestamp() as u64)
    }

    async fn setup_test_server() -> Option<TestServer> {
        println!("Setting up test server...");
        let config = test_config();
        let db_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://keylo_user@localhost:5432/keylo".to_string());

        match init_app_router_with_db_and_admin(
            config,
            &db_url,
            "user-test-admin",
            "UserTestAdmin#123",
        )
        .await
        {
            Ok(router) => {
                println!("Test server initialized successfully");
                Some(TestServer::new(router))
            }
            Err(e) => {
                println!("Skipping test: DB unavailable ({})", e);
                None
            }
        }
    }

    #[tokio::test]
    async fn test_auth_me_returns_non_empty_uid() {
        let Some(server) = setup_test_server().await else {
            return;
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let username = format!("auth_me_user_{}", timestamp);
        let email = format!("auth_me_{}@example.com", timestamp);

        let create_user_response = server
            .post("/v1/auth/register")
            .json(&json!({
                "username": username,
                "email": email,
                "password": "Password123!"
            }))
            .await;
        assert_eq!(create_user_response.status_code(), 200);

        let create_data: serde_json::Value = create_user_response.json::<serde_json::Value>();
        let user_id = create_data["data"]["id"].as_str().unwrap().to_string();

        let login_response = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": create_data["data"]["username"].as_str().unwrap(),
                "client_secret": "Password123!"
            }))
            .await;
        assert_eq!(login_response.status_code(), 200);

        let login_data: serde_json::Value = login_response.json::<serde_json::Value>();
        let access_token = login_data["access_token"].as_str().unwrap();

        let me_response = server
            .get("/v1/auth/me")
            .add_header("Authorization", format!("Bearer {}", access_token))
            .await;
        assert_eq!(me_response.status_code(), 200);

        let me_data: serde_json::Value = me_response.json::<serde_json::Value>();
        assert_eq!(me_data["uid"].as_str().unwrap(), user_id);
        assert!(!me_data["uid"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_change_password_success() {
        let Some(server) = setup_test_server().await else {
            return;
        };

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
                "password": "OldPassword123!"
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
                "client_secret": "OldPassword123!"
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

        // 更改密码
        let change_response = server
            .post("/v1/user/change-password")
            .add_header("Authorization", format!("Bearer {}", access_token))
            .json(&json!({
                "current_password": "OldPassword123!",
                "new_password": "NewPassword123!"
            }))
            .await;

        let status_code = change_response.status_code();
        let error_body: serde_json::Value = change_response.json::<serde_json::Value>();
        println!(
            "Status code: {}, Error response: {:?}",
            status_code, error_body
        );

        assert_eq!(status_code, 200);

        let change_data: serde_json::Value = change_response.json::<serde_json::Value>();
        assert_eq!(change_data["success"], true);
        assert_eq!(change_data["message"], "Password changed successfully");

        // 验证新密码可以登录
        let new_login_response = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "NewPassword123!"
            }))
            .await;

        assert_eq!(new_login_response.status_code(), 200);

        // 验证旧密码不能登录
        let old_login_response = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "OldPassword123!"
            }))
            .await;

        assert_eq!(old_login_response.status_code(), 401);
    }

    #[tokio::test]
    async fn test_change_password_wrong_current() {
        let Some(server) = setup_test_server().await else {
            return;
        };

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
                "password": "CorrectPassword123!"
            }))
            .await;

        assert_eq!(create_user_response.status_code(), 200);

        // 登录获取token
        let login_response = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username.clone(),
                "client_secret": "CorrectPassword123!"
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
                "current_password": "WrongPassword123!",
                "new_password": "NewPassword123!"
            }))
            .await;

        assert_eq!(change_response.status_code(), 400);

        let change_data: serde_json::Value = change_response.json::<serde_json::Value>();
        assert_eq!(change_data["success"], false);
        assert!(change_data["error"]
            .as_str()
            .unwrap()
            .contains("Current password is incorrect"));
    }

    #[tokio::test]
    async fn test_change_password_too_short() {
        let Some(server) = setup_test_server().await else {
            return;
        };

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
                "password": "OldPassword123!"
            }))
            .await;

        assert_eq!(create_user_response.status_code(), 200);

        // 登录获取token
        let login_response = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "OldPassword123!"
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
                "current_password": "OldPassword123!",
                "new_password": "short"
            }))
            .await;

        assert_eq!(change_response.status_code(), 400);

        let change_data: serde_json::Value = change_response.json::<serde_json::Value>();
        assert_eq!(change_data["success"], false);
        assert!(change_data["error"]
            .as_str()
            .unwrap()
            .contains("must be at least 8 characters"));
    }

    #[tokio::test]
    async fn test_change_password_unauthorized() {
        let Some(server) = setup_test_server().await else {
            return;
        };

        // 不带token尝试更改密码
        let change_response = server
            .post("/v1/user/change-password")
            .json(&json!({
                "current_password": "somepassword",
                "new_password": "NewPassword123!"
            }))
            .await;

        assert_eq!(change_response.status_code(), 401); // 缺少Authorization header
    }

    #[tokio::test]
    async fn test_totp_recovery_and_recent_mfa_lifecycle() {
        let Some(server) = setup_test_server().await else {
            return;
        };

        // The flow covers enrollment, one-time recovery use, token-bound MFA, and reset.
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let username = format!("mfa_user_{}", timestamp);
        let email = format!("mfa_{}@example.com", timestamp);
        let register = server
            .post("/v1/auth/register")
            .json(&json!({
                "username": username,
                "email": email,
                "password": "OldPassword123!"
            }))
            .await;
        assert_eq!(register.status_code(), 200);

        let login = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "OldPassword123!"
            }))
            .await;
        assert_eq!(login.status_code(), 200);
        let tokens: serde_json::Value = login.json::<serde_json::Value>();
        let access_token = tokens["access_token"].as_str().unwrap().to_string();

        let enrollment = server
            .post("/v1/user/mfa/totp/enroll")
            .add_header("Authorization", format!("Bearer {access_token}"))
            .await;
        assert_eq!(enrollment.status_code(), 200);
        let enrollment_data: serde_json::Value = enrollment.json::<serde_json::Value>();
        let seed = enrollment_data["data"]["manual_entry_key"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(!seed.is_empty());
        assert!(enrollment_data["data"]["provisioning_uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/"));

        let verify_enrollment = server
            .post("/v1/user/mfa/totp/verify")
            .add_header("Authorization", format!("Bearer {access_token}"))
            .json(&json!({"code": current_totp_code(&seed)}))
            .await;
        assert_eq!(verify_enrollment.status_code(), 200);
        let enabled_data: serde_json::Value = verify_enrollment.json::<serde_json::Value>();
        assert_eq!(enabled_data["data"]["enabled"], true);
        let recovery_code = enabled_data["data"]["recovery_codes"][0]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            enabled_data["data"]["recovery_codes"]
                .as_array()
                .unwrap()
                .len(),
            10
        );

        let blocked_change = server
            .post("/v1/user/change-password")
            .add_header("Authorization", format!("Bearer {access_token}"))
            .json(&json!({
                "current_password": "OldPassword123!",
                "new_password": "NewPassword123!"
            }))
            .await;
        assert_eq!(blocked_change.status_code(), 403);
        let blocked_data: serde_json::Value = blocked_change.json::<serde_json::Value>();
        assert_eq!(blocked_data["mfa_required"], true);

        let recent_mfa = server
            .post("/v1/user/mfa/verify")
            .add_header("Authorization", format!("Bearer {access_token}"))
            .json(&json!({"recovery_code": recovery_code}))
            .await;
        assert_eq!(recent_mfa.status_code(), 200);
        let recent_data: serde_json::Value = recent_mfa.json::<serde_json::Value>();
        assert_eq!(recent_data["data"]["method"], "recovery_code");

        let replay = server
            .post("/v1/user/mfa/verify")
            .add_header("Authorization", format!("Bearer {access_token}"))
            .json(&json!({"recovery_code": recovery_code}))
            .await;
        assert_eq!(replay.status_code(), 400);

        let changed = server
            .post("/v1/user/change-password")
            .add_header("Authorization", format!("Bearer {access_token}"))
            .json(&json!({
                "current_password": "OldPassword123!",
                "new_password": "NewPassword123!"
            }))
            .await;
        assert_eq!(changed.status_code(), 200);

        let reset = server
            .post("/v1/user/mfa/totp/reset")
            .add_header("Authorization", format!("Bearer {access_token}"))
            .await;
        assert_eq!(reset.status_code(), 200);
        let reset_data: serde_json::Value = reset.json::<serde_json::Value>();
        assert_eq!(reset_data["data"]["enabled"], false);

        let reset_again = server
            .post("/v1/user/mfa/totp/reset")
            .add_header("Authorization", format!("Bearer {access_token}"))
            .await;
        assert_eq!(reset_again.status_code(), 404);
    }
}
