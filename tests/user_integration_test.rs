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
    use std::time::{Duration, Instant};
    use tokio::net::TcpListener;
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

    fn smtp_test_config(port: u16, timeout_seconds: i64) -> Option<Config> {
        let host = std::env::var("SMTP_TEST_HOST").ok()?;
        let from = "Keylo Test <no-reply@example.test>".to_string();
        Some(Config {
            mail_provider: "smtp".to_string(),
            smtp_host: Some(host),
            smtp_port: port,
            smtp_from: Some(from),
            smtp_tls_mode: "plain".to_string(),
            smtp_timeout_seconds: timeout_seconds,
            ..test_config()
        })
    }

    async fn setup_smtp_test_server(port: u16) -> Option<TestServer> {
        setup_smtp_test_server_with_timeout(port, 2).await
    }

    async fn setup_smtp_test_server_with_timeout(
        port: u16,
        timeout_seconds: i64,
    ) -> Option<TestServer> {
        let Some(config) = smtp_test_config(port, timeout_seconds) else {
            println!("Skipping SMTP account flow: SMTP_TEST_HOST is not configured");
            return None;
        };
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
            Ok(router) => Some(TestServer::new(router)),
            Err(error) => {
                println!("Skipping SMTP account flow: DB unavailable ({error})");
                None
            }
        }
    }

    async fn wait_for_smtp_token(prefix: &str, recipient: &str, subject: &str) -> String {
        let api_url = std::env::var("SMTP_TEST_API_URL")
            .expect("SMTP_TEST_API_URL must be set for SMTP account flow tests");
        let api_base = api_url
            .strip_suffix("/messages")
            .expect("SMTP_TEST_API_URL must end with /messages");
        let client = reqwest::Client::new();
        let deadline = Instant::now() + Duration::from_secs(10);

        loop {
            let list_result = client.get(&api_url).send().await;
            if let Ok(response) = list_result {
                if let Ok(payload) = response.json::<serde_json::Value>().await {
                    let messages = payload
                        .get("messages")
                        .and_then(serde_json::Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    for message in messages {
                        let summary = message.to_string();
                        if !summary.contains(subject) || !summary.contains(recipient) {
                            continue;
                        }
                        let Some(message_id) = ["ID", "id"]
                            .iter()
                            .find_map(|field| message.get(*field).and_then(|value| value.as_str()))
                        else {
                            continue;
                        };
                        let detail_url = format!("{api_base}/message/{message_id}");
                        if let Ok(detail_response) = client.get(detail_url).send().await {
                            if let Ok(detail) = detail_response.text().await {
                                if let Some(start) = detail.find(prefix) {
                                    let token_start = start + prefix.len();
                                    let token = detail[token_start..]
                                        .split(['\\', '"', '\r', '\n'])
                                        .next()
                                        .unwrap_or_default()
                                        .trim();
                                    if !token.is_empty() {
                                        return token.to_string();
                                    }
                                }
                            }
                        }
                    }
                }
            }

            assert!(
                Instant::now() < deadline,
                "Mailpit did not expose the expected message for {recipient}"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    #[tokio::test]
    async fn test_smtp_account_flows_deliver_and_consume_real_tokens() {
        let Some(server) = setup_smtp_test_server(
            std::env::var("SMTP_TEST_PORT")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(1025),
        )
        .await
        else {
            return;
        };
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let username = format!("smtp-flow-{suffix}");
        let email = format!("smtp-flow-{suffix}@example.test");

        let registration = server
            .post("/v1/auth/register")
            .json(&json!({
                "username": username,
                "email": email,
                "password": "Password123!"
            }))
            .await;
        registration.assert_status_ok();

        let login = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "Password123!"
            }))
            .await;
        login.assert_status_ok();
        let access_token = login.json::<serde_json::Value>()["access_token"]
            .as_str()
            .unwrap()
            .to_string();

        let verification_request = server
            .post("/v1/user/email-verification/request")
            .add_header("Authorization", format!("Bearer {access_token}"))
            .await;
        verification_request.assert_status_ok();
        let verification_token = wait_for_smtp_token(
            "Use this one-time Keylo email verification token: ",
            &email,
            "Verify your Keylo email address",
        )
        .await;
        let confirmation = server
            .post("/v1/auth/email-verification/confirm")
            .json(&json!({ "token": verification_token }))
            .await;
        confirmation.assert_status_ok();

        let reset_request = server
            .post("/v1/auth/password-reset/request")
            .json(&json!({ "identifier": email }))
            .await;
        reset_request.assert_status_ok();
        let reset_token = wait_for_smtp_token(
            "Use this one-time Keylo password reset token: ",
            &email,
            "Reset your Keylo password",
        )
        .await;
        let reset = server
            .post("/v1/auth/password-reset/confirm")
            .json(&json!({
                "token": reset_token,
                "new_password": "ResetPassword#123"
            }))
            .await;
        reset.assert_status_ok();

        let reset_login = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "ResetPassword#123"
            }))
            .await;
        reset_login.assert_status_ok();
        let reset_login_body: serde_json::Value = reset_login.json::<serde_json::Value>();
        assert_eq!(reset_login_body["password_change_required"], true);
        let reset_access_token = reset_login_body["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let change_password = server
            .post("/v1/user/change-password")
            .add_header("Authorization", format!("Bearer {reset_access_token}"))
            .json(&json!({
                "current_password": "ResetPassword#123",
                "new_password": "FinalPassword#123"
            }))
            .await;
        change_password.assert_status_ok();

        let final_login = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "FinalPassword#123"
            }))
            .await;
        final_login.assert_status_ok();
        assert!(
            !final_login.json::<serde_json::Value>()["password_change_required"]
                .as_bool()
                .unwrap_or(false)
        );
    }

    #[tokio::test]
    async fn test_smtp_delivery_failure_revokes_password_reset_token() {
        let Some(server) = setup_smtp_test_server(1).await else {
            return;
        };
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let username = format!("smtp-failure-{suffix}");
        let email = format!("smtp-failure-{suffix}@example.test");
        let registration = server
            .post("/v1/auth/register")
            .json(&json!({
                "username": username,
                "email": email,
                "password": "Password123!"
            }))
            .await;
        registration.assert_status_ok();
        let user_id = registration.json::<serde_json::Value>()["data"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://keylo_user@localhost:5432/keylo".to_string());
        let pool = db::init_db_pool(&database_url).await.unwrap();
        db::mark_user_email_verified(&pool, &user_id, Some("test"))
            .await
            .unwrap();

        let response = server
            .post("/v1/auth/password-reset/request")
            .json(&json!({ "identifier": email }))
            .await;
        response.assert_status_ok();
        let revoked_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM password_reset_tokens
             WHERE user_id = $1 AND revoked_at IS NOT NULL",
        )
        .bind(&user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(revoked_count, 1);
        pool.close().await;
    }

    #[tokio::test]
    async fn test_smtp_timeout_failure_revokes_password_reset_token() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    drop(socket);
                });
            }
        });

        let Some(server) = setup_smtp_test_server_with_timeout(port, 1).await else {
            accept_task.abort();
            return;
        };
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let username = format!("smtp-timeout-{suffix}");
        let email = format!("smtp-timeout-{suffix}@example.test");
        let registration = server
            .post("/v1/auth/register")
            .json(&json!({
                "username": username,
                "email": email,
                "password": "Password123!"
            }))
            .await;
        registration.assert_status_ok();
        let user_id = registration.json::<serde_json::Value>()["data"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://keylo_user@localhost:5432/keylo".to_string());
        let pool = db::init_db_pool(&database_url).await.unwrap();
        db::mark_user_email_verified(&pool, &user_id, Some("test"))
            .await
            .unwrap();

        let response = server
            .post("/v1/auth/password-reset/request")
            .json(&json!({ "identifier": email }))
            .await;
        response.assert_status_ok();
        let revoked_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM password_reset_tokens
             WHERE user_id = $1 AND revoked_at IS NOT NULL",
        )
        .bind(&user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(revoked_count, 1);
        pool.close().await;
        accept_task.abort();
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

    #[tokio::test]
    async fn test_password_reset_is_non_enumerating_single_use_and_revokes_sessions() {
        let Some((server, provider)) = setup_email_verification_test_server().await else {
            return;
        };
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let username = format!("password-reset-{suffix}");
        let email = format!("password-reset-{suffix}@example.test");
        let registration = server
            .post("/v1/auth/register")
            .json(&json!({
                "username": username,
                "email": email,
                "password": "Password123!"
            }))
            .await;
        registration.assert_status_ok();
        let user_id = registration.json::<serde_json::Value>()["data"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://keylo_user@localhost:5432/keylo".to_string());
        let pool = db::init_db_pool(&database_url).await.unwrap();
        assert!(db::mark_user_email_verified(&pool, &user_id, Some("test"))
            .await
            .unwrap());

        let login = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "Password123!"
            }))
            .await;
        login.assert_status_ok();
        let login_data: serde_json::Value = login.json::<serde_json::Value>();
        let old_refresh_token = login_data["refresh_token"].as_str().unwrap().to_string();
        let browser_cookie = format!("password-reset-{suffix}");
        db::create_browser_session(
            &pool,
            &browser_cookie,
            &keylo::models::OidcBrowserSession {
                user_id: user_id.clone(),
                expires_at: chrono::Utc::now().timestamp() + 3600,
            },
        )
        .await
        .unwrap();

        let known = server
            .post("/v1/auth/password-reset/request")
            .json(&json!({"identifier": email}))
            .await;
        known.assert_status_ok();
        let known_body: serde_json::Value = known.json::<serde_json::Value>();
        assert_eq!(known_body["data"]["status"], "accepted");
        let token = provider.deliveries()[0]
            .text_body
            .strip_prefix("Use this one-time Keylo password reset token: ")
            .unwrap()
            .to_string();

        let unknown = server
            .post("/v1/auth/password-reset/request")
            .json(&json!({"identifier": format!("unknown-{suffix}@example.test")}))
            .await;
        unknown.assert_status_ok();
        assert_eq!(unknown.json::<serde_json::Value>(), known_body);

        let confirmation = server
            .post("/v1/auth/password-reset/confirm")
            .json(&json!({
                "token": token.clone(),
                "new_password": "ResetPassword#123"
            }))
            .await;
        confirmation.assert_status_ok();
        let confirmation_body: serde_json::Value = confirmation.json::<serde_json::Value>();
        assert_eq!(confirmation_body["data"]["password_reset"], true);
        assert_eq!(confirmation_body["data"]["password_change_required"], true);
        assert!(db::resolve_browser_session(&pool, &browser_cookie)
            .await
            .unwrap()
            .is_none());

        let old_refresh = server
            .post("/v1/auth/refresh")
            .json(&json!({"refresh_token": old_refresh_token}))
            .await;
        assert_eq!(old_refresh.status_code(), 401);

        let old_login = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "Password123!"
            }))
            .await;
        assert_eq!(old_login.status_code(), 401);

        let new_login = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "ResetPassword#123"
            }))
            .await;
        new_login.assert_status_ok();
        assert_eq!(
            new_login.json::<serde_json::Value>()["password_change_required"],
            true
        );

        let replay = server
            .post("/v1/auth/password-reset/confirm")
            .json(&json!({
                "token": token,
                "new_password": "AnotherPassword#123"
            }))
            .await;
        assert_eq!(replay.status_code(), 400);

        let user = db::get_user_by_id(&pool, &user_id).await.unwrap().unwrap();
        assert!(user.password_change_required);
        let stored_hash: String =
            sqlx::query_scalar("SELECT token_hash FROM password_reset_tokens WHERE user_id = $1")
                .bind(&user_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(!stored_hash.contains(&token));
        pool.close().await;
    }

    #[tokio::test]
    async fn test_password_reset_delivery_failure_keeps_public_response_and_revokes_token() {
        let Some((server, provider)) = setup_email_verification_test_server().await else {
            return;
        };
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let username = format!("password-failure-{suffix}");
        let email = format!("password-failure-{suffix}@example.test");
        let registration = server
            .post("/v1/auth/register")
            .json(&json!({
                "username": username,
                "email": email,
                "password": "Password123!"
            }))
            .await;
        registration.assert_status_ok();
        let user_id = registration.json::<serde_json::Value>()["data"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://keylo_user@localhost:5432/keylo".to_string());
        let pool = db::init_db_pool(&database_url).await.unwrap();
        db::mark_user_email_verified(&pool, &user_id, Some("test"))
            .await
            .unwrap();

        provider.set_failure(Some(MailDeliveryError::Timeout));
        let response = server
            .post("/v1/auth/password-reset/request")
            .json(&json!({"identifier": email}))
            .await;
        response.assert_status_ok();
        assert!(provider.deliveries().is_empty());
        let revoked_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM password_reset_tokens
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
