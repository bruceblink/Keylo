//! Real PostgreSQL HTTP regressions for shared API and OIDC login protection.
//!
//! These tests require TEST_DATABASE_URL and intentionally fail when the
//! configured PostgreSQL database cannot be reached or migrated.

use axum::extract::ConnectInfo;
use axum::http::StatusCode;
use axum::{body::Bytes, routing::post, Extension, Router};
use axum_test::{TestResponse, TestServer};
use keylo::{
    config::Config,
    db,
    handlers::{auth_token, oidc},
    models::{CreateOidcClientRequest, User},
    state::AppState,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::time::{sleep, timeout};

const USER_PASSWORD: &str = "OidcLoginProtection#123";
const WRONG_PASSWORD: &str = "IncorrectProtectionPassword#123";

struct TestContext {
    pool: PgPool,
    state: AppState,
    server: TestServer,
    oidc_client_id: String,
    suffix: String,
}

impl TestContext {
    async fn new(
        max_failed_attempts: u32,
        login_lockout_seconds: i64,
        scoped_rate_limit: u32,
        global_rate_limit: u32,
    ) -> Self {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("OIDC login PostgreSQL regressions require TEST_DATABASE_URL");
        assert!(
            !database_url.trim().is_empty(),
            "TEST_DATABASE_URL must not be empty"
        );

        let pool = db::init_db_pool(&database_url)
            .await
            .expect("The explicitly configured PostgreSQL test database must be reachable");
        db::run_migrations(&pool)
            .await
            .expect("PostgreSQL test database migrations must succeed");

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let config = test_config(
            &suffix,
            max_failed_attempts,
            login_lockout_seconds,
            scoped_rate_limit,
            global_rate_limit,
        );
        let state = AppState::new(config, Some(Arc::new(pool.clone())))
            .expect("Synthetic JWT configuration must initialize AppState");
        let app = Router::new()
            .route("/v1/auth/token", post(auth_token))
            .route("/v1/oidc/login", post(oidc::login))
            .route("/v1/oidc/consent", post(oidc::consent))
            .with_state(state.clone())
            .layer(Extension(ConnectInfo(SocketAddr::from((
                [198, 51, 100, 17],
                3001,
            )))));
        let server = TestServer::new(app);

        let oidc_client_id = format!("oidc-login-protection-{suffix}");
        db::create_oidc_client(
            &pool,
            &CreateOidcClientRequest {
                client_id: oidc_client_id.clone(),
                client_secret: None,
                name: "OIDC login protection regression".to_string(),
                description: None,
                client_type: "public".to_string(),
                redirect_uris: vec!["https://client.example.test/callback".to_string()],
                grant_types: None,
                scopes: None,
            },
        )
        .await
        .expect("Synthetic OIDC relying party creation must succeed");

        Self {
            pool,
            state,
            server,
            oidc_client_id,
            suffix,
        }
    }

    async fn user(&self, label: &str, password: Option<&str>) -> User {
        let username = format!("oidc-login-{label}-{}", self.suffix);
        db::create_user(
            &self.pool,
            &username,
            &format!("{username}@example.test"),
            password,
        )
        .await
        .expect("Synthetic user creation must succeed")
    }

    async fn api_login(&self, username: &str, password: &str) -> TestResponse {
        self.server
            .post("/v1/auth/token")
            .json(&json!({"client_id": username, "client_secret": password}))
            .await
    }

    async fn oidc_login(&self, username: &str, password: &str) -> TestResponse {
        post_oidc_login(&self.server, &self.oidc_client_id, username, password).await
    }

    async fn expire_rate_limit_entries(&self) {
        let expired_at =
            chrono::Utc::now().timestamp() - self.state.config.auth_rate_limit_window_seconds - 1;
        let mut rate_limits = self.state.auth_rate_limits.write().await;
        for timestamps in rate_limits.values_mut() {
            timestamps.fill(expired_at);
        }
    }

    async fn login_failures(&self, username: &str) -> Option<(u32, i64)> {
        self.state
            .login_attempts
            .read()
            .await
            .get(username)
            .copied()
    }
}

fn test_config(
    suffix: &str,
    max_failed_attempts: u32,
    login_lockout_seconds: i64,
    scoped_rate_limit: u32,
    global_rate_limit: u32,
) -> Config {
    Config {
        jwt_private_key_pem: super::TEST_JWT_PRIVATE_KEY_PEM.to_string(),
        jwt_public_key_pem: super::TEST_JWT_PUBLIC_KEY_PEM.to_string(),
        jwt_keys_generated: false,
        environment: "test".to_string(),
        redis_url: None,
        redis_key_prefix: format!("oidc-login-test-{suffix}"),
        max_failed_login_attempts: max_failed_attempts,
        login_lockout_seconds,
        auth_rate_limit_window_seconds: 60,
        auth_rate_limit_max_requests: scoped_rate_limit,
        auth_global_rate_limit_max_requests: global_rate_limit,
        trust_proxy_headers: false,
        enable_setup_wizard: false,
        enable_super_admin_bootstrap: false,
        ..Default::default()
    }
}

async fn post_oidc_login(
    server: &TestServer,
    client_id: &str,
    username: &str,
    password: &str,
) -> TestResponse {
    post_oidc_login_with_redirect_uri(
        server,
        client_id,
        username,
        password,
        "https://client.example.test/callback",
        None,
    )
    .await
}

async fn post_oidc_login_with_forwarded_for(
    server: &TestServer,
    client_id: &str,
    username: &str,
    password: &str,
    forwarded_for: &str,
) -> TestResponse {
    post_oidc_login_with_redirect_uri(
        server,
        client_id,
        username,
        password,
        "https://client.example.test/callback",
        Some(forwarded_for),
    )
    .await
}

async fn post_oidc_login_with_redirect_uri(
    server: &TestServer,
    client_id: &str,
    username: &str,
    password: &str,
    redirect_uri: &str,
    forwarded_for: Option<&str>,
) -> TestResponse {
    let mut form = authorization_form(client_id, redirect_uri);
    form.append_pair("username", username)
        .append_pair("password", password);
    let body = Bytes::from(form.finish());
    if let Some(forwarded_for) = forwarded_for {
        server
            .post("/v1/oidc/login")
            .add_header("content-type", "application/x-www-form-urlencoded")
            .add_header("x-forwarded-for", forwarded_for)
            .bytes(body)
            .await
    } else {
        server
            .post("/v1/oidc/login")
            .add_header("content-type", "application/x-www-form-urlencoded")
            .bytes(body)
            .await
    }
}

async fn post_oidc_consent(server: &TestServer, client_id: &str, cookie: &str) -> TestResponse {
    let mut form = authorization_form(client_id, "https://client.example.test/callback");
    form.append_pair("decision", "approve");
    server
        .post("/v1/oidc/consent")
        .add_header("content-type", "application/x-www-form-urlencoded")
        .add_header("cookie", cookie)
        .bytes(Bytes::from(form.finish()))
        .await
}

fn authorization_form(
    client_id: &str,
    redirect_uri: &str,
) -> url::form_urlencoded::Serializer<'static, String> {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", "openid profile")
        .append_pair("state", "synthetic-state")
        .append_pair("nonce", "synthetic-nonce")
        .append_pair("code_challenge", &"a".repeat(43))
        .append_pair("code_challenge_method", "S256");
    form
}

fn assert_json_rate_limited(response: TestResponse) {
    assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.maybe_header("set-cookie").is_none());
    assert!(response
        .header("content-type")
        .to_str()
        .expect("Rate-limit response content type must be valid")
        .starts_with("application/json"));
    let body: Value = response.json();
    assert_eq!(body["error"], "too_many_requests");
    assert_eq!(body["code"], 1011);
}

fn assert_api_wrong_credentials(response: TestResponse) {
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.json::<Value>()["error"], "wrong_credentials");
}

fn assert_oidc_retry(response: TestResponse, username: &str, password: &str) -> String {
    assert_eq!(response.status_code(), StatusCode::OK);
    assert!(response.maybe_header("set-cookie").is_none());
    assert!(response
        .header("content-type")
        .to_str()
        .expect("OIDC retry content type must be valid")
        .starts_with("text/html"));
    let page = response.text();
    assert!(page.contains("role=\"alert\">Incorrect username or password. Please try again."));
    assert!(page.contains(&format!("value=\"{username}\"")));
    assert!(page.contains("name=\"password\" type=\"password\""));
    assert!(!page.contains(password));
    page.replace(&format!("value=\"{username}\""), "value=\"USERNAME\"")
}

#[tokio::test]
async fn api_failures_lock_oidc_correct_password_without_issuing_a_session() {
    let context = TestContext::new(2, 30, 100, 1_000).await;
    let user = context.user("api-lock", Some(USER_PASSWORD)).await;

    assert_api_wrong_credentials(context.api_login(&user.username, WRONG_PASSWORD).await);
    assert_api_wrong_credentials(context.api_login(&user.username, WRONG_PASSWORD).await);

    assert_json_rate_limited(context.oidc_login(&user.username, USER_PASSWORD).await);
    assert_json_rate_limited(context.api_login(&user.username, USER_PASSWORD).await);

    let browser_sessions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM oidc_browser_sessions WHERE user_id = $1")
            .bind(&user.id)
            .fetch_one(&context.pool)
            .await
            .expect("OIDC browser session count query must succeed");
    assert_eq!(browser_sessions, 0);
}

#[tokio::test]
async fn oidc_and_api_failures_share_lock_and_successful_oidc_login_clears_failures() {
    let context = TestContext::new(2, 30, 100, 1_000).await;
    let user = context.user("shared-lock", Some(USER_PASSWORD)).await;

    assert_api_wrong_credentials(context.api_login(&user.username, WRONG_PASSWORD).await);

    let success = context.oidc_login(&user.username, USER_PASSWORD).await;
    assert_eq!(success.status_code(), StatusCode::OK);
    let cookie = success
        .header("set-cookie")
        .to_str()
        .expect("Successful OIDC login must set its browser session cookie")
        .split(';')
        .next()
        .expect("OIDC session cookie must include its name and value")
        .to_string();
    assert!(cookie.starts_with("keylo_oidc_session="));

    let codes_before_consent: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM oidc_authorization_codes WHERE user_id = $1 AND client_id = $2",
    )
    .bind(&user.id)
    .bind(&context.oidc_client_id)
    .fetch_one(&context.pool)
    .await
    .expect("OIDC authorization code count query must succeed");
    assert_eq!(codes_before_consent, 0);

    let consent = post_oidc_consent(&context.server, &context.oidc_client_id, &cookie).await;
    assert_eq!(consent.status_code(), StatusCode::SEE_OTHER);

    let codes_after_consent: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM oidc_authorization_codes WHERE user_id = $1 AND client_id = $2",
    )
    .bind(&user.id)
    .bind(&context.oidc_client_id)
    .fetch_one(&context.pool)
    .await
    .expect("OIDC authorization code count query must succeed");
    assert_eq!(codes_after_consent, 1);

    // The API failure before the successful browser login was cleared. These
    // next failures, one from each entry point, reach the shared threshold.
    assert_api_wrong_credentials(context.api_login(&user.username, WRONG_PASSWORD).await);
    assert_oidc_retry(
        context.oidc_login(&user.username, WRONG_PASSWORD).await,
        &user.username,
        WRONG_PASSWORD,
    );

    assert_json_rate_limited(context.api_login(&user.username, USER_PASSWORD).await);
    assert_json_rate_limited(context.oidc_login(&user.username, USER_PASSWORD).await);
}

#[tokio::test]
async fn expired_lock_allows_correct_credentials_again() {
    let context = TestContext::new(1, 30, 1_000, 2_000).await;
    let user = context.user("lock-expiry", Some(USER_PASSWORD)).await;

    assert_api_wrong_credentials(context.api_login(&user.username, WRONG_PASSWORD).await);
    assert_json_rate_limited(context.api_login(&user.username, USER_PASSWORD).await);
    assert_json_rate_limited(context.oidc_login(&user.username, USER_PASSWORD).await);

    // Establish the lock with a generous duration before shortening it. This
    // avoids crossing a one-second boundary during the initial assertions.
    context
        .state
        .login_attempts
        .write()
        .await
        .get_mut(&user.username)
        .expect("The shared account lock must exist")
        .1 = chrono::Utc::now().timestamp() + 1;

    let recovered = timeout(Duration::from_secs(5), async {
        loop {
            let response = context.oidc_login(&user.username, USER_PASSWORD).await;
            if response.status_code() == StatusCode::OK
                && response.maybe_header("set-cookie").is_some()
            {
                break response;
            }
            assert_eq!(
                response.status_code(),
                StatusCode::TOO_MANY_REQUESTS,
                "Only the active account lock may reject correct OIDC credentials before expiry"
            );
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("One-second login lock must expire within the bounded recovery window");
    assert_eq!(recovered.status_code(), StatusCode::OK);
    assert!(recovered.maybe_header("set-cookie").is_some());
    assert_eq!(
        context
            .api_login(&user.username, USER_PASSWORD)
            .await
            .status_code(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn expired_rate_limit_entries_allow_a_new_http_request() {
    let context = TestContext::new(20, 30, 1, 1_000).await;
    let user = context
        .user("rate-window-expiry", Some(USER_PASSWORD))
        .await;

    assert_api_wrong_credentials(context.api_login(&user.username, WRONG_PASSWORD).await);
    assert_json_rate_limited(context.api_login(&user.username, USER_PASSWORD).await);

    context.expire_rate_limit_entries().await;
    let recovered = context.api_login(&user.username, USER_PASSWORD).await;
    assert_eq!(recovered.status_code(), StatusCode::OK);
}

#[tokio::test]
async fn api_and_oidc_share_scoped_and_global_ip_rate_limits() {
    let scoped = TestContext::new(20, 30, 2, 1_000).await;
    let scoped_user = scoped.user("scoped-rate", Some(USER_PASSWORD)).await;

    assert_api_wrong_credentials(
        scoped
            .api_login(&scoped_user.username, WRONG_PASSWORD)
            .await,
    );
    assert_oidc_retry(
        scoped
            .oidc_login(&scoped_user.username, WRONG_PASSWORD)
            .await,
        &scoped_user.username,
        WRONG_PASSWORD,
    );
    assert_json_rate_limited(
        scoped
            .oidc_login(&scoped_user.username, USER_PASSWORD)
            .await,
    );

    let global = TestContext::new(20, 30, 100, 2).await;
    let first_username = format!("oidc-login-unknown-first-{}", global.suffix);
    let second_username = format!("oidc-login-unknown-second-{}", global.suffix);
    let third_user = global.user("global-rate-target", Some(USER_PASSWORD)).await;

    assert_api_wrong_credentials(global.api_login(&first_username, WRONG_PASSWORD).await);
    assert_oidc_retry(
        global.oidc_login(&second_username, WRONG_PASSWORD).await,
        &second_username,
        WRONG_PASSWORD,
    );
    assert_json_rate_limited(global.oidc_login(&third_user.username, USER_PASSWORD).await);
}

#[tokio::test]
async fn unknown_inactive_and_passwordless_accounts_share_the_retry_page_and_count_failures() {
    let context = TestContext::new(1, 30, 100, 1_000).await;
    let unknown_username = format!("oidc-login-unknown-{}", context.suffix);
    let inactive = context.user("inactive", Some(USER_PASSWORD)).await;
    db::set_user_active(&context.pool, &inactive.id, false)
        .await
        .expect("Synthetic inactive account update must succeed");
    let passwordless = context.user("passwordless", None).await;

    let unknown_page = assert_oidc_retry(
        context.oidc_login(&unknown_username, WRONG_PASSWORD).await,
        &unknown_username,
        WRONG_PASSWORD,
    );
    let inactive_page = assert_oidc_retry(
        context.oidc_login(&inactive.username, USER_PASSWORD).await,
        &inactive.username,
        USER_PASSWORD,
    );
    let passwordless_page = assert_oidc_retry(
        context
            .oidc_login(&passwordless.username, USER_PASSWORD)
            .await,
        &passwordless.username,
        USER_PASSWORD,
    );
    assert_eq!(unknown_page, inactive_page);
    assert_eq!(unknown_page, passwordless_page);

    // A correct API password still receives the account lock for each category,
    // proving these generic browser failures all advanced the same counter.
    assert_json_rate_limited(context.api_login(&unknown_username, USER_PASSWORD).await);
    assert_json_rate_limited(context.api_login(&inactive.username, USER_PASSWORD).await);
    assert_json_rate_limited(
        context
            .api_login(&passwordless.username, USER_PASSWORD)
            .await,
    );
}

#[tokio::test]
async fn forwarded_headers_cannot_bypass_the_real_peer_ip_quota() {
    let context = TestContext::new(20, 30, 100, 2).await;
    let first_username = format!("oidc-login-forwarded-first-{}", context.suffix);
    let second_username = format!("oidc-login-forwarded-second-{}", context.suffix);
    let target = context.user("forwarded-target", Some(USER_PASSWORD)).await;

    assert_api_wrong_credentials(context.api_login(&first_username, WRONG_PASSWORD).await);
    assert_oidc_retry(
        post_oidc_login_with_forwarded_for(
            &context.server,
            &context.oidc_client_id,
            &second_username,
            WRONG_PASSWORD,
            "203.0.113.41",
        )
        .await,
        &second_username,
        WRONG_PASSWORD,
    );
    assert_json_rate_limited(
        post_oidc_login_with_forwarded_for(
            &context.server,
            &context.oidc_client_id,
            &target.username,
            USER_PASSWORD,
            "192.0.2.99",
        )
        .await,
    );
    let rate_keys = context.state.auth_rate_limits.read().await;
    assert!(rate_keys.contains_key("global:198.51.100.17"));
    assert!(!rate_keys.contains_key("global:203.0.113.41"));
    assert!(!rate_keys.contains_key("global:192.0.2.99"));
    drop(rate_keys);
    let metrics = context.state.runtime_metrics.prometheus_text();
    assert!(metrics.contains("keylo_rate_limit_rejections_total 1"));
    assert!(!metrics.contains(&target.username));
    assert!(!metrics.contains("198.51.100.17"));

    let events: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT event_type, detail FROM audit_logs WHERE actor = $1 ORDER BY created_at",
    )
    .bind(&target.username)
    .fetch_all(&context.pool)
    .await
    .expect("OIDC rate-limit audit must persist");
    assert!(events
        .iter()
        .any(|(event, _)| event == "oidc.login.rate_limited.global"));
    for (_, detail) in events {
        let detail = detail.unwrap_or_default();
        assert!(!detail.contains(USER_PASSWORD));
        assert!(!detail.contains(WRONG_PASSWORD));
        assert!(!detail.contains("198.51.100.17"));
    }
}

#[tokio::test]
async fn invalid_oidc_authorization_parameters_do_not_change_login_failures() {
    let context = TestContext::new(5, 30, 100, 1_000).await;
    let user = context
        .user("invalid-authorization", Some(USER_PASSWORD))
        .await;

    assert_api_wrong_credentials(context.api_login(&user.username, WRONG_PASSWORD).await);
    let failures_before = context
        .login_failures(&user.username)
        .await
        .expect("The failed API login must create a username failure count");

    let invalid_authorization = post_oidc_login_with_redirect_uri(
        &context.server,
        &context.oidc_client_id,
        &user.username,
        WRONG_PASSWORD,
        "https://unregistered.example.test/callback",
        None,
    )
    .await;
    assert_eq!(invalid_authorization.status_code(), StatusCode::BAD_REQUEST);
    assert!(invalid_authorization.maybe_header("set-cookie").is_none());
    assert_eq!(
        context.login_failures(&user.username).await,
        Some(failures_before)
    );
}

#[tokio::test]
async fn policy_and_session_storage_failures_do_not_clear_login_failures() {
    let context = TestContext::new(3, 30, 100, 1_000).await;
    let restricted = context.user("password-change", Some(USER_PASSWORD)).await;
    assert_api_wrong_credentials(
        context
            .api_login(&restricted.username, WRONG_PASSWORD)
            .await,
    );
    let previous_failures = context.login_failures(&restricted.username).await;
    sqlx::query("UPDATE users SET password_change_required = TRUE WHERE id = $1")
        .bind(&restricted.id)
        .execute(&context.pool)
        .await
        .expect("Synthetic user must require a password change");
    let denied = context
        .oidc_login(&restricted.username, USER_PASSWORD)
        .await;
    assert_eq!(denied.status_code(), StatusCode::FORBIDDEN);
    assert_eq!(denied.json::<Value>()["error"], "password_change_required");
    assert!(denied.maybe_header("set-cookie").is_none());
    assert_eq!(
        context.login_failures(&restricted.username).await,
        previous_failures
    );

    let user = context.user("session-storage", Some(USER_PASSWORD)).await;
    assert_api_wrong_credentials(context.api_login(&user.username, WRONG_PASSWORD).await);
    let previous_failures = context.login_failures(&user.username).await;
    // Only this generated user's session insert is rejected; other fixtures
    // sharing the test database remain valid.
    let constraint = format!("oidc_session_failure_{}", context.suffix);
    sqlx::raw_sql(&format!(
        "ALTER TABLE oidc_browser_sessions ADD CONSTRAINT {constraint} CHECK (user_id <> '{}')",
        user.id
    ))
    .execute(&context.pool)
    .await
    .expect("Synthetic session storage failure must be installed");
    let failed = context.oidc_login(&user.username, USER_PASSWORD).await;
    sqlx::raw_sql(&format!(
        "ALTER TABLE oidc_browser_sessions DROP CONSTRAINT {constraint}"
    ))
    .execute(&context.pool)
    .await
    .expect("Synthetic session storage failure must be removed");
    assert_eq!(failed.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(failed.maybe_header("set-cookie").is_none());
    assert_eq!(
        context.login_failures(&user.username).await,
        previous_failures
    );

    let success = context.oidc_login(&user.username, USER_PASSWORD).await;
    assert_eq!(success.status_code(), StatusCode::OK);
    assert!(success.maybe_header("set-cookie").is_some());
    assert_eq!(context.login_failures(&user.username).await, None);
}
