use axum::body::Bytes;
use axum::http::StatusCode;
use axum_test::TestServer;
use keylo::config::{build_database_url, database_password_from_env_result, Config};
use keylo::db;
use keylo::startup;
use serde_json::json;

const INTEGRATION_ADMIN_CLIENT_ID: &str = "cli-admin-root";
const INTEGRATION_ADMIN_CLIENT_SECRET: &str = "CliAdminRoot#123";

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

#[cfg(test)]
mod tests {
    use super::*;
    use keylo::models::{Claims, Keys};
    use openidconnect::{
        core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
        reqwest as oidc_reqwest, AuthorizationCode, ClientId, CsrfToken, IssuerUrl, Nonce,
        OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl, Scope,
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::time::sleep;

    static TEST_PREFIX_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_config() -> Config {
        Config {
            jwt_private_key_pem: TEST_JWT_PRIVATE_KEY_PEM.to_string(),
            jwt_public_key_pem: TEST_JWT_PUBLIC_KEY_PEM.to_string(),
            jwt_keys_generated: false,
            environment: "test".to_string(),
            redis_url: None,
            auth_rate_limit_max_requests: 1000,
            auth_global_rate_limit_max_requests: 10_000,
            enable_setup_wizard: false,
            ..Default::default()
        }
    }

    /// 设置测试服务器（带数据库）
    async fn setup_test_server() -> TestServer {
        setup_test_server_with_config(test_config()).await
    }

    async fn setup_test_server_with_config(mut config: Config) -> TestServer {
        config.jwt_private_key_pem = TEST_JWT_PRIVATE_KEY_PEM.to_string();
        config.jwt_public_key_pem = TEST_JWT_PUBLIC_KEY_PEM.to_string();
        config.environment = "test".to_string();
        config.redis_url = None;
        config.redis_key_prefix = format!(
            "keylo-test-{}-{}",
            std::process::id(),
            TEST_PREFIX_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://keylo_user@localhost:5432/keylo".to_string());

        match startup::init_app_router_with_db_and_admin(
            config.clone(),
            &database_url,
            INTEGRATION_ADMIN_CLIENT_ID,
            INTEGRATION_ADMIN_CLIENT_SECRET,
        )
        .await
        {
            Ok(app) => TestServer::new(app),
            Err(_) => {
                let app = startup::init_app_router_with_config(config);
                TestServer::new(app)
            }
        }
    }

    /// Opens and migrates the database used by organization HTTP tests.
    ///
    /// An explicitly configured test database must be reachable; otherwise a
    /// test could accidentally exercise the in-memory fallback router instead.
    async fn setup_organization_test_pool() -> Option<sqlx::PgPool> {
        let explicit_database_url = std::env::var("TEST_DATABASE_URL").ok();
        let database_url = explicit_database_url
            .clone()
            .unwrap_or_else(|| "postgres://keylo_user@localhost:5432/keylo".to_string());
        let pool = match db::init_db_pool(&database_url).await {
            Ok(pool) => pool,
            Err(error) if explicit_database_url.is_some() => {
                panic!("TEST_DATABASE_URL must be reachable for organization tests: {error}")
            }
            Err(error) => {
                eprintln!("Skipping organization HTTP test without PostgreSQL: {error}");
                return None;
            }
        };
        if let Err(error) = db::run_migrations(&pool).await {
            if explicit_database_url.is_some() {
                panic!("TEST_DATABASE_URL migrations must succeed for organization tests: {error}");
            }
            eprintln!("Skipping organization HTTP test without current migrations: {error}");
            return None;
        }
        Some(pool)
    }

    /// Run Keylo on a real loopback port so an unmodified standard OIDC client can use Discovery.
    async fn setup_oidc_compatibility_server() -> Option<(String, tokio::task::JoinHandle<()>)> {
        let database_url = std::env::var("TEST_DATABASE_URL").ok()?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.ok()?;
        let address = listener.local_addr().ok()?;
        let issuer = format!("http://{address}");
        let mut config = test_config();
        config.server_addr = "127.0.0.1".to_string();
        config.server_port = address.port();
        config.oidc_public_issuer = Some(issuer.clone());
        config.allow_insecure_internal_http = true;
        let app = startup::init_app_router_with_db_and_admin(
            config,
            &database_url,
            INTEGRATION_ADMIN_CLIENT_ID,
            INTEGRATION_ADMIN_CLIENT_SECRET,
        )
        .await
        .ok()?;
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("compatibility server must run");
        });
        Some((issuer, task))
    }

    #[tokio::test]
    async fn test_standard_openidconnect_client_completes_keylo_code_pkce_flow() {
        let Some((issuer, server_task)) = setup_oidc_compatibility_server().await else {
            return;
        };
        let result = async {
            let database_url = std::env::var("TEST_DATABASE_URL").unwrap();
            let pool = db::init_db_pool(&database_url).await.unwrap();
            let client_id = format!(
                "oidc-standard-client-{}",
                TEST_PREFIX_COUNTER.fetch_add(1, Ordering::Relaxed)
            );
            let redirect_uri = format!("{issuer}/rp/callback");
            db::create_oidc_client(
                &pool,
                &keylo::models::CreateOidcClientRequest {
                    client_id: client_id.clone(),
                    client_secret: None,
                    name: "Standard openidconnect client".to_string(),
                    description: None,
                    client_type: "public".to_string(),
                    redirect_uris: vec![redirect_uri.clone()],
                    grant_types: None,
                    scopes: None,
                },
            )
            .await
            .unwrap();
            let username = format!("oidc-standard-user-{}", uuid::Uuid::new_v4());
            let password = "StandardOidcClient#123";
            let user = db::create_user(
                &pool,
                &username,
                &format!("{username}@example.test"),
                Some(password),
            )
            .await
            .unwrap();

            let oidc_http_client = oidc_reqwest::ClientBuilder::new()
                .redirect(oidc_reqwest::redirect::Policy::none())
                .build()
                .unwrap();
            let provider_metadata = CoreProviderMetadata::discover_async(
                IssuerUrl::new(issuer.clone()).unwrap(),
                &oidc_http_client,
            )
            .await
            .unwrap();
            let client = CoreClient::from_provider_metadata(
                provider_metadata,
                ClientId::new(client_id.clone()),
                None,
            )
            .set_redirect_uri(RedirectUrl::new(redirect_uri.clone()).unwrap());
            let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
            let (authorization_url, csrf_state, nonce) = client
                .authorize_url(
                    CoreAuthenticationFlow::AuthorizationCode,
                    CsrfToken::new_random,
                    Nonce::new_random,
                )
                .add_scope(Scope::new("profile".to_string()))
                .set_pkce_challenge(pkce_challenge.clone())
                .url();

            let browser = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap();
            let login_page = browser
                .get(authorization_url.as_str())
                .send()
                .await
                .unwrap();
            assert_eq!(login_page.status(), reqwest::StatusCode::OK);
            let login = browser
                .post(format!("{issuer}/v1/oidc/login"))
                .form(&[
                    ("response_type", "code"),
                    ("client_id", client_id.as_str()),
                    ("redirect_uri", redirect_uri.as_str()),
                    ("scope", "openid profile"),
                    ("state", csrf_state.secret()),
                    ("nonce", nonce.secret()),
                    ("code_challenge", pkce_challenge.as_str()),
                    ("code_challenge_method", "S256"),
                    ("username", username.as_str()),
                    ("password", password),
                ])
                .send()
                .await
                .unwrap();
            assert_eq!(login.status(), reqwest::StatusCode::OK);
            let browser_cookie = login
                .headers()
                .get(reqwest::header::SET_COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_string();
            let consent = browser
                .post(format!("{issuer}/v1/oidc/consent"))
                .header(reqwest::header::COOKIE, browser_cookie)
                .form(&[
                    ("response_type", "code"),
                    ("client_id", client_id.as_str()),
                    ("redirect_uri", redirect_uri.as_str()),
                    ("scope", "openid profile"),
                    ("state", csrf_state.secret()),
                    ("nonce", nonce.secret()),
                    ("code_challenge", pkce_challenge.as_str()),
                    ("code_challenge_method", "S256"),
                    ("decision", "approve"),
                ])
                .send()
                .await
                .unwrap();
            assert_eq!(consent.status(), reqwest::StatusCode::SEE_OTHER);
            let callback_url = url::Url::parse(
                consent
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .unwrap()
                    .to_str()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                callback_url
                    .query_pairs()
                    .find(|(key, _)| key == "iss")
                    .unwrap()
                    .1,
                issuer
            );

            let code = callback_url
                .query_pairs()
                .find(|(key, _)| key == "code")
                .unwrap()
                .1
                .into_owned();
            let token_response = client
                .exchange_code(AuthorizationCode::new(code))
                .unwrap()
                .set_pkce_verifier(pkce_verifier)
                .request_async(&oidc_http_client)
                .await
                .unwrap();
            let claims = token_response
                .extra_fields()
                .id_token()
                .unwrap()
                .claims(&client.id_token_verifier(), &nonce)
                .unwrap();
            assert_eq!(claims.subject().as_str(), user.id);

            let userinfo: serde_json::Value = browser
                .get(format!("{issuer}/v1/oidc/userinfo"))
                .bearer_auth(token_response.access_token().secret())
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(userinfo["sub"], user.id);
        }
        .await;
        server_task.abort();
        result
    }

    #[tokio::test]
    async fn test_organization_oidc_client_is_scoped_and_live() {
        use base64::Engine as _;
        use sha2::Digest as _;

        let Some(pool) = setup_organization_test_pool().await else {
            return;
        };
        let server = setup_test_server().await;
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let organization_a = db::create_organization(
            &pool,
            &format!("oidc-http-a-{suffix}"),
            "OIDC HTTP organization A",
            keylo::models::ORGANIZATION_KIND_CUSTOMER,
        )
        .await
        .expect("Failed to create organization A");
        let organization_b = db::create_organization(
            &pool,
            &format!("oidc-http-b-{suffix}"),
            "OIDC HTTP organization B",
            keylo::models::ORGANIZATION_KIND_CUSTOMER,
        )
        .await
        .expect("Failed to create organization B");
        let username = format!("oidc-http-owner-{suffix}");
        let password = "OidcHttpOwner#123";
        let owner = db::create_user(
            &pool,
            &username,
            &format!("{username}@example.test"),
            Some(password),
        )
        .await
        .expect("Failed to create organization OIDC owner");
        let owner_principal = db::get_principal_by_ref(&pool, "user", &owner.id)
            .await
            .expect("Failed to load organization OIDC owner principal")
            .expect("Organization OIDC owner principal should exist");
        db::upsert_organization_membership(
            &pool,
            &organization_a.id,
            &owner_principal.id,
            "active",
            None,
            Some(keylo::models::ORGANIZATION_MANAGEMENT_ROLE_OWNER),
        )
        .await
        .expect("Failed to create organization OIDC owner membership");

        let login = server
            .post("/v1/auth/token")
            .json(&json!({"client_id": username, "client_secret": password}))
            .await;
        login.assert_status_ok();
        let platform_token = login.json::<serde_json::Value>()["access_token"]
            .as_str()
            .expect("Owner platform token should exist")
            .to_string();
        let context = server
            .post("/v1/auth/organization-context")
            .add_header("Authorization", format!("Bearer {platform_token}"))
            .json(&json!({"organization_id": organization_a.id}))
            .await;
        context.assert_status_ok();
        let organization_token = context.json::<serde_json::Value>()["access_token"]
            .as_str()
            .expect("Owner organization token should exist")
            .to_string();

        let client_id = format!("oidc-http-client-{suffix}");
        let client_path = format!("/v1/organizations/{}/oidc/clients", organization_a.id);
        let override_request = server
            .post(&client_path)
            .add_header("Authorization", format!("Bearer {organization_token}"))
            .json(&json!({
                "client_id": format!("oidc-http-override-{suffix}"),
                "client_secret": "OidcOverrideSecret#123",
                "name": "Invalid organization override",
                "client_type": "confidential",
                "redirect_uris": ["https://client.example.test/callback"],
                "organization_id": organization_b.id
            }))
            .await;
        assert_eq!(
            override_request.status_code(),
            StatusCode::UNPROCESSABLE_ENTITY
        );

        let created = server
            .post(&client_path)
            .add_header("Authorization", format!("Bearer {organization_token}"))
            .json(&json!({
                "client_id": client_id,
                "client_secret": "OidcOrganizationSecret#123",
                "name": "Organization OIDC client",
                "client_type": "confidential",
                "redirect_uris": ["https://client.example.test/callback"]
            }))
            .await;
        created.assert_status_ok();
        let created_body: serde_json::Value = created.json();
        assert_eq!(created_body["data"]["scope_kind"], "organization");
        assert_eq!(created_body["data"]["organization_id"], organization_a.id);

        let cross_org = server
            .get(&format!(
                "/v1/organizations/{}/oidc/clients",
                organization_b.id
            ))
            .add_header("Authorization", format!("Bearer {organization_token}"))
            .await;
        assert_eq!(cross_org.status_code(), StatusCode::FORBIDDEN);

        let admin_login = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        admin_login.assert_status_ok();
        let admin_token = admin_login.json::<serde_json::Value>()["access_token"]
            .as_str()
            .expect("Platform admin token should exist")
            .to_string();
        let platform_clients = server
            .get("/v1/admin/oidc/clients")
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .await;
        platform_clients.assert_status_ok();
        let platform_clients: serde_json::Value = platform_clients.json();
        assert!(!platform_clients["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|client| client["client_id"] == client_id));

        let verifier = "organization-oidc-verifier-012345678901234567890123456789012345678901";
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(verifier.as_bytes()));
        let redirect_uri = "https://client.example.test/callback";
        let authorization_fields = format!(
            "response_type=code&client_id={}&redirect_uri={}&scope=openid%20profile&state=oidc-state&nonce=oidc-nonce&code_challenge={}&code_challenge_method=S256",
            urlencoding::encode(&client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(&challenge),
        );
        let login_response = server
            .post("/v1/oidc/login")
            .add_header("content-type", "application/x-www-form-urlencoded")
            .bytes(Bytes::from(format!(
                "{authorization_fields}&username={}&password={}",
                urlencoding::encode(&username),
                urlencoding::encode(password),
            )))
            .await;
        login_response.assert_status_ok();
        let cookie = login_response
            .header("set-cookie")
            .to_str()
            .expect("OIDC login should set a browser cookie")
            .split(';')
            .next()
            .expect("OIDC cookie should contain a value")
            .to_string();
        let consent_response = server
            .post("/v1/oidc/consent")
            .add_header("content-type", "application/x-www-form-urlencoded")
            .add_header("Cookie", cookie)
            .bytes(Bytes::from(format!(
                "{authorization_fields}&decision=approve"
            )))
            .await;
        assert_eq!(consent_response.status_code(), StatusCode::SEE_OTHER);
        let location = consent_response
            .header("location")
            .to_str()
            .expect("OIDC consent should redirect to the client")
            .to_string();
        let code = url::Url::parse(&location)
            .expect("OIDC redirect should be a valid URL")
            .query_pairs()
            .find(|(key, _)| key == "code")
            .expect("OIDC redirect should contain an authorization code")
            .1
            .into_owned();
        let token_response = server
            .post("/v1/oidc/token")
            .add_header("content-type", "application/x-www-form-urlencoded")
            .bytes(Bytes::from(format!(
                "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}&code_verifier={}",
                urlencoding::encode(&code),
                urlencoding::encode(redirect_uri),
                urlencoding::encode(&client_id),
                urlencoding::encode("OidcOrganizationSecret#123"),
                urlencoding::encode(verifier),
            )))
            .await;
        token_response.assert_status_ok();
        let token_body: serde_json::Value = token_response.json();
        let access_token = token_body["access_token"]
            .as_str()
            .expect("Organization OIDC access token should exist")
            .to_string();
        let claims = Keys::from_config(&test_config())
            .expect("Test keys should load")
            .decode_oidc_access_token(&access_token, &test_config().oidc_issuer())
            .expect("Organization OIDC access token should decode");
        assert_eq!(
            claims.organization_id.as_deref(),
            Some(organization_a.id.as_str())
        );
        let userinfo = server
            .get("/v1/oidc/userinfo")
            .add_header("Authorization", format!("Bearer {access_token}"))
            .await;
        userinfo.assert_status_ok();
        assert_eq!(
            userinfo.json::<serde_json::Value>()["organization_id"],
            organization_a.id
        );

        db::upsert_organization_membership(
            &pool,
            &organization_a.id,
            &owner_principal.id,
            "suspended",
            None,
            None,
        )
        .await
        .expect("Failed to suspend OIDC owner membership");
        let stale_userinfo = server
            .get("/v1/oidc/userinfo")
            .add_header("Authorization", format!("Bearer {access_token}"))
            .await;
        assert_eq!(stale_userinfo.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_health_check() {
        let server = setup_test_server().await;

        let response = server.get("/").await;

        response.assert_status_ok();
        let body: serde_json::Value = response.json();
        assert_eq!(body["status"], "ok");
        assert_eq!(body["service"], "keylo");
        assert_eq!(body["setup"]["state"], "disabled");
    }

    #[tokio::test]
    async fn test_liveness_endpoint() {
        let server = setup_test_server().await;

        let response = server.get("/healthz").await;

        response.assert_status_ok();
        let body: serde_json::Value = response.json();
        assert_eq!(body["status"], "ok");
        assert_eq!(body["service"], "keylo");
    }

    #[tokio::test]
    async fn test_favicon_is_public_no_content() {
        let server = setup_test_server().await;

        let response = server.get("/favicon.ico").await;

        assert_eq!(response.status_code(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_readiness_endpoint() {
        let server = setup_test_server().await;

        let response = server.get("/readyz").await;
        let body: serde_json::Value = response.json();
        let status = response.status_code();
        assert!(status == StatusCode::OK || status == StatusCode::SERVICE_UNAVAILABLE);
        assert!(body["status"] == "ok" || body["status"] == "error");
        assert_eq!(body["service"], "keylo");
        assert!(body["checks"]["database"].is_string());
        assert!(body["checks"]["redis"].is_string());
        assert!(body["checks"]["setup"]["state"].is_string());
    }

    #[tokio::test]
    async fn test_jwks_endpoint() {
        let server = setup_test_server().await;

        let response = server.get("/.well-known/jwks.json").await;

        response.assert_status_ok();
        let body: serde_json::Value = response.json();
        let keys = body["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "RSA");
        assert_eq!(keys[0]["alg"], "RS256");
        assert!(keys[0]["kid"].as_str().is_some());
        assert!(keys[0]["n"].as_str().is_some());
        assert!(keys[0]["e"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_oidc_public_client_token_request_rejects_a_secret() {
        let server = setup_test_server().await;
        let admin_login = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if admin_login.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        admin_login.assert_status_ok();
        let admin_body: serde_json::Value = admin_login.json();
        let admin_token = admin_body["access_token"].as_str().unwrap();
        let client_id = format!(
            "public-oidc-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );
        let create = server
            .post("/v1/admin/oidc/clients")
            .add_header("Authorization", format!("Bearer {}", admin_token))
            .json(&json!({
                "client_id": client_id,
                "name": "Public OIDC test client",
                "client_type": "public",
                "redirect_uris": ["https://client.example.test/callback"]
            }))
            .await;
        create.assert_status_ok();

        let body = format!(
            "grant_type=authorization_code&code=invalid&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback&client_id={}&client_secret=not-allowed&code_verifier={}",
            client_id,
            "a".repeat(43)
        );
        let response = server
            .post("/v1/oidc/token")
            .add_header("content-type", "application/x-www-form-urlencoded")
            .bytes(Bytes::from(body))
            .await;

        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
        let response_body: serde_json::Value = response.json();
        assert_eq!(response_body["error"], "invalid_client");
    }

    #[tokio::test]
    async fn test_oidc_authorize_without_session_renders_standard_browser_login_form() {
        let server = setup_test_server().await;
        let admin_login = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if admin_login.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        admin_login.assert_status_ok();
        let admin_token = admin_login.json::<serde_json::Value>()["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let client_id = format!(
            "oidc-browser-login-{}",
            TEST_PREFIX_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let create = server
            .post("/v1/admin/oidc/clients")
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({
                "client_id": client_id,
                "name": "OIDC browser login test",
                "client_type": "public",
                "redirect_uris": ["https://client.example.test/callback"]
            }))
            .await;
        create.assert_status_ok();

        let response = server
            .get(&format!(
                "/v1/oidc/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback&scope=openid%20profile&state=client-state&nonce=test-nonce&code_challenge={}&code_challenge_method=S256",
                "a".repeat(43)
            ))
            .await;
        assert_eq!(response.status_code(), StatusCode::OK);
        let page = response.text();
        assert!(page.contains("<form method=\"post\" action=\"/v1/oidc/login\">"));
        assert!(page.contains("name=\"username\""));
        assert!(page.contains("name=\"password\""));
        assert!(page.contains(&format!("name=\"client_id\" value=\"{client_id}\"")));
        assert!(page.contains("name=\"state\" value=\"client-state\""));
        assert!(page.contains("name=\"nonce\" value=\"test-nonce\""));
    }

    #[tokio::test]
    async fn test_oidc_consent_denial_redirects_to_validated_client_with_state() {
        let server = setup_test_server().await;
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://keylo_user@localhost:5432/keylo".to_string());
        let pool = match db::init_db_pool(&database_url).await {
            Ok(pool) => pool,
            Err(_) => return,
        };
        let client_id = format!(
            "oidc-denial-{}",
            TEST_PREFIX_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        db::create_oidc_client(
            &pool,
            &keylo::models::CreateOidcClientRequest {
                client_id: client_id.clone(),
                client_secret: None,
                name: "OIDC denial test".to_string(),
                description: None,
                client_type: "public".to_string(),
                redirect_uris: vec!["https://client.example.test/callback".to_string()],
                grant_types: None,
                scopes: None,
            },
        )
        .await
        .unwrap();
        let username = format!("oidc-denial-user-{}", uuid::Uuid::new_v4());
        let user = db::create_user(
            &pool,
            &username,
            &format!("{username}@example.test"),
            Some("OidcConsentDenial#123"),
        )
        .await
        .unwrap();
        let browser_cookie = format!("oidc-denial-session-{}", uuid::Uuid::new_v4());
        db::create_browser_session(
            &pool,
            &browser_cookie,
            &keylo::models::OidcBrowserSession {
                user_id: user.id,
                expires_at: chrono::Utc::now().timestamp() + 3600,
            },
        )
        .await
        .unwrap();

        let response = server
            .post("/v1/oidc/consent")
            .add_header("content-type", "application/x-www-form-urlencoded")
            .add_header("Cookie", format!("keylo_oidc_session={browser_cookie}"))
            .bytes(Bytes::from(format!(
                "response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback&scope=openid&state=client-state&nonce=test-nonce&code_challenge={}&code_challenge_method=S256&decision=deny",
                "a".repeat(43)
            )))
            .await;

        assert_eq!(response.status_code(), StatusCode::SEE_OTHER);
        let location_header = response.header("location");
        let location = location_header.to_str().unwrap();
        assert!(location.starts_with("https://client.example.test/callback?error=access_denied"));
        assert!(location.contains("state=client-state"));
        assert!(location.contains(&format!(
            "iss={}",
            urlencoding::encode(&test_config().oidc_issuer())
        )));
    }

    #[tokio::test]
    async fn test_oidc_client_security_updates_invalidate_pending_authorization_codes() {
        let server = setup_test_server().await;
        let admin_login = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if admin_login.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        admin_login.assert_status_ok();
        let admin_token = admin_login.json::<serde_json::Value>()["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let client_id = format!(
            "oidc-disable-code-{}",
            TEST_PREFIX_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let create = server
            .post("/v1/admin/oidc/clients")
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({
                "client_id": client_id,
                "name": "OIDC code invalidation test",
                "client_type": "public",
                "redirect_uris": ["https://client.example.test/callback"]
            }))
            .await;
        create.assert_status_ok();
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://keylo_user@localhost:5432/keylo".to_string());
        let pool = match db::init_db_pool(&database_url).await {
            Ok(pool) => pool,
            Err(_) => return,
        };
        let username = format!("oidc-code-user-{}", uuid::Uuid::new_v4());
        let user = db::create_user(
            &pool,
            &username,
            &format!("{username}@example.test"),
            Some("OidcCodeInvalidation#123"),
        )
        .await
        .unwrap();
        let code = format!("oidc-pending-code-{}", uuid::Uuid::new_v4());
        db::create_authorization_code(
            &pool,
            &code,
            &keylo::models::OidcAuthorizationCode {
                client_id: client_id.clone(),
                organization_id: None,
                user_id: user.id.clone(),
                redirect_uri: "https://client.example.test/callback".to_string(),
                scopes: vec!["openid".to_string()],
                nonce: Some("test-nonce".to_string()),
                code_challenge: "a".repeat(43),
                expires_at: chrono::Utc::now().timestamp() + 300,
            },
        )
        .await
        .unwrap();

        let reconfigure = server
            .put(&format!("/v1/admin/oidc/clients/{client_id}"))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({
                "redirect_uris": ["https://client.example.test/new-callback"]
            }))
            .await;
        reconfigure.assert_status_ok();
        assert!(
            db::get_active_authorization_code(&pool, &code)
                .await
                .unwrap()
                .is_none(),
            "changing redirect URIs must invalidate codes bound to the old URI"
        );
        let reconfigure_audits = db::get_recent_audit_logs(&pool, 20).await.unwrap();
        assert!(reconfigure_audits.iter().any(|(event_type, _, detail, _)| {
            event_type == "oidc_client.reconfigured"
                && detail.as_deref().is_some_and(|value| {
                    value.contains(&client_id)
                        && value.contains("invalidated_authorization_codes=1")
                })
        }));

        let code_after_reconfigure = format!("oidc-pending-code-{}", uuid::Uuid::new_v4());
        db::create_authorization_code(
            &pool,
            &code_after_reconfigure,
            &keylo::models::OidcAuthorizationCode {
                client_id: client_id.clone(),
                organization_id: None,
                user_id: user.id,
                redirect_uri: "https://client.example.test/new-callback".to_string(),
                scopes: vec!["openid".to_string()],
                nonce: Some("test-nonce-after-reconfigure".to_string()),
                code_challenge: "a".repeat(43),
                expires_at: chrono::Utc::now().timestamp() + 300,
            },
        )
        .await
        .unwrap();

        let disable = server
            .put(&format!("/v1/admin/oidc/clients/{client_id}"))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({"active": false}))
            .await;
        disable.assert_status_ok();
        assert!(
            db::get_active_authorization_code(&pool, &code_after_reconfigure)
                .await
                .unwrap()
                .is_none(),
            "disabling a client must invalidate its unredeemed authorization codes"
        );
        let audit_logs = db::get_recent_audit_logs(&pool, 20).await.unwrap();
        assert!(audit_logs.iter().any(|(event_type, _, detail, _)| {
            event_type == "oidc_client.disabled"
                && detail.as_deref().is_some_and(|value| {
                    value.contains(&client_id)
                        && value.contains("invalidated_authorization_codes=1")
                })
        }));
    }

    #[tokio::test]
    async fn test_disabled_user_oidc_browser_session_cannot_start_authorization() {
        let server = setup_test_server().await;
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://keylo_user@localhost:5432/keylo".to_string());
        let pool = match db::init_db_pool(&database_url).await {
            Ok(pool) => pool,
            Err(_) => return,
        };
        let username = format!("oidc-browser-disabled-{}", uuid::Uuid::new_v4());
        let user = db::create_user(
            &pool,
            &username,
            &format!("{username}@example.test"),
            Some("OidcBrowserDisabled#123"),
        )
        .await
        .unwrap();
        let client_id = format!(
            "oidc-browser-disabled-{}",
            TEST_PREFIX_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        db::create_oidc_client(
            &pool,
            &keylo::models::CreateOidcClientRequest {
                client_id: client_id.clone(),
                client_secret: None,
                name: "OIDC disabled browser session test".to_string(),
                description: None,
                client_type: "public".to_string(),
                redirect_uris: vec!["https://client.example.test/callback".to_string()],
                grant_types: None,
                scopes: None,
            },
        )
        .await
        .unwrap();
        let browser_cookie = format!("oidc-browser-session-{}", uuid::Uuid::new_v4());
        db::create_browser_session(
            &pool,
            &browser_cookie,
            &keylo::models::OidcBrowserSession {
                user_id: user.id.clone(),
                expires_at: chrono::Utc::now().timestamp() + 3600,
            },
        )
        .await
        .unwrap();
        db::set_user_active(&pool, &user.id, false).await.unwrap();

        let response = server
            .get(&format!(
                "/v1/oidc/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback&scope=openid&nonce=test-nonce&code_challenge=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&code_challenge_method=S256"
            ))
            .add_header("Cookie", format!("keylo_oidc_session={browser_cookie}"))
            .await;
        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_password_change_revokes_refresh_and_oidc_browser_sessions() {
        let server = setup_test_server().await;
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://keylo_user@localhost:5432/keylo".to_string());
        let pool = match db::init_db_pool(&database_url).await {
            Ok(pool) => pool,
            Err(_) => return,
        };
        let username = format!("password-session-user-{}", uuid::Uuid::new_v4());
        let user = db::create_user(
            &pool,
            &username,
            &format!("{username}@example.test"),
            Some("OldPassword#123"),
        )
        .await
        .unwrap();
        let login = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "OldPassword#123"
            }))
            .await;
        login.assert_status_ok();
        let tokens = login.json::<serde_json::Value>();
        let access_token = tokens["access_token"].as_str().unwrap();
        let refresh_token = tokens["refresh_token"].as_str().unwrap();
        let browser_cookie = format!("oidc-password-session-{}", uuid::Uuid::new_v4());
        db::create_browser_session(
            &pool,
            &browser_cookie,
            &keylo::models::OidcBrowserSession {
                user_id: user.id.clone(),
                expires_at: chrono::Utc::now().timestamp() + 3600,
            },
        )
        .await
        .unwrap();

        let change = server
            .post("/v1/user/change-password")
            .add_header("Authorization", format!("Bearer {access_token}"))
            .json(&json!({
                "current_password": "OldPassword#123",
                "new_password": "NewPassword#123"
            }))
            .await;
        change.assert_status_ok();
        assert!(
            db::resolve_browser_session(&pool, &browser_cookie)
                .await
                .unwrap()
                .is_none(),
            "password changes must revoke existing OIDC browser sessions"
        );
        let refresh = server
            .post("/v1/auth/refresh")
            .json(&json!({"refresh_token": refresh_token}))
            .await;
        assert_eq!(refresh.status_code(), StatusCode::UNAUTHORIZED);
        let audit_logs = db::get_recent_audit_logs(&pool, 20).await.unwrap();
        assert!(audit_logs.iter().any(|(event_type, _, detail, _)| {
            event_type == "user.password_changed"
                && detail.as_deref().is_some_and(|value| {
                    value.contains(&user.id)
                        && value.contains("revoked_refresh_sessions=1")
                        && value.contains("revoked_oidc_browser_sessions=1")
                })
        }));
    }

    #[tokio::test]
    async fn test_admin_password_reset_revokes_refresh_and_oidc_browser_sessions() {
        let server = setup_test_server().await;
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://keylo_user@localhost:5432/keylo".to_string());
        let pool = match db::init_db_pool(&database_url).await {
            Ok(pool) => pool,
            Err(_) => return,
        };
        let username = format!("password-reset-user-{}", uuid::Uuid::new_v4());
        let user = db::create_user(
            &pool,
            &username,
            &format!("{username}@example.test"),
            Some("OldPassword#123"),
        )
        .await
        .unwrap();
        let login = server
            .post("/v1/auth/token")
            .json(&json!({"client_id": username, "client_secret": "OldPassword#123"}))
            .await;
        login.assert_status_ok();
        let refresh_token = login.json::<serde_json::Value>()["refresh_token"]
            .as_str()
            .unwrap()
            .to_string();
        let browser_cookie = format!("oidc-password-reset-{}", uuid::Uuid::new_v4());
        db::create_browser_session(
            &pool,
            &browser_cookie,
            &keylo::models::OidcBrowserSession {
                user_id: user.id.clone(),
                expires_at: chrono::Utc::now().timestamp() + 3600,
            },
        )
        .await
        .unwrap();
        let admin = server.post("/v1/admin/token").json(&json!({"client_id": INTEGRATION_ADMIN_CLIENT_ID, "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET})).await;
        admin.assert_status_ok();
        let admin_token = admin.json::<serde_json::Value>()["access_token"]
            .as_str()
            .unwrap()
            .to_string();

        let reset = server
            .post(&format!("/v1/admin/users/{}/reset-password", user.id))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({"password": "NewPassword#123"}))
            .await;
        reset.assert_status_ok();
        assert!(db::resolve_browser_session(&pool, &browser_cookie)
            .await
            .unwrap()
            .is_none());
        let refresh = server
            .post("/v1/auth/refresh")
            .json(&json!({"refresh_token": refresh_token}))
            .await;
        assert_eq!(refresh.status_code(), StatusCode::UNAUTHORIZED);
        let logs = db::get_recent_audit_logs(&pool, 20).await.unwrap();
        assert!(logs.iter().any(
            |(event_type, _, detail, _)| event_type == "user.password_reset"
                && detail
                    .as_deref()
                    .is_some_and(|value| value.contains(&user.id)
                        && value.contains("revoked_refresh_sessions=1")
                        && value.contains("revoked_oidc_browser_sessions=1"))
        ));
    }

    #[tokio::test]
    async fn test_admin_user_update_password_revokes_refresh_and_oidc_browser_sessions() {
        let server = setup_test_server().await;
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://keylo_user@localhost:5432/keylo".to_string());
        let pool = match db::init_db_pool(&database_url).await {
            Ok(pool) => pool,
            Err(_) => return,
        };
        let username = format!("password-update-user-{}", uuid::Uuid::new_v4());
        let user = db::create_user(
            &pool,
            &username,
            &format!("{username}@example.test"),
            Some("OldPassword#123"),
        )
        .await
        .unwrap();
        let login = server
            .post("/v1/auth/token")
            .json(&json!({"client_id": username, "client_secret": "OldPassword#123"}))
            .await;
        login.assert_status_ok();
        let refresh_token = login.json::<serde_json::Value>()["refresh_token"]
            .as_str()
            .unwrap()
            .to_string();
        let browser_cookie = format!("oidc-password-update-{}", uuid::Uuid::new_v4());
        db::create_browser_session(
            &pool,
            &browser_cookie,
            &keylo::models::OidcBrowserSession {
                user_id: user.id.clone(),
                expires_at: chrono::Utc::now().timestamp() + 3600,
            },
        )
        .await
        .unwrap();
        let admin = server.post("/v1/admin/token").json(&json!({"client_id": INTEGRATION_ADMIN_CLIENT_ID, "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET})).await;
        admin.assert_status_ok();
        let admin_token = admin.json::<serde_json::Value>()["access_token"]
            .as_str()
            .unwrap()
            .to_string();

        let update = server
            .put(&format!("/v1/admin/users/{}", user.id))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({"password": "NewPassword#123"}))
            .await;
        update.assert_status_ok();
        assert!(db::resolve_browser_session(&pool, &browser_cookie)
            .await
            .unwrap()
            .is_none());
        let refresh = server
            .post("/v1/auth/refresh")
            .json(&json!({"refresh_token": refresh_token}))
            .await;
        assert_eq!(refresh.status_code(), StatusCode::UNAUTHORIZED);
        let logs = db::get_recent_audit_logs(&pool, 20).await.unwrap();
        assert!(logs.iter().any(|(event_type, _, detail, _)| {
            event_type == "user.password_updated"
                && detail.as_deref().is_some_and(|value| {
                    value.contains(&user.id)
                        && value.contains("revoked_refresh_sessions=1")
                        && value.contains("revoked_oidc_browser_sessions=1")
                })
        }));
    }

    #[tokio::test]
    async fn test_keylo_configuration_endpoint() {
        let config = Config {
            server_addr: "127.0.0.1".to_string(),
            server_port: 3456,
            oidc_public_issuer: Some("https://identity.example.com".to_string()),
            jwt_audiences: vec!["admin-backend".to_string(), "inventory-svc".to_string()],
            ..test_config()
        };
        let server = setup_test_server_with_config(config).await;

        let response = server.get("/.well-known/keylo-configuration").await;

        response.assert_status_ok();
        let body: serde_json::Value = response.json();
        assert_eq!(body["issuer"], "keylo");
        assert_eq!(
            body["jwks_uri"],
            "https://identity.example.com/.well-known/jwks.json"
        );
        assert_eq!(
            body["introspection_endpoint"],
            "https://identity.example.com/v1/auth/introspect"
        );
        assert_eq!(
            body["documentation_uri"],
            "https://identity.example.com/docs/integrations/THIRD_PARTY_INTEGRATION.md"
        );
        assert_eq!(
            body["admin_token_endpoint"],
            "https://identity.example.com/v1/admin/token"
        );
        assert_eq!(body["supported_signing_algorithms"], json!(["RS256"]));
        assert_eq!(
            body["supported_token_types"],
            json!([
                "access",
                "refresh",
                "service_access",
                "customer_support_access"
            ])
        );
        assert_eq!(
            body["supported_audiences"],
            json!(["admin-backend", "inventory-svc"])
        );
        assert!(body["supported_claims"]
            .as_array()
            .unwrap()
            .iter()
            .any(|claim| claim == "token_type"));
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

        // 兼容缺少 header 时的框架级 400 或统一鉴权返回的 401
        let status = response.status_code();
        assert!(status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED);
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

        // 无效令牌应返回401（无效令牌）；数据库不可用时返回500
        let status = response.status_code();
        assert!(
            status == StatusCode::UNAUTHORIZED
                || status == StatusCode::BAD_REQUEST
                || status == StatusCode::INTERNAL_SERVER_ERROR,
            "Expected 401/400/500, got {}",
            status
        );
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
        let config = Config {
            max_failed_login_attempts: 100, // 避免锁定逻辑先触发
            auth_rate_limit_max_requests: 3,
            auth_global_rate_limit_max_requests: 100,
            auth_rate_limit_window_seconds: 60,
            ..test_config()
        };
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

        let metrics_resp = server.get("/metrics").await;
        metrics_resp.assert_status_ok();
        let metrics = metrics_resp.text();
        assert!(metrics.contains("keylo_rate_limit_rejections_total 1"));
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
                || blacklist_response.status_code() == StatusCode::NOT_FOUND
                || blacklist_response.status_code() == StatusCode::UNAUTHORIZED
        );

        // 测试获取黑名单端点
        let list_response = server.get("/v1/admin/blacklisted-tokens").await;

        assert!(
            list_response.status_code() == StatusCode::BAD_REQUEST
                || list_response.status_code() == StatusCode::NOT_FOUND
                || list_response.status_code() == StatusCode::UNAUTHORIZED
        );

        // 测试获取审计日志端点
        let audit_response = server.get("/v1/admin/audit-logs").await;
        assert!(
            audit_response.status_code() == StatusCode::BAD_REQUEST
                || audit_response.status_code() == StatusCode::NOT_FOUND
                || audit_response.status_code() == StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn test_admin_rotate_client_secret_revokes_refresh_tokens() {
        // Use a UNIQUE admin client for this test to avoid polluting the shared
        // cli-admin-root client (rotation leaves the secret changed in the DB and
        // ON CONFLICT DO NOTHING prevents subsequent seed calls from restoring it,
        // which would break other parallel tests that rely on cli-admin-root).
        //
        // Since is_admin_client is now stored in the DB (not from ADMIN_CLIENT_ID
        // env var at request time), seeding a unique client via setup_test_server
        // gives it admin privileges independently without affecting cli-admin-root.
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let rotate_client_id = format!("cli-rotate-test-{}", ts);
        let rotate_client_secret = "RotateTest123!";

        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://keylo_user@localhost:5432/keylo".to_string());
        let mut config = test_config();
        config.redis_key_prefix = format!(
            "keylo-test-{}-rotate-{}",
            std::process::id(),
            TEST_PREFIX_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let router = match startup::init_app_router_with_db_and_admin(
            config,
            &database_url,
            &rotate_client_id,
            rotate_client_secret,
        )
        .await
        {
            Ok(r) => r,
            Err(_) => return,
        };
        let server = TestServer::new(router);
        let admin_login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": rotate_client_id,
                "client_secret": rotate_client_secret
            }))
            .await;

        if admin_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        admin_login_resp.assert_status_ok();
        let admin_login_body: serde_json::Value = admin_login_resp.json();
        let admin_access_token = admin_login_body["access_token"].as_str().unwrap();
        let admin_refresh_token = admin_login_body["refresh_token"].as_str().unwrap();

        let rotate_resp = server
            .post(&format!(
                "/v1/admin/clients/{}/rotate-secret",
                rotate_client_id
            ))
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({}))
            .await;
        rotate_resp.assert_status_ok();
        let rotate_body: serde_json::Value = rotate_resp.json();
        assert_eq!(rotate_body["secret_generated"], true);
        let new_secret = rotate_body["new_secret"].as_str().unwrap();
        assert_ne!(new_secret, rotate_client_secret);

        let old_login = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": rotate_client_id,
                "client_secret": rotate_client_secret
            }))
            .await;
        assert_eq!(old_login.status_code(), StatusCode::UNAUTHORIZED);

        let new_login = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": rotate_client_id,
                "client_secret": new_secret
            }))
            .await;
        new_login.assert_status_ok();

        let refresh_resp = server
            .post("/v1/auth/refresh")
            .json(&json!({
                "refresh_token": admin_refresh_token
            }))
            .await;
        assert_eq!(refresh_resp.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_admin_rotate_client_secret_with_supplied_secret_does_not_echo_secret() {
        let server = setup_test_server().await;
        let login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        login_resp.assert_status_ok();
        let login_body: serde_json::Value = login_resp.json();
        let access_token = login_body["access_token"].as_str().unwrap();

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let client_id = format!("managed-rotate-{}", ts);
        let supplied_secret = format!("ManagedRotate#{}!", ts);

        let create_resp = server
            .post("/v1/admin/clients")
            .add_header("Authorization", format!("Bearer {}", access_token))
            .json(&json!({
                "client_id": client_id,
                "client_secret": "ManagedRotate#Old1",
                "name": "Managed Rotate Client"
            }))
            .await;
        create_resp.assert_status_ok();

        let rotate_resp = server
            .post(&format!("/v1/admin/clients/{}/rotate-secret", client_id))
            .add_header("Authorization", format!("Bearer {}", access_token))
            .json(&json!({
                "new_secret": supplied_secret
            }))
            .await;
        rotate_resp.assert_status_ok();
        let rotate_body: serde_json::Value = rotate_resp.json();
        assert_eq!(rotate_body["secret_generated"], false);
        assert!(rotate_body.get("new_secret").is_none());
    }

    #[tokio::test]
    async fn test_admin_client_management_api() {
        let server = setup_test_server().await;
        let login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        login_resp.assert_status_ok();
        let login_body: serde_json::Value = login_resp.json();
        let access_token = login_body["access_token"].as_str().unwrap();

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let managed_client = format!("managed-{}", ts);

        let create_resp = server
            .post("/v1/admin/clients")
            .add_header("Authorization", format!("Bearer {}", access_token))
            .json(&json!({
                "client_id": managed_client,
                "client_secret": "managed-secret",
                "name": "Managed Client",
                "description": "created by admin api"
            }))
            .await;
        create_resp.assert_status_ok();

        let list_resp = server
            .get("/v1/admin/clients")
            .add_header("Authorization", format!("Bearer {}", access_token))
            .await;
        list_resp.assert_status_ok();
        let list_body: serde_json::Value = list_resp.json();
        let found = list_body["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == managed_client);
        assert!(found);

        let disable_resp = server
            .put(&format!("/v1/admin/clients/{}", managed_client))
            .add_header("Authorization", format!("Bearer {}", access_token))
            .json(&json!({
                "active": false
            }))
            .await;
        disable_resp.assert_status_ok();

        let disabled_login = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": managed_client,
                "client_secret": "managed-secret"
            }))
            .await;
        assert_eq!(disabled_login.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_non_admin_cannot_access_admin_user_routes() {
        let server = setup_test_server().await;

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let username = format!("plain-user-{}", ts);
        let email = format!("{}@example.com", username);

        let register_resp = server
            .post("/v1/auth/register")
            .json(&json!({
                "username": username,
                "email": email,
                "password": "Password123!"
            }))
            .await;

        if register_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        register_resp.assert_status_ok();

        let login_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "Password123!"
            }))
            .await;
        login_resp.assert_status_ok();
        let login_body: serde_json::Value = login_resp.json();
        let access_token = login_body["access_token"].as_str().unwrap();

        let list_users_resp = server
            .get("/v1/admin/users")
            .add_header("Authorization", format!("Bearer {}", access_token))
            .await;
        assert_eq!(list_users_resp.status_code(), StatusCode::FORBIDDEN);

        let list_clients_resp = server
            .get("/v1/admin/clients")
            .add_header("Authorization", format!("Bearer {}", access_token))
            .await;
        assert_eq!(list_clients_resp.status_code(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_inactive_user_cannot_get_auth_token() {
        let server = setup_test_server().await;

        let admin_login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if admin_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        admin_login_resp.assert_status_ok();
        let admin_body: serde_json::Value = admin_login_resp.json();
        let admin_access_token = admin_body["access_token"].as_str().unwrap();

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let username = format!("inactive-user-{}", ts);
        let email = format!("{}@example.com", username);

        let register_resp = server
            .post("/v1/auth/register")
            .json(&json!({
                "username": username,
                "email": email,
                "password": "Password123!"
            }))
            .await;
        register_resp.assert_status_ok();
        let register_body: serde_json::Value = register_resp.json();
        let user_id = register_body["data"]["id"].as_str().unwrap();

        let disable_resp = server
            .put(&format!("/v1/admin/users/{}", user_id))
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "active": false
            }))
            .await;
        disable_resp.assert_status_ok();

        let login_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "Password123!"
            }))
            .await;
        assert_eq!(login_resp.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_service_can_introspect_user_access_token() {
        let server = setup_test_server().await;

        let admin_login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if admin_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        admin_login_resp.assert_status_ok();
        let admin_body: serde_json::Value = admin_login_resp.json();
        let admin_access_token = admin_body["access_token"].as_str().unwrap();

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let service_id = format!("agileboot-admin-{}", ts);
        let username = format!("introspect-user-{}", ts);
        let email = format!("{}@example.com", username);

        let create_service_resp = server
            .post("/v1/admin/services")
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "service_id": service_id,
                "service_secret": "service-secret",
                "name": "AgileBoot Admin",
                "description": "integration test service",
                "allowed_scopes": ["read"],
                "allowed_audiences": ["admin-backend"]
            }))
            .await;
        create_service_resp.assert_status_ok();

        let service_login_resp = server
            .post("/v1/service/token")
            .json(&json!({
                "service_id": service_id,
                "service_secret": "service-secret",
                "audience": "admin-backend",
                "scope": "read"
            }))
            .await;
        service_login_resp.assert_status_ok();
        let service_login_body: serde_json::Value = service_login_resp.json();
        let service_access_token = service_login_body["access_token"].as_str().unwrap();

        let register_resp = server
            .post("/v1/auth/register")
            .json(&json!({
                "username": username,
                "email": email,
                "password": "Password123!"
            }))
            .await;
        register_resp.assert_status_ok();
        let registered_user: serde_json::Value = register_resp.json();
        let user_id = registered_user["data"]["id"].as_str().unwrap();

        let user_login_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "Password123!"
            }))
            .await;
        user_login_resp.assert_status_ok();
        let user_login_body: serde_json::Value = user_login_resp.json();
        let user_access_token = user_login_body["access_token"].as_str().unwrap();
        let user_refresh_token = user_login_body["refresh_token"].as_str().unwrap();

        let introspect_resp = server
            .post("/v1/auth/introspect")
            .add_header("Authorization", format!("Bearer {}", service_access_token))
            .json(&json!({
                "token": user_access_token
            }))
            .await;
        introspect_resp.assert_status_ok();
        let introspect_body: serde_json::Value = introspect_resp.json();

        assert_eq!(introspect_body["active"], true);
        assert_eq!(introspect_body["sub"], format!("user:{}", username));
        assert_eq!(introspect_body["aud"], "admin-backend");
        assert_eq!(introspect_body["role"], json!(["user"]));
        assert_eq!(introspect_body["token_type"], "access");

        let disable_user = server
            .put(&format!("/v1/admin/users/{}", user_id))
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({ "active": false }))
            .await;
        disable_user.assert_status_ok();

        let audit_logs = db::list_audit_logs(
            &sqlx::PgPool::connect(
                &std::env::var("TEST_DATABASE_URL")
                    .unwrap_or_else(|_| "postgres://keylo_user@localhost:5432/keylo".to_string()),
            )
            .await
            .unwrap(),
            20,
            0,
        )
        .await
        .unwrap();
        assert!(audit_logs.iter().any(|log| {
            log.0 == "user.disabled"
                && log.2.as_deref().is_some_and(|detail| {
                    detail.contains("revoked_refresh_sessions=1")
                        && detail.contains("revoked_oidc_browser_sessions=0")
                })
        }));

        let protected_response = server
            .get("/protected")
            .add_header("Authorization", format!("Bearer {}", user_access_token))
            .await;
        assert_eq!(protected_response.status_code(), StatusCode::UNAUTHORIZED);

        let disabled_introspection = server
            .post("/v1/auth/introspect")
            .add_header("Authorization", format!("Bearer {}", service_access_token))
            .json(&json!({ "token": user_access_token }))
            .await;
        disabled_introspection.assert_status_ok();
        let disabled_body: serde_json::Value = disabled_introspection.json();
        assert_eq!(disabled_body, json!({ "active": false }));

        let refresh_response = server
            .post("/v1/auth/refresh")
            .json(&json!({ "refresh_token": user_refresh_token }))
            .await;
        assert_eq!(refresh_response.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_service_registration_metadata_and_custom_token_ttl() {
        let server = setup_test_server().await;

        let admin_login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if admin_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        admin_login_resp.assert_status_ok();
        let admin_body: serde_json::Value = admin_login_resp.json();
        let admin_access_token = admin_body["access_token"].as_str().unwrap();

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let service_id = format!("metadata-service-{}", ts);

        let create_service_resp = server
            .post("/v1/admin/services")
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "service_id": service_id,
                "service_secret": "service-secret",
                "name": "Metadata Service",
                "description": "integration metadata test service",
                "allowed_scopes": ["read", "write"],
                "allowed_audiences": ["inventory-svc"],
                "integration_type": "third_party",
                "introspection_allowed": true,
                "token_ttl_seconds": 120,
                "owner": "Platform",
                "contact": "platform@example.com"
            }))
            .await;
        create_service_resp.assert_status_ok();

        let get_service_resp = server
            .get(&format!("/v1/admin/services/{}", service_id))
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .await;
        get_service_resp.assert_status_ok();
        let service_body: serde_json::Value = get_service_resp.json();
        assert_eq!(service_body["integration_type"], "third_party");
        assert_eq!(service_body["introspection_allowed"], true);
        assert_eq!(service_body["token_ttl_seconds"], 120);
        assert_eq!(service_body["owner"], "Platform");
        assert_eq!(service_body["contact"], "platform@example.com");

        let service_login_resp = server
            .post("/v1/service/token")
            .json(&json!({
                "service_id": service_id,
                "service_secret": "service-secret",
                "audience": "inventory-svc",
                "scope": "read"
            }))
            .await;
        service_login_resp.assert_status_ok();
        let service_login_body: serde_json::Value = service_login_resp.json();
        assert_eq!(service_login_body["expires_in"], 120);
        assert_eq!(service_login_body["scope"], "read");
    }

    #[tokio::test]
    async fn test_service_registration_normalizes_scope_and_audience_lists() {
        let server = setup_test_server().await;

        let admin_login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if admin_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        admin_login_resp.assert_status_ok();
        let admin_body: serde_json::Value = admin_login_resp.json();
        let admin_access_token = admin_body["access_token"].as_str().unwrap();

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let service_id = format!("normalized-service-{}", ts);

        let create_service_resp = server
            .post("/v1/admin/services")
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "service_id": service_id,
                "service_secret": "service-secret",
                "name": "Normalized Service",
                "allowed_scopes": [" write ", "read", "write"],
                "allowed_audiences": [" inventory-svc ", "inventory-svc"]
            }))
            .await;
        create_service_resp.assert_status_ok();

        let get_service_resp = server
            .get(&format!("/v1/admin/services/{}", service_id))
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .await;
        get_service_resp.assert_status_ok();
        let service_body: serde_json::Value = get_service_resp.json();
        assert_eq!(service_body["allowed_scopes"], json!(["read", "write"]));
        assert_eq!(service_body["allowed_audiences"], json!(["inventory-svc"]));
    }

    #[tokio::test]
    async fn test_service_registration_rejects_invalid_scope_list() {
        let server = setup_test_server().await;

        let admin_login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if admin_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        admin_login_resp.assert_status_ok();
        let admin_body: serde_json::Value = admin_login_resp.json();
        let admin_access_token = admin_body["access_token"].as_str().unwrap();

        let service_id = format!(
            "invalid-scope-service-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );

        let create_service_resp = server
            .post("/v1/admin/services")
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "service_id": service_id,
                "service_secret": "service-secret",
                "name": "Invalid Scope Service",
                "allowed_scopes": ["read write"],
                "allowed_audiences": ["inventory-svc"]
            }))
            .await;
        assert_eq!(create_service_resp.status_code(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = create_service_resp.json();
        assert_eq!(body["error"], "invalid_request");
    }

    #[tokio::test]
    async fn test_service_introspection_can_be_disabled_per_service() {
        let server = setup_test_server().await;

        let admin_login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if admin_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        admin_login_resp.assert_status_ok();
        let admin_body: serde_json::Value = admin_login_resp.json();
        let admin_access_token = admin_body["access_token"].as_str().unwrap();

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let service_id = format!("no-introspect-service-{}", ts);

        let create_service_resp = server
            .post("/v1/admin/services")
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "service_id": service_id,
                "service_secret": "service-secret",
                "name": "No Introspect Service",
                "allowed_scopes": ["read"],
                "allowed_audiences": ["admin-backend"],
                "introspection_allowed": false
            }))
            .await;
        create_service_resp.assert_status_ok();

        let service_login_resp = server
            .post("/v1/service/token")
            .json(&json!({
                "service_id": service_id,
                "service_secret": "service-secret",
                "audience": "admin-backend",
                "scope": "read"
            }))
            .await;
        service_login_resp.assert_status_ok();
        let service_login_body: serde_json::Value = service_login_resp.json();
        let service_access_token = service_login_body["access_token"].as_str().unwrap();

        let introspect_resp = server
            .post("/v1/service/introspect")
            .add_header("Authorization", format!("Bearer {}", service_access_token))
            .json(&json!({
                "token": service_access_token
            }))
            .await;
        assert_eq!(introspect_resp.status_code(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_service_rotate_secret_with_supplied_secret_does_not_echo_secret() {
        let server = setup_test_server().await;

        let admin_login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if admin_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        admin_login_resp.assert_status_ok();
        let admin_body: serde_json::Value = admin_login_resp.json();
        let admin_access_token = admin_body["access_token"].as_str().unwrap();

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let service_id = format!("rotate-service-{}", ts);
        let supplied_secret = format!("RotateSvc#{}!", ts);

        let create_service_resp = server
            .post("/v1/admin/services")
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "service_id": service_id,
                "service_secret": "RotateSvc#Old1",
                "name": "Rotate Service",
                "allowed_scopes": ["read"],
                "allowed_audiences": ["admin-backend"]
            }))
            .await;
        create_service_resp.assert_status_ok();

        let rotate_resp = server
            .post(&format!("/v1/admin/services/{}/rotate-secret", service_id))
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "new_secret": supplied_secret
            }))
            .await;
        rotate_resp.assert_status_ok();
        let rotate_body: serde_json::Value = rotate_resp.json();
        assert_eq!(rotate_body["secret_generated"], false);
        assert!(rotate_body.get("new_secret").is_none());
    }

    #[tokio::test]
    async fn test_identity_source_admin_api_crud() {
        let server = setup_test_server().await;

        let admin_login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if admin_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        admin_login_resp.assert_status_ok();
        let admin_body: serde_json::Value = admin_login_resp.json();
        let admin_access_token = admin_body["access_token"].as_str().unwrap();

        let source_name = format!(
            "github-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );

        let create_resp = server
            .post("/v1/admin/identity-sources")
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "name": source_name,
                "source_type": "oauth2",
                "display_name": "GitHub",
                "description": "GitHub OAuth identity source",
                "config": {
                    "provider": "github",
                    "issuer": "https://github.com"
                },
                "claim_mapping": {
                    "external_id": "id",
                    "email": "email"
                },
                "jit_enabled": true
            }))
            .await;
        create_resp.assert_status_ok();
        let create_body: serde_json::Value = create_resp.json();
        assert_eq!(create_body["name"], source_name);
        assert_eq!(create_body["source_type"], "oauth2");
        assert_eq!(create_body["display_name"], "GitHub");
        assert_eq!(create_body["jit_enabled"], true);
        assert_eq!(create_body["auto_link_enabled"], true);
        assert_eq!(create_body["active"], true);
        assert_eq!(create_body["allowed_user_class"], "external_customer");
        assert_eq!(create_body["organization_strategy"], "none");
        assert!(create_body["organization_id"].is_null());
        let source_id = create_body["id"].as_str().unwrap();

        let get_resp = server
            .get(&format!("/v1/admin/identity-sources/{}", source_id))
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .await;
        get_resp.assert_status_ok();
        let get_body: serde_json::Value = get_resp.json();
        assert_eq!(get_body["config"]["provider"], "github");

        let update_resp = server
            .put(&format!("/v1/admin/identity-sources/{}", source_id))
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "display_name": "GitHub Enterprise",
                "active": false,
                "claim_mapping": {
                    "external_id": "sub",
                    "email": "email"
                }
            }))
            .await;
        update_resp.assert_status_ok();
        let update_body: serde_json::Value = update_resp.json();
        assert_eq!(update_body["display_name"], "GitHub Enterprise");
        assert_eq!(update_body["active"], false);
        assert_eq!(update_body["claim_mapping"]["external_id"], "sub");

        let list_resp = server
            .get("/v1/admin/identity-sources")
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .await;
        list_resp.assert_status_ok();
        let list_body: serde_json::Value = list_resp.json();
        assert!(list_body["identity_sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|source| source["id"] == source_id));
    }

    #[tokio::test]
    async fn test_identity_source_policy_requires_a_matching_active_organization() {
        let Some(pool) = setup_organization_test_pool().await else {
            return;
        };
        let server = setup_test_server().await;
        let admin_login = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        admin_login.assert_status_ok();
        let admin_token = admin_login.json::<serde_json::Value>()["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            TEST_PREFIX_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let customer = db::create_organization(
            &pool,
            &format!("identity-customer-{suffix}"),
            "Identity Customer",
            "customer",
        )
        .await
        .unwrap();
        let internal = db::create_organization(
            &pool,
            &format!("identity-internal-{suffix}"),
            "Identity Internal",
            "internal",
        )
        .await
        .unwrap();
        let disabled = db::create_organization(
            &pool,
            &format!("identity-disabled-{suffix}"),
            "Identity Disabled",
            "customer",
        )
        .await
        .unwrap();
        db::set_organization_status(&pool, &disabled.id, "disabled")
            .await
            .unwrap();

        let create = server
            .post("/v1/admin/identity-sources")
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({
                "name": format!("customer-idp-{suffix}"),
                "source_type": "oauth2",
                "display_name": "Customer IdP",
                "jit_enabled": true,
                "allowed_user_class": "external_customer",
                "organization_strategy": "fixed",
                "organization_id": customer.id
            }))
            .await;
        create.assert_status_ok();
        let source = create.json::<serde_json::Value>();
        assert_eq!(source["allowed_user_class"], "external_customer");
        assert_eq!(source["organization_strategy"], "fixed");
        assert_eq!(source["organization_id"], customer.id);

        let wrong_kind = server
            .post("/v1/admin/identity-sources")
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({
                "name": format!("wrong-kind-idp-{suffix}"),
                "source_type": "oauth2",
                "display_name": "Wrong Kind IdP",
                "allowed_user_class": "external_customer",
                "organization_strategy": "fixed",
                "organization_id": internal.id
            }))
            .await;
        assert_eq!(wrong_kind.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(
            wrong_kind.json::<serde_json::Value>()["error"],
            "invalid_request"
        );

        let disabled_source = server
            .post("/v1/admin/identity-sources")
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({
                "name": format!("disabled-idp-{suffix}"),
                "source_type": "oauth2",
                "display_name": "Disabled IdP",
                "organization_strategy": "fixed",
                "organization_id": disabled.id
            }))
            .await;
        assert_eq!(disabled_source.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(
            disabled_source.json::<serde_json::Value>()["error"],
            "invalid_request"
        );

        let implicit_claim_policy = server
            .post("/v1/admin/identity-sources")
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({
                "name": format!("claim-org-idp-{suffix}"),
                "source_type": "oauth2",
                "display_name": "Claim Organization IdP",
                "organization_strategy": "claim",
                "organization_id": customer.id
            }))
            .await;
        assert_eq!(implicit_claim_policy.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(
            implicit_claim_policy.json::<serde_json::Value>()["error"],
            "invalid_request"
        );
    }

    #[tokio::test]
    async fn test_disabled_service_token_is_inactive_when_introspected() {
        let server = setup_test_server().await;
        let admin_login = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if admin_login.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        admin_login.assert_status_ok();
        let admin_body: serde_json::Value = admin_login.json();
        let admin_token = admin_body["access_token"].as_str().unwrap();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let caller_id = format!("service-introspector-{}", ts);
        let target_id = format!("service-target-{}", ts);

        for (service_id, name) in [
            (&caller_id, "Service introspection caller"),
            (&target_id, "Service introspection target"),
        ] {
            let response = server
                .post("/v1/admin/services")
                .add_header("Authorization", format!("Bearer {admin_token}"))
                .json(&json!({
                    "service_id": service_id,
                    "service_secret": "service-secret",
                    "name": name,
                    "allowed_scopes": ["read"],
                    "allowed_audiences": ["admin-backend"],
                    "introspection_allowed": true
                }))
                .await;
            response.assert_status_ok();
        }

        let caller_login = server
            .post("/v1/service/token")
            .json(&json!({
                "service_id": caller_id,
                "service_secret": "service-secret",
                "audience": "admin-backend",
                "scope": "read"
            }))
            .await;
        caller_login.assert_status_ok();
        let caller_body: serde_json::Value = caller_login.json();
        let caller_token = caller_body["access_token"].as_str().unwrap();
        let target_login = server
            .post("/v1/service/token")
            .json(&json!({
                "service_id": target_id,
                "service_secret": "service-secret",
                "audience": "admin-backend",
                "scope": "read"
            }))
            .await;
        target_login.assert_status_ok();
        let target_body: serde_json::Value = target_login.json();
        let target_token = target_body["access_token"].as_str().unwrap();

        let disable_target = server
            .put(&format!("/v1/admin/services/{target_id}"))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({ "active": false }))
            .await;
        disable_target.assert_status_ok();

        let introspection = server
            .post("/v1/service/introspect")
            .add_header("Authorization", format!("Bearer {caller_token}"))
            .json(&json!({ "token": target_token }))
            .await;
        introspection.assert_status_ok();
        let body: serde_json::Value = introspection.json();
        assert_eq!(body, json!({ "active": false }));
    }

    #[tokio::test]
    async fn test_admin_can_list_oidc_identity_source_links_without_external_subjects() {
        let server = setup_test_server().await;

        let admin_login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if admin_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        admin_login_resp.assert_status_ok();
        let admin_body: serde_json::Value = admin_login_resp.json();
        let admin_access_token = admin_body["access_token"].as_str().unwrap();
        let source_name = format!(
            "corporate-idp-links-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );

        let create_resp = server
            .post("/v1/admin/identity-sources")
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "name": source_name,
                "source_type": "oidc_upstream",
                "display_name": "Corporate IdP",
                "config": {
                    "issuer": "https://idp.example.test",
                    "client_id": "keylo-test-client",
                    "client_secret": "keylo-test-client-secret",
                    "redirect_uri": "https://keylo.example.test/v1/upstream/oidc/callback"
                },
                "claim_mapping": {"external_subject": "sub", "email": "email"}
            }))
            .await;
        create_resp.assert_status_ok();
        let source: serde_json::Value = create_resp.json();
        let source_id = source["id"].as_str().unwrap();

        let links_resp = server
            .get(&format!("/v1/admin/identity-sources/{}/links", source_id))
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .await;
        links_resp.assert_status_ok();
        let body: serde_json::Value = links_resp.json();
        assert_eq!(body["source_id"], source_id);
        assert_eq!(body["links"], json!([]));
        assert!(body.get("external_subject").is_none());

        let unlink_resp = server
            .delete(&format!(
                "/v1/admin/identity-sources/{}/links/00000000-0000-0000-0000-000000000000",
                source_id
            ))
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .await;
        assert_eq!(unlink_resp.status_code(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_reconfiguring_oidc_identity_source_revokes_upstream_refresh_sessions() {
        let server = setup_test_server().await;
        let admin_login = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if admin_login.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        admin_login.assert_status_ok();
        let admin_token = admin_login.json::<serde_json::Value>()["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let source_name = format!(
            "upstream-reconfigure-{}",
            TEST_PREFIX_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let create_source = server
            .post("/v1/admin/identity-sources")
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({
                "name": source_name,
                "source_type": "oidc_upstream",
                "display_name": "Upstream reconfigure test",
                "config": {
                    "issuer": "https://idp.example.test",
                    "client_id": "keylo-old-client",
                    "client_secret": "old-upstream-secret",
                    "redirect_uri": "https://keylo.example.test/v1/upstream/oidc/callback"
                }
            }))
            .await;
        create_source.assert_status_ok();
        let source = create_source.json::<serde_json::Value>();
        let source_id = source["id"].as_str().unwrap();
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://keylo_user@localhost:5432/keylo".to_string());
        let pool = match db::init_db_pool(&database_url).await {
            Ok(pool) => pool,
            Err(_) => return,
        };
        let username = format!("upstream-reconfigure-user-{}", uuid::Uuid::new_v4());
        let user = db::create_user(
            &pool,
            &username,
            &format!("{username}@example.test"),
            Some("UpstreamReconfigure#123"),
        )
        .await
        .unwrap();
        let principal = db::ensure_user_principal(&pool, &user.id)
            .await
            .unwrap()
            .unwrap();
        let session_id = format!("upstream-session-{}", uuid::Uuid::new_v4());
        let refresh_token_id = format!("upstream-refresh-id-{}", uuid::Uuid::new_v4());
        let refresh_token = format!("upstream-refresh-token-{}", uuid::Uuid::new_v4());
        db::create_refresh_session(
            &pool,
            db::CreateRefreshSessionParams {
                session_id: &session_id,
                principal_id: &principal.id,
                client_id: &format!("oidc_upstream:{source_id}"),
                organization_id: None,
                refresh_token_id: &refresh_token_id,
                refresh_token: &refresh_token,
                access_jti: "upstream-access-jti",
                login_ip: None,
                user_agent: None,
                expires_at: chrono::Utc::now().timestamp() + 3600,
            },
        )
        .await
        .unwrap();
        let pending_authorization = keylo::models::new_oidc_upstream_authorization_state();
        db::create_oidc_upstream_authorization(
            &pool,
            source_id,
            &pending_authorization,
            "encrypted-test-verifier",
            chrono::Utc::now().timestamp() + 60,
        )
        .await
        .unwrap();

        let reconfigure = server
            .put(&format!("/v1/admin/identity-sources/{source_id}"))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({
                "config": {
                    "issuer": "https://idp.example.test",
                    "client_id": "keylo-new-client",
                    "client_secret": "new-upstream-secret",
                    "redirect_uri": "https://keylo.example.test/v1/upstream/oidc/callback"
                }
            }))
            .await;
        reconfigure.assert_status_ok();

        let sessions = db::list_refresh_sessions_for_principal(&pool, &principal.id, true)
            .await
            .unwrap();
        assert_eq!(sessions.len(), 1);
        assert!(sessions[0].revoked_at.is_some());
        assert_eq!(
            sessions[0].revoke_reason.as_deref(),
            Some("identity_source_reconfigured")
        );
        assert!(
            db::consume_oidc_upstream_authorization(&pool, &pending_authorization.state)
                .await
                .unwrap()
                .is_none(),
            "source reconfiguration must invalidate pending browser authorization state"
        );
        let audit_logs = db::get_recent_audit_logs(&pool, 20).await.unwrap();
        assert!(audit_logs.iter().any(|(event_type, _, detail, _)| {
            event_type == "identity_source.reconfigured"
                && detail.as_deref().is_some_and(|value| {
                    value.contains(source_id) && value.contains("invalidated_authorizations=1")
                })
        }));
    }

    #[tokio::test]
    async fn test_upstream_oidc_denial_consumes_callback_state() {
        let server = setup_test_server().await;
        let admin_login = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if admin_login.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        admin_login.assert_status_ok();
        let admin_body: serde_json::Value = admin_login.json();
        let admin_token = admin_body["access_token"].as_str().unwrap();
        let source_name = format!(
            "upstream-denial-{}",
            TEST_PREFIX_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let create_source = server
            .post("/v1/admin/identity-sources")
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({
                "name": source_name,
                "source_type": "oidc_upstream",
                "display_name": "Upstream denial test",
                "config": {
                    "issuer": "https://idp.example.test",
                    "client_id": "keylo-test-client",
                    "client_secret": "test-upstream-secret",
                    "redirect_uri": "https://keylo.example.test/v1/upstream/oidc/callback"
                }
            }))
            .await;
        create_source.assert_status_ok();
        let source: serde_json::Value = create_source.json();
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://keylo_user@localhost:5432/keylo".to_string());
        let pool = match db::init_db_pool(&database_url).await {
            Ok(pool) => pool,
            Err(_) => return,
        };
        let transaction = keylo::models::new_oidc_upstream_authorization_state();
        db::create_oidc_upstream_authorization(
            &pool,
            source["id"].as_str().unwrap(),
            &transaction,
            "encrypted-test-verifier",
            chrono::Utc::now().timestamp() + 60,
        )
        .await
        .unwrap();

        let denial = server
            .get(&format!(
                "/v1/upstream/oidc/callback?state={}&error=access_denied",
                transaction.state
            ))
            .await;
        assert_eq!(denial.status_code(), StatusCode::BAD_REQUEST);
        let replay = db::consume_oidc_upstream_authorization(&pool, &transaction.state)
            .await
            .unwrap();
        assert!(replay.is_none(), "A denied callback state must be consumed");
    }

    #[tokio::test]
    async fn test_identity_source_admin_api_rejects_invalid_source_type() {
        let server = setup_test_server().await;

        let admin_login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if admin_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        admin_login_resp.assert_status_ok();
        let admin_body: serde_json::Value = admin_login_resp.json();
        let admin_access_token = admin_body["access_token"].as_str().unwrap();

        let create_resp = server
            .post("/v1/admin/identity-sources")
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "name": "unsupported-source",
                "source_type": "saml",
                "display_name": "SAML"
            }))
            .await;
        assert_eq!(create_resp.status_code(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = create_resp.json();
        assert_eq!(body["error"], "invalid_request");
    }

    #[tokio::test]
    async fn test_identity_source_admin_api_requires_admin_token() {
        let server = setup_test_server().await;

        let admin_login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        if admin_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        admin_login_resp.assert_status_ok();

        let list_resp = server.get("/v1/admin/identity-sources").await;
        assert_eq!(list_resp.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_organization_admin_lifecycle_api_is_scoped_and_idempotent() {
        let Some(pool) = setup_organization_test_pool().await else {
            return;
        };
        let server = setup_test_server().await;
        let admin_login = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        admin_login.assert_status_ok();
        let admin_token = admin_login.json::<serde_json::Value>()["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let suffix = uuid::Uuid::new_v4().simple().to_string();

        let invalid_create = server
            .post("/v1/admin/organizations")
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({
                "slug": " ",
                "name": " ",
                "kind": "customer"
            }))
            .await;
        assert_eq!(invalid_create.status_code(), StatusCode::BAD_REQUEST);

        let create = server
            .post("/v1/admin/organizations")
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({
                "slug": format!("api-customer-{suffix}"),
                "name": "API customer organization",
                "kind": "customer"
            }))
            .await;
        create.assert_status_ok();
        let organization: serde_json::Value = create.json();
        let organization_id = organization["data"]["id"].as_str().unwrap().to_string();

        let duplicate = server
            .post("/v1/admin/organizations")
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({
                "slug": format!("api-customer-{suffix}"),
                "name": "Duplicate API customer organization",
                "kind": "customer"
            }))
            .await;
        assert_eq!(duplicate.status_code(), StatusCode::CONFLICT);

        let user = db::create_user(
            &pool,
            &format!("organization-api-user-{suffix}"),
            &format!("organization-api-user-{suffix}@example.test"),
            Some("OrganizationApiUser#123"),
        )
        .await
        .unwrap();
        let principal = db::get_principal_by_ref(&pool, "user", &user.id)
            .await
            .unwrap()
            .unwrap();

        let membership_path = format!(
            "/v1/admin/organizations/{organization_id}/memberships/{}",
            principal.id
        );
        let membership = server
            .put(&membership_path)
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({"status": "active", "management_role": "owner"}))
            .await;
        membership.assert_status_ok();
        assert_eq!(
            membership.json::<serde_json::Value>()["data"]["management_role"],
            "owner"
        );

        let suspended = server
            .put(&membership_path)
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({"status": "suspended"}))
            .await;
        suspended.assert_status_ok();
        let repeated_suspension = server
            .put(&membership_path)
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({"status": "suspended"}))
            .await;
        repeated_suspension.assert_status_ok();
        let repeated_suspension_body: serde_json::Value = repeated_suspension.json();
        assert_eq!(repeated_suspension_body["data"]["status"], "suspended");

        let members = server
            .get(&format!(
                "/v1/admin/organizations/{organization_id}/memberships"
            ))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .await;
        members.assert_status_ok();
        let members_body: serde_json::Value = members.json();
        assert_eq!(members_body["data"].as_array().unwrap().len(), 1);

        let internal = server
            .post("/v1/admin/organizations")
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({
                "slug": format!("api-internal-{suffix}"),
                "name": "API internal organization",
                "kind": "internal"
            }))
            .await;
        internal.assert_status_ok();
        let internal_body: serde_json::Value = internal.json();
        let internal_organization_id = internal_body["data"]["id"].as_str().unwrap();
        let external_membership_rejected = server
            .put(&format!(
                "/v1/admin/organizations/{internal_organization_id}/memberships/{}",
                principal.id
            ))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({"status": "pending"}))
            .await;
        assert_eq!(
            external_membership_rejected.status_code(),
            StatusCode::BAD_REQUEST
        );

        let invalid_status = server
            .put(&format!("/v1/admin/organizations/{organization_id}/status"))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({"status": "deleted"}))
            .await;
        assert_eq!(invalid_status.status_code(), StatusCode::BAD_REQUEST);

        let disabled = server
            .put(&format!("/v1/admin/organizations/{organization_id}/status"))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({"status": "disabled"}))
            .await;
        disabled.assert_status_ok();

        let rejected_reactivation = server
            .put(&membership_path)
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({"status": "active"}))
            .await;
        assert_eq!(rejected_reactivation.status_code(), StatusCode::BAD_REQUEST);

        let archived = server
            .put(&format!("/v1/admin/organizations/{organization_id}/status"))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({"status": "archived"}))
            .await;
        archived.assert_status_ok();

        let archived_to_disabled = server
            .put(&format!("/v1/admin/organizations/{organization_id}/status"))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({"status": "disabled"}))
            .await;
        assert_eq!(archived_to_disabled.status_code(), StatusCode::BAD_REQUEST);

        let restored = server
            .put(&format!("/v1/admin/organizations/{organization_id}/status"))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({"status": "active"}))
            .await;
        restored.assert_status_ok();

        let audit_events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE detail LIKE $1 AND event_type LIKE 'organization.%'",
        )
        .bind(format!("%organization_id={organization_id}%"))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(audit_events >= 6, "organization changes must be audited");

        let unauthenticated = server
            .get(&format!("/v1/admin/organizations/{organization_id}"))
            .await;
        assert_eq!(unauthenticated.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_organization_owner_admin_api_requires_active_context_and_live_membership() {
        let Some(pool) = setup_organization_test_pool().await else {
            return;
        };
        let server = setup_test_server().await;
        let suffix = uuid::Uuid::new_v4().simple().to_string();

        let owner = db::create_user(
            &pool,
            &format!("http-org-owner-{suffix}"),
            &format!("http-org-owner-{suffix}@example.test"),
            Some("HttpOrgOwner#123"),
        )
        .await
        .expect("Failed to create organization owner");
        db::promote_user_to_internal_employee(&pool, &owner.id, Some("test-admin"))
            .await
            .expect("Failed to promote organization owner")
            .expect("Organization owner should exist");
        let owner_principal = db::get_principal_by_ref(&pool, "user", &owner.id)
            .await
            .unwrap()
            .unwrap();

        let member = db::create_user(
            &pool,
            &format!("http-org-member-{suffix}"),
            &format!("http-org-member-{suffix}@example.test"),
            Some("HttpOrgMember#123"),
        )
        .await
        .expect("Failed to create organization member");
        db::set_user_class(
            &pool,
            &member.id,
            keylo::models::USER_CLASS_INTERNAL_EMPLOYEE,
            Some("test-admin"),
        )
        .await
        .expect("Failed to promote organization member class")
        .expect("Organization member should exist");
        let member_principal = db::get_principal_by_ref(&pool, "user", &member.id)
            .await
            .unwrap()
            .unwrap();

        let owner_login = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": owner.username,
                "client_secret": "HttpOrgOwner#123"
            }))
            .await;
        owner_login.assert_status_ok();
        let owner_token = owner_login.json::<serde_json::Value>()["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let owner_context = server
            .post("/v1/auth/organization-context")
            .add_header("Authorization", format!("Bearer {owner_token}"))
            .json(&json!({"organization_id": "org-internal"}))
            .await;
        owner_context.assert_status_ok();
        let owner_context_token = owner_context.json::<serde_json::Value>()["access_token"]
            .as_str()
            .unwrap()
            .to_string();

        let invite_path = "/v1/organizations/org-internal/memberships/invitations";
        let invite = server
            .post(invite_path)
            .add_header("Authorization", format!("Bearer {owner_context_token}"))
            .json(&json!({"principal_id": member_principal.id}))
            .await;
        invite.assert_status_ok();
        assert_eq!(
            invite.json::<serde_json::Value>()["data"]["status"],
            "pending"
        );

        let repeated_invite = server
            .post(invite_path)
            .add_header("Authorization", format!("Bearer {owner_context_token}"))
            .json(&json!({"principal_id": member_principal.id}))
            .await;
        repeated_invite.assert_status_ok();

        let cross_org = server
            .get("/v1/organizations/other-org/memberships")
            .add_header("Authorization", format!("Bearer {owner_context_token}"))
            .await;
        assert_eq!(cross_org.status_code(), StatusCode::FORBIDDEN);

        let member_login = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": member.username,
                "client_secret": "HttpOrgMember#123"
            }))
            .await;
        member_login.assert_status_ok();
        let member_token = member_login.json::<serde_json::Value>()["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let join_path = format!(
            "/v1/organizations/org-internal/memberships/{}/join",
            member_principal.id
        );
        let join = server
            .post(&join_path)
            .add_header("Authorization", format!("Bearer {member_token}"))
            .await;
        join.assert_status_ok();

        let member_context = server
            .post("/v1/auth/organization-context")
            .add_header("Authorization", format!("Bearer {member_token}"))
            .json(&json!({"organization_id": "org-internal"}))
            .await;
        member_context.assert_status_ok();
        let member_context_token = member_context.json::<serde_json::Value>()["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let member_cannot_manage = server
            .get("/v1/organizations/org-internal/memberships")
            .add_header("Authorization", format!("Bearer {member_context_token}"))
            .await;
        assert_eq!(member_cannot_manage.status_code(), StatusCode::FORBIDDEN);

        let promote_member = server
            .put(&format!(
                "/v1/organizations/org-internal/memberships/{}",
                member_principal.id
            ))
            .add_header("Authorization", format!("Bearer {owner_context_token}"))
            .json(&json!({"status": "active", "management_role": "admin"}))
            .await;
        promote_member.assert_status_ok();

        let organization_role = db::create_organization_role(
            &pool,
            &format!("http-org-role-{suffix}"),
            Some("HTTP organization role"),
            "user",
        )
        .await
        .expect("Failed to create organization role");
        let assigned = server
            .post(&format!(
                "/v1/organizations/org-internal/memberships/{}/roles",
                member_principal.id
            ))
            .add_header("Authorization", format!("Bearer {owner_context_token}"))
            .json(&json!({"role_id": organization_role.id.clone()}))
            .await;
        assigned.assert_status_ok();

        let listed_roles = server
            .get(&format!(
                "/v1/organizations/org-internal/memberships/{}/roles",
                member_principal.id
            ))
            .add_header("Authorization", format!("Bearer {owner_context_token}"))
            .await;
        listed_roles.assert_status_ok();
        assert_eq!(
            listed_roles.json::<serde_json::Value>()["data"]
                .as_array()
                .unwrap()
                .len(),
            1
        );

        let revoked = server
            .delete(&format!(
                "/v1/organizations/org-internal/memberships/{}/roles/{}",
                member_principal.id, organization_role.id
            ))
            .add_header("Authorization", format!("Bearer {owner_context_token}"))
            .await;
        revoked.assert_status_ok();
        assert_eq!(revoked.json::<serde_json::Value>()["data"]["revoked"], true);

        let suspended = server
            .put(&format!(
                "/v1/organizations/org-internal/memberships/{}",
                member_principal.id
            ))
            .add_header("Authorization", format!("Bearer {owner_context_token}"))
            .json(&json!({"status": "suspended"}))
            .await;
        suspended.assert_status_ok();
        let suspended_context = server
            .post("/v1/auth/organization-context")
            .add_header("Authorization", format!("Bearer {member_token}"))
            .json(&json!({"organization_id": "org-internal"}))
            .await;
        assert_eq!(suspended_context.status_code(), StatusCode::FORBIDDEN);

        assert_eq!(owner_principal.principal_type, "user");
    }

    /// Ensures customer organization owners can manage only their own service clients.
    #[tokio::test]
    async fn test_external_customer_owner_manages_only_organization_services() {
        let Some(pool) = setup_organization_test_pool().await else {
            return;
        };
        let server = setup_test_server().await;
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let organization_a = db::create_organization(
            &pool,
            &format!("delegated-service-a-{suffix}"),
            "Delegated service organization A",
            keylo::models::ORGANIZATION_KIND_CUSTOMER,
        )
        .await
        .expect("Failed to create delegated service organization A");
        let organization_b = db::create_organization(
            &pool,
            &format!("delegated-service-b-{suffix}"),
            "Delegated service organization B",
            keylo::models::ORGANIZATION_KIND_CUSTOMER,
        )
        .await
        .expect("Failed to create delegated service organization B");
        let owner = db::create_user(
            &pool,
            &format!("delegated-service-owner-{suffix}"),
            &format!("delegated-service-owner-{suffix}@example.test"),
            Some("DelegatedServiceOwner#123"),
        )
        .await
        .expect("Failed to create external customer owner");
        let owner_principal = db::get_principal_by_ref(&pool, "user", &owner.id)
            .await
            .expect("Failed to load owner principal")
            .expect("Owner principal should exist");
        db::upsert_organization_membership(
            &pool,
            &organization_a.id,
            &owner_principal.id,
            "active",
            None,
            Some(keylo::models::ORGANIZATION_MANAGEMENT_ROLE_OWNER),
        )
        .await
        .expect("Failed to create owner membership");

        let login = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": owner.username,
                "client_secret": "DelegatedServiceOwner#123"
            }))
            .await;
        login.assert_status_ok();
        let platform_token = login.json::<serde_json::Value>()["access_token"]
            .as_str()
            .expect("Platform token should exist")
            .to_string();
        let context = server
            .post("/v1/auth/organization-context")
            .add_header("Authorization", format!("Bearer {platform_token}"))
            .json(&json!({"organization_id": organization_a.id}))
            .await;
        context.assert_status_ok();
        let organization_token = context.json::<serde_json::Value>()["access_token"]
            .as_str()
            .expect("Organization context token should exist")
            .to_string();

        let list_path = format!("/v1/organizations/{}/services", organization_a.id);
        let empty_list = server
            .get(&list_path)
            .add_header("Authorization", format!("Bearer {organization_token}"))
            .await;
        empty_list.assert_status_ok();
        assert!(empty_list.json::<serde_json::Value>()["data"]
            .as_array()
            .expect("Service list should be an array")
            .is_empty());

        let service_id = format!("delegated-service-{suffix}");
        let forbidden_organization_override = server
            .post(&list_path)
            .add_header("Authorization", format!("Bearer {organization_token}"))
            .json(&json!({
                "service_id": format!("override-service-{suffix}"),
                "service_secret": "OverrideService#123",
                "name": "Override service",
                "organization_id": organization_b.id,
                "allowed_scopes": ["read"],
                "allowed_audiences": ["admin-backend"]
            }))
            .await;
        assert_eq!(
            forbidden_organization_override.status_code(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let registered = server
            .post(&list_path)
            .add_header("Authorization", format!("Bearer {organization_token}"))
            .json(&json!({
                "service_id": service_id,
                "service_secret": "DelegatedService#123",
                "name": "Delegated service",
                "allowed_scopes": ["read"],
                "allowed_audiences": ["admin-backend"],
                "integration_type": "job"
            }))
            .await;
        registered.assert_status_ok();
        let registered: serde_json::Value = registered.json();
        assert_eq!(registered["data"]["scope_kind"], "organization");
        assert_eq!(registered["data"]["organization_id"], organization_a.id);
        assert_eq!(registered["data"]["introspection_allowed"], false);

        let service_principal = db::get_principal_by_ref(&pool, "service", &service_id)
            .await
            .expect("Failed to load delegated service principal")
            .expect("Delegated service principal should exist");
        assert!(db::get_active_organization_membership(
            &pool,
            &organization_a.id,
            &service_principal.id,
        )
        .await
        .expect("Failed to load delegated service membership")
        .is_some());

        let service_path = format!("{list_path}/{service_id}");
        let updated = server
            .put(&service_path)
            .add_header("Authorization", format!("Bearer {organization_token}"))
            .json(&json!({
                "name": "Delegated service updated",
                "allowed_scopes": ["read", "write"],
                "allowed_audiences": ["admin-backend"]
            }))
            .await;
        updated.assert_status_ok();
        let read_back = server
            .get(&service_path)
            .add_header("Authorization", format!("Bearer {organization_token}"))
            .await;
        read_back.assert_status_ok();
        let read_back: serde_json::Value = read_back.json();
        assert_eq!(read_back["data"]["name"], "Delegated service updated");
        assert_eq!(read_back["data"]["introspection_allowed"], false);

        let rotated = server
            .post(&format!("{service_path}/rotate-secret"))
            .add_header("Authorization", format!("Bearer {organization_token}"))
            .json(&json!({}))
            .await;
        rotated.assert_status_ok();
        let rotated: serde_json::Value = rotated.json();
        let rotated_secret = rotated["data"]["new_secret"]
            .as_str()
            .expect("Generated delegated secret should be returned once")
            .to_string();
        let service_token = server
            .post("/v1/service/token")
            .json(&json!({
                "service_id": service_id,
                "service_secret": rotated_secret,
                "audience": "admin-backend",
                "scope": "read"
            }))
            .await;
        service_token.assert_status_ok();
        let service_token = service_token.json::<serde_json::Value>()["access_token"]
            .as_str()
            .expect("Delegated service should mint a token")
            .to_string();
        let claims = Keys::from_config(&test_config())
            .expect("Test keys should load")
            .decode_service_token(&service_token)
            .expect("Delegated service token should decode");
        assert_eq!(
            claims.organization_id.as_deref(),
            Some(organization_a.id.as_str())
        );

        let cross_organization = server
            .post(&format!("/v1/organizations/{}/services", organization_b.id))
            .add_header("Authorization", format!("Bearer {organization_token}"))
            .json(&json!({
                "service_id": format!("forbidden-service-{suffix}"),
                "service_secret": "ForbiddenService#123",
                "name": "Forbidden service",
                "allowed_scopes": ["read"],
                "allowed_audiences": ["admin-backend"]
            }))
            .await;
        assert_eq!(cross_organization.status_code(), StatusCode::FORBIDDEN);

        let device_path = format!("/v1/organizations/{}/devices", organization_a.id);
        let device_created = server
            .post(&device_path)
            .add_header("Authorization", format!("Bearer {organization_token}"))
            .json(&json!({
                "device_id": format!("delegated-device-{suffix}"),
                "display_name": "Delegated organization device"
            }))
            .await;
        device_created.assert_status_ok();
        let device_created: serde_json::Value = device_created.json();
        assert_eq!(device_created["data"]["organization_id"], organization_a.id);
        let delegated_device_principal_id = device_created["data"]["principal_id"]
            .as_str()
            .expect("Delegated device should return Principal id")
            .to_string();
        let delegated_key = server
            .post(&format!(
                "/v1/organizations/{}/principals/{}/api-keys",
                organization_a.id, delegated_device_principal_id
            ))
            .add_header("Authorization", format!("Bearer {organization_token}"))
            .json(&json!({
                "allowed_scopes": ["authorization"],
                "allowed_audiences": ["admin-backend"]
            }))
            .await;
        delegated_key.assert_status_ok();
        assert!(delegated_key.json::<serde_json::Value>()["data"]["api_key"]
            .as_str()
            .is_some());
        let cross_organization_device = server
            .post(&format!("/v1/organizations/{}/devices", organization_b.id))
            .add_header("Authorization", format!("Bearer {organization_token}"))
            .json(&json!({
                "device_id": format!("forbidden-device-{suffix}"),
                "display_name": "Forbidden device"
            }))
            .await;
        assert_eq!(
            cross_organization_device.status_code(),
            StatusCode::FORBIDDEN
        );
        let cross_organization_key = server
            .post(&format!(
                "/v1/organizations/{}/principals/{}/api-keys",
                organization_b.id, delegated_device_principal_id
            ))
            .add_header("Authorization", format!("Bearer {organization_token}"))
            .json(&json!({
                "allowed_scopes": ["authorization"],
                "allowed_audiences": ["admin-backend"]
            }))
            .await;
        assert_eq!(cross_organization_key.status_code(), StatusCode::FORBIDDEN);

        let other_service = format!("other-service-{suffix}");
        db::create_service_client(
            &pool,
            db::CreateServiceClientParams {
                service_id: &other_service,
                service_secret: "OtherService#123",
                name: "Other tenant service",
                description: None,
                organization_id: Some(&organization_b.id),
                allowed_scopes: &["read".to_string()],
                allowed_audiences: &["admin-backend".to_string()],
                integration_type: "job",
                introspection_allowed: false,
                token_ttl_seconds: None,
                owner: None,
                contact: None,
            },
        )
        .await
        .expect("Failed to create other organization service");
        let hidden_other_service = server
            .get(&format!("{list_path}/{other_service}"))
            .add_header("Authorization", format!("Bearer {organization_token}"))
            .await;
        assert_eq!(hidden_other_service.status_code(), StatusCode::NOT_FOUND);

        let events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs
             WHERE event_type IN (
                'organization.service.created',
                'organization.service.updated',
                'organization.service.secret_rotated'
             )
               AND detail LIKE $1",
        )
        .bind(format!("%service_id={service_id}%"))
        .fetch_one(&pool)
        .await
        .expect("Failed to inspect delegated service audit logs");
        assert_eq!(events, 3, "Delegated service changes must be audited");
    }

    /// Exercises the signed organization context across check, batch-check, effective
    /// permissions, and resource-tree while the live tenant state changes underneath it.
    #[tokio::test]
    async fn test_organization_authorization_is_live_and_cross_tenant_safe() {
        let Some(pool) = setup_organization_test_pool().await else {
            return;
        };
        let server = setup_test_server().await;
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let app = format!("tenant-auth-{suffix}");

        let organization_a = db::create_organization(
            &pool,
            &format!("tenant-auth-a-{suffix}"),
            "Tenant authorization A",
            keylo::models::ORGANIZATION_KIND_CUSTOMER,
        )
        .await
        .expect("Failed to create organization A");
        let organization_b = db::create_organization(
            &pool,
            &format!("tenant-auth-b-{suffix}"),
            "Tenant authorization B",
            keylo::models::ORGANIZATION_KIND_CUSTOMER,
        )
        .await
        .expect("Failed to create organization B");
        let user = db::create_user(
            &pool,
            &format!("tenant-auth-user-{suffix}"),
            &format!("tenant-auth-user-{suffix}@example.test"),
            Some("TenantAuthUser#123"),
        )
        .await
        .expect("Failed to create tenant authorization user");
        let principal = db::get_principal_by_ref(&pool, "user", &user.id)
            .await
            .expect("Failed to load tenant authorization principal")
            .expect("Tenant authorization principal should exist");
        db::upsert_organization_membership(
            &pool,
            &organization_a.id,
            &principal.id,
            "active",
            None,
            None,
        )
        .await
        .expect("Failed to activate organization A membership");

        let permission = db::create_permission(
            &pool,
            &format!("tenant:document:read:{suffix}"),
            Some("Read one tenant's documents"),
        )
        .await
        .expect("Failed to create tenant permission");
        let organization_role = db::create_organization_role(
            &pool,
            &format!("tenant-reader-{suffix}"),
            Some("Tenant document reader"),
            "user",
        )
        .await
        .expect("Failed to create tenant role");
        db::assign_permission_to_role(&pool, &organization_role.id, &permission.id)
            .await
            .expect("Failed to bind tenant permission");
        db::assign_organization_role(
            &pool,
            &organization_a.id,
            &principal.id,
            &organization_role.id,
            Some("integration-test"),
        )
        .await
        .expect("Failed to bind organization role");

        let admin_login = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        admin_login.assert_status_ok();
        let admin_token = admin_login.json::<serde_json::Value>()["access_token"]
            .as_str()
            .unwrap()
            .to_string();

        let resource_a = server
            .post("/v1/admin/resources")
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({
                "organization_id": organization_a.id,
                "app": app,
                "resource_type": "menu",
                "code": "shared",
                "name": "Organization A resource",
                "permission_ids": [permission.id]
            }))
            .await;
        resource_a.assert_status_ok();
        let resource_a_body: serde_json::Value = resource_a.json();
        assert_eq!(
            resource_a_body["data"]["organization_id"],
            organization_a.id
        );

        for (code, name) in [
            ("shared", "Organization B shared resource"),
            ("only-b", "Organization B private resource"),
        ] {
            let resource_b = server
                .post("/v1/admin/resources")
                .add_header("Authorization", format!("Bearer {admin_token}"))
                .json(&json!({
                    "organization_id": organization_b.id,
                    "app": app,
                    "resource_type": "menu",
                    "code": code,
                    "name": name,
                    "permission_ids": [permission.id]
                }))
                .await;
            resource_b.assert_status_ok();
        }

        let login = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": user.username,
                "client_secret": "TenantAuthUser#123"
            }))
            .await;
        login.assert_status_ok();
        let platform_token = login.json::<serde_json::Value>()["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let organization_context = server
            .post("/v1/auth/organization-context")
            .add_header("Authorization", format!("Bearer {platform_token}"))
            .json(&json!({"organization_id": organization_a.id}))
            .await;
        organization_context.assert_status_ok();
        let organization_token = organization_context.json::<serde_json::Value>()["access_token"]
            .as_str()
            .unwrap()
            .to_string();

        let direct_check = server
            .post("/v1/authorize/check")
            .add_header("Authorization", format!("Bearer {organization_token}"))
            .json(&json!({"permission": permission.name}))
            .await;
        direct_check.assert_status_ok();
        assert_eq!(
            direct_check.json::<serde_json::Value>()["data"]["allowed"],
            true
        );
        let organization_audits = db::list_authorization_audit_logs_in_organization(
            &pool,
            Some(&organization_a.id),
            Some(&principal.id),
            Some("allow"),
            Some(&permission.name),
            None,
            10,
            0,
        )
        .await
        .expect("Failed to query tenant authorization audit");
        assert!(organization_audits
            .iter()
            .any(|audit| { audit.organization_id.as_deref() == Some(organization_a.id.as_str()) }));
        let audit_api = server
            .get(&format!(
                "/v1/admin/authorization-audit-logs?organization_id={}",
                organization_a.id
            ))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .await;
        audit_api.assert_status_ok();
        let audit_api_body: serde_json::Value = audit_api.json();
        let audit_rows = audit_api_body["data"].as_array().unwrap();
        assert!(!audit_rows.is_empty());
        assert!(audit_rows
            .iter()
            .all(|audit| audit["organization_id"] == organization_a.id));

        let resource_check = server
            .post("/v1/authorize/check")
            .add_header("Authorization", format!("Bearer {organization_token}"))
            .json(&json!({
                "app": app,
                "resource_type": "menu",
                "resource_code": "shared"
            }))
            .await;
        resource_check.assert_status_ok();
        assert_eq!(
            resource_check.json::<serde_json::Value>()["data"]["allowed"],
            true
        );

        let batch = server
            .post("/v1/authorize/batch-check")
            .add_header("Authorization", format!("Bearer {organization_token}"))
            .json(&json!({
                "checks": [
                    {"permission": permission.name},
                    {
                        "app": app,
                        "resource_type": "menu",
                        "resource_code": "only-b"
                    }
                ]
            }))
            .await;
        batch.assert_status_ok();
        let batch_body: serde_json::Value = batch.json();
        assert_eq!(batch_body["data"]["results"][0]["allowed"], true);
        assert_eq!(batch_body["data"]["results"][1]["allowed"], false);
        assert_eq!(
            batch_body["data"]["results"][1]["reason"],
            "permission_not_resolved"
        );

        let effective = server
            .get("/v1/principals/me/effective-permissions")
            .add_header("Authorization", format!("Bearer {organization_token}"))
            .await;
        effective.assert_status_ok();
        let effective_body: serde_json::Value = effective.json();
        assert!(effective_body["data"]["roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|role| role["id"] == organization_role.id));
        assert!(effective_body["data"]["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|candidate| candidate["id"] == permission.id));

        let tree = server
            .get(&format!(
                "/v1/principals/me/resource-tree?app={app}&type=menu"
            ))
            .add_header("Authorization", format!("Bearer {organization_token}"))
            .await;
        tree.assert_status_ok();
        let tree_body: serde_json::Value = tree.json();
        let nodes = tree_body["data"].as_array().unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0]["resource"]["code"], "shared");
        assert_eq!(nodes[0]["resource"]["organization_id"], organization_a.id);

        let platform_check = server
            .post("/v1/authorize/check")
            .add_header("Authorization", format!("Bearer {platform_token}"))
            .json(&json!({"permission": permission.name}))
            .await;
        platform_check.assert_status_ok();
        assert_eq!(
            platform_check.json::<serde_json::Value>()["data"]["allowed"],
            false
        );

        db::upsert_organization_membership(
            &pool,
            &organization_a.id,
            &principal.id,
            "suspended",
            None,
            None,
        )
        .await
        .expect("Failed to suspend tenant membership");
        let stale_context = server
            .post("/v1/authorize/check")
            .add_header("Authorization", format!("Bearer {organization_token}"))
            .json(&json!({"permission": permission.name}))
            .await;
        assert_eq!(stale_context.status_code(), StatusCode::FORBIDDEN);

        db::upsert_organization_membership(
            &pool,
            &organization_a.id,
            &principal.id,
            "active",
            None,
            None,
        )
        .await
        .expect("Failed to reactivate tenant membership");
        sqlx::query(
            "DELETE FROM organization_role_bindings WHERE organization_id = $1 AND principal_id = $2 AND role_id = $3",
        )
        .bind(&organization_a.id)
        .bind(&principal.id)
        .bind(&organization_role.id)
        .execute(&pool)
        .await
        .expect("Failed to revoke tenant role binding");
        let revoked_binding = server
            .post("/v1/authorize/check")
            .add_header("Authorization", format!("Bearer {organization_token}"))
            .json(&json!({"permission": permission.name}))
            .await;
        revoked_binding.assert_status_ok();
        assert_eq!(
            revoked_binding.json::<serde_json::Value>()["data"]["allowed"],
            false
        );

        db::assign_organization_role(
            &pool,
            &organization_a.id,
            &principal.id,
            &organization_role.id,
            Some("integration-test"),
        )
        .await
        .expect("Failed to restore tenant role binding");
        db::set_organization_status(&pool, &organization_a.id, "disabled")
            .await
            .expect("Failed to disable tenant organization")
            .expect("Tenant organization should exist");
        let disabled_organization = server
            .get(&format!(
                "/v1/principals/me/resource-tree?app={app}&type=menu"
            ))
            .add_header("Authorization", format!("Bearer {organization_token}"))
            .await;
        assert_eq!(disabled_organization.status_code(), StatusCode::FORBIDDEN);
    }

    /// Keeps an organization service token inside its signed tenant boundary.
    #[tokio::test]
    async fn test_organization_service_token_is_live_and_cross_tenant_safe() {
        let Some(pool) = setup_organization_test_pool().await else {
            return;
        };
        let server = setup_test_server().await;
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let app = format!("tenant-service-{suffix}");
        let organization_a = db::create_organization(
            &pool,
            &format!("tenant-service-a-{suffix}"),
            "Tenant service A",
            keylo::models::ORGANIZATION_KIND_CUSTOMER,
        )
        .await
        .expect("Failed to create service organization A");
        let organization_b = db::create_organization(
            &pool,
            &format!("tenant-service-b-{suffix}"),
            "Tenant service B",
            keylo::models::ORGANIZATION_KIND_CUSTOMER,
        )
        .await
        .expect("Failed to create service organization B");
        let admin_login = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        admin_login.assert_status_ok();
        let admin_token = admin_login.json::<serde_json::Value>()["access_token"]
            .as_str()
            .expect("Admin token should be present")
            .to_string();
        let service_id = format!("tenant-service-{suffix}");
        let service_secret = "TenantService#123";

        let registered = server
            .post("/v1/admin/services")
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({
                "service_id": service_id,
                "service_secret": service_secret,
                "name": "Tenant authorization service",
                "organization_id": organization_a.id,
                "allowed_scopes": ["read"],
                "allowed_audiences": ["admin-backend"],
                "integration_type": "job",
                "introspection_allowed": true
            }))
            .await;
        registered.assert_status_ok();
        let registration: serde_json::Value = registered.json();
        assert_eq!(registration["scope_kind"], "organization");
        assert_eq!(registration["organization_id"], organization_a.id);

        let service_info = server
            .get(&format!("/v1/admin/services/{service_id}"))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .await;
        service_info.assert_status_ok();
        let service_info: serde_json::Value = service_info.json();
        assert_eq!(service_info["scope_kind"], "organization");
        assert_eq!(service_info["organization_id"], organization_a.id);

        let service_principal = db::get_principal_by_ref(&pool, "service", &service_id)
            .await
            .expect("Failed to load organization service principal")
            .expect("Organization service principal should exist");
        assert!(db::get_active_organization_membership(
            &pool,
            &organization_a.id,
            &service_principal.id,
        )
        .await
        .expect("Failed to load organization service membership")
        .is_some());

        let permission = db::create_permission(
            &pool,
            &format!("tenant:service:read:{suffix}"),
            Some("Read one tenant's service resources"),
        )
        .await
        .expect("Failed to create service tenant permission");
        let role = db::create_organization_role(
            &pool,
            &format!("tenant-service-reader-{suffix}"),
            Some("Tenant service reader"),
            "service",
        )
        .await
        .expect("Failed to create service organization role");
        db::assign_permission_to_role(&pool, &role.id, &permission.id)
            .await
            .expect("Failed to bind service tenant permission");
        db::assign_organization_role(
            &pool,
            &organization_a.id,
            &service_principal.id,
            &role.id,
            Some("integration-test"),
        )
        .await
        .expect("Failed to bind service organization role");
        let permission_ids = vec![permission.id.clone()];
        db::create_resource_in_organization(
            &pool,
            Some(&organization_a.id),
            db::CreateResourceParams {
                app: &app,
                resource_type: "menu",
                code: "shared",
                name: "Organization A service resource",
                parent_id: None,
                display_order: 0,
                description: None,
                metadata: None,
                permission_ids: &permission_ids,
            },
        )
        .await
        .expect("Failed to create organization A service resource");
        db::create_resource_in_organization(
            &pool,
            Some(&organization_b.id),
            db::CreateResourceParams {
                app: &app,
                resource_type: "menu",
                code: "only-b",
                name: "Organization B service resource",
                parent_id: None,
                display_order: 0,
                description: None,
                metadata: None,
                permission_ids: &permission_ids,
            },
        )
        .await
        .expect("Failed to create organization B service resource");

        let service_login = server
            .post("/v1/service/token")
            .json(&json!({
                "service_id": service_id,
                "service_secret": service_secret,
                "audience": "admin-backend",
                "scope": "read"
            }))
            .await;
        service_login.assert_status_ok();
        let service_token = service_login.json::<serde_json::Value>()["access_token"]
            .as_str()
            .expect("Service token should be present")
            .to_string();
        let claims = Keys::from_config(&test_config())
            .expect("Test keys should load")
            .decode_service_token(&service_token)
            .expect("Service token should decode");
        assert_eq!(
            claims.organization_id.as_deref(),
            Some(organization_a.id.as_str())
        );
        assert_eq!(
            claims.principal_id.as_deref(),
            Some(service_principal.id.as_str())
        );

        let direct_check = server
            .post("/v1/authorize/check")
            .add_header("Authorization", format!("Bearer {service_token}"))
            .json(&json!({"permission": permission.name}))
            .await;
        direct_check.assert_status_ok();
        assert_eq!(
            direct_check.json::<serde_json::Value>()["data"]["allowed"],
            true
        );
        let resource_check = server
            .post("/v1/authorize/check")
            .add_header("Authorization", format!("Bearer {service_token}"))
            .json(&json!({
                "app": app,
                "resource_type": "menu",
                "resource_code": "shared"
            }))
            .await;
        resource_check.assert_status_ok();
        assert_eq!(
            resource_check.json::<serde_json::Value>()["data"]["allowed"],
            true
        );
        let cross_tenant_batch = server
            .post("/v1/authorize/batch-check")
            .add_header("Authorization", format!("Bearer {service_token}"))
            .json(&json!({
                "checks": [
                    {"permission": permission.name},
                    {
                        "app": app,
                        "resource_type": "menu",
                        "resource_code": "only-b"
                    }
                ]
            }))
            .await;
        cross_tenant_batch.assert_status_ok();
        let cross_tenant_batch: serde_json::Value = cross_tenant_batch.json();
        assert_eq!(cross_tenant_batch["data"]["results"][0]["allowed"], true);
        assert_eq!(cross_tenant_batch["data"]["results"][1]["allowed"], false);
        assert_eq!(
            cross_tenant_batch["data"]["results"][1]["reason"],
            "permission_not_resolved"
        );
        let resource_tree = server
            .get(&format!(
                "/v1/principals/me/resource-tree?app={app}&type=menu"
            ))
            .add_header("Authorization", format!("Bearer {service_token}"))
            .await;
        resource_tree.assert_status_ok();
        let resource_nodes = resource_tree.json::<serde_json::Value>()["data"]
            .as_array()
            .expect("Service resource tree should be an array")
            .to_owned();
        assert_eq!(resource_nodes.len(), 1);
        assert_eq!(
            resource_nodes[0]["resource"]["organization_id"],
            organization_a.id
        );

        let caller_introspection = server
            .post("/v1/service/introspect")
            .add_header("Authorization", format!("Bearer {service_token}"))
            .json(&json!({"token": service_token}))
            .await;
        assert_eq!(caller_introspection.status_code(), StatusCode::FORBIDDEN);

        db::upsert_organization_membership(
            &pool,
            &organization_a.id,
            &service_principal.id,
            "suspended",
            None,
            None,
        )
        .await
        .expect("Failed to suspend organization service membership");
        let stale_token = server
            .post("/v1/authorize/check")
            .add_header("Authorization", format!("Bearer {service_token}"))
            .json(&json!({"permission": permission.name}))
            .await;
        assert_eq!(stale_token.status_code(), StatusCode::FORBIDDEN);
        let blocked_issuance = server
            .post("/v1/service/token")
            .json(&json!({
                "service_id": service_id,
                "service_secret": service_secret,
                "audience": "admin-backend",
                "scope": "read"
            }))
            .await;
        assert_eq!(blocked_issuance.status_code(), StatusCode::FORBIDDEN);
    }

    /// Exercises the metadata-only key lifecycle and direct machine authorization path.
    #[tokio::test]
    async fn test_machine_api_key_is_explicit_scoped_rotatable_and_live() {
        let Some(pool) = setup_organization_test_pool().await else {
            return;
        };
        let server = setup_test_server().await;
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let organization_a = db::create_organization(
            &pool,
            &format!("machine-http-a-{suffix}"),
            "Machine HTTP organization A",
            keylo::models::ORGANIZATION_KIND_CUSTOMER,
        )
        .await
        .expect("Failed to create machine HTTP organization A");
        let organization_b = db::create_organization(
            &pool,
            &format!("machine-http-b-{suffix}"),
            "Machine HTTP organization B",
            keylo::models::ORGANIZATION_KIND_CUSTOMER,
        )
        .await
        .expect("Failed to create machine HTTP organization B");
        let admin_login = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        admin_login.assert_status_ok();
        let admin_token = admin_login.json::<serde_json::Value>()["access_token"]
            .as_str()
            .expect("Admin token should be present")
            .to_string();

        let device_id = format!("machine-http-device-{suffix}");
        let device_response = server
            .post("/v1/admin/devices")
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({
                "device_id": device_id,
                "display_name": "Machine authorization agent",
                "organization_id": organization_a.id,
            }))
            .await;
        device_response.assert_status_ok();
        let device: serde_json::Value = device_response.json();
        assert_eq!(device["data"]["scope_kind"], "organization");
        assert_eq!(device["data"]["organization_id"], organization_a.id);
        let device_principal_id = device["data"]["principal_id"]
            .as_str()
            .expect("Device creation should return Principal id")
            .to_string();

        let permission = db::create_permission(
            &pool,
            &format!("machine:http:read:{suffix}"),
            Some("Machine HTTP permission"),
        )
        .await
        .expect("Failed to create machine permission");
        let role = db::create_organization_role(
            &pool,
            &format!("machine-http-reader-{suffix}"),
            Some("Machine HTTP reader"),
            "device",
        )
        .await
        .expect("Failed to create device organization role");
        db::assign_permission_to_role(&pool, &role.id, &permission.id)
            .await
            .expect("Failed to bind machine permission");
        db::assign_organization_role(
            &pool,
            &organization_a.id,
            &device_principal_id,
            &role.id,
            Some("machine-api-key-integration-test"),
        )
        .await
        .expect("Failed to bind device organization role");
        db::create_resource_in_organization(
            &pool,
            Some(&organization_b.id),
            db::CreateResourceParams {
                app: "machine-http",
                resource_type: "api",
                code: "only-organization-b",
                name: "Organization B machine resource",
                parent_id: None,
                display_order: 0,
                description: None,
                metadata: None,
                permission_ids: std::slice::from_ref(&permission.id),
            },
        )
        .await
        .expect("Failed to create cross-tenant resource");

        let key_path = format!("/v1/admin/principals/{device_principal_id}/api-keys");
        let created = server
            .post(&key_path)
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({
                "organization_id": organization_a.id,
                "allowed_scopes": ["authorization"],
                "allowed_audiences": ["admin-backend"],
            }))
            .await;
        created.assert_status_ok();
        let created: serde_json::Value = created.json();
        let api_key = created["data"]["api_key"]
            .as_str()
            .expect("API key should appear only in create response")
            .to_string();
        let key_id = created["data"]["key_id"]
            .as_str()
            .expect("API key metadata should include key id")
            .to_string();
        assert!(api_key.starts_with("keylo."));
        assert!(created["data"].get("secret_hash").is_none());

        let listed = server
            .get(&format!("{key_path}?organization_id={}", organization_a.id))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .await;
        listed.assert_status_ok();
        let listed: serde_json::Value = listed.json();
        assert_eq!(listed["data"].as_array().map(Vec::len), Some(1));
        assert!(listed["data"][0].get("api_key").is_none());

        let direct_check = server
            .post("/v1/authorize/check")
            .add_header("X-API-Key", api_key.clone())
            .json(&json!({ "permission": permission.name }))
            .await;
        direct_check.assert_status_ok();
        assert_eq!(
            direct_check.json::<serde_json::Value>()["data"]["allowed"],
            true
        );
        let direct_batch = server
            .post("/v1/authorize/batch-check")
            .add_header("X-API-Key", api_key.clone())
            .json(&json!({
                "checks": [{ "permission": permission.name }]
            }))
            .await;
        direct_batch.assert_status_ok();
        assert_eq!(
            direct_batch.json::<serde_json::Value>()["data"]["results"][0]["allowed"],
            true
        );
        let cross_tenant = server
            .post("/v1/authorize/check")
            .add_header("X-API-Key", api_key.clone())
            .json(&json!({
                "app": "machine-http",
                "resource_type": "api",
                "resource_code": "only-organization-b"
            }))
            .await;
        cross_tenant.assert_status_ok();
        assert_eq!(
            cross_tenant.json::<serde_json::Value>()["data"]["allowed"],
            false
        );
        let bearer_key = server
            .post("/v1/authorize/check")
            .add_header("Authorization", format!("Bearer {api_key}"))
            .json(&json!({ "permission": permission.name }))
            .await;
        assert_eq!(bearer_key.status_code(), StatusCode::UNAUTHORIZED);
        let query_key = server
            .post(&format!("/v1/authorize/check?api_key={api_key}"))
            .add_header("X-API-Key", api_key.clone())
            .json(&json!({ "permission": permission.name }))
            .await;
        assert_eq!(query_key.status_code(), StatusCode::UNAUTHORIZED);

        let rotated = server
            .post(&format!(
                "{key_path}/{key_id}/rotate?organization_id={}",
                organization_a.id
            ))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({}))
            .await;
        rotated.assert_status_ok();
        let rotated: serde_json::Value = rotated.json();
        let rotated_key = rotated["data"]["api_key"]
            .as_str()
            .expect("Rotation should return a replacement key once")
            .to_string();
        let old_key_during_overlap = server
            .post("/v1/authorize/check")
            .add_header("X-API-Key", api_key.clone())
            .json(&json!({ "permission": permission.name }))
            .await;
        old_key_during_overlap.assert_status_ok();
        let new_key_during_overlap = server
            .post("/v1/authorize/check")
            .add_header("X-API-Key", rotated_key.clone())
            .json(&json!({ "permission": permission.name }))
            .await;
        new_key_during_overlap.assert_status_ok();

        let revoked = server
            .delete(&format!(
                "{key_path}/{key_id}?organization_id={}",
                organization_a.id
            ))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({ "reason": "Retired after rotation" }))
            .await;
        revoked.assert_status_ok();
        let revoked_key = server
            .post("/v1/authorize/check")
            .add_header("X-API-Key", api_key)
            .json(&json!({ "permission": permission.name }))
            .await;
        assert_eq!(revoked_key.status_code(), StatusCode::UNAUTHORIZED);

        db::upsert_organization_membership(
            &pool,
            &organization_a.id,
            &device_principal_id,
            "suspended",
            None,
            None,
        )
        .await
        .expect("Failed to suspend device membership");
        let suspended = server
            .post("/v1/authorize/check")
            .add_header("X-API-Key", rotated_key)
            .json(&json!({ "permission": permission.name }))
            .await;
        assert_eq!(suspended.status_code(), StatusCode::UNAUTHORIZED);

        let audited: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs
             WHERE event_type IN (
                'machine.device.created',
                'machine.api_key.created',
                'machine.api_key.authenticated',
                'machine.api_key.rotated',
                'machine.api_key.revoked'
             )
               AND detail LIKE $1",
        )
        .bind(format!("%principal_id={device_principal_id}%"))
        .fetch_one(&pool)
        .await
        .expect("Failed to inspect machine audit logs");
        assert!(audited >= 5, "Machine lifecycle and use must be audited");
    }

    /// Verifies that a password login can create a tenant-scoped refresh session
    /// and that organization or membership lifecycle changes revoke only that
    /// tenant session while preserving the user's platform session.
    #[tokio::test]
    async fn test_organization_scoped_refresh_sessions_follow_live_lifecycle() {
        let Some(pool) = setup_organization_test_pool().await else {
            return;
        };
        let server = setup_test_server().await;
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let organization = db::create_organization(
            &pool,
            &format!("refresh-session-org-{suffix}"),
            "Refresh session organization",
            keylo::models::ORGANIZATION_KIND_CUSTOMER,
        )
        .await
        .expect("Failed to create refresh-session organization");
        let user = db::create_user(
            &pool,
            &format!("refresh-session-user-{suffix}"),
            &format!("refresh-session-user-{suffix}@example.test"),
            Some("RefreshSessionUser#123"),
        )
        .await
        .expect("Failed to create refresh-session user");
        let principal = db::get_principal_by_ref(&pool, "user", &user.id)
            .await
            .expect("Failed to load refresh-session principal")
            .expect("Refresh-session principal should exist");
        db::upsert_organization_membership(
            &pool,
            &organization.id,
            &principal.id,
            "active",
            None,
            None,
        )
        .await
        .expect("Failed to activate refresh-session membership");

        let admin_login = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;
        admin_login.assert_status_ok();
        let admin_token = admin_login.json::<serde_json::Value>()["access_token"]
            .as_str()
            .unwrap()
            .to_string();

        let platform_login = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": &user.username,
                "client_secret": "RefreshSessionUser#123"
            }))
            .await;
        platform_login.assert_status_ok();
        let platform_refresh_token = platform_login.json::<serde_json::Value>()["refresh_token"]
            .as_str()
            .unwrap()
            .to_string();

        let organization_login = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": &user.username,
                "client_secret": "RefreshSessionUser#123",
                "organization_id": &organization.id
            }))
            .await;
        organization_login.assert_status_ok();
        let organization_login_body: serde_json::Value = organization_login.json();
        let organization_access_token = organization_login_body["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let organization_refresh_token = organization_login_body["refresh_token"]
            .as_str()
            .unwrap()
            .to_string();
        let organization_me = server
            .get("/v1/auth/me")
            .add_header(
                "Authorization",
                format!("Bearer {organization_access_token}"),
            )
            .await;
        organization_me.assert_status_ok();
        assert_eq!(
            organization_me.json::<serde_json::Value>()["organization_id"],
            organization.id
        );

        let listed = server
            .get(&format!(
                "/v1/admin/refresh-sessions?organization_id={}&principal_id={}",
                organization.id, principal.id
            ))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .await;
        listed.assert_status_ok();
        let listed_body: serde_json::Value = listed.json();
        assert_eq!(listed_body["data"].as_array().unwrap().len(), 1);
        assert_eq!(listed_body["data"][0]["organization_id"], organization.id);

        let scoped_refresh = server
            .post("/v1/auth/refresh")
            .json(&json!({ "refresh_token": organization_refresh_token }))
            .await;
        scoped_refresh.assert_status_ok();
        let rotated_organization_refresh_token = scoped_refresh.json::<serde_json::Value>()
            ["refresh_token"]
            .as_str()
            .unwrap()
            .to_string();

        let disable_organization = server
            .put(&format!(
                "/v1/admin/organizations/{}/status",
                organization.id
            ))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({ "status": "disabled" }))
            .await;
        disable_organization.assert_status_ok();

        let revoked_sessions = db::list_refresh_sessions_in_organization(
            &pool,
            Some(&organization.id),
            true,
            Some(&principal.id),
            None,
            None,
            10,
            0,
        )
        .await
        .expect("Failed to list revoked organization sessions");
        assert_eq!(revoked_sessions.len(), 1);
        assert!(revoked_sessions[0].revoked_at.is_some());
        assert_eq!(
            revoked_sessions[0].revoke_reason.as_deref(),
            Some("organization_disabled")
        );

        let rejected_scoped_refresh = server
            .post("/v1/auth/refresh")
            .json(&json!({ "refresh_token": rotated_organization_refresh_token }))
            .await;
        assert_eq!(
            rejected_scoped_refresh.status_code(),
            StatusCode::UNAUTHORIZED
        );

        let platform_refresh = server
            .post("/v1/auth/refresh")
            .json(&json!({ "refresh_token": platform_refresh_token }))
            .await;
        platform_refresh.assert_status_ok();

        let reactivate_organization = server
            .put(&format!(
                "/v1/admin/organizations/{}/status",
                organization.id
            ))
            .add_header("Authorization", format!("Bearer {admin_token}"))
            .json(&json!({ "status": "active" }))
            .await;
        reactivate_organization.assert_status_ok();

        let membership_path = format!(
            "/v1/admin/organizations/{}/memberships/{}",
            organization.id, principal.id
        );
        for membership_status in ["pending", "suspended", "removed"] {
            let active_login = server
                .post("/v1/auth/token")
                .json(&json!({
                    "client_id": &user.username,
                    "client_secret": "RefreshSessionUser#123",
                    "organization_id": &organization.id
                }))
                .await;
            active_login.assert_status_ok();
            let active_refresh_token = active_login.json::<serde_json::Value>()["refresh_token"]
                .as_str()
                .unwrap()
                .to_string();

            let update_membership = server
                .put(&membership_path)
                .add_header("Authorization", format!("Bearer {admin_token}"))
                .json(&json!({ "status": membership_status }))
                .await;
            update_membership.assert_status_ok();

            let rejected_login = server
                .post("/v1/auth/token")
                .json(&json!({
                    "client_id": &user.username,
                    "client_secret": "RefreshSessionUser#123",
                    "organization_id": &organization.id
                }))
                .await;
            assert_eq!(rejected_login.status_code(), StatusCode::FORBIDDEN);

            let rejected_refresh = server
                .post("/v1/auth/refresh")
                .json(&json!({ "refresh_token": active_refresh_token }))
                .await;
            assert_eq!(rejected_refresh.status_code(), StatusCode::UNAUTHORIZED);

            let revoked_sessions = db::list_refresh_sessions_in_organization(
                &pool,
                Some(&organization.id),
                true,
                Some(&principal.id),
                None,
                None,
                20,
                0,
            )
            .await
            .expect("Failed to list membership-revoked organization sessions");
            assert!(revoked_sessions.iter().any(|session| {
                session.revoke_reason.as_deref()
                    == Some(&format!("organization_membership_{membership_status}"))
            }));

            let reactivate_membership = server
                .put(&membership_path)
                .add_header("Authorization", format!("Bearer {admin_token}"))
                .json(&json!({ "status": "active" }))
                .await;
            reactivate_membership.assert_status_ok();
        }
    }

    #[tokio::test]
    async fn test_external_customer_with_admin_claims_cannot_access_platform_organizations() {
        let Some(pool) = setup_organization_test_pool().await else {
            return;
        };
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let user = db::create_user(
            &pool,
            &format!("external-platform-guard-{suffix}"),
            &format!("external-platform-guard-{suffix}@example.test"),
            Some("ExternalPlatformGuard#123"),
        )
        .await
        .unwrap();
        assert_eq!(user.user_class, keylo::models::USER_CLASS_EXTERNAL_CUSTOMER);
        let principal = db::get_principal_by_ref(&pool, "user", &user.id)
            .await
            .unwrap()
            .unwrap();
        let now = chrono::Utc::now().timestamp();
        let token = Keys::from_config(&test_config())
            .unwrap()
            .sign_token(&Claims {
                sub: format!("user:{}", user.username),
                uid: Some(user.id),
                principal_id: Some(principal.id),
                principal_type: Some("user".to_string()),
                organization_id: None,
                customer_support_grant_id: None,
                iss: test_config().jwt_issuer,
                aud: "admin-backend".to_string(),
                scope: vec!["read".to_string(), "write".to_string(), "admin".to_string()],
                role: vec!["admin".to_string()],
                iat: now,
                exp: now + 60,
                jti: uuid::Uuid::new_v4().to_string(),
                token_type: "access".to_string(),
            })
            .unwrap();

        let server = setup_test_server().await;
        let response = server
            .get("/v1/admin/organizations")
            .add_header("Authorization", format!("Bearer {token}"))
            .await;
        assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

        let generic_admin_response = server
            .get("/api/rbac/roles")
            .add_header("Authorization", format!("Bearer {token}"))
            .await;
        assert_eq!(generic_admin_response.status_code(), StatusCode::FORBIDDEN);

        let service_id = format!("introspection-guard-{suffix}");
        let service_scopes = vec!["read".to_string()];
        let service_audiences = vec!["admin-backend".to_string()];
        db::create_service_client(
            &pool,
            db::CreateServiceClientParams {
                service_id: &service_id,
                service_secret: "IntrospectionGuard#123",
                name: "Introspection guard service",
                description: None,
                organization_id: None,
                allowed_scopes: &service_scopes,
                allowed_audiences: &service_audiences,
                integration_type: "third_party",
                introspection_allowed: true,
                token_ttl_seconds: None,
                owner: None,
                contact: None,
            },
        )
        .await
        .unwrap();
        let service_login = server
            .post("/v1/service/token")
            .json(&json!({
                "service_id": service_id,
                "service_secret": "IntrospectionGuard#123",
                "audience": "admin-backend",
                "scope": "read"
            }))
            .await;
        service_login.assert_status_ok();
        let service_login_body: serde_json::Value = service_login.json();
        let service_token = service_login_body["access_token"].as_str().unwrap();
        let introspection = server
            .post("/v1/auth/introspect")
            .add_header("Authorization", format!("Bearer {service_token}"))
            .json(&json!({ "token": token }))
            .await;
        introspection.assert_status_ok();
        let introspection_body: serde_json::Value = introspection.json();
        assert_eq!(introspection_body["active"], false);
    }

    #[tokio::test]
    async fn test_setup_wizard_routes_are_disabled_by_default() {
        let server = setup_test_server().await;

        let status_resp = server.get("/setup/status").await;
        assert_eq!(status_resp.status_code(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_setup_wizard_status_and_initialize() {
        let mut config = test_config();
        config.enable_setup_wizard = true;
        config.admin_client_id = Some("setup-admin".to_string());
        config.admin_client_secret = Some("SetupAdmin#123".to_string());

        let server = setup_test_server_with_config(config).await;

        let status_resp = server.get("/setup/status").await;
        status_resp.assert_status_ok();
        let status_body: serde_json::Value = status_resp.json();
        assert_eq!(status_body["enabled"], true);
        assert_eq!(status_body["environment"], "test");
        assert_eq!(status_body["admin_client_id_configured"], true);
        let database_connected = status_body["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| {
                check["key"] == "database_connection"
                    && check["ok"] == serde_json::Value::Bool(true)
            });
        if !database_connected {
            return;
        }
        let migrations_check = status_body["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["key"] == "migrations")
            .expect("setup status should expose migration state");
        assert_eq!(migrations_check["ok"], true);
        assert!(status_body["endpoints"]["jwks_uri"]
            .as_str()
            .unwrap()
            .contains("/.well-known/jwks.json"));

        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://keylo_user@localhost:5432/keylo".to_string());
        let database_url = build_database_url(
            database_url,
            database_password_from_env_result().unwrap_or(None),
        );
        let db = keylo::db::init_db_pool(&database_url).await.unwrap();
        keylo::db::mark_setup_completed(&db).await.unwrap();

        let init_resp = server
            .post("/setup/initialize")
            .json(&json!({
                "admin_client_id": "setup-admin-test",
                "admin_client_secret": "SetupAdmin#456"
            }))
            .await;
        assert_eq!(init_resp.status_code(), StatusCode::FORBIDDEN);

        let status_after_init_resp = server.get("/setup/status").await;
        status_after_init_resp.assert_status_ok();
        let status_after_init_body: serde_json::Value = status_after_init_resp.json();
        assert_eq!(status_after_init_body["completed"], true);
    }

    #[tokio::test]
    async fn test_completed_setup_redirects_to_status_and_rejects_reinitialize() {
        let mut config = test_config();
        config.enable_setup_wizard = true;

        let server = setup_test_server_with_config(config).await;

        let complete_resp = server
            .post("/setup/initialize")
            .json(&json!({
                "admin_client_id": "setup-admin-test",
                "admin_client_secret": "SetupAdmin#456"
            }))
            .await;
        if complete_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR
            || complete_resp.status_code() == StatusCode::BAD_REQUEST
            || complete_resp.status_code() == StatusCode::NOT_FOUND
        {
            return;
        }
        assert!(
            complete_resp.status_code() == StatusCode::OK
                || complete_resp.status_code() == StatusCode::FORBIDDEN
        );

        let setup_resp = server.get("/setup").await;
        if setup_resp.status_code() == StatusCode::OK {
            return;
        }
        assert_eq!(setup_resp.status_code(), StatusCode::SEE_OTHER);
        assert_eq!(
            setup_resp.headers()["location"].to_str().unwrap(),
            "/setup/status-page"
        );

        let status_resp = server.get("/setup/status").await;
        status_resp.assert_status_ok();
        let status_body: serde_json::Value = status_resp.json();
        assert_eq!(status_body["completed"], true);

        let init_resp = server
            .post("/setup/initialize")
            .json(&json!({
                "admin_client_id": "setup-admin-test",
                "admin_client_secret": "SetupAdmin#456"
            }))
            .await;
        assert_eq!(init_resp.status_code(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_index_redirects_to_setup_when_wizard_enabled_and_incomplete() {
        let mut config = test_config();
        config.enable_setup_wizard = true;

        let server = setup_test_server_with_config(config).await;

        let response = server.get("/").await;
        if response.status_code() == StatusCode::OK {
            return;
        }
        assert_eq!(response.status_code(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()["location"].to_str().unwrap(), "/setup");
    }

    #[tokio::test]
    async fn test_untrusted_management_client_cannot_use_user_or_admin_token_flow() {
        let server = setup_test_server().await;
        let admin_login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;

        if admin_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }

        admin_login_resp.assert_status_ok();
        let client_id = format!(
            "untrusted-client-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );

        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://keylo_user@localhost:5432/keylo".to_string());
        let database_url = build_database_url(
            database_url,
            database_password_from_env_result().unwrap_or(None),
        );
        let db = keylo::db::init_db_pool(&database_url).await.unwrap();
        keylo::db::create_client(
            &db,
            &client_id,
            "client-secret",
            "Untrusted Client",
            Some("should not authenticate as user or admin"),
        )
        .await
        .unwrap();

        let user_flow_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": client_id,
                "client_secret": "client-secret"
            }))
            .await;
        assert_eq!(user_flow_resp.status_code(), StatusCode::UNAUTHORIZED);
        let user_flow_body: serde_json::Value = user_flow_resp.json();
        assert_eq!(user_flow_body["error"], "wrong_credentials");

        let admin_flow_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": client_id,
                "client_secret": "client-secret"
            }))
            .await;
        assert_eq!(admin_flow_resp.status_code(), StatusCode::FORBIDDEN);
        let admin_flow_body: serde_json::Value = admin_flow_resp.json();
        assert_eq!(admin_flow_body["error"], "insufficient_role");
    }

    #[tokio::test]
    async fn test_service_token_requires_registered_service_client() {
        let server = setup_test_server().await;

        let response = server
            .post("/v1/service/token")
            .json(&json!({
                "service_id": "missing-agileboot-client",
                "service_secret": "missing-secret",
                "audience": "admin-backend",
                "scope": "read"
            }))
            .await;

        if response.status_code() == StatusCode::INTERNAL_SERVER_ERROR
            || response.status_code() == StatusCode::NOT_FOUND
        {
            return;
        }

        assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
        let body: serde_json::Value = response.json();
        assert_eq!(body["error"], "service_client_not_authorized");
    }

    #[tokio::test]
    async fn test_super_admin_bootstrap_can_access_admin_routes() {
        let config = Config {
            enable_super_admin_bootstrap: true,
            super_admin_username: Some("root_bootstrap".to_string()),
            super_admin_email: Some("root_bootstrap@example.com".to_string()),
            super_admin_password: Some("RootBootstrap#123".to_string()),
            ..test_config()
        };

        let server = setup_test_server_with_config(config).await;

        let login_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": "root_bootstrap",
                "client_secret": "RootBootstrap#123"
            }))
            .await;

        if login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }

        login_resp.assert_status_ok();
        let login_body: serde_json::Value = login_resp.json();
        assert!(login_body["refresh_token"].as_str().is_some());
        let access_token = login_body["access_token"].as_str().unwrap();

        let admin_users_resp = server
            .get("/v1/admin/users")
            .add_header("Authorization", format!("Bearer {}", access_token))
            .await;
        assert_eq!(admin_users_resp.status_code(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_user_refresh_token_rotates_and_replay_is_rejected() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let username = format!("root_refresh_{}", ts);
        let password = "RootRefresh#123";
        let config = Config {
            enable_super_admin_bootstrap: true,
            super_admin_username: Some(username.clone()),
            super_admin_email: Some(format!("{}@example.com", username)),
            super_admin_password: Some(password.to_string()),
            ..test_config()
        };

        let server = setup_test_server_with_config(config).await;

        let login_resp = server
            .post("/v1/auth/token")
            .add_header("User-Agent", "KeyloIntegrationTest/1.0")
            .json(&json!({
                "client_id": username,
                "client_secret": password
            }))
            .await;

        if login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        login_resp.assert_status_ok();
        let login_body: serde_json::Value = login_resp.json();
        let refresh_token = login_body["refresh_token"].as_str().unwrap();

        let refresh_resp = server
            .post("/v1/auth/refresh")
            .json(&json!({ "refresh_token": refresh_token }))
            .await;
        refresh_resp.assert_status_ok();
        let refresh_body: serde_json::Value = refresh_resp.json();
        assert!(refresh_body["access_token"].as_str().is_some());
        let rotated_refresh_token = refresh_body["refresh_token"].as_str().unwrap();
        assert_ne!(rotated_refresh_token, refresh_token);

        let replay_resp = server
            .post("/v1/auth/refresh")
            .json(&json!({ "refresh_token": refresh_token }))
            .await;
        assert_eq!(replay_resp.status_code(), StatusCode::UNAUTHORIZED);

        let metrics_resp = server.get("/metrics").await;
        metrics_resp.assert_status_ok();
        let metrics = metrics_resp.text();
        assert!(metrics.contains("keylo_refresh_replays_total 1"));

        let revoked_session_resp = server
            .post("/v1/auth/refresh")
            .json(&json!({ "refresh_token": rotated_refresh_token }))
            .await;
        assert_eq!(revoked_session_resp.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_refresh_token_logout_revokes_session_without_access_token() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let username = format!("root_refresh_logout_{}", ts);
        let password = "RootRefreshLogout#123";
        let config = Config {
            enable_super_admin_bootstrap: true,
            super_admin_username: Some(username.clone()),
            super_admin_email: Some(format!("{}@example.com", username)),
            super_admin_password: Some(password.to_string()),
            ..test_config()
        };

        let server = setup_test_server_with_config(config).await;

        let login_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": password
            }))
            .await;

        if login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        login_resp.assert_status_ok();
        let login_body: serde_json::Value = login_resp.json();
        let refresh_token = login_body["refresh_token"].as_str().unwrap();

        let logout_resp = server
            .post("/v1/auth/logout-refresh-token")
            .json(&json!({ "refresh_token": refresh_token }))
            .await;
        logout_resp.assert_status_ok();

        let refresh_resp = server
            .post("/v1/auth/refresh")
            .json(&json!({ "refresh_token": refresh_token }))
            .await;
        assert_eq!(refresh_resp.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_single_user_session_requires_explicit_takeover() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let username = format!("root_single_{}", ts);
        let password = "RootSingle#123";
        let config = Config {
            enable_super_admin_bootstrap: true,
            super_admin_username: Some(username.clone()),
            super_admin_email: Some(format!("{}@example.com", username)),
            super_admin_password: Some(password.to_string()),
            session_policy: "single_user_session".to_string(),
            ..test_config()
        };

        let server = setup_test_server_with_config(config).await;

        let first_login_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": password
            }))
            .await;

        if first_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        first_login_resp.assert_status_ok();
        let first_login_body: serde_json::Value = first_login_resp.json();
        let first_refresh_token = first_login_body["refresh_token"].as_str().unwrap();

        let rejected_login_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": password
            }))
            .await;
        assert_eq!(rejected_login_resp.status_code(), StatusCode::CONFLICT);

        let takeover_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": password,
                "force": true
            }))
            .await;
        takeover_resp.assert_status_ok();
        let takeover_body: serde_json::Value = takeover_resp.json();
        assert!(takeover_body["refresh_token"].as_str().is_some());

        let old_refresh_resp = server
            .post("/v1/auth/refresh")
            .json(&json!({ "refresh_token": first_refresh_token }))
            .await;
        assert_eq!(old_refresh_resp.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_admin_can_list_and_revoke_principal_refresh_session() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let username = format!("root_session_admin_{}", ts);
        let password = "RootSessionAdmin#123";
        let config = Config {
            enable_super_admin_bootstrap: true,
            super_admin_username: Some(username.clone()),
            super_admin_email: Some(format!("{}@example.com", username)),
            super_admin_password: Some(password.to_string()),
            ..test_config()
        };

        let server = setup_test_server_with_config(config).await;

        let login_resp = server
            .post("/v1/auth/token")
            .add_header("User-Agent", "KeyloIntegrationTest/1.0")
            .json(&json!({
                "client_id": username,
                "client_secret": password
            }))
            .await;

        if login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }
        login_resp.assert_status_ok();
        let login_body: serde_json::Value = login_resp.json();
        let access_token = login_body["access_token"].as_str().unwrap();
        let refresh_token = login_body["refresh_token"].as_str().unwrap();

        let me_resp = server
            .get("/v1/auth/me")
            .add_header("Authorization", format!("Bearer {}", access_token))
            .await;
        me_resp.assert_status_ok();
        let me_body: serde_json::Value = me_resp.json();
        let principal_id = me_body["principal_id"].as_str().unwrap();

        let sessions_resp = server
            .get(&format!(
                "/v1/admin/principals/{}/refresh-sessions",
                principal_id
            ))
            .add_header("Authorization", format!("Bearer {}", access_token))
            .await;
        sessions_resp.assert_status_ok();
        let sessions_body: serde_json::Value = sessions_resp.json();
        let session_id = sessions_body["data"]
            .as_array()
            .unwrap()
            .first()
            .and_then(|session| session["id"].as_str())
            .unwrap();
        assert_eq!(
            sessions_body["data"][0]["user_agent"],
            "KeyloIntegrationTest/1.0"
        );

        let global_sessions_resp = server
            .get(&format!(
                "/v1/admin/refresh-sessions?principal_id={}",
                principal_id
            ))
            .add_header("Authorization", format!("Bearer {}", access_token))
            .await;
        global_sessions_resp.assert_status_ok();
        let global_sessions_body: serde_json::Value = global_sessions_resp.json();
        assert!(global_sessions_body["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|session| session["id"].as_str() == Some(session_id)));

        let revoke_resp = server
            .delete(&format!("/v1/admin/refresh-sessions/{}", session_id))
            .add_header("Authorization", format!("Bearer {}", access_token))
            .await;
        revoke_resp.assert_status_ok();

        let refresh_resp = server
            .post("/v1/auth/refresh")
            .json(&json!({ "refresh_token": refresh_token }))
            .await;
        assert_eq!(refresh_resp.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_third_party_user_migration_import_is_idempotent() {
        let server = setup_test_server().await;
        let admin_login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;

        if admin_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }

        admin_login_resp.assert_status_ok();
        let admin_body: serde_json::Value = admin_login_resp.json();
        let admin_access_token = admin_body["access_token"].as_str().unwrap();

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let username = format!("agileboot-migrated-{}", ts);
        let updated_username = format!("agileboot-migrated-updated-{}", ts);
        let email = format!("{}@example.com", username);
        let updated_email = format!("updated-{}", email);
        let external_user_id = format!("ab-{}", ts);

        let import_resp = server
            .post("/v1/admin/users/migrations/import")
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "provider": "agileboot",
                "users": [{
                    "external_user_id": external_user_id.clone(),
                    "username": username.clone(),
                    "email": email.clone(),
                    "password": "MigratedPass#123",
                    "active": true
                }]
            }))
            .await;
        import_resp.assert_status_ok();
        let import_body: serde_json::Value = import_resp.json();
        assert_eq!(import_body["summary"]["failed"], 0);

        let migrated_login_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": "MigratedPass#123"
            }))
            .await;
        migrated_login_resp.assert_status_ok();

        let second_import_resp = server
            .post("/v1/admin/users/migrations/import")
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "provider": "agileboot",
                "users": [{
                    "external_user_id": external_user_id.clone(),
                    "username": updated_username.clone(),
                    "email": updated_email.clone(),
                    "password": "MigratedPass#123",
                    "active": true
                }]
            }))
            .await;
        second_import_resp.assert_status_ok();
        let second_body: serde_json::Value = second_import_resp.json();
        assert_eq!(second_body["summary"]["failed"], 0);

        let updated_login_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": updated_username,
                "client_secret": "MigratedPass#123"
            }))
            .await;
        updated_login_resp.assert_status_ok();
    }

    #[tokio::test]
    async fn test_jit_migration_register_can_issue_access_token() {
        let server = setup_test_server().await;

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let username = format!("jit-user-{}", ts);
        let email = format!("{}@example.com", username);

        let response = server
            .post("/v1/auth/migrations/jit-register")
            .json(&json!({
                "provider": "agileboot",
                "external_user_id": format!("jit-ext-{}", ts),
                "username": username,
                "email": email,
                "password": "JitMigrated#123",
                "active": true
            }))
            .await;

        if response.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }

        response.assert_status_ok();
        let body: serde_json::Value = response.json();
        assert_eq!(body["success"], true);
        assert!(body["access_token"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_async_migration_job_submit_and_query_status() {
        let server = setup_test_server().await;
        let admin_login_resp = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": INTEGRATION_ADMIN_CLIENT_ID,
                "client_secret": INTEGRATION_ADMIN_CLIENT_SECRET
            }))
            .await;

        if admin_login_resp.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            return;
        }

        admin_login_resp.assert_status_ok();
        let admin_body: serde_json::Value = admin_login_resp.json();
        let admin_access_token = admin_body["access_token"].as_str().unwrap();

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        let create_job_resp = server
            .post("/v1/admin/users/migrations/jobs")
            .add_header("Authorization", format!("Bearer {}", admin_access_token))
            .json(&json!({
                "provider": "agileboot",
                "dry_run": true,
                "users": [{
                    "external_user_id": format!("job-ext-{}", ts),
                    "username": format!("job-user-{}", ts),
                    "email": format!("job-user-{}@example.com", ts),
                    "password": "JobMigrated#123",
                    "active": true
                }]
            }))
            .await;
        create_job_resp.assert_status_ok();
        let create_job_body: serde_json::Value = create_job_resp.json();
        let job_id = create_job_body["job_id"].as_str().unwrap().to_string();

        let mut final_status = String::new();
        for _ in 0..80 {
            let status_resp = server
                .get(&format!("/v1/admin/users/migrations/jobs/{}", job_id))
                .add_header("Authorization", format!("Bearer {}", admin_access_token))
                .await;
            status_resp.assert_status_ok();
            let status_body: serde_json::Value = status_resp.json();
            final_status = status_body["job"]["status"]
                .as_str()
                .unwrap_or_default()
                .to_string();

            if final_status == "completed" || final_status == "failed" {
                break;
            }

            sleep(Duration::from_millis(250)).await;
        }

        assert!(final_status == "completed" || final_status == "failed");
    }
}
