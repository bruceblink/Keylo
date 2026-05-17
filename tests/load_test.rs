use axum::http::StatusCode;
use axum_test::TestServer;
use keylo::{config::Config, startup};
use serde_json::json;
use std::time::Instant;
use tokio::time::{timeout, Duration};

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
mod load_tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            jwt_private_key_pem: TEST_JWT_PRIVATE_KEY_PEM.to_string(),
            jwt_public_key_pem: TEST_JWT_PUBLIC_KEY_PEM.to_string(),
            jwt_keys_generated: false,
            enable_setup_wizard: false,
            ..Default::default()
        }
    }

    /// 创建测试服务器
    async fn setup_test_server() -> TestServer {
        let app = startup::init_app_router_with_config(test_config());
        TestServer::new(app)
    }

    #[tokio::test]
    async fn test_basic_load_health_checks() {
        let server = setup_test_server().await;
        let start = Instant::now();

        for i in 0..50 {
            let response = timeout(Duration::from_secs(5), server.get("/")).await;

            match response {
                Ok(resp) => {
                    assert_eq!(resp.status_code(), StatusCode::OK);
                    let body = resp.text();
                    assert_eq!(body, "Welcome to the keylo :)");
                }
                Err(_) => panic!("Request {} timeout", i),
            }
        }

        let elapsed = start.elapsed();
        println!(
            "50 health checks completed in {:.2}s",
            elapsed.as_secs_f64()
        );
        assert!(
            elapsed < Duration::from_secs(30),
            "Should complete within 30 seconds"
        );
    }

    #[tokio::test]
    async fn test_error_handling_load() {
        let server = setup_test_server().await;
        let start = Instant::now();

        for i in 0..20 {
            let response = timeout(
                Duration::from_secs(5),
                server
                    .post("/v1/auth/token")
                    .json(&json!({"invalid": "payload"})),
            )
            .await;

            match response {
                Ok(resp) => {
                    let status = resp.status_code();
                    println!("Request {} returned status: {}", i, status);
                    assert!(
                        status == StatusCode::BAD_REQUEST
                            || status == StatusCode::UNAUTHORIZED
                            || status == StatusCode::INTERNAL_SERVER_ERROR
                            || status == StatusCode::UNPROCESSABLE_ENTITY
                    );
                }
                Err(_) => panic!("Request {} timeout", i),
            }
        }

        let elapsed = start.elapsed();
        println!(
            "20 error requests completed in {:.2}s",
            elapsed.as_secs_f64()
        );
        assert!(
            elapsed < Duration::from_secs(20),
            "Should complete within 20 seconds"
        );
    }

    #[tokio::test]
    async fn test_mixed_load() {
        let server = setup_test_server().await;
        let start = Instant::now();

        for i in 0..30 {
            if i % 2 == 0 {
                let response = timeout(Duration::from_secs(2), server.get("/")).await;

                match response {
                    Ok(resp) => {
                        assert_eq!(resp.status_code(), StatusCode::OK);
                    }
                    Err(_) => panic!("Health check {} timeout", i),
                }
            } else {
                let response = timeout(
                    Duration::from_secs(2),
                    server
                        .post("/v1/auth/token")
                        .json(&json!({"invalid": "data"})),
                )
                .await;

                match response {
                    Ok(resp) => {
                        let status = resp.status_code();
                        assert!(
                            status == StatusCode::BAD_REQUEST
                                || status == StatusCode::UNAUTHORIZED
                                || status == StatusCode::INTERNAL_SERVER_ERROR
                                || status == StatusCode::UNPROCESSABLE_ENTITY
                        );
                    }
                    Err(_) => panic!("Error request {} timeout", i),
                }
            }
        }

        let elapsed = start.elapsed();
        println!(
            "30 mixed requests completed in {:.2}s",
            elapsed.as_secs_f64()
        );
        assert!(
            elapsed < Duration::from_secs(15),
            "Should complete within 15 seconds"
        );
    }
}
