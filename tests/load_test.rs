use axum::http::StatusCode;
use axum_test::TestServer;
use keylo::startup;
use serde_json::json;
use std::time::Instant;
use tokio::time::{timeout, Duration};

#[cfg(test)]
mod load_tests {
    use super::*;

    /// 创建测试服务器
    async fn setup_test_server() -> TestServer {
        let app = startup::init_app_router();
        TestServer::new(app).unwrap()
    }

    #[tokio::test]
    async fn test_basic_load_health_checks() {
        let server = setup_test_server().await;
        let start = Instant::now();

        // 执行多个顺序请求测试基本负载
        for i in 0..50 {
            let response = timeout(
                Duration::from_secs(5),
                server.get("/")
            ).await;

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
        println!("50 health checks completed in {:.2}s", elapsed.as_secs_f64());
        assert!(elapsed < Duration::from_secs(30), "Should complete within 30 seconds");
    }

    #[tokio::test]
    async fn test_error_handling_load() {
        let server = setup_test_server().await;
        let start = Instant::now();

        // 测试错误处理负载
        for i in 0..20 {
            let response = timeout(
                Duration::from_secs(5),
                server
                    .post("/v1/auth/token")
                    .json(&json!({"invalid": "payload"}))
            ).await;

            match response {
                Ok(resp) => {
                    let status = resp.status_code();
                    // 打印实际状态码用于调试
                    println!("Request {} returned status: {}", i, status);
                    // 接受各种错误状态（取决于是否有数据库）
                    assert!(status == StatusCode::BAD_REQUEST ||
                           status == StatusCode::UNAUTHORIZED ||
                           status == StatusCode::INTERNAL_SERVER_ERROR ||
                           status == StatusCode::UNPROCESSABLE_ENTITY);
                }
                Err(_) => panic!("Request {} timeout", i),
            }
        }

        let elapsed = start.elapsed();
        println!("20 error requests completed in {:.2}s", elapsed.as_secs_f64());
        assert!(elapsed < Duration::from_secs(20), "Should complete within 20 seconds");
    }

    #[tokio::test]
    async fn test_mixed_load() {
        let server = setup_test_server().await;
        let start = Instant::now();

        // 混合健康检查和错误请求
        for i in 0..30 {
            if i % 2 == 0 {
                // 健康检查
                let response = timeout(
                    Duration::from_secs(2),
                    server.get("/")
                ).await;

                match response {
                    Ok(resp) => {
                        assert_eq!(resp.status_code(), StatusCode::OK);
                    }
                    Err(_) => panic!("Health check {} timeout", i),
                }
            } else {
                // 错误请求
                let response = timeout(
                    Duration::from_secs(2),
                    server
                        .post("/v1/auth/token")
                        .json(&json!({"invalid": "data"}))
                ).await;

                match response {
                    Ok(resp) => {
                        let status = resp.status_code();
                        assert!(status == StatusCode::BAD_REQUEST ||
                               status == StatusCode::UNAUTHORIZED ||
                               status == StatusCode::INTERNAL_SERVER_ERROR ||
                               status == StatusCode::UNPROCESSABLE_ENTITY);
                    }
                    Err(_) => panic!("Error request {} timeout", i),
                }
            }
        }

        let elapsed = start.elapsed();
        println!("30 mixed requests completed in {:.2}s", elapsed.as_secs_f64());
        assert!(elapsed < Duration::from_secs(15), "Should complete within 15 seconds");
    }
}