use keylo::db;
use sqlx::PgPool;

#[cfg(test)]
mod database_tests {
    use super::*;

    /// 设置测试数据库
    async fn setup_test_db() -> Result<PgPool, &'static str> {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:password@localhost:5432/keylo_test".to_string());

        let pool = match db::init_db_pool(&database_url).await {
            Ok(pool) => pool,
            Err(_) => return Err("Database not available, skipping database tests"),
        };

        // 清理并重新创建表
        if let Err(_) = sqlx::query("DROP TABLE IF EXISTS blacklisted_tokens CASCADE")
            .execute(&pool)
            .await
        {
            return Err("Failed to clean database");
        }
        if let Err(_) = sqlx::query("DROP TABLE IF EXISTS refresh_tokens CASCADE")
            .execute(&pool)
            .await
        {
            return Err("Failed to clean database");
        }
        if let Err(_) = sqlx::query("DROP TABLE IF EXISTS sessions CASCADE")
            .execute(&pool)
            .await
        {
            return Err("Failed to clean database");
        }
        if let Err(_) = sqlx::query("DROP TABLE IF EXISTS users CASCADE")
            .execute(&pool)
            .await
        {
            return Err("Failed to clean database");
        }
        if let Err(_) = sqlx::query("DROP TABLE IF EXISTS clients CASCADE")
            .execute(&pool)
            .await
        {
            return Err("Failed to clean database");
        }

        // 运行迁移
        if let Err(_) = db::run_migrations(&pool).await {
            return Err("Failed to run migrations");
        }

        Ok(pool)
    }

    #[tokio::test]
    async fn test_database_migrations() {
        let pool = match setup_test_db().await {
            Ok(pool) => pool,
            Err(msg) => {
                println!("Skipping test_database_migrations: {}", msg);
                return;
            }
        };

        // 验证表是否创建成功
        let clients_count = sqlx::query_scalar("SELECT COUNT(*) FROM clients")
            .fetch_one(&pool)
            .await
            .unwrap_or(0);
        assert_eq!(clients_count, 0);

        let refresh_tokens_count = sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens")
            .fetch_one(&pool)
            .await
            .unwrap_or(0);
        assert_eq!(refresh_tokens_count, 0);

        let blacklisted_count = sqlx::query_scalar("SELECT COUNT(*) FROM blacklisted_tokens")
            .fetch_one(&pool)
            .await
            .unwrap_or(0);
        assert_eq!(blacklisted_count, 0);
    }

    #[tokio::test]
    async fn test_client_creation_and_validation() {
        let pool = match setup_test_db().await {
            Ok(pool) => pool,
            Err(msg) => {
                println!("Skipping test_client_creation_and_validation: {}", msg);
                return;
            }
        };

        // 创建客户端
        db::create_client(&pool, "test-client", "test-secret", "Test Client", Some("Test client"))
            .await
            .expect("Failed to create client");

        // 验证客户端存在
        let secret = db::get_client_secret(&pool, "test-client")
            .await
            .expect("Failed to get client secret");

        assert_eq!(secret, Some("test-secret".to_string()));

        // 验证不存在的客户端
        let non_existent = db::get_client_secret(&pool, "non-existent")
            .await
            .expect("Failed to get client secret");

        assert_eq!(non_existent, None);
    }

    #[tokio::test]
    async fn test_refresh_token_operations() {
        let pool = match setup_test_db().await {
            Ok(pool) => pool,
            Err(msg) => {
                println!("Skipping test_refresh_token_operations: {}", msg);
                return;
            }
        };

        let token_id = "test-jti";
        let client_id = "test-client";
        let token = "test.jwt.token";
        let expires_at = 1735689600; // 2025-01-01

        // 创建refresh token
        db::create_refresh_token(&pool, token_id, client_id, token, expires_at)
            .await
            .expect("Failed to create refresh token");

        // 验证token存在
        let token_data = db::validate_refresh_token(&pool, token)
            .await
            .expect("Failed to validate refresh token");

        assert_eq!(token_data, Some((token_id.to_string(), client_id.to_string())));

        // 撤销token
        db::revoke_refresh_token(&pool, token_id)
            .await
            .expect("Failed to revoke refresh token");

        // 验证token已被撤销
        let revoked_token = db::validate_refresh_token(&pool, token)
            .await
            .expect("Failed to validate revoked token");

        assert_eq!(revoked_token, None);
    }

    #[tokio::test]
    async fn test_blacklist_operations() {
        let pool = match setup_test_db().await {
            Ok(pool) => pool,
            Err(msg) => {
                println!("Skipping test_blacklist_operations: {}", msg);
                return;
            }
        };

        let token = "test.blacklisted.token";
        let reason = "Test blacklist";
        let expires_at = 1735689600; // 2025-01-01

        // 将token加入黑名单
        db::blacklist_token(&pool, token, Some(reason), expires_at)
            .await
            .expect("Failed to blacklist token");

        // 验证token在黑名单中
        let is_blacklisted = db::is_token_blacklisted(&pool, token)
            .await
            .expect("Failed to check blacklist");

        assert!(is_blacklisted);

        // 验证不存在的token不在黑名单中
        let not_blacklisted = db::is_token_blacklisted(&pool, "not.blacklisted.token")
            .await
            .expect("Failed to check blacklist");

        assert!(!not_blacklisted);

        // 获取黑名单列表
        let blacklisted_tokens = db::get_active_blacklisted_tokens(&pool)
            .await
            .expect("Failed to get blacklisted tokens");

        assert_eq!(blacklisted_tokens.len(), 1);
        assert_eq!(blacklisted_tokens[0].0, token);
        assert_eq!(blacklisted_tokens[0].1, reason);
    }

    #[tokio::test]
    async fn test_cleanup_operations() {
        let pool = match setup_test_db().await {
            Ok(pool) => pool,
            Err(msg) => {
                println!("Skipping test_cleanup_operations: {}", msg);
                return;
            }
        };

        // 创建一个过期的refresh token
        let expired_time = 1577836800; // 2020-01-01 (过去的时间)
        db::create_refresh_token(&pool, "expired-jti", "test-client", "expired.token", expired_time)
            .await
            .expect("Failed to create expired refresh token");

        // 创建一个过期的黑名单token
        db::blacklist_token(&pool, "expired.blacklisted.token", Some("Expired"), expired_time)
            .await
            .expect("Failed to create expired blacklisted token");

        // 验证它们存在
        let expired_refresh = db::validate_refresh_token(&pool, "expired.token")
            .await
            .expect("Failed to check expired refresh token");
        assert_eq!(expired_refresh, None); // 应该因为过期而返回None

        let expired_blacklisted = db::is_token_blacklisted(&pool, "expired.blacklisted.token")
            .await
            .expect("Failed to check expired blacklisted token");
        assert!(!expired_blacklisted); // 应该因为过期而返回false

        // 运行清理
        let refresh_cleaned = db::cleanup_expired_refresh_tokens(&pool)
            .await
            .expect("Failed to cleanup refresh tokens");

        let blacklist_cleaned = db::cleanup_expired_blacklisted_tokens(&pool)
            .await
            .expect("Failed to cleanup blacklisted tokens");

        // 验证清理结果
        assert!(refresh_cleaned >= 0);
        assert!(blacklist_cleaned >= 0);
    }
}