use axum::http::StatusCode;
use axum::response::Json;
use chrono::Utc;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// 生成唯一的JWT ID
pub fn generate_jti() -> String {
    Uuid::new_v4().to_string()
}

/// 生成唯一的会话ID
pub fn generate_session_id() -> String {
    Uuid::new_v4().to_string()
}

/// 获取当前时间戳
pub fn now_timestamp() -> i64 {
    Utc::now().timestamp()
}

/// 计算过期时间
pub fn calculate_expiry(seconds_from_now: i64) -> i64 {
    now_timestamp() + seconds_from_now
}

/// 检查token是否过期
pub fn is_token_expired(exp: i64) -> bool {
    now_timestamp() > exp
}

pub type ApiResponse = Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)>;

pub fn require_db(state: &crate::state::AppState) -> Result<&PgPool, (StatusCode, Json<serde_json::Value>)> {
    state.db.as_deref().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": "Database not initialized",
            })),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_jti() {
        let jti = generate_jti();
        assert!(!jti.is_empty());
        assert_eq!(jti.len(), 36); // UUID字符串长度
    }

    #[test]
    fn test_calculate_expiry() {
        let now = now_timestamp();
        let expiry = calculate_expiry(900);
        assert!(expiry > now);
        assert!(expiry - now >= 899 && expiry - now <= 901); // 允许1秒误差
    }

    #[test]
    fn test_is_token_expired() {
        let past = now_timestamp() - 100;
        let future = now_timestamp() + 100;

        assert!(is_token_expired(past));
        assert!(!is_token_expired(future));
    }
}
