use crate::config::Config;
use crate::models::Keys;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AppState {
    /// JWT 签名和验证 key
    pub jwt_keys: Keys,

    /// 客户端 ID -> client_secret 的映射
    pub clients: Arc<HashMap<String, String>>,

    /// 可选：受信任的 JWT audience 白名单
    pub audiences: Arc<Vec<String>>,

    /// 数据库连接池
    pub db: Option<Arc<PgPool>>,

    /// 应用配置
    pub config: Arc<Config>,

    /// OAuth state 临时存储（用于防止 CSRF/replay）
    pub oauth_states: Arc<RwLock<HashMap<String, i64>>>,

    /// 登录失败记录：client_id/username -> (failed_count, locked_until_unix_ts)
    pub login_attempts: Arc<RwLock<HashMap<String, (u32, i64)>>>,

    /// 认证接口频率限制记录：principal -> timestamps(unix)
    pub auth_rate_limits: Arc<RwLock<HashMap<String, Vec<i64>>>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new(Config::default(), None)
    }
}

pub static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    // 从环境变量读取 JWT secret
    let secret = std::env::var("JWT_SECRET").unwrap_or("my-jwt-secret".to_string());
    Keys::new(secret.as_bytes())
});

impl AppState {
    pub fn new(config: Config, db: Option<Arc<PgPool>>) -> Self {
        // 默认客户端，可以替换成从配置文件或数据库加载
        let mut clients = HashMap::new();
        clients.insert("web".into(), "web-secret".into());
        clients.insert("cli".into(), "cli-secret".into());

        // 默认允许的 audience
        let audiences = vec!["admin-backend".into(), "crawler".into()];

        Self {
            jwt_keys: KEYS.clone(),
            clients: Arc::new(clients),
            audiences: Arc::new(audiences),
            db,
            config: Arc::new(config),
            oauth_states: Arc::new(RwLock::new(HashMap::new())),
            login_attempts: Arc::new(RwLock::new(HashMap::new())),
            auth_rate_limits: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 校验 client_id + secret 是否存在
    pub fn validate_client(&self, client_id: &str, client_secret: &str) -> bool {
        self.clients
            .get(client_id)
            .is_some_and(|secret| secret == client_secret)
    }

    /// 获取动态的允许 audience
    pub fn allowed_audiences(&self) -> Vec<&str> {
        self.audiences.iter().map(|s| s.as_str()).collect()
    }

    /// 从数据库重新加载客户端列表
    pub async fn reload_clients_from_db(&mut self) -> Result<(), String> {
        if let Some(db) = &self.db {
            match crate::db::get_all_active_clients(db).await {
                Ok(clients) => {
                    let mut client_map = HashMap::new();
                    for (id, secret) in clients {
                        client_map.insert(id, secret);
                    }
                    self.clients = Arc::new(client_map);
                    Ok(())
                }
                Err(e) => Err(e.to_string()),
            }
        } else {
            Err("Database not initialized".to_string())
        }
    }

    pub async fn store_oauth_state(&self, state: String, expires_at: i64) {
        let mut states = self.oauth_states.write().await;
        states.insert(state, expires_at);
    }

    pub async fn consume_oauth_state(&self, state: &str) -> bool {
        let now = chrono::Utc::now().timestamp();
        let mut states = self.oauth_states.write().await;

        // 清理过期 state
        states.retain(|_, exp| *exp > now);

        match states.get(state).copied() {
            Some(exp) if exp > now => {
                states.remove(state);
                true
            }
            _ => false,
        }
    }

    pub async fn is_login_locked(&self, principal: &str) -> Option<i64> {
        let now = chrono::Utc::now().timestamp();
        let mut attempts = self.login_attempts.write().await;

        // 清理过期且无失败计数的记录
        attempts.retain(|_, (count, locked_until)| *locked_until > now || *count > 0);

        match attempts.get(principal).copied() {
            Some((_, locked_until)) if locked_until > now => Some(locked_until - now),
            Some((_, locked_until)) if locked_until <= now && locked_until > 0 => {
                attempts.remove(principal);
                None
            }
            _ => None,
        }
    }

    pub async fn record_login_failure(
        &self,
        principal: &str,
        max_failed_attempts: u32,
        lockout_seconds: i64,
    ) {
        let now = chrono::Utc::now().timestamp();
        let mut attempts = self.login_attempts.write().await;

        let entry = attempts.entry(principal.to_string()).or_insert((0, 0));

        // 仍在锁定中，不重复累计
        if entry.1 > now {
            return;
        }

        entry.0 += 1;
        if entry.0 >= max_failed_attempts {
            entry.0 = 0;
            entry.1 = now + lockout_seconds;
        }
    }

    pub async fn clear_login_failures(&self, principal: &str) {
        let mut attempts = self.login_attempts.write().await;
        attempts.remove(principal);
    }

    pub async fn allow_auth_request(
        &self,
        principal: &str,
        window_seconds: i64,
        max_requests: u32,
    ) -> bool {
        let now = chrono::Utc::now().timestamp();
        let threshold = now - window_seconds;
        let mut limits = self.auth_rate_limits.write().await;

        let entries = limits.entry(principal.to_string()).or_default();
        entries.retain(|ts| *ts > threshold);

        if entries.len() as u32 >= max_requests {
            return false;
        }

        entries.push(now);
        true
    }
}
