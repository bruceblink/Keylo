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
}
