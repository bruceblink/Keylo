use crate::config::Config;
use crate::models::Keys;
use crate::models::MigrationBatchJob;
use redis::AsyncCommands;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
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

    /// Redis 客户端（可选）
    pub redis_client: Option<redis::Client>,

    /// 异步迁移任务状态
    pub migration_jobs: Arc<RwLock<HashMap<String, MigrationBatchJob>>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new(Config::default(), None)
    }
}

impl AppState {
    fn redis_key(&self, suffix: &str) -> String {
        format!("{}:{}", self.config.redis_key_prefix, suffix)
    }

    pub fn new(config: Config, db: Option<Arc<PgPool>>) -> Self {
        // 默认客户端，可以替换成从配置文件或数据库加载
        let mut clients = HashMap::new();
        clients.insert("web".into(), "web-secret".into());

        // 默认允许的 audience
        let audiences = vec!["admin-backend".into(), "crawler".into()];
        let redis_client = config
            .redis_url
            .as_deref()
            .and_then(|url| redis::Client::open(url).ok());
        let jwt_keys = Keys::from_config(&config)
            .unwrap_or_else(|err| panic!("Failed to initialize JWT keys: {}", err));

        Self {
            jwt_keys,
            clients: Arc::new(clients),
            audiences: Arc::new(audiences),
            db,
            config: Arc::new(config),
            oauth_states: Arc::new(RwLock::new(HashMap::new())),
            login_attempts: Arc::new(RwLock::new(HashMap::new())),
            auth_rate_limits: Arc::new(RwLock::new(HashMap::new())),
            redis_client,
            migration_jobs: Arc::new(RwLock::new(HashMap::new())),
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
        if let Some(redis_client) = &self.redis_client {
            let ttl = (expires_at - chrono::Utc::now().timestamp()).max(1) as u64;
            if let Ok(mut conn) = redis_client.get_multiplexed_tokio_connection().await {
                let key = format!("oauth:state:{}", state);
                let namespaced_key = self.redis_key(&key);
                if conn
                    .set_ex::<_, _, ()>(&namespaced_key, "1", ttl)
                    .await
                    .is_ok()
                {
                    return;
                }
            }
        }

        let mut states = self.oauth_states.write().await;
        states.insert(state, expires_at);
    }

    pub async fn consume_oauth_state(&self, state: &str) -> bool {
        if let Some(redis_client) = &self.redis_client {
            if let Ok(mut conn) = redis_client.get_multiplexed_tokio_connection().await {
                let key = format!("oauth:state:{}", state);
                let namespaced_key = self.redis_key(&key);
                let existed = conn
                    .exists::<_, bool>(&namespaced_key)
                    .await
                    .unwrap_or(false);
                if existed {
                    let _ = conn.del::<_, i32>(&namespaced_key).await;
                    return true;
                }
                return false;
            }
        }

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
        if let Some(redis_client) = &self.redis_client {
            if let Ok(mut conn) = redis_client.get_multiplexed_tokio_connection().await {
                let key = format!("auth:lock:{}", principal);
                let namespaced_key = self.redis_key(&key);
                if let Ok(Some(locked_until)) = conn.get::<_, Option<i64>>(&namespaced_key).await {
                    let now = chrono::Utc::now().timestamp();
                    if locked_until > now {
                        return Some(locked_until - now);
                    }
                    let _ = conn.del::<_, i32>(&namespaced_key).await;
                    return None;
                }
            }
        }

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
        if let Some(redis_client) = &self.redis_client {
            if let Ok(mut conn) = redis_client.get_multiplexed_tokio_connection().await {
                let now = chrono::Utc::now().timestamp();
                let lock_key = self.redis_key(&format!("auth:lock:{}", principal));
                let fail_key = self.redis_key(&format!("auth:fail:{}", principal));

                if conn.exists::<_, bool>(&lock_key).await.unwrap_or(false) {
                    return;
                }

                let failures = conn.incr::<_, _, i64>(&fail_key, 1).await.unwrap_or(1);
                let _ = conn.expire::<_, bool>(&fail_key, lockout_seconds).await;
                if failures as u32 >= max_failed_attempts {
                    let locked_until = now + lockout_seconds;
                    let _ = conn
                        .set_ex::<_, _, ()>(&lock_key, locked_until, lockout_seconds as u64)
                        .await;
                    let _ = conn.del::<_, i32>(&fail_key).await;
                }
                return;
            }
        }

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
        if let Some(redis_client) = &self.redis_client {
            if let Ok(mut conn) = redis_client.get_multiplexed_tokio_connection().await {
                let fail_key = format!("auth:fail:{}", principal);
                let lock_key = format!("auth:lock:{}", principal);
                let _ = conn.del::<_, i32>(&self.redis_key(&fail_key)).await;
                let _ = conn.del::<_, i32>(&self.redis_key(&lock_key)).await;
                return;
            }
        }

        let mut attempts = self.login_attempts.write().await;
        attempts.remove(principal);
    }

    pub async fn allow_auth_request(
        &self,
        principal: &str,
        window_seconds: i64,
        max_requests: u32,
    ) -> bool {
        if let Some(redis_client) = &self.redis_client {
            if let Ok(mut conn) = redis_client.get_multiplexed_tokio_connection().await {
                let now = chrono::Utc::now().timestamp();
                let bucket = now / window_seconds.max(1);
                let key = format!("auth:rate:{}:{}", principal, bucket);
                let namespaced_key = self.redis_key(&key);
                let count = conn
                    .incr::<_, _, i64>(&namespaced_key, 1)
                    .await
                    .unwrap_or(1);
                if count == 1 {
                    let _ = conn
                        .expire::<_, bool>(&namespaced_key, window_seconds)
                        .await;
                }
                return (count as u32) <= max_requests;
            }
        }

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
