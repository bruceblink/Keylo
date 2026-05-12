use std::env;
use std::fs;
use std::io;
use std::sync::Once;

static DOTENV_INIT: Once = Once::new();

fn read_env_or_file(value_key: &str, path_key: &str) -> Option<String> {
    if let Ok(value) = env::var(value_key) {
        if !value.trim().is_empty() {
            return Some(value);
        }
    }

    if let Ok(path) = env::var(path_key) {
        if !path.trim().is_empty() {
            if let Ok(contents) = fs::read_to_string(&path) {
                if !contents.trim().is_empty() {
                    return Some(contents);
                }
            }
        }
    }

    None
}

pub fn load_dotenv() {
    DOTENV_INIT.call_once(|| {
        if let Err(err) = dotenvy::dotenv() {
            match &err {
                dotenvy::Error::Io(io_err) if io_err.kind() == io::ErrorKind::NotFound => {}
                _ => panic!("Failed to load .env: {err}"),
            }
        }
    });
}

fn dotenv_value(key: &str) -> Option<String> {
    let iter = match dotenvy::dotenv_iter() {
        Ok(iter) => iter,
        Err(dotenvy::Error::Io(err)) if err.kind() == io::ErrorKind::NotFound => return None,
        Err(err) => panic!("Failed to read .env: {err}"),
    };

    for item in iter {
        let (dotenv_key, value) = item.unwrap_or_else(|err| panic!("Failed to parse .env: {err}"));
        if dotenv_key == key {
            return Some(value);
        }
    }

    None
}

fn env_non_empty_or_dotenv(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| dotenv_value(key).filter(|value| !value.trim().is_empty()))
}

/// 应用配置
#[derive(Clone, Debug)]
pub struct Config {
    /// JWT Issuer
    pub jwt_issuer: String,
    /// JWT Key ID
    pub jwt_key_id: String,
    /// JWT 私钥 PEM（RS256）
    pub jwt_private_key_pem: String,
    /// JWT 公钥 PEM（RS256）
    pub jwt_public_key_pem: String,
    /// 是否正在使用内置开发密钥
    pub jwt_using_default_dev_keys: bool,
    /// 数据库URL
    pub database_url: String,
    /// 服务监听地址
    pub server_addr: String,
    /// 服务监听端口
    pub server_port: u16,
    /// 环境
    pub environment: String,
    /// JWT token过期时间（秒）
    pub token_expiry_seconds: i64,
    /// 刷新token过期时间（秒）
    pub refresh_token_expiry_seconds: i64,
    /// 连续登录失败次数阈值
    pub max_failed_login_attempts: u32,
    /// 登录锁定时长（秒）
    pub login_lockout_seconds: i64,
    /// 认证接口限流窗口（秒）
    pub auth_rate_limit_window_seconds: i64,
    /// 认证接口限流窗口内最大请求数
    pub auth_rate_limit_max_requests: u32,
    /// 全局认证接口限流窗口内最大请求数
    pub auth_global_rate_limit_max_requests: u32,
    /// 是否信任代理转发头（X-Forwarded-For/X-Real-IP）
    pub trust_proxy_headers: bool,
    /// Admin client ID seeded at startup when both ID and secret are configured.
    pub admin_client_id: Option<String>,
    /// Admin client secret seeded at startup when both ID and secret are configured.
    pub admin_client_secret: Option<String>,
    /// Redis URL（可选，配置后用于分布式状态存储）
    pub redis_url: Option<String>,
    /// Redis key 前缀（用于多环境隔离）
    pub redis_key_prefix: String,
    /// 审计日志保留天数
    pub audit_log_retention_days: i64,
    /// 服务间鉴权 Token 过期时间（秒），默认 3600（1 小时）
    pub service_token_expiry_seconds: i64,
    /// 是否启用超级管理员初始化引导
    pub enable_super_admin_bootstrap: bool,
    /// 超级管理员用户名
    pub super_admin_username: Option<String>,
    /// 超级管理员邮箱
    pub super_admin_email: Option<String>,
    /// 超级管理员初始密码
    pub super_admin_password: Option<String>,
    /// 是否同时输出日志到文件
    pub log_to_file: bool,
    /// 日志目录
    pub log_dir: String,
    /// 日志文件名前缀
    pub log_file_prefix: String,
    /// Allow non-production startup to fall back to a no-database router.
    pub allow_in_memory_fallback: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self::from_env()
    }
}

impl Config {
    pub fn from_env() -> Self {
        load_dotenv();

        let jwt_issuer = env::var("JWT_ISSUER").unwrap_or_else(|_| "keylo".to_string());
        let jwt_key_id = env::var("JWT_KEY_ID").unwrap_or_else(|_| "keylo-rs256-1".to_string());
        let jwt_private_key_pem =
            read_env_or_file("JWT_PRIVATE_KEY_PEM", "JWT_PRIVATE_KEY_PATH").unwrap_or_default();
        let jwt_public_key_pem =
            read_env_or_file("JWT_PUBLIC_KEY_PEM", "JWT_PUBLIC_KEY_PATH").unwrap_or_default();
        let jwt_using_default_dev_keys = false;

        let database_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://user:password@localhost:5432/keylo".to_string());

        let server_addr = env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());

        let server_port = env::var("SERVER_PORT")
            .unwrap_or_else(|_| "2345".to_string())
            .parse::<u16>()
            .unwrap_or(2345);

        let environment = env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());

        let token_expiry_seconds = env::var("TOKEN_EXPIRY_SECONDS")
            .unwrap_or_else(|_| "900".to_string()) // 15 minutes
            .parse::<i64>()
            .unwrap_or(900);

        let refresh_token_expiry_seconds = env::var("REFRESH_TOKEN_EXPIRY_SECONDS")
            .unwrap_or_else(|_| "2592000".to_string()) // 30 days
            .parse::<i64>()
            .unwrap_or(2592000);

        let max_failed_login_attempts = env::var("MAX_FAILED_LOGIN_ATTEMPTS")
            .unwrap_or_else(|_| "5".to_string())
            .parse::<u32>()
            .unwrap_or(5);

        let login_lockout_seconds = env::var("LOGIN_LOCKOUT_SECONDS")
            .unwrap_or_else(|_| "300".to_string())
            .parse::<i64>()
            .unwrap_or(300);

        let auth_rate_limit_window_seconds = env::var("AUTH_RATE_LIMIT_WINDOW_SECONDS")
            .unwrap_or_else(|_| "60".to_string())
            .parse::<i64>()
            .unwrap_or(60);

        let auth_rate_limit_max_requests = env::var("AUTH_RATE_LIMIT_MAX_REQUESTS")
            .unwrap_or_else(|_| "30".to_string())
            .parse::<u32>()
            .unwrap_or(30);

        let auth_global_rate_limit_max_requests = env::var("AUTH_GLOBAL_RATE_LIMIT_MAX_REQUESTS")
            .unwrap_or_else(|_| "300".to_string())
            .parse::<u32>()
            .unwrap_or(300);

        let trust_proxy_headers = env::var("TRUST_PROXY_HEADERS")
            .ok()
            .map(|value| matches!(value.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);

        let admin_client_id = env_non_empty_or_dotenv("ADMIN_CLIENT_ID");
        let admin_client_secret = env_non_empty_or_dotenv("ADMIN_CLIENT_SECRET");

        let redis_url = env::var("REDIS_URL").ok();
        let redis_key_prefix = env::var("REDIS_KEY_PREFIX").unwrap_or_else(|_| "keylo".into());

        let audit_log_retention_days = env::var("AUDIT_LOG_RETENTION_DAYS")
            .unwrap_or_else(|_| "30".to_string())
            .parse::<i64>()
            .unwrap_or(30);

        let service_token_expiry_seconds = env::var("SERVICE_TOKEN_EXPIRY_SECONDS")
            .unwrap_or_else(|_| "3600".to_string()) // 1 hour
            .parse::<i64>()
            .unwrap_or(3600);

        let enable_super_admin_bootstrap = env::var("ENABLE_SUPER_ADMIN_BOOTSTRAP")
            .ok()
            .map(|value| matches!(value.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);

        let super_admin_username = env::var("SUPER_ADMIN_USERNAME").ok();
        let super_admin_email = env::var("SUPER_ADMIN_EMAIL").ok();
        let super_admin_password = env::var("SUPER_ADMIN_PASSWORD").ok();

        let log_to_file = env::var("LOG_TO_FILE")
            .ok()
            .map(|value| matches!(value.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(true);
        let log_dir = env::var("LOG_DIR").unwrap_or_else(|_| "./logs".to_string());
        let log_file_prefix = env::var("LOG_FILE_PREFIX").unwrap_or_else(|_| "keylo".to_string());
        let allow_in_memory_fallback = env::var("ALLOW_IN_MEMORY_FALLBACK")
            .ok()
            .map(|value| matches!(value.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);

        Self {
            jwt_issuer,
            jwt_key_id,
            jwt_private_key_pem,
            jwt_public_key_pem,
            jwt_using_default_dev_keys,
            database_url,
            server_addr,
            server_port,
            environment,
            token_expiry_seconds,
            refresh_token_expiry_seconds,
            max_failed_login_attempts,
            login_lockout_seconds,
            auth_rate_limit_window_seconds,
            auth_rate_limit_max_requests,
            auth_global_rate_limit_max_requests,
            trust_proxy_headers,
            admin_client_id,
            admin_client_secret,
            redis_url,
            redis_key_prefix,
            audit_log_retention_days,
            service_token_expiry_seconds,
            enable_super_admin_bootstrap,
            super_admin_username,
            super_admin_email,
            super_admin_password,
            log_to_file,
            log_dir,
            log_file_prefix,
            allow_in_memory_fallback,
        }
    }

    /// 获取完整的服务器地址
    pub fn server_url(&self) -> String {
        format!("http://{}:{}", self.server_addr, self.server_port)
    }

    /// 判断是否生产环境
    pub fn is_production(&self) -> bool {
        self.environment.to_lowercase() == "production"
    }
}
