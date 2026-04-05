use std::env;

/// 应用配置
#[derive(Clone, Debug)]
pub struct Config {
    /// JWT密钥
    pub jwt_secret: String,
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
}

impl Default for Config {
    fn default() -> Self {
        Self::from_env()
    }
}

impl Config {
    pub fn from_env() -> Self {
        let jwt_secret = env::var("JWT_SECRET")
            .unwrap_or_else(|_| "my-jwt-secret-change-in-production".to_string());

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

        Self {
            jwt_secret,
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
