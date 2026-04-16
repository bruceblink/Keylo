use std::env;
use std::fs;
use std::sync::Once;

static DOTENV_INIT: Once = Once::new();

const DEFAULT_DEV_JWT_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
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

const DEFAULT_DEV_JWT_PUBLIC_KEY_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArK1XQnj3S4ev/F2s5Ofe
w7az0tq0Rxv0/DPZHyHqrl65UWmIcEJBy6BiytD59sAZluRKfNTNwkRwiSc6LKrO
jGC35Nn69CMK2tIgZDUMdr8BFpkmdymeMBhka5UCOOb1zjgANiemtSOiJLfG1fTd
tY0P6WA6SPUshy77x7rWZsmR6dDxhzWop1BHXR7FKj1IMDaQ7AZfr/Xy1TgobAd/
NkU31+bUnfbOyKoRUTpTqFqnWZuvo0cyKbrAmKCnWun8XgTwtNBOXmTbFTwwSmwE
hTqy0z7yJ7nMrODYl2Nt3t1PjomeoUqVsDEsveR0DpFaN+ChhVldGYGgbyu/QIMr
wwIDAQAB
-----END PUBLIC KEY-----"#;

fn read_env_or_file(value_key: &str, path_key: &str, default_value: &str) -> (String, bool) {
    if let Ok(value) = env::var(value_key) {
        if !value.trim().is_empty() {
            return (value, false);
        }
    }

    if let Ok(path) = env::var(path_key) {
        if !path.trim().is_empty() {
            if let Ok(contents) = fs::read_to_string(&path) {
                return (contents, false);
            }
        }
    }

    (default_value.to_string(), true)
}

pub fn load_dotenv() {
    DOTENV_INIT.call_once(|| {
        let _ = dotenvy::dotenv();
    });
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
        let jwt_key_id = env::var("JWT_KEY_ID").unwrap_or_else(|_| "keylo-dev-rs256-1".to_string());
        let (jwt_private_key_pem, private_default) = read_env_or_file(
            "JWT_PRIVATE_KEY_PEM",
            "JWT_PRIVATE_KEY_PATH",
            DEFAULT_DEV_JWT_PRIVATE_KEY_PEM,
        );
        let (jwt_public_key_pem, public_default) = read_env_or_file(
            "JWT_PUBLIC_KEY_PEM",
            "JWT_PUBLIC_KEY_PATH",
            DEFAULT_DEV_JWT_PUBLIC_KEY_PEM,
        );
        let jwt_using_default_dev_keys = private_default && public_default;

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
            redis_url,
            redis_key_prefix,
            audit_log_retention_days,
            service_token_expiry_seconds,
            enable_super_admin_bootstrap,
            super_admin_username,
            super_admin_email,
            super_admin_password,
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
