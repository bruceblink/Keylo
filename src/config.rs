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

        let database_url = env::var("DATABASE_URL").unwrap_or_default();

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

    pub fn validate_for_database_startup(&self) -> Result<(), String> {
        let mut errors = Vec::new();

        self.validate_common(&mut errors);
        self.validate_management_client(&mut errors);

        if self.database_url.trim().is_empty() {
            errors.push(
                "DATABASE_URL must be set when starting Keylo with database support".to_string(),
            );
        }

        if self.is_production() && option_is_blank(self.redis_url.as_deref()) {
            errors.push("REDIS_URL must be set in production".to_string());
        }

        config_result(errors)
    }

    pub fn validate_for_in_memory_startup(&self) -> Result<(), String> {
        let mut errors = Vec::new();

        self.validate_common(&mut errors);
        self.validate_management_client(&mut errors);

        if self.is_production() {
            errors.push("ALLOW_IN_MEMORY_FALLBACK cannot be used in production".to_string());
        }

        if !self.allow_in_memory_fallback {
            errors.push(
                "ALLOW_IN_MEMORY_FALLBACK=true is required to start without database support"
                    .to_string(),
            );
        }

        config_result(errors)
    }

    fn validate_management_client(&self, errors: &mut Vec<String>) {
        if option_is_blank(self.admin_client_id.as_deref()) {
            errors.push("ADMIN_CLIENT_ID must be set to seed the management client".to_string());
        }

        if option_is_blank(self.admin_client_secret.as_deref()) {
            errors
                .push("ADMIN_CLIENT_SECRET must be set to seed the management client".to_string());
        }
    }

    fn validate_common(&self, errors: &mut Vec<String>) {
        require_non_empty(errors, "JWT_ISSUER", &self.jwt_issuer);
        require_non_empty(errors, "JWT_KEY_ID", &self.jwt_key_id);

        if self.jwt_private_key_pem.trim().is_empty() {
            errors.push(
                "JWT_PRIVATE_KEY_PEM or JWT_PRIVATE_KEY_PATH must be set to an RSA private key"
                    .to_string(),
            );
        }

        if self.jwt_public_key_pem.trim().is_empty() {
            errors.push(
                "JWT_PUBLIC_KEY_PEM or JWT_PUBLIC_KEY_PATH must be set to an RSA public key"
                    .to_string(),
            );
        }

        require_non_empty(errors, "ENVIRONMENT", &self.environment);
        require_non_empty(errors, "SERVER_ADDR", &self.server_addr);
        require_positive(errors, "SERVER_PORT", self.server_port as i64);
        require_positive(errors, "TOKEN_EXPIRY_SECONDS", self.token_expiry_seconds);
        require_positive(
            errors,
            "REFRESH_TOKEN_EXPIRY_SECONDS",
            self.refresh_token_expiry_seconds,
        );
        require_positive(
            errors,
            "MAX_FAILED_LOGIN_ATTEMPTS",
            self.max_failed_login_attempts as i64,
        );
        require_positive(errors, "LOGIN_LOCKOUT_SECONDS", self.login_lockout_seconds);
        require_positive(
            errors,
            "AUTH_RATE_LIMIT_WINDOW_SECONDS",
            self.auth_rate_limit_window_seconds,
        );
        require_positive(
            errors,
            "AUTH_RATE_LIMIT_MAX_REQUESTS",
            self.auth_rate_limit_max_requests as i64,
        );
        require_positive(
            errors,
            "AUTH_GLOBAL_RATE_LIMIT_MAX_REQUESTS",
            self.auth_global_rate_limit_max_requests as i64,
        );
        require_positive(
            errors,
            "SERVICE_TOKEN_EXPIRY_SECONDS",
            self.service_token_expiry_seconds,
        );
        require_positive(
            errors,
            "AUDIT_LOG_RETENTION_DAYS",
            self.audit_log_retention_days,
        );

        if self.enable_super_admin_bootstrap {
            if option_is_blank(self.super_admin_username.as_deref()) {
                errors.push(
                    "SUPER_ADMIN_USERNAME must be set when ENABLE_SUPER_ADMIN_BOOTSTRAP=true"
                        .to_string(),
                );
            }
            if option_is_blank(self.super_admin_email.as_deref()) {
                errors.push(
                    "SUPER_ADMIN_EMAIL must be set when ENABLE_SUPER_ADMIN_BOOTSTRAP=true"
                        .to_string(),
                );
            }
            if option_is_blank(self.super_admin_password.as_deref()) {
                errors.push(
                    "SUPER_ADMIN_PASSWORD must be set when ENABLE_SUPER_ADMIN_BOOTSTRAP=true"
                        .to_string(),
                );
            }
        }

        if self.log_to_file {
            require_non_empty(errors, "LOG_DIR", &self.log_dir);
            require_non_empty(errors, "LOG_FILE_PREFIX", &self.log_file_prefix);
        }
    }
}

fn require_non_empty(errors: &mut Vec<String>, name: &str, value: &str) {
    if value.trim().is_empty() {
        errors.push(format!("{name} must not be empty"));
    }
}

fn require_positive(errors: &mut Vec<String>, name: &str, value: i64) {
    if value <= 0 {
        errors.push(format!("{name} must be greater than 0"));
    }
}

fn option_is_blank(value: Option<&str>) -> bool {
    value.is_none_or(|value| value.trim().is_empty())
}

fn config_result(errors: Vec<String>) -> Result<(), String> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Invalid startup configuration:\n- {}",
            errors.join("\n- ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> Config {
        Config {
            jwt_issuer: "keylo".to_string(),
            jwt_key_id: "keylo-rs256-1".to_string(),
            jwt_private_key_pem: "private-key".to_string(),
            jwt_public_key_pem: "public-key".to_string(),
            jwt_using_default_dev_keys: false,
            database_url: "postgres://keylo_user:keylo_password@localhost:5432/keylo".to_string(),
            server_addr: "127.0.0.1".to_string(),
            server_port: 2345,
            environment: "development".to_string(),
            token_expiry_seconds: 900,
            refresh_token_expiry_seconds: 2_592_000,
            max_failed_login_attempts: 5,
            login_lockout_seconds: 300,
            auth_rate_limit_window_seconds: 60,
            auth_rate_limit_max_requests: 30,
            auth_global_rate_limit_max_requests: 300,
            trust_proxy_headers: false,
            admin_client_id: Some("cli-admin-root".to_string()),
            admin_client_secret: Some("strong-admin-secret".to_string()),
            redis_url: None,
            redis_key_prefix: "keylo".to_string(),
            audit_log_retention_days: 30,
            service_token_expiry_seconds: 3600,
            enable_super_admin_bootstrap: false,
            super_admin_username: None,
            super_admin_email: None,
            super_admin_password: None,
            log_to_file: false,
            log_dir: "./logs".to_string(),
            log_file_prefix: "keylo".to_string(),
            allow_in_memory_fallback: false,
        }
    }

    #[test]
    fn database_startup_requires_admin_client_credentials() {
        let mut config = valid_config();
        config.admin_client_id = None;
        config.admin_client_secret = None;

        let err = config.validate_for_database_startup().unwrap_err();

        assert!(err.contains("ADMIN_CLIENT_ID"));
        assert!(err.contains("ADMIN_CLIENT_SECRET"));
    }

    #[test]
    fn database_startup_requires_jwt_keys() {
        let mut config = valid_config();
        config.jwt_private_key_pem.clear();
        config.jwt_public_key_pem.clear();

        let err = config.validate_for_database_startup().unwrap_err();

        assert!(err.contains("JWT_PRIVATE_KEY_PEM or JWT_PRIVATE_KEY_PATH"));
        assert!(err.contains("JWT_PUBLIC_KEY_PEM or JWT_PUBLIC_KEY_PATH"));
    }

    #[test]
    fn production_database_startup_requires_redis() {
        let mut config = valid_config();
        config.environment = "production".to_string();
        config.redis_url = None;

        let err = config.validate_for_database_startup().unwrap_err();

        assert!(err.contains("REDIS_URL"));
    }

    #[test]
    fn in_memory_startup_requires_admin_client_credentials() {
        let mut config = valid_config();
        config.allow_in_memory_fallback = true;
        config.admin_client_id = None;
        config.admin_client_secret = None;
        config.database_url.clear();

        let err = config.validate_for_in_memory_startup().unwrap_err();

        assert!(err.contains("ADMIN_CLIENT_ID"));
        assert!(err.contains("ADMIN_CLIENT_SECRET"));
    }

    #[test]
    fn in_memory_startup_is_forbidden_in_production() {
        let mut config = valid_config();
        config.allow_in_memory_fallback = true;
        config.environment = "production".to_string();

        let err = config.validate_for_in_memory_startup().unwrap_err();

        assert!(err.contains("cannot be used in production"));
    }
}
