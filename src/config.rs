use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::rand_core::OsRng;
use rsa::RsaPrivateKey;
use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::Once;
use urlencoding::encode;

static DOTENV_INIT: Once = Once::new();

const DEFAULT_JWT_ISSUER: &str = "keylo";
const DEFAULT_JWT_KEY_ID: &str = "keylo-rs256-1";
const DEFAULT_JWT_AUDIENCES: &str = "admin-backend,crawler";
const DEFAULT_CORS_ALLOWED_ORIGINS: &str =
    "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173";
const DEFAULT_ADMIN_CLIENT_ID: &str = "cli-admin-root";
const DEFAULT_JWT_PRIVATE_KEY_PATH: &str = "./keys/private.pem";
const DEFAULT_JWT_PUBLIC_KEY_PATH: &str = "./keys/public.pem";
const DEFAULT_DATABASE_PASSWORD_ENC_PATHS: [&str; 3] = [
    "./secrets/postgres_password.enc",
    "/run/secrets/postgres_password_enc",
    "/run/secrets/postgres_password.enc",
];
const DEFAULT_DATABASE_PASSWORD_KEY_PATHS: [&str; 3] = [
    "./secrets/database_password.key",
    "/run/secrets/database_password_key",
    "/run/secrets/database_password.key",
];

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

fn read_first_existing_file(paths: &[&str]) -> Option<String> {
    paths.iter().find_map(|path| {
        fs::read_to_string(path)
            .ok()
            .filter(|contents| !contents.trim().is_empty())
    })
}

fn any_default_file_exists(paths: &[&str]) -> bool {
    paths.iter().any(|path| {
        fs::metadata(path)
            .map(|metadata| metadata.is_file() && metadata.len() > 0)
            .unwrap_or(false)
    })
}

fn read_env_or_file_with_default_path(
    value_key: &str,
    path_key: &str,
    default_path: &str,
) -> Option<String> {
    read_env_or_file(value_key, path_key).or_else(|| read_first_existing_file(&[default_path]))
}

fn env_or_default_path(path_key: &str, default_path: &str) -> String {
    env::var(path_key)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default_path.to_string())
}

fn generate_and_store_rsa_key_pair(
    private_key_path: &str,
    public_key_path: &str,
) -> Result<(String, String), String> {
    let private_path = Path::new(private_key_path);
    let public_path = Path::new(public_key_path);

    if let Some(parent) = private_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "Failed to create JWT private key directory '{}': {err}",
                parent.display()
            )
        })?;
    }
    if let Some(parent) = public_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "Failed to create JWT public key directory '{}': {err}",
                parent.display()
            )
        })?;
    }

    let private_key = RsaPrivateKey::new(&mut OsRng, 2048)
        .map_err(|err| format!("Failed to generate RSA private key: {err}"))?;
    let public_key = private_key.to_public_key();
    let private_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|err| format!("Failed to encode RSA private key: {err}"))?
        .to_string();
    let public_pem = public_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|err| format!("Failed to encode RSA public key: {err}"))?;

    fs::write(private_path, private_pem.as_bytes()).map_err(|err| {
        format!(
            "Failed to write JWT private key '{}': {err}",
            private_path.display()
        )
    })?;
    fs::write(public_path, public_pem.as_bytes()).map_err(|err| {
        format!(
            "Failed to write JWT public key '{}': {err}",
            public_path.display()
        )
    })?;

    Ok((private_pem, public_pem))
}

fn load_or_generate_jwt_keys() -> (String, String, bool) {
    let private_key = read_env_or_file_with_default_path(
        "JWT_PRIVATE_KEY_PEM",
        "JWT_PRIVATE_KEY_PATH",
        DEFAULT_JWT_PRIVATE_KEY_PATH,
    );
    let public_key = read_env_or_file_with_default_path(
        "JWT_PUBLIC_KEY_PEM",
        "JWT_PUBLIC_KEY_PATH",
        DEFAULT_JWT_PUBLIC_KEY_PATH,
    );

    match (private_key, public_key) {
        (Some(private_key), Some(public_key)) => (private_key, public_key, false),
        (Some(_), None) => {
            panic!("JWT private key is configured but JWT public key is missing")
        }
        (None, Some(_)) => panic!("JWT public key is configured but JWT private key is missing"),
        (None, None) => {
            let private_key_path =
                env_or_default_path("JWT_PRIVATE_KEY_PATH", DEFAULT_JWT_PRIVATE_KEY_PATH);
            let public_key_path =
                env_or_default_path("JWT_PUBLIC_KEY_PATH", DEFAULT_JWT_PUBLIC_KEY_PATH);
            let (private_key, public_key) =
                generate_and_store_rsa_key_pair(&private_key_path, &public_key_path)
                    .unwrap_or_else(|err| panic!("{err}"));
            (private_key, public_key, true)
        }
    }
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

fn default_admin_client_id() -> String {
    DEFAULT_ADMIN_CLIENT_ID.to_string()
}

pub fn build_database_url(base_url: String, password: Option<String>) -> String {
    let Some(password) = password else {
        return base_url;
    };

    let password = password.trim();
    if password.is_empty() {
        return base_url;
    }

    let Some((scheme, rest)) = base_url.split_once("://") else {
        return base_url;
    };
    let Some((userinfo, host_and_path)) = rest.split_once('@') else {
        return base_url;
    };
    if userinfo.contains(':') {
        return base_url;
    }

    format!(
        "{}://{}:{}@{}",
        scheme,
        userinfo,
        encode(password),
        host_and_path
    )
}

fn parse_csv_env(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

fn default_cors_allowed_origins() -> Vec<String> {
    parse_csv_env(DEFAULT_CORS_ALLOWED_ORIGINS)
}

fn parse_cors_origins(value: &str) -> Vec<String> {
    parse_csv_env(value)
        .into_iter()
        .map(|origin| origin.trim_end_matches('/').to_string())
        .collect()
}

pub fn database_password_from_env_result() -> Result<Option<String>, String> {
    let encrypted_password =
        read_env_or_file("DATABASE_PASSWORD_ENC", "DATABASE_PASSWORD_ENC_FILE")
            .or_else(|| read_first_existing_file(&DEFAULT_DATABASE_PASSWORD_ENC_PATHS));
    if let Some(encrypted_password) = encrypted_password {
        let key = read_env_or_file("DATABASE_PASSWORD_KEY", "DATABASE_PASSWORD_KEY_FILE")
            .or_else(|| read_first_existing_file(&DEFAULT_DATABASE_PASSWORD_KEY_PATHS))
            .ok_or_else(|| {
                "DATABASE_PASSWORD_KEY or DATABASE_PASSWORD_KEY_FILE must be set when using encrypted database password"
                    .to_string()
            })?;
        return decrypt_database_password(&encrypted_password, &key).map(Some);
    }

    Ok(read_env_or_file(
        "DATABASE_PASSWORD",
        "DATABASE_PASSWORD_FILE",
    ))
}

pub fn database_password_source_is_plaintext() -> bool {
    env_value_is_non_empty("DATABASE_PASSWORD") || env_value_is_non_empty("DATABASE_PASSWORD_FILE")
}

pub fn database_password_source_is_encrypted() -> bool {
    env_value_is_non_empty("DATABASE_PASSWORD_ENC")
        || env_value_is_non_empty("DATABASE_PASSWORD_ENC_FILE")
        || any_default_file_exists(&DEFAULT_DATABASE_PASSWORD_ENC_PATHS)
}

pub fn configured_database_url_contains_password() -> bool {
    env::var("DATABASE_URL")
        .ok()
        .is_some_and(|url| database_url_contains_password(&url))
}

pub fn decrypt_database_password(encrypted: &str, key: &str) -> Result<String, String> {
    let encrypted = encrypted.trim();
    let parts = encrypted.split(':').collect::<Vec<_>>();
    if parts.len() != 5 || parts[0] != "secret" || parts[1] != "v1" || parts[2] != "aes-256-gcm" {
        return Err(
            "DATABASE_PASSWORD_ENC must use format secret:v1:aes-256-gcm:<nonce_base64>:<ciphertext_base64>"
                .to_string(),
        );
    }

    let nonce = BASE64
        .decode(parts[3])
        .map_err(|err| format!("Invalid DATABASE_PASSWORD_ENC nonce: {err}"))?;
    if nonce.len() != 12 {
        return Err("DATABASE_PASSWORD_ENC nonce must decode to 12 bytes".to_string());
    }

    let ciphertext = BASE64
        .decode(parts[4])
        .map_err(|err| format!("Invalid DATABASE_PASSWORD_ENC ciphertext: {err}"))?;
    let key = decode_database_password_key(key)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| "DATABASE_PASSWORD_KEY must decode to 32 bytes".to_string())?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| "Failed to decrypt DATABASE_PASSWORD_ENC".to_string())?;

    String::from_utf8(plaintext)
        .map_err(|_| "DATABASE_PASSWORD_ENC decrypted to non-UTF-8 data".to_string())
}

fn decode_database_password_key(key: &str) -> Result<Vec<u8>, String> {
    let key = key.trim();
    if let Ok(decoded) = BASE64.decode(key) {
        if decoded.len() == 32 {
            return Ok(decoded);
        }
    }

    let raw = key.as_bytes().to_vec();
    if raw.len() == 32 {
        return Ok(raw);
    }

    Err("DATABASE_PASSWORD_KEY must be 32 bytes or base64-encoded 32 bytes".to_string())
}

/// 应用配置
#[derive(Clone, Debug)]
pub struct Config {
    /// JWT Issuer
    pub jwt_issuer: String,
    /// JWT Key ID
    pub jwt_key_id: String,
    /// JWT audiences accepted for user/admin access tokens
    pub jwt_audiences: Vec<String>,
    /// JWT 私钥 PEM（RS256）
    pub jwt_private_key_pem: String,
    /// JWT 公钥 PEM（RS256）
    pub jwt_public_key_pem: String,
    /// Whether JWT key files were generated during startup because no key config was found.
    pub jwt_keys_generated: bool,
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
    /// Allowed browser origins for credentialed CORS requests.
    pub cors_allowed_origins: Vec<String>,
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
    /// Enable first-run setup wizard routes.
    pub enable_setup_wizard: bool,
    /// Bearer token required by setup APIs. Required in production when setup wizard is enabled.
    pub setup_token: Option<String>,
    /// Directory where setup wizard can generate RSA key files.
    pub setup_keys_dir: String,
}

impl Default for Config {
    fn default() -> Self {
        Self::from_env()
    }
}

impl Config {
    pub fn from_env() -> Self {
        load_dotenv();

        let jwt_issuer = env::var("JWT_ISSUER").unwrap_or_else(|_| DEFAULT_JWT_ISSUER.to_string());
        let jwt_key_id = env::var("JWT_KEY_ID").unwrap_or_else(|_| DEFAULT_JWT_KEY_ID.to_string());
        let jwt_audiences = parse_csv_env(
            &env::var("JWT_AUDIENCES").unwrap_or_else(|_| DEFAULT_JWT_AUDIENCES.to_string()),
        );
        let (jwt_private_key_pem, jwt_public_key_pem, jwt_keys_generated) =
            load_or_generate_jwt_keys();

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
        let cors_allowed_origins = env::var("CORS_ALLOWED_ORIGINS").map_or_else(
            |_| default_cors_allowed_origins(),
            |value| parse_cors_origins(&value),
        );

        let admin_client_id =
            env_non_empty_or_dotenv("ADMIN_CLIENT_ID").or_else(|| Some(default_admin_client_id()));
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
        let enable_setup_wizard = env::var("ENABLE_SETUP_WIZARD")
            .ok()
            .map(|value| matches!(value.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(true);
        let setup_token = env_non_empty_or_dotenv("SETUP_TOKEN");
        let setup_keys_dir = env::var("SETUP_KEYS_DIR").unwrap_or_else(|_| "./keys".to_string());

        Self {
            jwt_issuer,
            jwt_key_id,
            jwt_audiences,
            jwt_private_key_pem,
            jwt_public_key_pem,
            jwt_keys_generated,
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
            cors_allowed_origins,
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
            enable_setup_wizard,
            setup_token,
            setup_keys_dir,
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

        if self.is_production() {
            if database_password_source_is_plaintext() {
                errors.push(
                    "DATABASE_PASSWORD/DATABASE_PASSWORD_FILE cannot be used in production; use DATABASE_PASSWORD_ENC or DATABASE_PASSWORD_ENC_FILE"
                        .to_string(),
                );
            }

            if configured_database_url_contains_password()
                || (!database_password_source_is_encrypted()
                    && database_url_contains_password(&self.database_url))
            {
                errors.push(
                    "DATABASE_URL must not contain a plaintext password in production; use DATABASE_PASSWORD_ENC or DATABASE_PASSWORD_ENC_FILE"
                        .to_string(),
                );
            }
        }

        if self.is_production() && option_is_blank(self.redis_url.as_deref()) {
            errors.push("REDIS_URL must be set in production".to_string());
        }

        self.validate_setup_wizard(&mut errors);

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

        self.validate_setup_wizard(&mut errors);

        config_result(errors)
    }

    fn validate_setup_wizard(&self, errors: &mut Vec<String>) {
        if !self.enable_setup_wizard {
            return;
        }

        if self.is_production() && option_is_blank(self.setup_token.as_deref()) {
            errors.push(
                "SETUP_TOKEN must be set when ENABLE_SETUP_WIZARD=true in production".to_string(),
            );
        }

        if self.setup_keys_dir.trim().is_empty() {
            errors.push("SETUP_KEYS_DIR must not be empty".to_string());
        }
    }

    fn validate_management_client(&self, errors: &mut Vec<String>) {
        if option_is_blank(self.admin_client_id.as_deref()) {
            errors.push("ADMIN_CLIENT_ID must not be empty".to_string());
        }

        if option_is_blank(self.admin_client_secret.as_deref()) {
            errors
                .push("ADMIN_CLIENT_SECRET must be set to seed the management client".to_string());
        }
    }

    fn validate_common(&self, errors: &mut Vec<String>) {
        require_non_empty(errors, "JWT_ISSUER", &self.jwt_issuer);
        require_non_empty(errors, "JWT_KEY_ID", &self.jwt_key_id);
        if self.jwt_audiences.is_empty() {
            errors.push("JWT_AUDIENCES must include at least one audience".to_string());
        }
        if self.cors_allowed_origins.is_empty() {
            errors.push("CORS_ALLOWED_ORIGINS must include at least one origin".to_string());
        }
        for origin in &self.cors_allowed_origins {
            if !valid_cors_origin(origin) {
                errors.push(format!(
                    "CORS_ALLOWED_ORIGINS contains invalid origin '{}'",
                    origin
                ));
            }
        }

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

fn database_url_contains_password(database_url: &str) -> bool {
    let Some((_, rest)) = database_url.split_once("://") else {
        return false;
    };
    let Some((userinfo, _)) = rest.split_once('@') else {
        return false;
    };
    userinfo.contains(':')
}

fn valid_cors_origin(origin: &str) -> bool {
    let Ok(uri) = origin.parse::<http::Uri>() else {
        return false;
    };

    matches!(uri.scheme_str(), Some("http" | "https"))
        && uri.host().is_some()
        && uri
            .path_and_query()
            .is_none_or(|path_and_query| path_and_query.as_str() == "/")
}

fn env_value_is_non_empty(key: &str) -> bool {
    env::var(key)
        .ok()
        .is_some_and(|value| !value.trim().is_empty())
        || dotenv_value(key).is_some_and(|value| !value.trim().is_empty())
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
            jwt_audiences: vec!["admin-backend".to_string(), "crawler".to_string()],
            jwt_private_key_pem: "private-key".to_string(),
            jwt_public_key_pem: "public-key".to_string(),
            jwt_keys_generated: false,
            database_url: "postgres://keylo_user@localhost:5432/keylo".to_string(),
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
            cors_allowed_origins: default_cors_allowed_origins(),
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
            enable_setup_wizard: true,
            setup_token: None,
            setup_keys_dir: "./keys".to_string(),
        }
    }

    #[test]
    fn database_password_file_can_complete_passwordless_url() {
        let url = build_database_url(
            "postgres://keylo_user@postgres:5432/keylo".to_string(),
            Some("<encoded-secret>".to_string()),
        );

        assert!(url.starts_with("postgres://keylo_user:"));
        assert!(url.contains("%3Cencoded-secret%3E"));
        assert!(url.ends_with("@postgres:5432/keylo"));
    }

    #[test]
    fn explicit_database_url_password_is_preserved() {
        let url_with_password = format!(
            "{}{}{}",
            "postgres://keylo_user:", "<existing-secret>", "@postgres:5432/keylo"
        );
        let url = build_database_url(url_with_password.clone(), Some("ignored".to_string()));

        assert_eq!(url, url_with_password);
    }

    #[test]
    fn generated_jwt_key_files_are_valid_and_reused() {
        let temp_root = std::env::temp_dir().join(format!(
            "keylo-test-keys-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ));
        let private_path = temp_root.join("private.pem");
        let public_path = temp_root.join("public.pem");

        let (private_key, public_key) = generate_and_store_rsa_key_pair(
            private_path.to_str().unwrap(),
            public_path.to_str().unwrap(),
        )
        .unwrap();

        assert!(private_key.contains("BEGIN PRIVATE KEY"));
        assert!(public_key.contains("BEGIN PUBLIC KEY"));
        assert_eq!(fs::read_to_string(&private_path).unwrap(), private_key);
        assert_eq!(fs::read_to_string(&public_path).unwrap(), public_key);

        let jwt_keys = crate::models::Keys::from_config(&Config {
            jwt_private_key_pem: private_key,
            jwt_public_key_pem: public_key,
            ..valid_config()
        })
        .unwrap();
        assert_eq!(jwt_keys.jwks().keys.len(), 1);

        let _ = fs::remove_dir_all(temp_root);
    }

    #[test]
    fn encrypted_database_password_can_be_decrypted() {
        let key = "0123456789abcdef0123456789abcdef";
        let nonce = b"123456789012";
        let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).unwrap();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(nonce), b"db-secret".as_ref())
            .unwrap();
        let encrypted = format!(
            "secret:v1:aes-256-gcm:{}:{}",
            BASE64.encode(nonce),
            BASE64.encode(ciphertext)
        );

        let password = decrypt_database_password(&encrypted, key).unwrap();

        assert_eq!(password, "db-secret");
    }

    #[test]
    fn encrypted_database_password_rejects_legacy_keylo_format() {
        let key = "0123456789abcdef0123456789abcdef";
        let encrypted = format!(
            "keylo:v1:{}:{}",
            BASE64.encode(b"123456789012"),
            BASE64.encode(b"ciphertext")
        );

        let err = decrypt_database_password(&encrypted, key).unwrap_err();

        assert!(err.contains("secret:v1:aes-256-gcm"));
    }

    #[test]
    fn encrypted_database_password_accepts_python_secret_tool_vector() {
        let key = "oN06GRBVOr2G8lFxKisSmnONozK0Ru8z9Og2q7Bsbww=";
        let encrypted = "secret:v1:aes-256-gcm:Mq+2ogeNoFKYIQYe:ZXSfffeenjQZTYXIRWJpH2xaBZgiRBAiuv4qVpzIZMrZy/B/rw==";

        let password = decrypt_database_password(encrypted, key).unwrap();

        assert_eq!(password, "python-rust-db-secret");
    }

    #[test]
    fn production_database_startup_rejects_plaintext_password_source() {
        std::env::set_var("DATABASE_PASSWORD", "plain-secret");
        let mut config = valid_config();
        config.environment = "production".to_string();
        config.redis_url = Some("redis://localhost:6379".to_string());

        let err = config.validate_for_database_startup().unwrap_err();

        std::env::remove_var("DATABASE_PASSWORD");
        assert!(err.contains("DATABASE_PASSWORD/DATABASE_PASSWORD_FILE cannot be used"));
    }

    #[test]
    fn production_database_startup_rejects_plaintext_password_file_config() {
        std::env::set_var("DATABASE_PASSWORD_FILE", "./secrets/postgres_password");
        let mut config = valid_config();
        config.environment = "production".to_string();
        config.redis_url = Some("redis://localhost:6379".to_string());

        let err = config.validate_for_database_startup().unwrap_err();

        std::env::remove_var("DATABASE_PASSWORD_FILE");
        assert!(err.contains("DATABASE_PASSWORD/DATABASE_PASSWORD_FILE cannot be used"));
    }

    #[test]
    fn production_database_startup_rejects_password_in_database_url() {
        let mut config = valid_config();
        config.environment = "production".to_string();
        config.redis_url = Some("redis://localhost:6379".to_string());
        config.database_url = format!(
            "{}{}{}",
            "postgres://keylo_user:", "<plain-secret>", "@localhost:5432/keylo"
        );

        let err = config.validate_for_database_startup().unwrap_err();

        assert!(err.contains("Invalid startup configuration"));
    }

    #[test]
    fn database_startup_requires_admin_client_credentials() {
        let mut config = valid_config();
        config.admin_client_id = Some("".to_string());
        config.admin_client_secret = None;

        let err = config.validate_for_database_startup().unwrap_err();

        assert!(err.contains("ADMIN_CLIENT_ID"));
        assert!(err.contains("ADMIN_CLIENT_SECRET"));
    }

    #[test]
    fn config_uses_conventional_admin_client_id() {
        assert_eq!(default_admin_client_id(), "cli-admin-root");
    }

    #[test]
    fn config_parses_jwt_audiences_from_csv() {
        std::env::set_var(
            "JWT_AUDIENCES",
            "admin-backend, inventory-svc,, payment-svc ",
        );

        let config = Config::from_env();

        std::env::remove_var("JWT_AUDIENCES");
        assert_eq!(
            config.jwt_audiences,
            vec![
                "admin-backend".to_string(),
                "inventory-svc".to_string(),
                "payment-svc".to_string()
            ]
        );
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
        config.admin_client_id = Some("".to_string());
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
