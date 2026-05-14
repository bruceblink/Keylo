use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::Aes256Gcm;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use std::env;
use std::fs;

fn read_env_or_file(value_key: &str, path_key: &str) -> Result<String, String> {
    if let Ok(value) = env::var(value_key) {
        if !value.trim().is_empty() {
            return Ok(value);
        }
    }

    if let Ok(path) = env::var(path_key) {
        if !path.trim().is_empty() {
            let contents = fs::read_to_string(&path)
                .map_err(|err| format!("Failed to read {path_key} '{}': {err}", path))?;
            if !contents.trim().is_empty() {
                return Ok(contents);
            }
        }
    }

    Err(format!("{value_key} or {path_key} must be set"))
}

fn decode_key(key: &str) -> Result<Vec<u8>, String> {
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

fn main() -> Result<(), String> {
    let password = read_env_or_file("DATABASE_PASSWORD", "DATABASE_PASSWORD_FILE")?;
    let key = decode_key(&read_env_or_file(
        "DATABASE_PASSWORD_KEY",
        "DATABASE_PASSWORD_KEY_FILE",
    )?)?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| "DATABASE_PASSWORD_KEY must decode to 32 bytes".to_string())?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, password.trim_end_matches(['\r', '\n']).as_bytes())
        .map_err(|_| "Failed to encrypt database password".to_string())?;

    println!(
        "keylo:v1:{}:{}",
        BASE64.encode(nonce),
        BASE64.encode(ciphertext)
    );

    Ok(())
}
