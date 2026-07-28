use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sqlx::FromRow;
use uuid::Uuid;

/// An encrypted TOTP credential; the seed is never returned through API responses.
#[derive(Debug, Clone, FromRow)]
pub struct MfaTotpCredential {
    pub user_id: String,
    pub encrypted_seed: String,
    pub enabled_at: Option<chrono::NaiveDateTime>,
    pub last_verified_step: Option<i64>,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

/// Encrypt a TOTP seed with the configured AES-256 key before it is persisted.
pub fn encrypt_totp_seed(seed: &str, key: &[u8]) -> Result<String, String> {
    if seed.trim().is_empty() {
        return Err("TOTP seed must not be empty".to_string());
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "MFA encryption key must be exactly 32 bytes".to_string())?;
    let nonce_id = Uuid::new_v4();
    let nonce = &nonce_id.as_bytes()[..12];
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(nonce), seed.as_bytes())
        .map_err(|_| "Failed to encrypt TOTP seed".to_string())?;

    Ok(format!(
        "v1.{}.{}",
        URL_SAFE_NO_PAD.encode(nonce),
        URL_SAFE_NO_PAD.encode(ciphertext)
    ))
}

/// Decrypt a versioned stored seed and reject malformed or tampered data.
pub fn decrypt_totp_seed(encrypted_seed: &str, key: &[u8]) -> Result<String, String> {
    let mut parts = encrypted_seed.split('.');
    let version = parts.next();
    let nonce = parts.next();
    let ciphertext = parts.next();
    if version != Some("v1") || nonce.is_none() || ciphertext.is_none() || parts.next().is_some() {
        return Err("Stored TOTP seed has an unsupported format".to_string());
    }

    let nonce = URL_SAFE_NO_PAD
        .decode(nonce.expect("validated above"))
        .map_err(|_| "Stored TOTP seed has an invalid nonce".to_string())?;
    if nonce.len() != 12 {
        return Err("Stored TOTP seed nonce must be 12 bytes".to_string());
    }
    let ciphertext = URL_SAFE_NO_PAD
        .decode(ciphertext.expect("validated above"))
        .map_err(|_| "Stored TOTP seed has invalid ciphertext".to_string())?;
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "MFA encryption key must be exactly 32 bytes".to_string())?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| "Failed to decrypt stored TOTP seed".to_string())?;

    String::from_utf8(plaintext).map_err(|_| "Stored TOTP seed is not valid UTF-8".to_string())
}

#[cfg(test)]
mod tests {
    use super::{decrypt_totp_seed, encrypt_totp_seed};

    const KEY: &[u8; 32] = b"01234567890123456789012345678901";

    #[test]
    fn encrypted_totp_seed_round_trips_without_exposing_plaintext() {
        let encrypted = encrypt_totp_seed("JBSWY3DPEHPK3PXP", KEY).unwrap();

        assert!(encrypted.starts_with("v1."));
        assert!(!encrypted.contains("JBSWY3DPEHPK3PXP"));
        assert_eq!(
            decrypt_totp_seed(&encrypted, KEY).unwrap(),
            "JBSWY3DPEHPK3PXP"
        );
    }

    #[test]
    fn encrypted_totp_seed_rejects_tampering_and_invalid_keys() {
        let encrypted = encrypt_totp_seed("JBSWY3DPEHPK3PXP", KEY).unwrap();
        let tampered = format!("{encrypted}x");

        assert!(decrypt_totp_seed(&tampered, KEY).is_err());
        assert!(decrypt_totp_seed(&encrypted, b"too-short").is_err());
    }
}
