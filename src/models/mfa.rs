use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sqlx::FromRow;
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;

pub const TOTP_STEP_SECONDS: u64 = 30;
const TOTP_DIGITS: usize = 6;

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

/// Create a random Base32 seed suitable for a standard authenticator application.
pub fn generate_totp_seed() -> String {
    Secret::generate_secret().to_encoded().to_string()
}

/// Build the standard provisioning URI without persisting or logging the seed.
pub fn totp_provisioning_uri(
    seed: &str,
    issuer: &str,
    account_name: &str,
) -> Result<String, String> {
    let totp = build_totp(seed, issuer, account_name)?;
    Ok(totp.get_url())
}

/// Verify a six-digit code and return its exact time step for replay protection.
pub fn verify_totp_code(seed: &str, code: &str, unix_seconds: u64) -> Result<Option<i64>, String> {
    if code.len() != TOTP_DIGITS || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(None);
    }

    let totp = build_totp(seed, "Keylo", "verification")?;
    let current_step = unix_seconds / TOTP_STEP_SECONDS;
    for step in [
        current_step.saturating_sub(1),
        current_step,
        current_step.saturating_add(1),
    ] {
        if totp.check(code, step * TOTP_STEP_SECONDS) {
            return i64::try_from(step)
                .map(Some)
                .map_err(|_| "TOTP time step is out of range".to_string());
        }
    }

    Ok(None)
}

/// Construct Keylo's fixed TOTP profile and validate the input secret and labels.
fn build_totp(seed: &str, issuer: &str, account_name: &str) -> Result<TOTP, String> {
    let secret = Secret::Encoded(seed.to_string())
        .to_bytes()
        .map_err(|_| "TOTP seed must be valid Base32".to_string())?;
    TOTP::new(
        Algorithm::SHA1,
        TOTP_DIGITS,
        0,
        TOTP_STEP_SECONDS,
        secret,
        Some(issuer.to_string()),
        account_name.to_string(),
    )
    .map_err(|_| "TOTP enrollment labels are invalid".to_string())
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
    use super::{
        decrypt_totp_seed, encrypt_totp_seed, generate_totp_seed, totp_provisioning_uri,
        verify_totp_code, TOTP_STEP_SECONDS,
    };
    use totp_rs::{Algorithm, Secret, TOTP};

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

    #[test]
    fn totp_uses_the_rfc_6238_sha1_test_vector() {
        let totp = TOTP::new(
            Algorithm::SHA1,
            8,
            0,
            TOTP_STEP_SECONDS,
            Secret::Raw(b"12345678901234567890".to_vec())
                .to_bytes()
                .unwrap(),
            Some("Keylo".to_string()),
            "user".to_string(),
        )
        .unwrap();

        assert_eq!(totp.generate(59), "94287082");
    }

    #[test]
    fn totp_verification_accepts_a_single_adjacent_time_step() {
        let seed = generate_totp_seed();
        let at = 1_700_000_000;
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            0,
            TOTP_STEP_SECONDS,
            Secret::Encoded(seed.clone()).to_bytes().unwrap(),
            Some("Keylo".to_string()),
            "verification".to_string(),
        )
        .unwrap();
        let previous_step = (at / TOTP_STEP_SECONDS) - 1;
        let previous_code = totp.generate(previous_step * TOTP_STEP_SECONDS);

        assert_eq!(
            verify_totp_code(&seed, &previous_code, at).unwrap(),
            Some(previous_step as i64)
        );
        assert_eq!(verify_totp_code(&seed, "abcdef", at).unwrap(), None);
        assert_eq!(verify_totp_code(&seed, "123456", at).unwrap(), None);
    }

    #[test]
    fn provisioning_uri_does_not_change_the_stored_seed() {
        let seed = generate_totp_seed();
        let uri = totp_provisioning_uri(&seed, "Keylo", "alice@example.com").unwrap();

        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("issuer=Keylo"));
        assert!(uri.contains(&format!("secret={seed}")));
    }
}
