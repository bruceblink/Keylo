//! Docker-backed SMTP delivery verification.
//!
//! The test is opt-in through `SMTP_TEST_HOST` so ordinary unit and database
//! test runs do not require a mail server. The repository test script and CI
//! provide Mailpit, allowing this test to verify the real SMTP transport and
//! the provider's public delivery boundary without using a mock.

use keylo::config::Config;
use keylo::mail::{MailMessage, MailProvider, SmtpMailProvider};
use std::env;
use std::time::{Duration, Instant};
use uuid::Uuid;

fn configured_port(name: &str, default: u16) -> u16 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

#[tokio::test]
async fn smtp_provider_delivers_a_message_to_mailpit() {
    let Ok(host) = env::var("SMTP_TEST_HOST") else {
        println!("Skipping SMTP integration test: SMTP_TEST_HOST is not configured");
        return;
    };
    let api_url = env::var("SMTP_TEST_API_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8025/api/v1/messages".to_string());

    let config = Config {
        environment: "test".to_string(),
        mail_provider: "smtp".to_string(),
        smtp_host: Some(host),
        smtp_port: configured_port("SMTP_TEST_PORT", 1025),
        smtp_from: Some("Keylo Test <no-reply@example.test>".to_string()),
        smtp_tls_mode: "plain".to_string(),
        smtp_timeout_seconds: 5,
        smtp_username: None,
        smtp_password: None,
        ..Default::default()
    };

    let provider = SmtpMailProvider::from_config(&config).expect("Mailpit SMTP config is valid");
    let subject = format!("Keylo SMTP integration {}", Uuid::new_v4());
    let recipient = format!("smtp-test-{}@example.test", Uuid::new_v4());
    provider
        .send(MailMessage::new(
            &recipient,
            &subject,
            "Keylo SMTP integration body",
        ))
        .await
        .expect("Mailpit should accept the SMTP message");

    let client = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = client.get(&api_url).send().await;
        if let Ok(response) = response {
            if let Ok(body) = response.text().await {
                if body.contains(&subject) && body.contains(&recipient) {
                    return;
                }
            }
        }

        assert!(
            Instant::now() < deadline,
            "Mailpit did not expose the delivered message through {api_url}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
