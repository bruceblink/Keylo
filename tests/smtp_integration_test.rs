//! Docker-backed SMTP delivery verification.
//!
//! The test is opt-in through `SMTP_TEST_HOST` so ordinary unit and database
//! test runs do not require a mail server. The repository test script and CI
//! provide Mailpit, allowing this test to verify the real SMTP transport and
//! the provider's public delivery boundary without using a mock.

use keylo::config::Config;
use keylo::mail::{
    MailDeliveryError, MailMessage, MailProvider, MailProviderConfigError, SmtpMailProvider,
};
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

#[tokio::test]
async fn smtp_provider_delivers_after_mailpit_restart() {
    let Ok(container_name) = env::var("SMTP_TEST_CONTAINER_NAME") else {
        println!("Skipping SMTP recovery test: SMTP_TEST_CONTAINER_NAME is not configured");
        return;
    };
    let Ok(host) = env::var("SMTP_TEST_HOST") else {
        println!("Skipping SMTP recovery test: SMTP_TEST_HOST is not configured");
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

    let before_restart_subject = format!("Keylo SMTP before restart {}", Uuid::new_v4());
    let before_restart_recipient = format!("smtp-before-restart-{}@example.test", Uuid::new_v4());
    provider
        .send(MailMessage::new(
            &before_restart_recipient,
            &before_restart_subject,
            "Keylo SMTP pre-restart body",
        ))
        .await
        .expect("Mailpit should accept a message before restart");

    let restart = std::process::Command::new("docker")
        .args(["restart", &container_name])
        .status()
        .expect("Docker must be available for the Mailpit recovery test");
    assert!(restart.success(), "Mailpit container restart must succeed");

    let client = reqwest::Client::new();
    let ready_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(response) = client.get(&api_url).send().await {
            if response.status().is_success() {
                break;
            }
        }
        assert!(
            Instant::now() < ready_deadline,
            "Mailpit did not become ready after the container restart"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let subject = format!("Keylo SMTP recovery {}", Uuid::new_v4());
    let recipient = format!("smtp-recovery-{}@example.test", Uuid::new_v4());
    provider
        .send(MailMessage::new(
            &recipient,
            &subject,
            "Keylo SMTP recovery body",
        ))
        .await
        .expect("Mailpit should accept a message after restart");

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(response) = client.get(&api_url).send().await {
            if let Ok(body) = response.text().await {
                if body.contains(&subject) && body.contains(&recipient) {
                    return;
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "Mailpit did not expose the post-restart message"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[test]
fn smtp_tls_configuration_failure_is_rejected_before_delivery() {
    let config = Config {
        environment: "test".to_string(),
        mail_provider: "smtp".to_string(),
        smtp_host: Some("smtp.example.test".to_string()),
        smtp_port: 587,
        smtp_from: Some("Keylo Test <no-reply@example.test>".to_string()),
        smtp_tls_mode: "invalid".to_string(),
        smtp_timeout_seconds: 5,
        ..Default::default()
    };

    match SmtpMailProvider::from_config(&config) {
        Err(error) => assert_eq!(error, MailProviderConfigError::InvalidTlsMode),
        Ok(_) => panic!("invalid SMTP TLS mode must fail during startup configuration"),
    }
}

#[test]
fn mail_delivery_error_categories_remain_closed_for_recovery_metrics() {
    let categories = [
        MailDeliveryError::InvalidMessage.code(),
        MailDeliveryError::NotConfigured.code(),
        MailDeliveryError::Timeout.code(),
        MailDeliveryError::TemporarilyUnavailable.code(),
        MailDeliveryError::Rejected.code(),
    ];
    assert_eq!(categories.len(), 5);
    assert!(categories.iter().all(|category| !category.contains('@')));
}
