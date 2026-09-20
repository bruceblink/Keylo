//! Pluggable mail delivery boundary used by account self-service flows.
//!
//! Authentication code should construct a [`MailMessage`] and depend only on
//! [`MailProvider`]. Concrete SMTP or external-service adapters belong outside
//! the authentication decision path and must map provider-specific failures to
//! [`MailDeliveryError`] without retaining raw credentials or message content.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
#[cfg(test)]
use std::sync::{Arc, Mutex};

/// A text-only message passed from an account workflow to a mail provider.
///
/// The message body may contain a one-time token, so this type deliberately
/// redacts every field in debug output and never exposes message content in
/// provider errors.
#[derive(Clone, PartialEq, Eq)]
pub struct MailMessage {
    pub recipient: String,
    pub subject: String,
    pub text_body: String,
}

impl MailMessage {
    /// Build a message while leaving address and template validation to the boundary.
    pub fn new(
        recipient: impl Into<String>,
        subject: impl Into<String>,
        text_body: impl Into<String>,
    ) -> Self {
        Self {
            recipient: recipient.into(),
            subject: subject.into(),
            text_body: text_body.into(),
        }
    }

    /// Reject incomplete messages before a provider can attempt delivery.
    pub fn validate(&self) -> Result<(), MailDeliveryError> {
        if self.recipient.trim().is_empty()
            || self.subject.trim().is_empty()
            || self.text_body.trim().is_empty()
        {
            return Err(MailDeliveryError::InvalidMessage);
        }

        Ok(())
    }
}

impl fmt::Debug for MailMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MailMessage")
            .field("recipient", &"<redacted>")
            .field("subject", &"<redacted>")
            .field("text_body", &"<redacted>")
            .finish()
    }
}

/// Stable provider outcomes that callers can audit without leaking adapter details.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MailDeliveryError {
    InvalidMessage,
    NotConfigured,
    Timeout,
    TemporarilyUnavailable,
    Rejected,
}

impl fmt::Display for MailDeliveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidMessage => "Invalid mail message",
            Self::NotConfigured => "Mail provider is not configured",
            Self::Timeout => "Mail provider timed out",
            Self::TemporarilyUnavailable => "Mail provider is temporarily unavailable",
            Self::Rejected => "Mail provider rejected the message",
        };
        formatter.write_str(message)
    }
}

/// Future returned by a provider without requiring an async-trait dependency.
pub type MailDeliveryFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), MailDeliveryError>> + Send + 'a>>;

/// Minimal asynchronous contract used by account self-service workflows.
pub trait MailProvider: Send + Sync {
    fn send<'a>(&'a self, message: MailMessage) -> MailDeliveryFuture<'a>;
}

/// Default provider used until an explicitly configured delivery adapter exists.
#[derive(Clone, Copy, Debug, Default)]
pub struct DisabledMailProvider;

impl MailProvider for DisabledMailProvider {
    fn send<'a>(&'a self, message: MailMessage) -> MailDeliveryFuture<'a> {
        Box::pin(async move {
            message.validate()?;
            Err(MailDeliveryError::NotConfigured)
        })
    }
}

/// In-memory provider for deterministic tests of future account workflows.
#[cfg(test)]
#[derive(Clone, Default)]
pub struct InMemoryMailProvider {
    deliveries: Arc<Mutex<Vec<MailMessage>>>,
    failure: Arc<Mutex<Option<MailDeliveryError>>>,
}

#[cfg(test)]
impl InMemoryMailProvider {
    /// Create an empty provider whose successful sends are retained in memory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure a stable failure for subsequent sends without storing the message.
    pub fn set_failure(&self, failure: Option<MailDeliveryError>) {
        if let Ok(mut configured_failure) = self.failure.lock() {
            *configured_failure = failure;
        }
    }

    /// Return captured messages for assertions without exposing them through logs.
    pub fn deliveries(&self) -> Vec<MailMessage> {
        self.deliveries
            .lock()
            .map(|messages| messages.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
impl MailProvider for InMemoryMailProvider {
    fn send<'a>(&'a self, message: MailMessage) -> MailDeliveryFuture<'a> {
        let configured_failure = self.failure.lock().ok().and_then(|failure| *failure);
        let deliveries = Arc::clone(&self.deliveries);

        Box::pin(async move {
            message.validate()?;
            if let Some(failure) = configured_failure {
                return Err(failure);
            }

            deliveries
                .lock()
                .map_err(|_| MailDeliveryError::TemporarilyUnavailable)?
                .push(message);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message() -> MailMessage {
        MailMessage::new("person@example.test", "Reset password", "one-time-token")
    }

    #[tokio::test]
    async fn disabled_provider_returns_stable_configuration_error() {
        let error = DisabledMailProvider.send(message()).await.unwrap_err();

        assert_eq!(error, MailDeliveryError::NotConfigured);
        assert_eq!(error.to_string(), "Mail provider is not configured");
    }

    #[tokio::test]
    async fn in_memory_provider_captures_successful_message_without_debug_secrets() {
        let provider = InMemoryMailProvider::new();
        provider.send(message()).await.unwrap();

        let deliveries = provider.deliveries();
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].recipient, "person@example.test");
        assert!(!format!("{:?}", deliveries[0]).contains("one-time-token"));
    }

    #[tokio::test]
    async fn in_memory_provider_returns_configured_failure_without_capturing_message() {
        let provider = InMemoryMailProvider::new();
        provider.set_failure(Some(MailDeliveryError::Timeout));

        let error = provider.send(message()).await.unwrap_err();

        assert_eq!(error, MailDeliveryError::Timeout);
        assert!(provider.deliveries().is_empty());
    }

    #[tokio::test]
    async fn providers_reject_incomplete_messages() {
        let invalid = MailMessage::new("", "subject", "body");

        assert_eq!(
            DisabledMailProvider
                .send(invalid.clone())
                .await
                .unwrap_err(),
            MailDeliveryError::InvalidMessage
        );
        assert_eq!(
            InMemoryMailProvider::new().send(invalid).await.unwrap_err(),
            MailDeliveryError::InvalidMessage
        );
    }
}
