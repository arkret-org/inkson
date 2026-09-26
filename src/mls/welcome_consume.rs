//! The `keypackages/consume` a Welcome's endpoint owes once the group state
//! the Welcome joined is durable (device-lifecycle.md §9 consume, decision
//! 0121).
//!
//! The command is signed when the joined group is installed and is persisted
//! in the same durable flush as that group; it is sent only after the flush
//! resolves. A lost response is answered by resending the exact persisted
//! command, never by signing a new one, until the Station settles it.

use std::future::Future;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// What one consume attempt settled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsumeAttempt {
    /// The Station consumed the claim (or replayed the stored consume).
    Consumed,
    /// No answer, or a transient refusal: resend the same command later.
    Retry(String),
    /// A definitive refusal: resending the same bytes cannot succeed.
    Refused(String),
}

impl ConsumeAttempt {
    /// Whether the command is settled and no longer owed.
    #[must_use]
    pub fn settled(&self) -> bool {
        !matches!(self, Self::Retry(_))
    }
}

/// Classify one `keypackages/consume` response: a transport failure, a
/// timeout, rate limiting or a server error leaves the command owed.
pub(crate) fn classify_consume_response<T>(result: &anyhow::Result<T>) -> ConsumeAttempt {
    let Err(error) = result else {
        return ConsumeAttempt::Consumed;
    };
    match crate::api_error::api_error_status_and_envelope(error) {
        Some((status, _))
            if status.as_u16() == 408 || status.as_u16() == 429 || status.is_server_error() =>
        {
            ConsumeAttempt::Retry(error.to_string())
        }
        Some(_) => ConsumeAttempt::Refused(error.to_string()),
        None => ConsumeAttempt::Retry(error.to_string()),
    }
}

/// Send every owed command exactly as it was persisted, in order, and return
/// each one with what its attempt settled.
pub async fn drain_owed_consumes<T, F, Fut>(owed: Vec<T>, send: F) -> Vec<(T, ConsumeAttempt)>
where
    T: Clone,
    F: Fn(T) -> Fut,
    Fut: Future<Output = ConsumeAttempt>,
{
    let mut attempts = Vec::with_capacity(owed.len());
    for command in owed {
        let attempt = send(command.clone()).await;
        attempts.push((command, attempt));
    }
    attempts
}

/// Sign the consume command for a Welcome this device joined at
/// `joined_epoch`, under this device's active signer.
pub(crate) fn sign_welcome_consume(
    delivery: &arkret_wire::MlsWelcomeDelivery,
    outcome: &arkret_sdk::KeyPackagesClaimOutcome,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    station: &arkret_sdk::DidCoreId,
    joined_epoch: u64,
) -> Result<arkret_sdk::KeyPackagesConsumeRequestBody, String> {
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| "KeyPackage consume requires an active device signer".to_owned())?;
    let principal = arkret_sdk::Did::new(signer.signer_did().to_owned())
        .map_err(|error| format!("active device signer DID: {error}"))?;
    if arkret_sdk::project_did_to_core_id(&principal)
        .map_err(|error| format!("active device signer DID: {error}"))?
        != authority.principal_id
    {
        return Err("active device signer does not belong to the Welcome recipient".to_owned());
    }
    let method = signer
        .verification_method_for_principal(&principal)
        .map_err(|error| format!("active device verification method: {error}"))?;
    garth::mls::signed_welcome_consume(
        delivery,
        outcome,
        arkret_sdk::RecipientMlsDurableSigner::Device {
            recipient_account_id: authority.clone(),
            recipient_device_id: device_id.clone(),
            device_verification_method: method.clone(),
        },
        station,
        joined_epoch,
        crate::clock::now_utc(),
        |kid, input| {
            if kid != method.as_str() {
                return Err(garth::Error::Protocol(
                    "consume signature names another verification method".to_owned(),
                ));
            }
            let signature = signer
                .sign_raw(input)
                .map_err(|error| garth::Error::Protocol(error.to_string()))?;
            Ok(arkret_sdk::KeyOperationSignature {
                kid: arkret_sdk::NonEmptyString::new(kid.to_owned())
                    .map_err(|error| garth::Error::Protocol(error.to_string()))?,
                signature_algorithm: Some(
                    arkret_sdk::NonEmptyString::new(signer.algorithm().to_owned())
                        .map_err(|error| garth::Error::Protocol(error.to_string()))?,
                ),
                sig: arkret_sdk::Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature))
                    .map_err(|error| garth::Error::Protocol(error.to_string()))?,
            })
        },
    )
    .map_err(|error| error.to_string())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::cell::RefCell;

    use super::*;

    /// A lost response leaves the command owed; the next pass resends the
    /// exact same bytes, which then settle.
    #[tokio::test]
    async fn a_lost_consume_response_resends_the_same_command() {
        let owed = vec!["signed-consume-a".to_owned()];
        let sent = RefCell::new(Vec::new());
        let first = drain_owed_consumes(owed.clone(), |command| {
            sent.borrow_mut().push(command);
            async { ConsumeAttempt::Retry("response lost".to_owned()) }
        })
        .await;
        assert_eq!(first.len(), 1);
        assert!(!first[0].1.settled());
        let still_owed = first
            .into_iter()
            .filter(|(_, attempt)| !attempt.settled())
            .map(|(command, _)| command)
            .collect::<Vec<_>>();
        let second = drain_owed_consumes(still_owed, |command| {
            sent.borrow_mut().push(command);
            async { ConsumeAttempt::Consumed }
        })
        .await;
        assert!(second.iter().all(|(_, attempt)| attempt.settled()));
        assert_eq!(
            sent.into_inner(),
            vec!["signed-consume-a".to_owned(), "signed-consume-a".to_owned()]
        );
    }

    /// Nothing owed sends nothing.
    #[tokio::test]
    async fn nothing_owed_sends_nothing() {
        let sent = RefCell::new(0);
        let attempts = drain_owed_consumes(Vec::<String>::new(), |_| {
            *sent.borrow_mut() += 1;
            async { ConsumeAttempt::Consumed }
        })
        .await;
        assert!(attempts.is_empty());
        assert_eq!(sent.into_inner(), 0);
    }

    #[test]
    fn transport_loss_and_server_errors_keep_the_command_owed() {
        let lost: anyhow::Result<()> = Err(anyhow::anyhow!("connection reset"));
        assert!(matches!(
            classify_consume_response(&lost),
            ConsumeAttempt::Retry(_)
        ));
        let ok: anyhow::Result<()> = Ok(());
        assert_eq!(classify_consume_response(&ok), ConsumeAttempt::Consumed);
    }
}
