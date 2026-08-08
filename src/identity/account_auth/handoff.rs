//! Secure storage for the short-lived account-handoff credential.

use crate::secure_key_store::default_secure_key_store;

pub(crate) const ACCOUNT_HANDOFF_GRANT_SECRET_KEY: &str = "inkson.account_handoff_grant.v1";
pub(crate) const PREPARED_BOOTSTRAP_SESSION_REQUEST_SECRET_KEY: &str =
    "inkson.prepared_bootstrap_session_request.v1";

pub async fn persist_account_handoff_grant(grant: &str) -> anyhow::Result<()> {
    let grant = grant.trim();
    if grant.is_empty() {
        anyhow::bail!("account handoff grant is empty");
    }
    default_secure_key_store("inkson")
        .store_secret_durable(ACCOUNT_HANDOFF_GRANT_SECRET_KEY, grant)
        .await?;
    Ok(())
}

pub fn load_account_handoff_grant() -> anyhow::Result<Option<String>> {
    Ok(default_secure_key_store("inkson").get_secret(ACCOUNT_HANDOFF_GRANT_SECRET_KEY)?)
}

pub fn clear_account_handoff_grant() -> anyhow::Result<()> {
    default_secure_key_store("inkson").delete_secret(ACCOUNT_HANDOFF_GRANT_SECRET_KEY)?;
    Ok(())
}

/// Persist the complete signed bootstrap session request before network I/O.
/// Its proof challenge is the account-handoff bearer, so this material must
/// never enter the public onboarding checkpoint/localStorage.
pub async fn persist_prepared_bootstrap_session_request(
    request: &arkret_sdk::SessionGrantRequestBody,
) -> anyhow::Result<()> {
    let canonical = encode_prepared_bootstrap_session_request(request)?;
    default_secure_key_store("inkson")
        .store_secret_durable(PREPARED_BOOTSTRAP_SESSION_REQUEST_SECRET_KEY, &canonical)
        .await?;
    Ok(())
}

pub fn load_prepared_bootstrap_session_request()
-> anyhow::Result<Option<arkret_sdk::SessionGrantRequestBody>> {
    default_secure_key_store("inkson")
        .get_secret(PREPARED_BOOTSTRAP_SESSION_REQUEST_SECRET_KEY)?
        .map(|canonical| decode_prepared_bootstrap_session_request(&canonical))
        .transpose()
}

pub fn clear_prepared_bootstrap_session_request() -> anyhow::Result<()> {
    default_secure_key_store("inkson")
        .delete_secret(PREPARED_BOOTSTRAP_SESSION_REQUEST_SECRET_KEY)?;
    Ok(())
}

fn encode_prepared_bootstrap_session_request(
    request: &arkret_sdk::SessionGrantRequestBody,
) -> anyhow::Result<String> {
    Ok(String::from_utf8(
        arkret_sdk::canonical::canonical_json_bytes(request)?,
    )?)
}

fn decode_prepared_bootstrap_session_request(
    canonical: &str,
) -> anyhow::Result<arkret_sdk::SessionGrantRequestBody> {
    Ok(arkret_sdk::canonical::from_canonical_json_slice(
        canonical.as_bytes(),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_request_codec_replays_exact_bytes_and_is_indexeddb_only() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../arkret-spec/spec/v1/artifacts/fixtures/device-bootstrap-fixture.json"
        ))
        .unwrap();
        let enroll: arkret_sdk::AccountDeviceEnrollRequestBody =
            serde_json::from_value(fixture["enroll_request"].clone()).unwrap();
        let event_ids = fixture["founding_batch"]["event_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| arkret_sdk::EventId::new(value.as_str().unwrap().to_owned()).unwrap())
            .collect::<Vec<_>>();
        let bootstrap = arkret_sdk::SessionGrantDeviceBootstrapRequest {
            mode: arkret_sdk::SessionGrantDeviceBootstrapMode::Founding,
            authorize_event_preimage: enroll.authorize_event_preimage,
            founding_event_ids: event_ids,
            founding_batch_digest: arkret_sdk::Hash::new(
                fixture["founding_batch"]["expected_digest"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            )
            .unwrap(),
        };
        let request = garth::pre_registration_session_grant_request(
            arkret_sdk::Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            arkret_sdk::DeviceId::new("ak:device:019a0000-0000-7000-8000-000000000001").unwrap(),
            Vec::new(),
            bootstrap,
            &"handoff-secret".repeat(4),
            arkret_sdk::Did::new("did:webvh:z6mkfixture:principal.example").unwrap(),
            chrono::DateTime::parse_from_rfc3339("2026-08-08T12:05:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            |_| Ok("holder-signature".to_owned()),
        )
        .unwrap();

        let encoded = encode_prepared_bootstrap_session_request(&request).unwrap();
        let replay = decode_prepared_bootstrap_session_request(&encoded).unwrap();
        assert_eq!(
            encoded,
            encode_prepared_bootstrap_session_request(&replay).unwrap()
        );
        assert!(encoded.contains("handoff-secret"));
        assert!(
            crate::secure_key_store::is_wasm_indexeddb_required_secret_key(
                PREPARED_BOOTSTRAP_SESSION_REQUEST_SECRET_KEY
            )
        );
    }
}
