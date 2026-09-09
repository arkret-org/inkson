//! App-tree implementation of [`SignalProductSink`].
//!
//! The Signal receive engine has already admitted the envelope (structure,
//! TTL, sender key, device proof, MLS AEAD, replay) by the time anything here
//! runs, so this module owns only the product half: the receiver-side
//! authorization each profile requires before a body may drive UI, and the
//! handoff into the two Dioxus hubs mounted at the app root.

use std::cell::RefCell;
use std::collections::BTreeMap;

use dioxus::prelude::*;

use crate::runtime::projection::SignalProductSink;

/// How long one `(scope, sender, seal_ref, action)` authorization verdict is
/// reused. `signal.md` §7.1 binds the re-check to the envelope's `seal_ref`,
/// which is already part of the key, so this only bounds how stale a verdict
/// under an unchanged basis may get. A message-stream producer may emit five
/// frames a second per stream, so an uncached check would turn one preview
/// into a per-frame authz round trip.
const AUTHZ_VERDICT_TTL_MS: u64 = 30_000;

/// Hard cap on cached verdicts, evicting the oldest first.
const MAX_AUTHZ_VERDICTS: usize = 256;

fn signal_authorization_cache_key(
    actor: &arkret_sdk::ActorId,
    seal: &arkret_sdk::SealId,
    action: &str,
    realm: &arkret_sdk::RealmId,
) -> String {
    format!("{realm}|{actor}|{seal}|{action}")
}

fn signal_authorization_request(
    actor: &arkret_sdk::ActorId,
    action: &str,
    realm: arkret_sdk::RealmId,
) -> arkret_models_collaboration::governance::authorization::AuthzCheckRequestBody {
    arkret_models_collaboration::governance::authorization::AuthzCheckRequestBody {
        actor_id: actor.clone(),
        action: action.to_owned(),
        resource: Some(arkret_sdk::WireResourceSelector::realm(realm)),
        context: None,
    }
}

fn directory_prefetch_needed(lookup: &crate::identity::device_directory::CacheLookup) -> bool {
    matches!(lookup, crate::identity::device_directory::CacheLookup::Miss)
}

async fn prefetch_agent_sender_evidence(
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
    http: &arkret_sdk::http_client::Client,
    envelope: &arkret_wire::SignalEnvelope,
    recipient_account_id: arkret_sdk::AccountId,
) {
    // Release the signal read guard before suspending on the evidence query.
    // A temporary in the awaited argument list retains the lock while Realm
    // deliveries need to write, and also blocks caching a successful response.
    let cached_entries = state_store.peek().cached_agent_signer_evidence(
        envelope.sender_actor_id.signing_principal_id(),
        &envelope.proof.verification_method,
    );
    if let Some(entry) =
        crate::identity::agent_signer_evidence::resolve_current_signal_sender_evidence(
            http,
            envelope,
            recipient_account_id,
            cached_entries,
        )
        .await
    {
        if let Err(error) = state_store
            .write()
            .store_verified_agent_signer_evidence(entry)
        {
            tracing::warn!(%error, "verified Agent Signal evidence could not be stored");
        }
    }
}

#[derive(Clone, Copy)]
struct CachedVerdict {
    allowed: bool,
    expires_at_ms: u64,
}

pub(super) struct AppSignalProductSink {
    call_hub: crate::views::call_signals::CallSignalHub,
    message_hub: crate::views::message_streams::MessageStreamHub,
    read_receipt_hub: crate::views::read_receipts::ReadReceiptHub,
    base_url: Signal<String>,
    token: Signal<String>,
    principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    state_store: SyncSignal<crate::state::LocalStateStore>,
    authz_verdicts: RefCell<BTreeMap<String, CachedVerdict>>,
}

impl AppSignalProductSink {
    pub(super) fn new(
        call_hub: crate::views::call_signals::CallSignalHub,
        message_hub: crate::views::message_streams::MessageStreamHub,
        read_receipt_hub: crate::views::read_receipts::ReadReceiptHub,
        base_url: Signal<String>,
        token: Signal<String>,
        principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
        state_store: SyncSignal<crate::state::LocalStateStore>,
    ) -> Self {
        Self {
            call_hub,
            message_hub,
            read_receipt_hub,
            base_url,
            token,
            principal_id,
            state_store,
            authz_verdicts: RefCell::new(BTreeMap::new()),
        }
    }

    fn authenticated_api(&self) -> Option<crate::transport::TransportClient> {
        let base_url = self.base_url.peek().clone();
        let token = self.token.peek().clone();
        if base_url.trim().is_empty() || token.trim().is_empty() {
            return None;
        }
        crate::transport::auth::authed_api(&base_url, token).ok()
    }

    fn cached_verdict(&self, key: &str) -> Option<bool> {
        let now = crate::clock::now_unix_ms();
        let mut verdicts = self.authz_verdicts.borrow_mut();
        verdicts.retain(|_, verdict| verdict.expires_at_ms > now);
        verdicts.get(key).map(|verdict| verdict.allowed)
    }

    fn remember_verdict(&self, key: String, allowed: bool) {
        let now = crate::clock::now_unix_ms();
        let mut verdicts = self.authz_verdicts.borrow_mut();
        verdicts.insert(
            key,
            CachedVerdict {
                allowed,
                expires_at_ms: now.saturating_add(AUTHZ_VERDICT_TTL_MS),
            },
        );
        while verdicts.len() > MAX_AUTHZ_VERDICTS {
            let Some(soonest) = verdicts
                .iter()
                .min_by_key(|(_, verdict)| verdict.expires_at_ms)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            verdicts.remove(&soonest);
        }
    }

    /// Fail-closed authorization probe for one product action, memoized per
    /// `(realm, sender, seal_ref, action)`. A transport failure is a denial:
    /// §7.1 forbids showing a body whose authorization could not be verified.
    async fn action_allowed(
        &self,
        plaintext: &garth::SignalPlaintext,
        action: &str,
        realm_id: &str,
    ) -> bool {
        let Ok(resource_realm_id) = arkret_sdk::RealmId::new(realm_id.to_owned()) else {
            return false;
        };
        let key = signal_authorization_cache_key(
            &plaintext.actor_id,
            &plaintext.seal_ref,
            action,
            &resource_realm_id,
        );
        if let Some(allowed) = self.cached_verdict(&key) {
            return allowed;
        }
        let Some(api) = self.authenticated_api() else {
            return false;
        };
        // Admission already authenticated the full sender Actor. Reconstructing
        // an account from its principal and our Station would query a different
        // participant, losing the verified account's Station binding.
        let request = signal_authorization_request(&plaintext.actor_id, action, resource_realm_id);
        let allowed = match api.sdk_http_client() {
            Ok(http) => http
                .authz_check(&request)
                .await
                .is_ok_and(|outcome| crate::transport::realm_read::authz_allowed(&outcome)),
            Err(_) => false,
        };
        self.remember_verdict(key, allowed);
        allowed
    }
}

type LocalBoxFuture<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>>;

impl SignalProductSink for AppSignalProductSink {
    fn prefetch_sender_key<'a>(
        &'a self,
        envelope: &'a arkret_wire::SignalEnvelope,
    ) -> LocalBoxFuture<'a> {
        Box::pin(async move {
            let Some(device) = envelope.sender_device_id.as_ref() else {
                if crate::identity::agent_signer_evidence::cached_current_signal_sender_evidence(
                    &self.state_store.peek(),
                    envelope,
                )
                .is_some()
                {
                    return;
                }
                let Some(api) = self.authenticated_api() else {
                    tracing::warn!("Agent Signal evidence has no authenticated API");
                    return;
                };
                let Ok(http) = api.sdk_http_client().map_err(
                    |error| tracing::warn!(%error, "Agent Signal evidence client is unavailable"),
                ) else {
                    return;
                };
                let Some(recipient_account_id) = self.state_store.peek().active_authority() else {
                    tracing::warn!("Agent Signal evidence recipient Account is unavailable");
                    return;
                };
                prefetch_agent_sender_evidence(
                    self.state_store,
                    &http,
                    envelope,
                    recipient_account_id,
                )
                .await;
                return;
            };
            let actor = envelope.sender_actor_id.to_string();
            // The registered carrier is account-device only. A missing or
            // revoked directory key is never a hint to classify this as Agent.
            if envelope.sender_actor_id.as_account_id().is_none()
                || !directory_prefetch_needed(
                    &crate::identity::device_directory::cached_device_signing_key(
                        &actor,
                        device.as_str(),
                    ),
                )
            {
                return;
            }
            let Some(api) = self.authenticated_api() else {
                return;
            };
            let Ok(http) = api.sdk_http_client() else {
                return;
            };
            let Some(recipient_principal_id) = self.principal_id.peek().clone() else {
                return;
            };
            let Ok(recipient_station_id) = http.describe().await.map(|value| value.service_id)
            else {
                return;
            };
            let _ = crate::identity::device_directory::resolve_current_signal_device_evidence(
                &http,
                envelope,
                arkret_sdk::AccountId::new(recipient_principal_id, recipient_station_id),
            )
            .await;
        })
    }

    fn call_signal<'a>(
        &'a self,
        envelope: &'a arkret_wire::SignalEnvelope,
        body: serde_json::Value,
    ) -> LocalBoxFuture<'a> {
        Box::pin(async move {
            let mut hub = self.call_hub;
            let local_actor = self.principal_id.peek().clone();
            crate::views::call_signals::route_decrypted_call_signals(
                &mut hub,
                std::slice::from_ref(&(envelope.clone(), body)),
                crate::app::principal_id_text(&local_actor),
            )
            .await;
        })
    }

    fn message_stream<'a>(&'a self, plaintext: &'a garth::SignalPlaintext) -> LocalBoxFuture<'a> {
        Box::pin(async move {
            let realm_id = plaintext.scope_ref.realm_id().as_str().to_owned();
            // §7.1 — the sender must hold BOTH the preview action and the
            // authorization the final Message create needs. Neither is
            // observable from the outer envelope, so the recipient re-checks
            // them at the Seal basis before any body reaches a surface.
            for action in [
                arkret_sdk::CapabilityActionId::MESSAGE_STREAM_SEND,
                arkret_sdk::CapabilityActionId::MESSAGE_CREATE,
            ] {
                if !self.action_allowed(plaintext, action, &realm_id).await {
                    tracing::debug!(
                        action,
                        actor = %plaintext.actor_id,
                        "dropping message stream preview: sender is not authorized at seal_ref"
                    );
                    return;
                }
            }
            let mut hub = self.message_hub;
            if let Err(error) = hub.apply_authorized(plaintext, crate::clock::now_utc()) {
                tracing::debug!(%error, "message stream preview frame was not applied");
            }
        })
    }

    fn read_receipt(
        &self,
        plaintext: &garth::SignalPlaintext,
        policy: &arkret_sdk::ReadReceiptPolicy,
    ) {
        // No further authorization probe: unlike a message-stream preview, a
        // read receipt discloses no Message body, and `read-receipts.md` §2.4
        // makes display a local preference rather than a protocol gate. The
        // envelope admission already proved the sending device and bound the
        // plaintext `actor_id` to the authenticated `sender_actor_id`.
        //
        // §2.5 is the exception and is enforced inside the hub: `disabled` and
        // `private` are client-side discards, because a Sync Service cannot
        // read the receipt to apply them.
        let local_actor = self.principal_id.peek().clone();
        let mut hub = self.read_receipt_hub;
        hub.apply_authorized(
            plaintext,
            policy,
            crate::app::principal_id_text(&local_actor),
        );
    }

    fn advance_clock(&self, now: chrono::DateTime<chrono::Utc>) {
        let mut hub = self.message_hub;
        hub.maintain(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn agent_evidence_query_releases_state_lock_while_waiting_for_network() {
        let station = arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let actor = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
            station.clone(),
        ));
        let recipient = arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            station,
        );
        let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let now = crate::clock::now_utc();
        let mut envelope: arkret_wire::SignalEnvelope = serde_json::from_value(serde_json::json!({
            "realm_id": realm,
            "scope_ref": {"kind": "realm", "realm_id": realm},
            "sender_actor_id": actor,
            "seal_ref": format!("ak:seal:sha256:{}", "a".repeat(64)),
            "signal_class": "session",
            "sent_at": arkret_sdk::canonical::format_timestamp_canonical(now),
            "expires_at": arkret_sdk::canonical::format_timestamp_canonical(now + chrono::Duration::seconds(10)),
            "encrypted_payload": {
                "scheme": arkret_wire::signal::SIGNAL_AEAD_SCHEME,
                "key_ref": {"algorithm": "MLS-EXPORTER-AEAD", "group_state_ref": "ak:event:AZVgkcivLIz2PjwUcjuT5bTb6295nnowDbSQak0QfNCa"},
                "purpose": arkret_wire::signal::SIGNAL_AEAD_PURPOSE,
                "aead_profile": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
                "epoch": 4, "nonce": "AAAAAAAAAAAAAAAA", "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA",
                "aad_digest": format!("sha256:{}", "0".repeat(64))
            },
            "proof": {"kind": arkret_sdk::proof_kind::DETACHED_JWS,
                "verification_method": "did:web:agent.example#runtime",
                "envelope_digest": format!("sha256:{}", "0".repeat(64)), "jws": ""}
        }))
        .unwrap();
        envelope.encrypted_payload.aad_digest = envelope.expected_aad_digest().unwrap();
        envelope.proof.envelope_digest = envelope.envelope_digest().unwrap();
        // This test stops at the query; it does not claim signature admission.
        envelope.proof.jws = arkret_wire::test_support::structural_only_detached_jws(
            &envelope.proof.envelope_digest,
        );
        envelope.validate_structural().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http = arkret_sdk::http_client::Client::builder(
            format!("http://{}/", listener.local_addr().unwrap())
                .parse()
                .unwrap(),
        )
        .allow_insecure_localhost()
        .build()
        .unwrap();
        let dom = VirtualDom::new(|| rsx! {});
        let mut state_store = dom.in_scope(ScopeId::ROOT, || {
            SyncSignal::new_maybe_sync_in_scope(
                crate::state::LocalStateStore::with_path(std::env::temp_dir().join(format!(
                    "inkson-agent-signal-lock-{}.json",
                    std::process::id()
                ))),
                ScopeId::ROOT,
            )
        });
        let mut query = Box::pin(prefetch_agent_sender_evidence(
            state_store,
            &http,
            &envelope,
            recipient,
        ));
        let _connection = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::select! {
                result = listener.accept() => result.unwrap(),
                () = &mut query => panic!("the evidence query must reach the network"),
            }
        })
        .await
        .expect("evidence request reached the stalled server");
        let (written, observed) = tokio::sync::oneshot::channel();
        let writer = std::thread::spawn(move || {
            let _guard = state_store.write();
            let _ = written.send(());
        });
        let writable = tokio::time::timeout(std::time::Duration::from_secs(2), observed).await;
        // Release a regressed guard before joining so a failing test cannot hang.
        drop(query);
        writer.join().unwrap();
        writable
            .expect("Realm state must remain writable during an Agent evidence query")
            .unwrap();
    }

    #[test]
    fn signal_authorization_preserves_the_verified_actor_and_station() {
        let principal = arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let station_a = arkret_sdk::DidCoreId::new("ak:did_core:web:station-a.example").unwrap();
        let station_b = arkret_sdk::DidCoreId::new("ak:did_core:web:station-b.example").unwrap();
        let actors = [
            arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                principal.clone(),
                station_a.clone(),
            )),
            arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(principal.clone(), station_b)),
            arkret_sdk::ActorId::service(principal),
        ];
        let realm =
            arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap();
        let seal = arkret_sdk::SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap();
        let mut keys = std::collections::BTreeSet::new();
        for actor in actors {
            let request = signal_authorization_request(&actor, "ak.message.create", realm.clone());
            assert_eq!(request.actor_id, actor);
            assert!(keys.insert(signal_authorization_cache_key(
                &actor,
                &seal,
                "ak.message.create",
                &realm,
            )));
        }
    }

    #[test]
    fn negative_device_directory_verdict_does_not_trigger_agent_fallback() {
        assert!(!directory_prefetch_needed(
            &crate::identity::device_directory::CacheLookup::NegativeHit
        ));
        assert!(directory_prefetch_needed(
            &crate::identity::device_directory::CacheLookup::Miss
        ));
    }
}
