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
    did_cache: Signal<arkret_sdk::identity::DidResolutionCache>,
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
        did_cache: Signal<arkret_sdk::identity::DidResolutionCache>,
        state_store: SyncSignal<crate::state::LocalStateStore>,
    ) -> Self {
        Self {
            call_hub,
            message_hub,
            read_receipt_hub,
            base_url,
            token,
            principal_id,
            did_cache,
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
            // Control Seals can advance after the MLS epoch (for example the
            // final Direct Conversation binding). A valid live Signal can
            // therefore name a Seal newer than our pinned MLS proof. Resolve
            // and verify the complete closure before the receiver evaluates
            // it; neither the Signal nor an observed frontier is trusted here.
            let needs_checkpoint = {
                let store = self.state_store.peek();
                store
                    .trusted_mls_governance_checkpoint(envelope.realm_id.as_str())
                    .is_some_and(|checkpoint| {
                        let observed = store.seal_view_for_realm(envelope.realm_id.as_str());
                        !checkpoint
                            .accepted_seals
                            .iter()
                            .any(|seal| seal.id == envelope.seal_ref)
                            || (!observed.frontier.is_empty()
                                && observed
                                    .frontier
                                    .iter()
                                    .map(String::as_str)
                                    .collect::<std::collections::BTreeSet<_>>()
                                    != checkpoint
                                        .basis
                                        .leaves
                                        .iter()
                                        .map(|id| id.as_str())
                                        .collect())
                    })
            };
            if needs_checkpoint {
                if let Some(api) = self.authenticated_api() {
                    let state = crate::app::runtime_adapter::state_store_handle(self.state_store);
                    match crate::mls::governance_proof::verify_governance_checkpoint_candidate(
                        &api,
                        &state,
                        envelope.realm_id.as_str(),
                    )
                    .await
                    {
                        Ok(checkpoint) => {
                            if let Err(error) = state.write(|store| {
                                let mut observed =
                                    store.seal_view_for_realm(envelope.realm_id.as_str());
                                let observed_is_covered = observed.frontier.iter().all(|id| {
                                    checkpoint
                                        .accepted_seals
                                        .iter()
                                        .any(|seal| seal.id.as_str() == id)
                                });
                                let frontier = checkpoint
                                    .basis
                                    .leaves
                                    .iter()
                                    .map(ToString::to_string)
                                    .collect();
                                store.advance_verified_mls_governance_checkpoint(
                                    envelope.realm_id.as_str(),
                                    checkpoint,
                                )?;
                                if observed_is_covered {
                                    // Do not overwrite a concurrently observed newer Seal or
                                    // discard exposed conflict cells while advancing the view.
                                    observed.frontier = frontier;
                                    observed.state_root = None;
                                    store.set_realm_seal_view(
                                        envelope.realm_id.to_string(),
                                        observed,
                                    );
                                }
                                Ok::<_, String>(())
                            }) {
                                tracing::warn!(%error, "Signal governance checkpoint remains pending");
                            }
                        }
                        Err(error) => {
                            tracing::warn!(%error, "Signal governance closure verification failed")
                        }
                    }
                }
            }
            let Some(device) = envelope.sender_device_id.as_ref() else {
                let Some(api) = self.authenticated_api() else {
                    return;
                };
                let Ok(http) = api.sdk_http_client() else {
                    return;
                };
                let anchor = crate::identity::did_resolver::ResolverDidAnchor::from_profile(
                    crate::identity::did_resolver::DeploymentProfile::PersonalNode,
                    self.did_cache.peek().clone(),
                );
                let Some(recipient_principal_id) = self.principal_id.peek().clone() else {
                    return;
                };
                let Ok(recipient_station_id) = http.describe().await.map(|value| value.service_id)
                else {
                    return;
                };
                if let Some(entry) =
                    crate::identity::agent_signer_evidence::resolve_current_signal_sender_evidence(
                        &http,
                        envelope,
                        arkret_sdk::AccountId::new(recipient_principal_id, recipient_station_id),
                        &anchor,
                    )
                    .await
                {
                    let mut state_store = self.state_store;
                    let _ = state_store
                        .write()
                        .store_verified_agent_signer_evidence(entry);
                }
                let mut did_cache = self.did_cache;
                did_cache.set(anchor.into_cache());
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
            let anchor = crate::identity::did_resolver::ResolverDidAnchor::from_profile(
                crate::identity::did_resolver::DeploymentProfile::PersonalNode,
                self.did_cache.peek().clone(),
            );
            let _ = crate::identity::device_directory::resolve_current_signal_device_evidence(
                &http,
                &anchor,
                envelope,
                arkret_sdk::AccountId::new(recipient_principal_id, recipient_station_id),
            )
            .await;
            let mut did_cache = self.did_cache;
            did_cache.set(anchor.into_cache());
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
