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

#[derive(Clone, Copy)]
struct CachedVerdict {
    allowed: bool,
    expires_at_ms: u64,
}

pub(super) struct AppSignalProductSink {
    call_hub: crate::views::call_signals::CallSignalHub,
    message_hub: crate::views::message_streams::MessageStreamHub,
    base_url: Signal<String>,
    token: Signal<String>,
    account_did: Signal<String>,
    did_cache: Signal<arkret_sdk::identity::DidResolutionCache>,
    authz_verdicts: RefCell<BTreeMap<String, CachedVerdict>>,
}

impl AppSignalProductSink {
    pub(super) fn new(
        call_hub: crate::views::call_signals::CallSignalHub,
        message_hub: crate::views::message_streams::MessageStreamHub,
        base_url: Signal<String>,
        token: Signal<String>,
        account_did: Signal<String>,
        did_cache: Signal<arkret_sdk::identity::DidResolutionCache>,
    ) -> Self {
        Self {
            call_hub,
            message_hub,
            base_url,
            token,
            account_did,
            did_cache,
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
        let key = format!(
            "{realm_id}|{}|{}|{action}",
            plaintext.actor_id.as_str(),
            plaintext.seal_ref.as_str()
        );
        if let Some(allowed) = self.cached_verdict(&key) {
            return allowed;
        }
        let Some(api) = self.authenticated_api() else {
            return false;
        };
        let allowed = match api.sdk_http_client() {
            Ok(http) => crate::transport::realm_read::authz_check_resource(
                &http,
                plaintext.actor_id.as_str(),
                action,
                Some(serde_json::json!({"kind": "realm", "realm_id": realm_id})),
            )
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
            let actor = envelope.sender_actor_id.as_str();
            let device = envelope.sender_device_id.as_str();
            if !matches!(
                crate::identity::device_directory::cached_device_signing_key(actor, device),
                crate::identity::device_directory::CacheLookup::Miss
            ) {
                // A fresh positive or negative verdict already exists. Only a
                // miss is worth a network call, and the directory's negative
                // TTL is what bounds how often an unknown sender can trigger
                // one.
                return;
            }
            let Some(api) = self.authenticated_api() else {
                return;
            };
            let anchor = crate::identity::did_resolver::ResolverDidAnchor::from_profile(
                crate::identity::did_resolver::DeploymentProfile::PersonalNode,
                self.did_cache.peek().clone(),
            );
            let _ = crate::identity::device_directory::resolve_device_signing_key(
                &api, &anchor, actor, device,
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
            let local_actor = self.account_did.peek().clone();
            let api = self.authenticated_api();
            // A fresh anchor per batch keeps the resolver's ingested evidence
            // scoped to this routing pass; the (possibly back-filled) cache is
            // written back so the next Signal reuses the resolution.
            let anchor = crate::identity::did_resolver::ResolverDidAnchor::from_profile(
                crate::identity::did_resolver::DeploymentProfile::PersonalNode,
                self.did_cache.peek().clone(),
            );
            crate::views::call_signals::route_decrypted_call_signals(
                &mut hub,
                std::slice::from_ref(&(envelope.clone(), body)),
                &local_actor,
                api.as_ref(),
                &anchor,
            )
            .await;
            let mut did_cache = self.did_cache;
            did_cache.set(anchor.into_cache());
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

    fn advance_clock(&self, now: chrono::DateTime<chrono::Utc>) {
        let mut hub = self.message_hub;
        hub.maintain(now);
    }
}
