use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chime::{ChimePushRegisterDeviceRequest, ChimePushUnregisterDeviceRequest, CokretPushClient};
use cokret_sdk::ErrorEnvelope;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{OnceCell, RwLock};
use url::Url;

/// A token that can be used to cancel in-flight API requests.
#[derive(Clone, Debug)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PrincipalAuthBridgeDescribeView {
    pub contract: String,
    pub version: String,
    pub api_base_path: String,
    pub auth: PrincipalAuthBridgeAuthDescriptor,
    pub push: PrincipalAuthBridgePushDescriptor,
    pub examples: PrincipalAuthBridgeExamples,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PrincipalAuthBridgeAuthDescriptor {
    pub dev_login_path: String,
    pub principal_id_body_field: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PrincipalAuthBridgePushDescriptor {
    pub register_device_path: String,
    pub unregister_device_path: String,
    pub session_grant_header: String,
    pub principal_id_body_field: String,
    pub register_device_mode: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PrincipalAuthBridgeExamples {
    #[serde(default)]
    pub session_grant_issue_request: Value,
    #[serde(default)]
    pub register_device_request: Value,
    #[serde(default)]
    pub unregister_device_request: Value,
}

pub use cokret_sdk::SessionGrantIntrospectionProof;

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Cancel all requests using this token.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    /// Check if cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

use crate::config::validate_server_url;
use crate::identity_handle::parse_user_handle;
use crate::models::{
    AccountDataSetResult, AuthzCheckOutcome, BackfillView, BlobUploadOutcome, ContactListView,
    CurrentAccount, DeviceMessagesAckOutcome, DeviceMessagesAckRequestBody,
    DeviceMessagesGetOutcome, DeviceMessagesSendOutcome, DeviceTrustView, DirectoryDescription,
    GrantList, IdentityDescribeOutcome, IdentityResolveOutcome, IndexSearchView, KeysClaimOutcome,
    KeysQueryOutcome, KeysUploadOutcome, MediaIceConfigOutcome, MediaIceConfigRequestBody,
    ModerationReportOutcome, OP_SNAPSHOT_HEAD, OkOutcome, PresenceResult, PushRegisterView,
    RealmCreateResult, RealmJoinCandidate, RealmPolicyResult, ReceiptResult, ResolveHandleView,
    ResolveRealmOutcome, SearchActorsView, SearchOrganizationsView, ServerDescription,
    SpaceCreateResult, SubmitEventResult, TypingResult, VerifyDeviceResult,
};
use crate::operation::{EventKind, OperationBuilder, trim_realm_id, uuid_v7};

#[derive(Clone)]
pub struct CokretApi {
    base_url: Url,
    pub(crate) http: Client,
    authorization_credential: Option<String>,
    wait_for_sync_token: Option<String>,
    /// Coauth-issued session grant and optional introspection proof headers
    /// used by chime push register/unregister calls.
    chime_session_grant: Option<String>,
    chime_session_grant_proof: Option<SessionGrantIntrospectionProof>,
    network_state: Arc<RwLock<NetworkState>>,
    cancel_token: Option<CancellationToken>,
    /// SPEC-CR-001 — `ck.session.grant` signing key + its `keyid`. When set,
    /// requests to the `/_cokret/self/*` surface carry an RFC 9421 PoP
    /// signature (api-conventions.md §3.2).
    session_signing_key: Option<ed25519_dalek::SigningKey>,
    session_key_id: Option<String>,
    /// ②(A+②) — grant-binding (DPoP) key. When set together with a grant in
    /// `authorization_credential`, every `/_cokret/self/*` request carries a freshly-minted
    /// per-request `DPoP` proof (RFC 9449) bound to `htm`/`htu`/`ath=hash(grant)`
    /// (api-conventions.md §3.3). This is the default `/_cokret/self/*` session
    /// presentation: the held credential is the
    /// grant in `authorization_credential`, sender-constrained by this DPoP key.
    dpop_device: Option<crate::account_auth::grant_dpop::DpopHandle>,
    /// Cached `GET /_cokret/self/events/describe` response (spec
    /// `ServiceDescribe` shape) so repeat callers avoid re-hitting the
    /// network.
    events_describe_cache: Arc<OnceCell<cokret_sdk::ServiceDescribe>>,
    /// Cached `GET /_cokret/describe` response used to bind durable
    /// EventProof signatures to this service's trust domain and audience.
    service_describe_cache: Arc<OnceCell<ServerDescription>>,
}

impl fmt::Debug for CokretApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CokretApi")
            .field("base_url", &self.base_url)
            .field(
                "authorization_credential",
                &self.authorization_credential.as_ref().map(|_| "<redacted>"),
            )
            .field("wait_for_sync_token", &self.wait_for_sync_token)
            .field(
                "chime_session_grant",
                &self.chime_session_grant.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "chime_session_grant_proof",
                &self.chime_session_grant_proof.as_ref().map(|_| "<proof>"),
            )
            .field("cancel_token", &self.cancel_token)
            .field("dpop_device", &self.dpop_device.as_ref().map(|h| h.jkt()))
            .field(
                "events_describe_cache",
                &self
                    .events_describe_cache
                    .get()
                    .map(|_| "<cached>")
                    .unwrap_or("<empty>"),
            )
            .field(
                "service_describe_cache",
                &self
                    .service_describe_cache
                    .get()
                    .map(|_| "<cached>")
                    .unwrap_or("<empty>"),
            )
            .finish()
    }
}

/// Network connectivity state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkState {
    Online,
    Offline,
    Reconnecting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CokretApiOptions {
    pub timeout: Duration,
}

impl Default for CokretApiOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }
}

/// Context for `ck.find.directory.query.resolve_handle`.
///
/// Protocol distinction: `lookup` / `mention` are display-safe resolves;
/// `member_add` / `invite` request Realm/audience-bound membership-builder
/// material. Callers that are about to invite or add a member MUST provide
/// `intent`, `requester`, `realm_id`, and `audience`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ResolveHandleContext<'a> {
    pub intent: Option<&'a str>,
    pub requester: Option<&'a str>,
    pub audience: Option<&'a str>,
    pub realm_id: Option<&'a str>,
    pub expected_did: Option<&'a str>,
    pub proof_challenge: Option<&'a str>,
    pub proofs: &'a [&'a str],
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("Cokret API returned {status}: {error}")]
pub struct CokretApiError {
    pub status: StatusCode,
    pub error: ErrorEnvelope,
}

mod account;
mod agent;
mod applet;
// YGN-ARCH-01 step 1: authenticated-client builders + `with_authed_api*`
// wrapper moved here from `views/helpers.rs` (pure move; the helpers module
// re-exports them for existing view call sites).
mod authed;
mod blob;
mod blob_resumable;
// YOU-07-001: realm event / envelope builders moved out to `builders`.
// Re-exports preserve `crate::api::build_*` and sibling submodule `use super::*`
// resolution paths.
mod builders;
mod circle;
mod directory;
// Structural split: server error-envelope classifiers, account-subscribe gate /
// reconnect result types, the `wait_for` normalizer, and the blob-presign error
// class moved out of this file into `error_classify` (move only). The glob
// re-export keeps the `crate::api::*` public paths and sibling/tests `use
// super::*` resolution unchanged.
mod error_classify;
// Structural split: ephemeral / durable envelope builders + submit-acceptance
// helpers moved out of this file into `ephemeral` (move only).
mod ephemeral;
mod events;
// YOU-07-001: HTTP plumbing helpers (error decode, URL/query encoding, NDJSON
// subscribe parsing, small response parsers) moved out of this file into
// `http_helpers` and crate-root helpers. The glob re-export keeps the
// `crate::api::*` public paths and sibling/tests `use super::*` resolution
// unchanged.
mod http_helpers;
mod keys;
mod media;
mod mls;
mod moderation;
mod push;
mod realm;
// Structural split: directory resolve-handle request-body builders moved out of
// this file into `request_helpers` (move only). Kept `pub(crate)` so `directory`
// and tests reach them through `super::*`.
mod request_helpers;
// YOU-07-001: sync / account-subscribe parsers now live at crate root so E2 can
// delete `src/api/**` without carrying parser code in the old API module. The
// re-export keeps `crate::api::parse_sync` and sibling/tests `use super::*`
// resolution paths unchanged during the strangler migration.
// Structural split: core `impl CokretApi` HTTP transport (constructor, builder
// methods, SDK client construction, network state, and legacy URL helper)
// moved out of this file into `transport` (move only). All `impl CokretApi`
// inherent methods, so no free-item re-export is needed.
mod transport;
// Structural split: projection view models + recommended-encryption constants
// moved out of this file into `views` (move only). The glob re-export keeps the
// `crate::api::*` public paths and sibling/tests `use super::*` resolution unchanged.
mod views;
// Structural split: the former inline `#[cfg(test)] mod tests { … }` moved to
// `tests.rs` (move only); `use super::*` resolves against this module unchanged.
#[cfg(test)]
mod tests;

pub use authed::*;
pub use builders::*;
pub use ephemeral::*;
pub use error_classify::*;
pub use http_helpers::*;
pub(crate) use mls::{generate_mls_claim_nonce, keypackage_claim_record_to_mls_record};
pub(crate) use request_helpers::*;
pub use views::*;

pub use crate::sync_parse::*;
pub use crate::wire_helpers::*;

/// PoP signature validity window (seconds). Kept well under the 300s protocol
/// maximum (api-conventions.md §3.2) while tolerating modest clock skew.
const POP_SIGNATURE_WINDOW_SECONDS: i64 = 120;

// The RFC 7638 Ed25519 JWK thumbprint (the `keyid` soland accepts for the PoP
// binding check) is derived through `cokret_sdk::dpop`, keeping the PoP `jkt`
// and DPoP `jkt` on the same shared implementation.
