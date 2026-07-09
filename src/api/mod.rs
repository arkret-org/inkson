#[cfg(test)]
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use tokio::sync::OnceCell;
use url::Url;

use crate::config::validate_server_url;
use crate::models::{
    BlobUploadOutcome, DeviceMessagesAckOutcome,
    DeviceMessagesAckRequestBody, DeviceMessagesGetOutcome, DeviceMessagesSendOutcome,
    OP_SNAPSHOT_HEAD, RealmJoinCandidate, ResolveHandleView,
    ServerDescription, SubmitEventResult,
};
use crate::wire_helpers::{canonical_blob_ref, safe_blob_filename_header};

#[derive(Clone)]
pub struct CokretApi {
    base_url: Url,
    pub(crate) http: Client,
    authorization_credential: Option<String>,
    wait_for_sync_token: Option<String>,
    /// ②(A+②) — grant-binding (DPoP) key. When set together with a grant in
    /// `authorization_credential`, every `/_cokret/self/*` request carries a freshly-minted
    /// per-request `DPoP` proof (RFC 9449) bound to `htm`/`htu`/`ath=hash(grant)`
    /// (api-conventions.md §3.3). This is the default `/_cokret/self/*` session
    /// presentation: the held credential is the
    /// grant in `authorization_credential`, sender-constrained by this DPoP key.
    dpop_device: Option<crate::account_auth::grant_dpop::DpopHandle>,
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
            .field("dpop_device", &self.dpop_device.as_ref().map(|h| h.jkt()))
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

mod account;
mod blob;
mod blob_resumable;
mod directory;
mod keys;
mod mls;
mod realm;
// YOU-07-001: sync / account-subscribe parsers now live at crate root so E2 can
// delete `src/api/**` without carrying parser code in the old API module.
// Structural split: core `impl CokretApi` HTTP transport (constructor, builder
// methods, SDK client construction, network state, and legacy URL helper)
// moved out of this file into `transport` (move only). All `impl CokretApi`
// inherent methods, so no free-item re-export is needed.
mod transport;
// Structural split: the former inline `#[cfg(test)] mod tests { … }` moved to
// `tests.rs` (move only); `use super::*` resolves against this module unchanged.
#[cfg(test)]
mod tests;
