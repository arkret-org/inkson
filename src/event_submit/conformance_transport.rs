//! A conformance-only crash point after real authenticated admission. It never
//! changes a request or invents an authority answer.
use std::sync::{Arc, Mutex, OnceLock};

use arkret_sdk::http_client::ClientRequestOptions;
use arkret_sdk::http_client::own_station_results::OwnStationResultClient;
use arkret_sdk::*;
use garth::AuthorityTransport;

struct LostResponse {
    account: AccountId,
    scope: ScopeRef,
    accepted: Mutex<Option<(SelfAuthoritySubmitRequest, RealmCommit)>>,
    ready: tokio::sync::Notify,
}

fn slot() -> &'static Mutex<Option<Arc<LostResponse>>> {
    static SLOT: OnceLock<Mutex<Option<Arc<LostResponse>>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

/// Holding this guard only loses the response of the exact Account/scope's
/// next real accepted ordinary Message. Drop the send future at `accepted()`.
pub struct MessageResponseLoss(Arc<LostResponse>);

impl MessageResponseLoss {
    pub fn arm(account: AccountId, scope: ScopeRef) -> anyhow::Result<Self> {
        let mut slot = slot().lock().unwrap();
        anyhow::ensure!(slot.is_none(), "another response-loss observer is active");
        let state = Arc::new(LostResponse {
            account,
            scope,
            accepted: Mutex::new(None),
            ready: tokio::sync::Notify::new(),
        });
        *slot = Some(state.clone());
        Ok(Self(state))
    }

    pub async fn accepted(&self) -> (SelfAuthoritySubmitRequest, RealmCommit) {
        self.0.ready.notified().await;
        self.0.accepted.lock().unwrap().clone().unwrap()
    }
}

impl Drop for MessageResponseLoss {
    fn drop(&mut self) {
        let mut slot = slot().lock().unwrap();
        if slot
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &self.0))
        {
            *slot = None;
        }
    }
}

pub(crate) struct ObservedTransport(pub OwnStationResultClient);

impl AuthorityTransport for ObservedTransport {
    async fn submit(
        &self,
        request: &VerifiedSubmission<AuthoritySubmitRequest>,
        options: &ClientRequestOptions,
    ) -> garth::Result<AuthoritySubmitOutcome> {
        AuthorityTransport::submit(&self.0, request, options).await
    }

    async fn submit_self(
        &self,
        request: &VerifiedSubmission<SelfAuthoritySubmitRequest>,
        options: &ClientRequestOptions,
    ) -> garth::Result<SelfAuthoritySubmitOutcome> {
        let outcome = AuthorityTransport::submit_self(&self.0, request, options).await?;
        let observer = slot().lock().unwrap().clone();
        if let Some(observer) = observer
            && let SelfAuthoritySubmitRequest::Event(submission) = request.wire()
            && submission.event.kind == EventKind::MessageCreate
            && submission.event.actor_id == ActorId::account(observer.account.clone())
            && submission.event.scope_ref == observer.scope
            && let SelfAuthoritySubmitOutcome::Ordinary(AuthoritySubmitOutcome::Accepted {
                status: AuthorityCommitStatus::Committed,
                commit,
            }) = &outcome
        {
            *observer.accepted.lock().unwrap() = Some((request.wire().clone(), commit.clone()));
            observer.ready.notify_one();
            // The durable queue has recorded Forwarding, but cannot consume
            // this genuine reply. Cancellation models a crashed client.
            std::future::pending::<()>().await;
        }
        Ok(outcome)
    }

    async fn scan(&self, request: &StreamScanRequest) -> garth::Result<StreamScanOutcome> {
        AuthorityTransport::scan(&self.0, request).await
    }
    async fn authority_bundle(
        &self,
        request: &AuthorityBundleRequest,
    ) -> garth::Result<RealmAuthorityBundle> {
        AuthorityTransport::authority_bundle(&self.0, request).await
    }
    async fn install_handoff(
        &self,
        request: &AuthorityHandoffRequest,
        options: &ClientRequestOptions,
    ) -> garth::Result<RealmAuthorityHandoff> {
        AuthorityTransport::install_handoff(&self.0, request, options).await
    }
    async fn exact_snapshot(
        &self,
        realm: &RealmId,
        snapshot: &RealmSnapshotId,
    ) -> garth::Result<RealmStateSnapshot> {
        AuthorityTransport::exact_snapshot(&self.0, realm, snapshot).await
    }
}
