//! A conformance-only crash point after real authenticated admission. It never
//! changes a request or invents an authority answer.
use std::sync::{Arc, Mutex, OnceLock};

use arkret_models_collaboration::authority_commit::{
    SelfAuthoritySubmitRequestBody, SelfAuthoritySubmitResponseBody,
};
use arkret_sdk::http_client::ClientRequestOptions;
use arkret_sdk::http_client::own_station_results::OwnStationStateClient;
use arkret_sdk::*;
use garth::AuthorityTransport;

struct LostResponse {
    account: AccountId,
    scope: ScopeRef,
    accepted: Mutex<Option<(SelfAuthoritySubmitRequestBody, RealmCommit)>>,
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
        let mut slot = slot()
            .lock()
            .map_err(|_| anyhow::anyhow!("response-loss observer lock poisoned"))?;
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

    pub async fn accepted(&self) -> anyhow::Result<(SelfAuthoritySubmitRequestBody, RealmCommit)> {
        self.0.ready.notified().await;
        self.0
            .accepted
            .lock()
            .map_err(|_| anyhow::anyhow!("accepted response lock poisoned"))?
            .clone()
            .ok_or_else(|| {
                anyhow::anyhow!("response-loss observer signaled without accepted evidence")
            })
    }
}

impl Drop for MessageResponseLoss {
    fn drop(&mut self) {
        let Ok(mut slot) = slot().lock() else {
            return;
        };
        if slot
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &self.0))
        {
            *slot = None;
        }
    }
}

pub(crate) struct ObservedTransport(pub OwnStationStateClient);

impl AuthorityTransport for ObservedTransport {
    async fn submit(
        &self,
        request: &VerifiedSubmission<AuthoritySubmitRequestBody>,
        options: &ClientRequestOptions,
    ) -> garth::Result<AuthoritySubmitResponseBody> {
        AuthorityTransport::submit(&self.0, request, options).await
    }

    async fn submit_self(
        &self,
        request: &VerifiedSubmission<SelfAuthoritySubmitRequestBody>,
        options: &ClientRequestOptions,
    ) -> garth::Result<SelfAuthoritySubmitResponseBody> {
        let outcome = AuthorityTransport::submit_self(&self.0, request, options).await?;
        let observer = slot()
            .lock()
            .map_err(|_| garth::Error::Storage("response-loss observer lock poisoned".into()))?
            .clone();
        if let Some(observer) = observer
            && let SelfAuthoritySubmitRequestBody::Event(submission) = request.wire()
            && submission.event.kind == EventKind::MessageCreate
            && submission.event.actor_id == ActorId::account(observer.account.clone())
            && submission.event.scope_ref == observer.scope
            && let SelfAuthoritySubmitResponseBody::Ordinary(
                AuthoritySubmitResponseBody::Accepted {
                    status: AuthorityCommitStatus::Committed,
                    commit,
                },
            ) = &outcome
        {
            *observer
                .accepted
                .lock()
                .map_err(|_| garth::Error::Storage("accepted response lock poisoned".into()))? =
                Some((request.wire().clone(), commit.clone()));
            observer.ready.notify_one();
            // The durable queue has recorded Forwarding, but cannot consume
            // this genuine reply. Cancellation models a crashed client.
            std::future::pending::<()>().await;
        }
        Ok(outcome)
    }

    async fn scan(&self, request: &StreamScanRequestBody) -> garth::Result<StreamScanResponseBody> {
        AuthorityTransport::scan(&self.0, request).await
    }
    async fn authority_bundle(
        &self,
        request: &RealmAuthorityBundleRequestBody,
    ) -> garth::Result<RealmAuthorityBundle> {
        AuthorityTransport::authority_bundle(&self.0, request).await
    }
    async fn install_handoff(
        &self,
        request: &AuthorityRealmAuthorityHandoffRequestBody,
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
