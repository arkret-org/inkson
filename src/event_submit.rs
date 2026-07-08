//! `EventSubmitter` — the CokretApi-free durable/ephemeral event submission
//! engine. Holds the authenticated SDK http-client plus a lazily-populated,
//! per-instance service-describe cache. The cache lifetime matches the former
//! per-`CokretApi` `OnceCell`: the signing path (`event_proof_context`) fetches
//! `describe` at most once per submitter, and non-signing paths
//! (`submit_signed_*`, ephemeral, frontier, backfill) never fetch it.

#[cfg(test)]
use cokret_sdk::ErrorEnvelope;
use reqwest::StatusCode;
use serde_json::Value;
use tokio::sync::OnceCell;

use crate::api_error::CokretApiError;
use crate::ephemeral::{
    attach_broadcast_ephemeral_proof, build_presence_envelope, build_receipt_read_envelope,
    build_typing_envelope, ensure_events_submit_accepted,
    validate_outgoing_registered_event_payload,
};
use crate::models::{
    BackfillView, PresenceResult, ReceiptResult, ServerDescription, SubmitEventResult, TypingResult,
};
use crate::operation::uuid_v7;
#[cfg(test)]
use crate::service_parse::parse_server_description;
use crate::wire_helpers::query_component;

/// Authenticated durable/ephemeral event submission engine extracted from the
/// former `CokretApi` events surface. Constructed per authenticated call from
/// the shared SDK http-client (see `crate::authed_api::with_event_submitter`).
pub struct EventSubmitter {
    http: cokret_sdk::http_client::Client,
    describe_cache: OnceCell<ServerDescription>,
}

impl EventSubmitter {
    pub fn new(http: cokret_sdk::http_client::Client) -> Self {
        Self {
            http,
            describe_cache: OnceCell::new(),
        }
    }

    async fn describe(&self) -> anyhow::Result<ServerDescription> {
        self.http
            .describe()
            .await
            .map_err(|error| anyhow::anyhow!("server describe: {error}"))
    }

    /// Lazily fetch + cache the service describe for this submitter. Only the
    /// signing path calls this, so a submitter that never signs never fetches.
    async fn describe_cached(&self) -> anyhow::Result<&ServerDescription> {
        self.describe_cache
            .get_or_try_init(|| async { self.describe().await })
            .await
    }

    /// Mint a DataEvent `seal_ref` head from the membership-gated Realm Seal
    /// view. Only the CBA data-plane stamping path uses this.
    pub(crate) async fn current_seal_for(&self, realm_id: &str) -> anyhow::Result<String> {
        let view = self.events_frontier_realm_seal_view(realm_id).await?;
        Ok(view.seal_id.to_string())
    }
    /// Query durable events through the current `/_cokret/self/events` surface,
    /// following pagination to completion (COR-07).
    pub async fn backfill(&self, realm_id: &str) -> anyhow::Result<BackfillView> {
        let outcome = self
            .http
            .events_query_all_pages(realm_id)
            .await
            .map_err(anyhow::Error::from)?;
        Ok(outcome.into())
    }

    pub(crate) async fn find_mls_genesis_event_id(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<Option<cokret_sdk::EventId>> {
        // COR-07: the MLS genesis event may sit past the first page; paginate so
        // it is never silently judged "absent" because of front-page noise.
        let outcome = self
            .http
            .events_query_all_pages(realm_id)
            .await
            .map_err(anyhow::Error::from)?;
        Ok(mls_genesis_event_id_from_events(&outcome, realm_id))
    }

    /// Stream the canonical `/_cokret/self/events/subscribe` NDJSON response and
    /// invoke `on_frame` once per parsed frame.
    ///
    /// Round R2/R3 (T02) — typing notifications are wire-scope-ephemeral
    /// (`ck.typing`). They MUST strand through the canonical
    /// `ck.self.ephemeral.command.send` operation (`POST /_cokret/self/ephemeral`), never
    /// through `ck.self.events.command.submit` or a deployment-local typing shim.
    pub async fn send_typing(
        &self,
        realm_id: &str,
        actor: &str,
        device_id: &str,
        strand_id: &str,
        typing: bool,
    ) -> anyhow::Result<TypingResult> {
        let mut envelope = build_typing_envelope(realm_id, actor, device_id, strand_id, typing)?;
        attach_broadcast_ephemeral_proof(&mut envelope)?;
        let response = self.submit_ephemeral_envelope(&envelope).await?;
        Ok(TypingResult {
            ok: response.accepted,
        })
    }

    pub async fn send_presence(
        &self,
        realm_id: &str,
        actor: &str,
        device_id: &str,
        state: &str,
        status_message: Option<&str>,
        last_active_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> anyhow::Result<PresenceResult> {
        let mut envelope = build_presence_envelope(
            realm_id,
            actor,
            device_id,
            state,
            status_message,
            last_active_at,
        )?;
        attach_broadcast_ephemeral_proof(&mut envelope)?;
        let response = self.submit_ephemeral_envelope(&envelope).await?;
        Ok(PresenceResult {
            ok: response.accepted,
        })
    }

    /// Round R2/R3 (T02) — read receipts (`ck.receipt.read`) are wire-scope-
    /// ephemeral. They MUST strand through `ck.self.ephemeral.command.send`; the
    /// `ck.self.events.command.submit` durable path and deployment-local `/receipts`
    /// shims MUST NOT be used.
    pub async fn send_receipt(
        &self,
        realm_id: &str,
        actor: &str,
        device_id: &str,
        strand_id: &str,
        event_id: &str,
        receipt_type: &str,
    ) -> anyhow::Result<ReceiptResult> {
        // Only `ck.receipt.read` is an ephemeral receipt; other receipt
        // types (delivered/franking/etc.) stay on their own paths. Guard
        // the kind here so we don't accidentally widen the contract.
        if receipt_type != "ck.receipt.read" {
            anyhow::bail!("unsupported ephemeral receipt_type {receipt_type:?}");
        }
        let mut envelope =
            build_receipt_read_envelope(realm_id, actor, device_id, strand_id, event_id)?;
        attach_broadcast_ephemeral_proof(&mut envelope)?;
        let response = self.submit_ephemeral_envelope(&envelope).await?;
        Ok(ReceiptResult {
            ok: response.accepted,
        })
    }

    /// `GET /_cokret/self/events/frontier?realm_id=` — Realm Seal view
    /// `{realm_id, seal_id, control_event_set_root, state_root, hlc?}`.
    ///
    /// This is the spec-registered account-client sourcing for minting a
    /// single-leaf Control Move `seal_basis` (`view.seal_basis()`) and a
    /// DataEvent `seal_ref` (`view.seal_id`) — SPEC-SOL-003 resolution.
    /// Fails closed (never fabricates a basis) when the server cannot
    /// serve the view or answers for a different Realm.
    pub async fn events_frontier_realm_seal_view(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<cokret_sdk::RealmSealFrontierView> {
        let realm_id_query = query_component(realm_id);
        let state: cokret_sdk::EventsFrontierAccountClientState = self
            .http
            .get(&format!(
                "/_cokret/self/events/frontier?realm_id={realm_id_query}"
            ))
            .await
            .map_err(anyhow::Error::from)?;
        let cokret_sdk::EventsFrontierView::RealmSealView(view) = state.frontier else {
            anyhow::bail!(
                "events/frontier for realm_id={realm_id} did not return a Realm Seal view — \
                 cannot mint seal_basis / seal_ref"
            );
        };
        if view.realm_id.as_str() != realm_id {
            anyhow::bail!(
                "events/frontier answered for realm {} instead of {realm_id}",
                view.realm_id
            );
        }
        Ok(view)
    }

    /// `GET /_cokret/self/events/frontier?actor_id=` — actor frontier
    /// `{actor_id, actor_seq, event_id}` (highest accepted actor_seq
    /// visible to the caller).
    pub async fn events_frontier_actor(
        &self,
        actor_id: &str,
    ) -> anyhow::Result<cokret_sdk::ActorFrontierView> {
        let actor_id_query = query_component(actor_id);
        let state: cokret_sdk::EventsFrontierAccountClientState = self
            .http
            .get(&format!(
                "/_cokret/self/events/frontier?actor_id={actor_id_query}"
            ))
            .await
            .map_err(anyhow::Error::from)?;
        let cokret_sdk::EventsFrontierView::Actor(view) = state.frontier else {
            anyhow::bail!(
                "events/frontier for actor_id={actor_id} did not return an actor frontier"
            );
        };
        Ok(view)
    }

    /// `GET /_cokret/self/events/describe` — spec binds the response to the
    /// canonical `ServiceDescribe` shape (OpenAPI `ck.self.events.query.describe`).
    /// YOU-01-016: the former soland-private `SolandEventsDescribeResBody`
    /// mirror (with its non-spec `capabilities` blob) was removed.
    pub async fn events_describe(&self) -> anyhow::Result<cokret_sdk::ServiceDescribe> {
        self.http
            .events_describe()
            .await
            .map_err(|error| anyhow::anyhow!("events describe: {error}"))
    }

    pub(crate) async fn event_proof_context(
        &self,
    ) -> anyhow::Result<crate::event_signer::EventProofContext> {
        let describe = self.describe_cached().await?;
        Ok(event_proof_context_from_description(describe))
    }

    /// Wire-submit a fully-prepared, already-signed SDK [`cokret_sdk::Event`].
    /// This is the only single-event HTTP tail that serialises onto
    /// `POST /_cokret/self/events`.
    async fn post_signed_sdk_event(
        &self,
        signed: &cokret_sdk::Event,
        idempotency_key: String,
    ) -> anyhow::Result<SubmitEventResult> {
        validate_signed_sdk_event_for_submit(signed)?;
        let response: cokret_sdk::EventsSubmitOutcome = self
            .http
            .events_submit_with_options(
                signed,
                &cokret_sdk::http_client::ClientRequestOptions::new()
                    .request_id(idempotency_key.clone())
                    .idempotency_key(idempotency_key),
            )
            .await
            .map_err(anyhow::Error::from)?;
        ensure_events_submit_accepted(&response)?;
        Ok(SubmitEventResult::from(response))
    }

    /// Submit a fully-prepared, already-signed SDK [`cokret_sdk::Event`]
    /// without passing through the local builder path.
    ///
    /// This is for service-returned Events that are already the authoritative
    /// wire object, such as account-authority device enrollment. It does not
    /// stamp `seal_ref` or attach proofs because either change would mutate the
    /// signed transcript.
    pub(crate) async fn submit_signed_sdk_event(
        &self,
        signed: &cokret_sdk::Event,
    ) -> anyhow::Result<SubmitEventResult> {
        self.post_signed_sdk_event(signed, uuid_v7()).await
    }

    /// Submit a SDK-typed Event, signing it with the active signer when needed.
    pub(crate) async fn submit_sdk_event(
        &self,
        event: &cokret_sdk::Event,
    ) -> anyhow::Result<SubmitEventResult> {
        let retry_actor_seq_cas = event.proofs.is_empty();
        let (signed, idempotency_key) = self.prepare_sdk_event_for_submit(event).await?;
        match self
            .post_signed_sdk_event(&signed, idempotency_key.clone())
            .await
        {
            Ok(result) => Ok(result),
            Err(error) if retry_actor_seq_cas && is_actor_seq_cas_conflict(&error) => {
                tracing::warn!(
                    event_id = %event.event_id,
                    actor_id = %event.actor_id,
                    kind = %event.kind,
                    "actor frontier advanced during SDK Event submit; refreshing and retrying once"
                );
                let (signed, idempotency_key) = self.prepare_sdk_event_for_submit(event).await?;
                self.post_signed_sdk_event(&signed, idempotency_key).await
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) async fn prepare_sdk_event_for_submit(
        &self,
        event: &cokret_sdk::Event,
    ) -> anyhow::Result<(cokret_sdk::Event, String)> {
        let mut signed = event.clone();
        self.refresh_unsigned_sdk_event_actor_frontier(&mut signed)
            .await?;
        self.stamp_cba_basis_for_sdk_event(&mut signed).await?;
        if signed.proofs.is_empty() {
            let proof_context = self.event_proof_context().await?;
            crate::event_signer::sign_sdk_event_with_active_context(&mut signed, proof_context)
                .map_err(|err| {
                    anyhow::anyhow!(
                        "no active signer configured \u{2014} cannot submit unsigned SDK Event: {err}"
                    )
                })?;
        }
        let idempotency_key = signed
            .unsigned
            .get("local_operation_idempotency_alias")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(uuid_v7);
        Ok((signed, idempotency_key))
    }

    pub(crate) async fn stamp_cba_basis_for_sdk_event(
        &self,
        event: &mut cokret_sdk::Event,
    ) -> anyhow::Result<()> {
        if event.seal_ref.is_some()
            || event.auth_context.is_some()
            || event.seal_basis.is_some()
            || event.effects.is_empty()
            || cba_exempt_reducer_kind(&event.kind)
        {
            return Ok(());
        }
        match cba_effect_plane_for_event(event)? {
            CbaEffectPlane::Control => {
                let seal_view = self
                    .events_frontier_realm_seal_view(event.realm_id.as_str())
                    .await?;
                event.seal_basis = Some(seal_view.seal_basis());
            }
            CbaEffectPlane::Data => {
                if !event.preconditions.is_empty() {
                    anyhow::bail!(
                        "DataEvent {} carries preconditions; CBA DataEvents must use effects + seal_ref + auth_context only",
                        event.event_id
                    );
                }
                let seal = self.current_seal_for(event.realm_id.as_str()).await?;
                event.seal_ref = Some(
                    cokret_sdk::SealId::new(seal)
                        .map_err(|err| anyhow::anyhow!("current seal id is invalid: {err}"))?,
                );
                event.auth_context = Some(data_event_auth_context(event)?);
            }
        }
        Ok(())
    }

    async fn refresh_unsigned_sdk_event_actor_frontier(
        &self,
        event: &mut cokret_sdk::Event,
    ) -> anyhow::Result<()> {
        if !event.proofs.is_empty() {
            return Ok(());
        }
        let actor_id = event.actor_id.as_str().to_owned();
        match self.events_frontier_actor(&actor_id).await {
            Ok(frontier) => apply_actor_frontier_to_sdk_event(event, &frontier),
            Err(error) if is_actor_frontier_absent(&error) => {
                event.actor_seq = 1;
                event.prev_refs.clear();
                tracing::debug!(
                    actor_id = %actor_id,
                    event_id = %event.event_id,
                    "no actor frontier visible; submitting actor-chain genesis event"
                );
                Ok(())
            }
            Err(error) => Err(anyhow::anyhow!(
                "refresh actor frontier for {} before submit: {error}",
                actor_id
            )),
        }
    }

    /// `ck.self.events.command.submit` in batch form over typed envelopes. Spec binds
    /// events.submit to `POST /_cokret/self/events` and distinguishes the three
    /// accepted body shapes (single envelope,
    /// [`cokret_sdk::EventsSubmitBatchRequestBody`],
    /// [`cokret_sdk::EventsSubmitFederationRequestBody`]) by JSON shape, not
    /// by URL suffix. The federation shape is S2S only and inkson MUST
    /// NEVER serialise it.
    ///
    /// SDK Events MUST already be signed by the caller (typically via
    /// `event_signer::sign_sdk_event_with_active_context`) — the batch path
    /// does not auto-sign because callers commonly need an atomic seal_ref +
    /// sign sequence the per-event helper cannot replicate.
    pub(crate) async fn submit_signed_sdk_events_batch(
        &self,
        sdk_events: &[cokret_sdk::Event],
        idempotency_key: Option<&str>,
    ) -> anyhow::Result<cokret_sdk::EventsSubmitOutcome> {
        // YOU-01-016: the former `capabilities.batch_submit` probe (a
        // non-spec soland capability field) was removed. The batch request
        // body is one of the three spec-defined `ck.self.events.command.submit`
        // shapes (distinguished by JSON shape), so it is sent
        // unconditionally — no capability negotiation exists in the spec.
        for sdk_event in sdk_events {
            validate_signed_sdk_event_for_submit(sdk_event)?;
        }
        let body = cokret_sdk::EventsSubmitBatchRequestBody {
            events: sdk_events.to_vec(),
            idempotency_key: idempotency_key.map(ToOwned::to_owned),
        };
        let idem = idempotency_key
            .map(ToOwned::to_owned)
            .unwrap_or_else(uuid_v7);
        let response: cokret_sdk::EventsSubmitOutcome = self
            .http
            .post_with_options(
                "/_cokret/self/events",
                &body,
                &cokret_sdk::http_client::ClientRequestOptions::new()
                    .request_id(idem.clone())
                    .idempotency_key(idem),
            )
            .await
            .map_err(anyhow::Error::from)?;
        ensure_events_submit_accepted(&response)?;
        Ok(response)
    }

    pub(crate) async fn submit_sdk_events_batch(
        &self,
        _realm_id: &str,
        mut events: Vec<cokret_sdk::Event>,
        idempotency_key: Option<&str>,
    ) -> anyhow::Result<cokret_sdk::EventsSubmitOutcome> {
        for event in &mut events {
            self.stamp_cba_basis_for_sdk_event(event).await?;
        }
        let proof_context = self.event_proof_context().await?;
        for event in &mut events {
            if event.proofs.is_empty() {
                crate::event_signer::sign_sdk_event_with_active_context(
                    event,
                    proof_context.clone(),
                )
                .map_err(|err| {
                    anyhow::anyhow!(
                        "no active signer configured \u{2014} cannot submit SDK Event batch: {err}"
                    )
                })?;
            }
        }
        self.submit_signed_sdk_events_batch(&events, idempotency_key)
            .await
    }

    /// Round R2/R3 (T02) — POST a broadcast ephemeral signal to the
    /// canonical ephemeral channel (`POST /_cokret/self/ephemeral`) instead of the
    /// durable `/_cokret/self/events` endpoint. The envelope MUST validate against
    /// `ck.schema.ephemeral_envelope.v1` (kind in
    /// {`ck.call.signal`, `ck.presence`, `ck.typing`, `ck.receipt.read`}, and
    /// `expires_at - sent_at <= 300_000` ms). The four broadcast ephemeral
    /// signal kinds MUST NOT travel via `ck.self.events.command.submit`; this method is
    /// the single approved network path.
    pub async fn submit_ephemeral_envelope(
        &self,
        envelope: &cokret_sdk::EphemeralEnvelope,
    ) -> anyhow::Result<cokret_sdk::EphemeralSubmitOutcome> {
        // Defensive re-validation. The constructor already enforced this,
        // but a caller could mutate a raw envelope in place between build
        // and submit. Fail fast with the canonical error code rather than
        // shipping a non-conformant payload to the wire.
        if !cokret_sdk::events::is_ephemeral_kind(&envelope.kind) {
            anyhow::bail!(
                "ephemeral submit: kind {:?} is not in the broadcast ephemeral allowlist",
                envelope.kind
            );
        }
        let window_ms = envelope
            .expires_at
            .signed_duration_since(envelope.sent_at)
            .num_milliseconds();
        if window_ms <= 0
            || (window_ms as u64) > cokret_sdk::EPHEMERAL_ABSOLUTE_HARD_CEILING_MS as u64
        {
            anyhow::bail!(
                "ephemeral submit: expires_at - sent_at = {window_ms} ms violates 5-minute ceiling"
            );
        }
        self.http
            .post("/_cokret/self/ephemeral", envelope)
            .await
            .map_err(anyhow::Error::from)
    }

    /// `POST /_cokret/gate/account/agent-key-pair` —
    /// `ck.gate.account.command.pair_agent_key`. The runtime generated the
    /// key and PoP; the controller signs `authorize_event` locally before this
    /// method submits the pairing request.
    async fn agent_key_pair(
        &self,
        body: &cokret_sdk::models::AgentKeyPairRequestBody,
    ) -> anyhow::Result<cokret_sdk::models::AgentKeyPairOutcome> {
        self.http
            .agent_key_pair(body)
            .await
            .map_err(anyhow::Error::from)
    }

    pub(crate) async fn agent_key_pair_with_authorize_event(
        &self,
        mut body: cokret_sdk::models::AgentKeyPairRequestBody,
        authorize_event: &cokret_sdk::Event,
    ) -> anyhow::Result<cokret_sdk::models::AgentKeyPairOutcome> {
        let (signed, _) = self.prepare_sdk_event_for_submit(authorize_event).await?;
        body.authorize_event = serde_json::to_value(signed)?;
        self.agent_key_pair(&body).await
    }
}

fn ensure_sdk_event_proofs_are_domain_bound(event: &cokret_sdk::Event) -> anyhow::Result<()> {
    for proof in &event.proofs {
        if proof
            .domain
            .as_deref()
            .is_none_or(|domain| domain.trim().is_empty())
        {
            anyhow::bail!(
                "event proof for {} is missing domain binding",
                event.event_id
            );
        }
        if proof.audience.is_none() {
            anyhow::bail!(
                "event proof for {} is missing audience binding",
                event.event_id
            );
        }
    }
    Ok(())
}

fn validate_signed_sdk_event_for_submit(event: &cokret_sdk::Event) -> anyhow::Result<()> {
    if event.proofs.is_empty() {
        anyhow::bail!(
            "submit refuses unsigned SDK Event (event_id={}, kind={})",
            event.event_id,
            event.kind.as_str()
        );
    }
    ensure_sdk_event_proofs_are_domain_bound(event)?;
    event.validate_proof_bindings().map_err(|err| {
        anyhow::anyhow!("event proof binding invalid for {}: {err}", event.event_id)
    })?;
    validate_outgoing_registered_event_payload(event.kind.as_str(), &event.payload)
}

fn is_actor_frontier_absent(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<CokretApiError>()
        .is_some_and(|api_error| api_error.status == StatusCode::NOT_FOUND)
}

fn is_actor_seq_cas_conflict(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<CokretApiError>()
        .is_some_and(|api_error| {
            api_error.status == StatusCode::CONFLICT
                && api_error.error.code() == "cas_conflict"
                && api_error.error.message().contains("actor_seq")
        })
}

fn apply_actor_frontier_to_sdk_event(
    event: &mut cokret_sdk::Event,
    frontier: &cokret_sdk::ActorFrontierView,
) -> anyhow::Result<()> {
    if frontier.actor_id.as_str() != event.actor_id.as_str() {
        anyhow::bail!(
            "actor frontier mismatch: event actor {} but frontier actor {}",
            event.actor_id,
            frontier.actor_id
        );
    }
    event.actor_seq = frontier.actor_seq.checked_add(1).ok_or_else(|| {
        anyhow::anyhow!("actor frontier sequence overflow for {}", event.actor_id)
    })?;
    event.prev_refs = vec![frontier.event_id.clone()];
    Ok(())
}

fn mls_genesis_event_id_from_events(
    outcome: &cokret_sdk::EventsQueryOutcome,
    realm_id: &str,
) -> Option<cokret_sdk::EventId> {
    outcome
        .events
        .iter()
        .find(|event| {
            event.realm_id.as_str() == realm_id
                && event.kind.as_str() == cokret_sdk::events::kinds::MLS_GENESIS
        })
        .map(|event| event.event_id.clone())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CbaEffectPlane {
    Data,
    Control,
}

const DATA_PLANE_CELL_FAMILIES: &[&str] = &[
    "ck.component.strand.discussion.timeline.v1",
    "ck.component.message.reactions.v1",
    "ck.component.pin.v1",
];

fn cba_exempt_reducer_kind(kind: &cokret_sdk::events::kinds::EventKind) -> bool {
    matches!(
        kind,
        cokret_sdk::events::kinds::EventKind::RealmCreate
            | cokret_sdk::events::kinds::EventKind::MemberState
            | cokret_sdk::events::kinds::EventKind::RealmDiscovery
            | cokret_sdk::events::kinds::EventKind::RealmHistoryVisibility
            | cokret_sdk::events::kinds::EventKind::RealmJoinRule
            | cokret_sdk::events::kinds::EventKind::RealmPlaintextVisibleServices
            | cokret_sdk::events::kinds::EventKind::RealmPolicyComponents
    )
}

fn cba_effect_plane_for_event(event: &cokret_sdk::Event) -> anyhow::Result<CbaEffectPlane> {
    let mut observed = None;
    for effect in &event.effects {
        let plane = if DATA_PLANE_CELL_FAMILIES.contains(&cba_cell_family(effect.cell.as_str())?) {
            CbaEffectPlane::Data
        } else {
            CbaEffectPlane::Control
        };
        match observed {
            Some(existing) if existing != plane => {
                anyhow::bail!(
                    "event {} mixes data-plane and control-plane effects",
                    event.event_id
                );
            }
            Some(_) => {}
            None => observed = Some(plane),
        }
    }
    observed.ok_or_else(|| anyhow::anyhow!("event {} has no effects", event.event_id))
}

fn cba_cell_family(cell: &str) -> anyhow::Result<&str> {
    let rest = cell
        .strip_prefix("ck:cell:")
        .ok_or_else(|| anyhow::anyhow!("effects[].cell must use ck:cell: prefix"))?;
    let (family, subject) = rest
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("effects[].cell must include family and subject"))?;
    if family.trim().is_empty() || subject.trim().is_empty() {
        anyhow::bail!("effects[].cell must include non-empty family and subject");
    }
    Ok(family)
}

fn data_event_auth_context(event: &cokret_sdk::Event) -> anyhow::Result<cokret_sdk::AuthContext> {
    let Some(authorization_ref) = event.authorization_ref.as_deref() else {
        anyhow::bail!(
            "DataEvent {} requires authorization_ref so auth_context.capability_refs can be pinned",
            event.event_id
        );
    };
    if !authorization_ref.starts_with("ck:grant:") {
        anyhow::bail!(
            "DataEvent {} authorization_ref must be a ck:grant:* capability ref for auth_context",
            event.event_id
        );
    }
    let did = event
        .executed_by
        .clone()
        .unwrap_or_else(|| event.actor_id.clone());
    let key_id = data_event_key_id_for(event);
    Ok(cokret_sdk::AuthContext {
        did,
        key_id,
        key_epoch: 0,
        credential_epoch: None,
        capability_refs: vec![authorization_ref.to_owned()],
    })
}

fn data_event_key_id_for(event: &cokret_sdk::Event) -> String {
    let controller = event
        .executed_by
        .as_ref()
        .map(|did| did.as_str())
        .unwrap_or_else(|| event.actor_id.as_str());
    let Some(signer) = crate::event_signer::active_signer() else {
        return "device".to_owned();
    };
    if let Some(device_id) = signer.device_id() {
        return device_id.to_owned();
    }
    let method = signer.verification_method();
    let method_without_query = method
        .split_once('?')
        .map(|(head, _)| head)
        .unwrap_or(method);
    let Some((method_controller, fragment)) = method_without_query.split_once('#') else {
        return "device".to_owned();
    };
    if method_controller == controller && !fragment.is_empty() {
        fragment.to_owned()
    } else {
        "device".to_owned()
    }
}

fn event_proof_context_from_description(
    describe: &ServerDescription,
) -> crate::event_signer::EventProofContext {
    let service_did = describe.service_did.to_string();
    crate::event_signer::EventProofContext::new()
        .with_domain(service_did.clone())
        .with_audience(crate::operation::EventProofAudience::Single(
            service_did.to_owned(),
        ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn sdk_event_without_proof(actor_id: &str) -> cokret_sdk::Event {
        serde_json::from_value(json!({
            "event_id": "ck:event:01904100-0000-7000-8000-000000000001",
            "kind": "ck.presence",
            "realm_id": "ck:realm:01904100-0000-7000-8000-000000000001",
            "actor_id": actor_id,
            "actor_seq": 1,
            "created_at": "2026-05-19T00:00:00Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "payload": {
                "actor_id": actor_id,
                "state": "online"
            },
            "proofs": []
        }))
        .unwrap()
    }

    fn sdk_event_with_kind(
        event_id: &str,
        realm_id: &str,
        kind: &str,
        actor_id: &str,
    ) -> cokret_sdk::Event {
        serde_json::from_value(json!({
            "event_id": event_id,
            "kind": kind,
            "realm_id": realm_id,
            "actor_id": actor_id,
            "actor_seq": 1,
            "created_at": "2026-05-19T00:00:00Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "payload": {},
            "proofs": []
        }))
        .unwrap()
    }

    #[test]
    fn apply_actor_frontier_stamps_next_sequence_and_predecessor() {
        let mut event = sdk_event_without_proof("did:web:alice.example");
        let frontier = cokret_sdk::ActorFrontierView {
            actor_id: cokret_sdk::Did::new("did:web:alice.example").unwrap(),
            actor_seq: 7,
            event_id: cokret_sdk::EventId::new("ck:event:01904100-0000-7000-8000-000000000002")
                .unwrap(),
        };

        apply_actor_frontier_to_sdk_event(&mut event, &frontier).unwrap();

        assert_eq!(event.actor_seq, 8);
        assert_eq!(event.prev_refs, vec![frontier.event_id]);
    }

    #[test]
    fn apply_actor_frontier_rejects_wrong_actor() {
        let mut event = sdk_event_without_proof("did:web:alice.example");
        let frontier = cokret_sdk::ActorFrontierView {
            actor_id: cokret_sdk::Did::new("did:web:bob.example").unwrap(),
            actor_seq: 7,
            event_id: cokret_sdk::EventId::new("ck:event:01904100-0000-7000-8000-000000000002")
                .unwrap(),
        };

        let error = apply_actor_frontier_to_sdk_event(&mut event, &frontier)
            .unwrap_err()
            .to_string();

        assert!(error.contains("actor frontier mismatch"));
    }

    #[test]
    fn actor_seq_cas_conflict_classifier_is_narrow() {
        let cas: anyhow::Error = CokretApiError {
            status: StatusCode::CONFLICT,
            error: ErrorEnvelope::new(
                "cas_conflict",
                "actor_seq is older than the accepted actor frontier",
            ),
        }
        .into();
        assert!(is_actor_seq_cas_conflict(&cas));

        let different_conflict: anyhow::Error = CokretApiError {
            status: StatusCode::CONFLICT,
            error: ErrorEnvelope::new("cas_conflict", "expected head mismatch"),
        }
        .into();
        assert!(!is_actor_seq_cas_conflict(&different_conflict));
    }

    #[test]
    fn mls_genesis_event_lookup_filters_kind_and_realm() {
        let realm = "ck:realm:01904100-0000-7000-8000-000000000001";
        let other_realm = "ck:realm:01904100-0000-7000-8000-000000000099";
        let expected =
            cokret_sdk::EventId::new("ck:event:01904100-0000-7000-8000-000000000003").unwrap();
        let outcome = cokret_sdk::EventsQueryOutcome {
            events: vec![
                sdk_event_with_kind(
                    "ck:event:01904100-0000-7000-8000-000000000001",
                    realm,
                    "ck.message.create",
                    "did:web:alice.example",
                ),
                sdk_event_with_kind(
                    "ck:event:01904100-0000-7000-8000-000000000002",
                    other_realm,
                    "ck.mls.genesis",
                    "did:web:alice.example",
                ),
                sdk_event_with_kind(
                    expected.as_str(),
                    realm,
                    "ck.mls.genesis",
                    "did:web:alice.example",
                ),
            ],
            snapshot_bootstrap: None,
            next_cursor: None,
            prev_cursor: None,
            has_more: false,
            range_completeness: Value::Null,
        };

        assert_eq!(
            mls_genesis_event_id_from_events(&outcome, realm),
            Some(expected)
        );
        assert_eq!(
            mls_genesis_event_id_from_events(
                &outcome,
                "ck:realm:01904100-0000-7000-8000-000000000123"
            ),
            None
        );
    }

    #[test]
    fn event_proof_context_binds_domain_and_audience_to_service_did() {
        let describe = parse_server_description(json!({
            "service_did": "did:web:local.host",
            "trust_domain": "ck:trust_domain:local.host",
            "service_type": "principal_server",
            "protocol_version": "1.0",
            "supported_profiles": [
                "ck.profile.core_event_store.v1",
                "ck.profile.principal_server_events_api.v1"
            ],
            "supported_operations": [
                "ck.self.events.query.describe",
                "ck.self.events.command.submit"
            ],
            "supported_bindings": [{"kind": "http_json", "base_url": "https://local.host"}],
            "supported_features": ["ck.feature.soland.events.describe"],
            "auth_metadata": {"mode": "development"},
            "limits": {},
            "plaintext_visibility": {"default": "encrypted"},
            "implemented_features": ["ck.feature.soland.events.describe"],
            "claimed_profiles": [],
            "verified_profiles": [],
            "experimental_features": [],
            "compat_surfaces": [],
            "development_mode": true
        }))
        .unwrap();

        let context = event_proof_context_from_description(&describe);

        assert_eq!(context.domain.as_deref(), Some("did:web:local.host"));
        assert_eq!(
            context.audience,
            Some(crate::operation::EventProofAudience::Single(
                "did:web:local.host".to_owned()
            ))
        );
    }

    fn sdk_event_with_proof(domain: Option<&str>, audience: Option<&str>) -> cokret_sdk::Event {
        let mut proof = json!({
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": "did:web:alice.example#device-1",
            "event_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "created_at": "2026-05-19T00:00:00Z",
            "jws": "header.payload.signature"
        });
        if let Some(domain) = domain {
            proof["domain"] = json!(domain);
        }
        if let Some(audience) = audience {
            proof["audience"] = json!(audience);
        }
        serde_json::from_value(json!({
            "event_id": "ck:event:01904100-0000-7000-8000-000000000001",
            "kind": "ck.presence",
            "realm_id": "ck:realm:01904100-0000-7000-8000-000000000001",
            "actor_id": "did:web:alice.example",
            "actor_seq": 1,
            "created_at": "2026-05-19T00:00:00Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "payload": {
                "actor_id": "did:web:alice.example",
                "state": "online"
            },
            "proofs": [proof]
        }))
        .unwrap()
    }

    #[test]
    fn sdk_event_proof_gate_requires_domain_and_audience() {
        let ok = sdk_event_with_proof(Some("did:web:local.host"), Some("did:web:local.host"));
        ensure_sdk_event_proofs_are_domain_bound(&ok).unwrap();

        let missing_domain = sdk_event_with_proof(None, Some("did:web:local.host"));
        assert!(ensure_sdk_event_proofs_are_domain_bound(&missing_domain).is_err());

        let missing_audience = sdk_event_with_proof(Some("did:web:local.host"), None);
        assert!(ensure_sdk_event_proofs_are_domain_bound(&missing_audience).is_err());
    }
}
