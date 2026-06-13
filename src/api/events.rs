use super::*;

impl CokretApi {
    /// Query durable events through the current `/_cokret/self/events` surface.
    pub async fn backfill(&self, realm_id: &str) -> anyhow::Result<BackfillView> {
        self.get_json(&events_query_path(realm_id)).await
    }

    /// Stream the canonical `/_cokret/self/events/subscribe` NDJSON response and
    /// invoke `on_frame` once per parsed frame.
    ///
    /// Round 4 (spec a77b995) — the parser is now typed against
    /// [`cokret_sdk::EventsSubscribeFrameBody`] (the `tag = "kind"`,
    /// snake_case-discriminated frame body). Callers MUST route on the
    /// canonical variants: `Dropped { cursor }` → resume from `cursor`,
    /// `ResyncRequired` → full resync, `EpochRotation { epoch }` →
    /// refresh session keys. The pre-round-4 untyped string-line
    /// parser is wire-broken.
    ///
    /// Native-only: reqwest's wasm32 backend goes through the browser fetch
    /// API and does not expose `Response::chunk()` / `bytes_stream()`. A wasm
    /// subscription path needs a separate web-sys ReadableStream-based
    /// implementation (not wired up yet — no callers).
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn events_subscribe_ndjson<F>(
        &self,
        realm_id: &str,
        after: Option<&str>,
        include_history: Option<bool>,
        mut on_frame: F,
    ) -> anyhow::Result<()>
    where
        F: FnMut(cokret_sdk::EventsSubscribeFrameBody) -> anyhow::Result<()>,
    {
        if let Some(token) = after {
            validate_cursor(token)?;
        }
        let request = self
            .http
            .get(self.endpoint(&events_subscribe_path(realm_id, after, include_history))?)
            .header(ACCEPT, "application/x-ndjson");
        let mut response = self
            .send_with_retry(self.prepare_request(request), Method::GET, true)
            .await?;
        let status = response.status();
        if !status.is_success() {
            let bytes = response.bytes().await?;
            return Err(CokretApiError {
                status,
                error: decode_cokret_error(status, &bytes),
            }
            .into());
        }

        let mut pending = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            pending.extend_from_slice(&chunk);
            drain_events_subscribe_ndjson_lines(&mut pending, &mut on_frame)?;
        }

        if let Some(frame) = parse_events_subscribe_ndjson_line(&pending)? {
            on_frame(frame)?;
        }
        Ok(())
    }

    /// Round R2/R3 (T02) — typing notifications are wire-scope-ephemeral
    /// (`ck.typing`). They MUST flow through the canonical
    /// `ck.self.ephemeral.send` operation (`POST /_cokret/self/ephemeral`), never
    /// through `ck.self.events.submit` or a deployment-local typing shim.
    pub async fn send_typing(
        &self,
        realm_id: &str,
        actor: &str,
        device_id: Option<&str>,
        typing: bool,
    ) -> anyhow::Result<TypingResult> {
        let envelope = build_typing_envelope(realm_id, actor, device_id, typing)?;
        let response = self.submit_ephemeral_envelope(&envelope).await?;
        Ok(TypingResult {
            ok: response.accepted,
        })
    }

    /// Round R2/R3 (T02) — read receipts (`ck.receipt.read`) are wire-scope-
    /// ephemeral. They MUST flow through `ck.self.ephemeral.send`; the
    /// `ck.self.events.submit` durable path and deployment-local `/receipts`
    /// shims MUST NOT be used.
    pub async fn send_receipt(
        &self,
        realm_id: &str,
        actor: &str,
        event_id: &str,
        receipt_type: &str,
    ) -> anyhow::Result<ReceiptResult> {
        // Only `ck.receipt.read` is an ephemeral receipt; other receipt
        // types (delivered/franking/etc.) stay on their own paths. Guard
        // the kind here so we don't accidentally widen the contract.
        if receipt_type != "ck.receipt.read" {
            anyhow::bail!("unsupported ephemeral receipt_type {receipt_type:?}");
        }
        let envelope = build_receipt_read_envelope(realm_id, actor, event_id)?;
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
        let body: Value = self
            .get_json(&format!("_cokret/self/events/frontier?realm_id={realm_id}"))
            .await?;
        let state: cokret_sdk::EventsFrontierAccountClientState = serde_json::from_value(body)
            .map_err(|err| {
                anyhow::anyhow!("events/frontier account_client decode failed: {err}")
            })?;
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
        let body: Value = self
            .get_json(&format!("_cokret/self/events/frontier?actor_id={actor_id}"))
            .await?;
        let state: cokret_sdk::EventsFrontierAccountClientState = serde_json::from_value(body)
            .map_err(|err| {
                anyhow::anyhow!("events/frontier account_client decode failed: {err}")
            })?;
        let cokret_sdk::EventsFrontierView::Actor(view) = state.frontier else {
            anyhow::bail!(
                "events/frontier for actor_id={actor_id} did not return an actor frontier"
            );
        };
        Ok(view)
    }

    /// `GET /_cokret/self/events/describe` — spec binds the response to the
    /// canonical `ServiceDescribe` shape (OpenAPI `ck.self.events.describe`).
    /// YOU-01-016: the former soland-private `SolandEventsDescribeResBody`
    /// mirror (with its non-spec `capabilities` blob) was removed.
    pub async fn events_describe(&self) -> anyhow::Result<cokret_sdk::ServiceDescribe> {
        self.get_json("_cokret/self/events/describe").await
    }

    /// Return a cached `events_describe` body. The first call performs
    /// the round-trip; subsequent calls return the cached reference.
    pub async fn events_describe_cached(&self) -> anyhow::Result<&cokret_sdk::ServiceDescribe> {
        self.events_describe_cache
            .get_or_try_init(|| async { self.events_describe().await })
            .await
    }

    pub(crate) async fn event_proof_context(
        &self,
    ) -> anyhow::Result<crate::event_signer::EventProofContext> {
        let describe = self.describe_cached().await?;
        Ok(event_proof_context_from_description(describe))
    }

    /// Submit a typed [`EventEnvelope`] over `ck.self.events.submit`. The
    /// active-signer registry is the SINGLE source of detached JWS
    /// proofs — if no signer is installed this fails closed with
    /// `no active signer configured` rather than sending an unsigned
    /// or placeholder-signed envelope.
    ///
    /// For reducer-input event kinds, `seal_ref` is auto-filled from
    /// the current Realm seal (`/_cokret/self/snapshot/head`) when the
    /// caller did not supply one.
    pub async fn submit_event_envelope(
        &self,
        event: &EventEnvelope,
    ) -> anyhow::Result<SubmitEventResult> {
        let mut signed = event.clone();

        // Real seal_ref for reducer-input kinds. The simple heuristic
        // is: any envelope that already carries `effects[]` is a
        // reducer-input write and MUST point at the current Realm
        // seal head. Non-reducer kinds (ck.read_cursor.advance,
        // ck.account_data.set, ck.account.blocklist, etc.) have no
        // effects and keep `seal_ref: None`.
        if signed.seal_ref.is_none() && !signed.effects.is_empty() {
            let seal = self.current_seal_for(&signed.realm_id).await?;
            signed.seal_ref = Some(seal);
        }

        // Single signing path. No placeholder, no fallback.
        if signed.proofs.is_empty() {
            let proof_context = self.event_proof_context().await?;
            crate::event_signer::sign_with_active_context(&mut signed, proof_context).map_err(
                |err| {
                    anyhow::anyhow!(
                        "no active signer configured \u{2014} cannot submit unsigned event: {err}"
                    )
                },
            )?;
        }
        self.post_signed_event_envelope(&signed).await
    }

    /// Wire-submit a fully-prepared, already-signed [`EventEnvelope`]
    /// verbatim over `POST /_cokret/self/events`. This does NOT stamp
    /// `seal_ref` or sign — the caller owns both. It is the shared
    /// tail of [`Self::submit_event_envelope`] and the per-envelope
    /// fallback in [`Self::submit_events_batch`]: a genesis Realm
    /// bootstrap deliberately carries `seal_ref: None` (it asserts
    /// `head_eq null`, there is no prior seal head), so re-running the
    /// seal-stamp heuristic here would both 404 against the
    /// not-yet-existing Realm's snapshot head and corrupt the signature.
    async fn post_signed_event_envelope(
        &self,
        signed: &EventEnvelope,
    ) -> anyhow::Result<SubmitEventResult> {
        if signed.proofs.is_empty() {
            anyhow::bail!("no active signer configured \u{2014} cannot submit unsigned event");
        }
        ensure_event_proofs_are_domain_bound(signed)?;
        validate_outgoing_registered_payload(signed)?;
        let sdk_event = signed.to_sdk_event_for_submit()?;

        let idempotency_key = signed
            .local_operation_idempotency_alias()
            .map(ToOwned::to_owned)
            .unwrap_or_else(uuid_v7);
        let request = self
            .http
            .post(self.endpoint("_cokret/self/events")?)
            .json(&sdk_event);
        let request = self.with_write_request_headers(request, &idempotency_key);
        let response: cokret_sdk::EventsSubmitOutcome = self
            .send_json_retryable(self.prepare_request(request), Method::POST)
            .await?;
        Ok(SubmitEventResult::from(response))
    }

    /// `ck.self.events.submit` in batch form over typed envelopes. Spec binds
    /// events.submit to `POST /_cokret/self/events` and distinguishes the three
    /// accepted body shapes (single envelope,
    /// [`cokret_sdk::EventsSubmitBatchRequestBody`],
    /// [`cokret_sdk::EventsSubmitFederationRequestBody`]) by JSON shape, not
    /// by URL suffix. The federation shape is S2S only and yougen MUST
    /// NEVER serialise it.
    ///
    /// Envelopes MUST already be signed by the caller (typically via
    /// `event_signer::sign_with_active`) — the batch path does not
    /// auto-sign because callers commonly need an atomic seal_ref +
    /// sign sequence the per-envelope helper cannot replicate.
    pub async fn submit_events_batch(
        &self,
        envelopes: &[EventEnvelope],
        idempotency_key: Option<&str>,
    ) -> anyhow::Result<Value> {
        // Re-validate every envelope carries a signed proof. The batch
        // submit path is fail-closed by construction.
        for envelope in envelopes {
            if envelope.proofs.is_empty() {
                anyhow::bail!(
                    "submit_events_batch refuses unsigned envelope (event_id={}, kind={})",
                    envelope.event_id,
                    envelope.kind
                );
            }
            ensure_event_proofs_are_domain_bound(envelope)?;
            validate_outgoing_registered_payload(envelope)?;
        }

        // YOU-01-016: the former `capabilities.batch_submit` probe (a
        // non-spec soland capability field) was removed. The batch request
        // body is one of the three spec-defined `ck.self.events.submit`
        // shapes (distinguished by JSON shape), so it is sent
        // unconditionally — no capability negotiation exists in the spec.
        let sdk_events: Vec<cokret_sdk::Event> = envelopes
            .iter()
            .map(EventEnvelope::to_sdk_event_for_submit)
            .collect::<anyhow::Result<_>>()?;
        let events_value: Vec<Value> = sdk_events
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<_, _>>()?;
        let body = cokret_sdk::EventsSubmitBatchRequestBody {
            events: events_value,
            idempotency_key: idempotency_key.map(ToOwned::to_owned),
        };
        let request = self
            .http
            .post(self.endpoint("_cokret/self/events")?)
            .json(&body);
        let idem = idempotency_key
            .map(ToOwned::to_owned)
            .unwrap_or_else(uuid_v7);
        let request = self.with_write_request_headers(request, &idem);
        let response: cokret_sdk::EventsSubmitOutcome = self
            .send_json_retryable(self.prepare_request(request), Method::POST)
            .await?;
        let response = serde_json::to_value(response)?;
        ensure_events_submit_batch_accepted(&response)?;
        Ok(response)
    }

    /// Round R2/R3 (T02) — POST a broadcast ephemeral signal to the
    /// canonical ephemeral channel (`POST /_cokret/self/ephemeral`) instead of the
    /// durable `/_cokret/self/events` endpoint. The envelope MUST validate against
    /// `ck.schema.ephemeral_envelope.v1` (kind in
    /// {`ck.call.signal`, `ck.presence`, `ck.typing`, `ck.receipt.read`}, and
    /// `expires_at - sent_at <= 300_000` ms). The four broadcast ephemeral
    /// signal kinds MUST NOT travel via `ck.self.events.submit`; this method is
    /// the single approved network path.
    pub async fn submit_ephemeral_envelope(
        &self,
        envelope: &cokret_sdk::EphemeralEnvelope,
    ) -> anyhow::Result<EphemeralSubmitResult> {
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
        self.post_json("_cokret/self/ephemeral", envelope).await
    }

    /// Round R2/R3 (T02) — point-to-point to-device signals (the
    /// `ck.key.verification.*` family) MUST travel on the device-message
    /// channel, NOT through `ck.self.events.submit` or the broadcast ephemeral
    /// channel. Thin convenience wrapper around
    /// [`Self::send_device_message_envelope`] that asserts the kind belongs
    /// to the to-device ephemeral family.
    pub async fn submit_to_device_ephemeral(
        &self,
        txn_id: &str,
        target_actor: &str,
        target_device_id: &str,
        message_type: &str,
        content: Value,
    ) -> anyhow::Result<DeviceMessagesPutOutcome> {
        if !message_type.starts_with("ck.key.verification.") {
            anyhow::bail!(
                "to-device ephemeral submit: message_type {message_type:?} is not in the ck.key.verification.* family"
            );
        }
        // `device-lifecycle.md` §8.2 caps verification request.expires_at at
        // `timestamp + 10m`; use that window for every step of the family.
        self.send_device_message_envelope(
            txn_id,
            target_actor,
            target_device_id,
            message_type,
            &crate::clock::rfc3339_secs_in(10),
            content,
        )
        .await
    }
}

fn ensure_event_proofs_are_domain_bound(envelope: &EventEnvelope) -> anyhow::Result<()> {
    for proof in &envelope.proofs {
        if proof
            .domain
            .as_deref()
            .is_none_or(|domain| domain.trim().is_empty())
        {
            anyhow::bail!(
                "event proof for {} is missing domain binding",
                envelope.event_id
            );
        }
        if proof.audience.is_none() {
            anyhow::bail!(
                "event proof for {} is missing audience binding",
                envelope.event_id
            );
        }
    }
    Ok(())
}

fn event_proof_context_from_description(
    describe: &ServerDescription,
) -> crate::event_signer::EventProofContext {
    let service_did = describe.service_did.to_string();
    crate::event_signer::EventProofContext::new()
        .with_domain(service_did.clone())
        .with_audience(crate::operation::EventProofAudience::single(service_did))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

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
                "ck.self.events.describe",
                "ck.self.events.submit"
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
}
