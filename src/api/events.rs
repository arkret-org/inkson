use super::*;

impl CokretApi {
    /// Query durable events through the current `/_cokret/self/events` surface.
    pub async fn backfill(&self, realm_id: &str) -> anyhow::Result<BackfillView> {
        let outcome: cokret_sdk::EventsQueryOutcome =
            self.get_json(&events_query_path(realm_id)).await?;
        Ok(outcome.into())
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
    /// (`ck.typing`). They MUST strand through the canonical
    /// `ck.self.ephemeral.command.send` operation (`POST /_cokret/self/ephemeral`), never
    /// through `ck.self.events.command.submit` or a deployment-local typing shim.
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
    /// ephemeral. They MUST strand through `ck.self.ephemeral.command.send`; the
    /// `ck.self.events.command.submit` durable path and deployment-local `/receipts`
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
    /// canonical `ServiceDescribe` shape (OpenAPI `ck.self.events.query.describe`).
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

    /// Wire-submit a fully-prepared, already-signed SDK [`cokret_sdk::Event`].
    /// This is the only single-event HTTP tail that serialises onto
    /// `POST /_cokret/self/events`.
    async fn post_signed_sdk_event(
        &self,
        signed: &cokret_sdk::Event,
        idempotency_key: String,
    ) -> anyhow::Result<SubmitEventResult> {
        validate_signed_sdk_event_for_submit(signed)?;
        let request = self
            .http
            .post(self.endpoint("_cokret/self/events")?)
            .json(signed);
        let request = self.with_write_request_headers(request, &idempotency_key);
        let response: cokret_sdk::EventsSubmitOutcome = self
            .send_json_retryable(self.prepare_request(request), Method::POST)
            .await?;
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
        let mut signed = event.clone();
        if signed.seal_ref.is_none() && !signed.effects.is_empty() {
            let seal = self.current_seal_for(signed.realm_id.as_str()).await?;
            signed.seal_ref = Some(
                cokret_sdk::SealId::new(seal)
                    .map_err(|err| anyhow::anyhow!("current seal id is invalid: {err}"))?,
            );
        }
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
        self.post_signed_sdk_event(&signed, idempotency_key).await
    }

    /// `ck.self.events.command.submit` in batch form over typed envelopes. Spec binds
    /// events.submit to `POST /_cokret/self/events` and distinguishes the three
    /// accepted body shapes (single envelope,
    /// [`cokret_sdk::EventsSubmitBatchRequestBody`],
    /// [`cokret_sdk::EventsSubmitFederationRequestBody`]) by JSON shape, not
    /// by URL suffix. The federation shape is S2S only and yougen MUST
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
        ensure_events_submit_batch_accepted(&response)?;
        Ok(response)
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
    /// channel, NOT through `ck.self.events.command.submit` or the broadcast ephemeral
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
    ) -> anyhow::Result<DeviceMessagesSendOutcome> {
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
    validate_outgoing_registered_event_payload(event.kind.as_str(), &event.content)
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
                "status": "online"
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
