use super::*;

impl CokretApi {
    /// Query durable events through the current `/_cokret/self/events` surface.
    pub async fn backfill(&self, space_id: &str) -> anyhow::Result<BackfillResBody> {
        self.get_json(&events_query_path(space_id)).await
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
        space_id: &str,
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
            .get(self.endpoint(&events_subscribe_path(space_id, after, include_history))?)
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
    /// `ck.ephemeral.send` operation (`POST /_cokret/self/ephemeral`), never
    /// through `ck.events.submit` or a deployment-local typing shim.
    pub async fn send_typing(
        &self,
        space_id: &str,
        actor: &str,
        device_id: Option<&str>,
        typing: bool,
    ) -> anyhow::Result<TypingResponse> {
        let envelope = build_typing_envelope(space_id, actor, device_id, typing)?;
        let response = self.submit_ephemeral_envelope(&envelope).await?;
        Ok(TypingResponse {
            ok: response.accepted,
        })
    }

    /// Round R2/R3 (T02) — read receipts (`ck.receipt.read`) are wire-scope-
    /// ephemeral. They MUST flow through `ck.ephemeral.send`; the
    /// `ck.events.submit` durable path and deployment-local `/receipts`
    /// shims MUST NOT be used.
    pub async fn send_receipt(
        &self,
        space_id: &str,
        actor: &str,
        event_id: &str,
        receipt_type: &str,
    ) -> anyhow::Result<ReceiptResponse> {
        // Only `ck.receipt.read` is an ephemeral receipt; other receipt
        // types (delivered/franking/etc.) stay on their own paths. Guard
        // the kind here so we don't accidentally widen the contract.
        if receipt_type != "ck.receipt.read" {
            anyhow::bail!("unsupported ephemeral receipt_type {receipt_type:?}");
        }
        let envelope = build_receipt_read_envelope(space_id, actor, event_id)?;
        let response = self.submit_ephemeral_envelope(&envelope).await?;
        Ok(ReceiptResponse {
            ok: response.accepted,
        })
    }

    // ── Identity (extended) ─────────────────────────────────────────

    pub async fn submit_did_operation(
        &self,
        did: &str,
        operation: Value,
    ) -> anyhow::Result<SubmitDidOperationResBody> {
        self.post_json(
            "_cokret/root/identity/submit-did-operation",
            json!({"did": did, "operation": operation}),
        )
        .await
    }

    /// Round 4 (spec a77b995) — `GET /_cokret/self/events/frontier` as the
    /// `account_client` variant. Wire-breaking: the round-4
    /// `account_client` variant carries `peer_role`, `frontier`,
    /// `actor_seq_upper_bounds` ONLY — it does NOT include
    /// `frontier_root`, transport signatures, or receipts. Those moved
    /// to the `federation_peer` variant which is S2S-only and clients
    /// MUST NEVER consume.
    ///
    /// The caller MUST pre-confirm that the route is signed-in (the
    /// account-client variant is gated on the principal session token).
    /// Anonymous-health probes go through a separate route.
    pub async fn events_frontier_account_client(
        &self,
    ) -> anyhow::Result<cokret_sdk::EventsFrontierAccountClientResponse> {
        let body: Value = self.get_json("_cokret/self/events/frontier").await?;
        let frontier: cokret_sdk::EventsFrontierAccountClientResponse =
            serde_json::from_value(body).map_err(|err| {
                anyhow::anyhow!(
                    "events/frontier account_client decode failed (round 4 wire shape): {err}"
                )
            })?;
        if !matches!(
            frontier.peer_role,
            cokret_sdk::FrontierPeerRole::AccountClient
        ) {
            anyhow::bail!(
                "events/frontier peer_role {:?} is not account_client (federation_peer / \
                 anonymous_health are off-limits to clients)",
                frontier.peer_role
            );
        }
        Ok(frontier)
    }

    pub async fn events_describe(&self) -> anyhow::Result<EventsDescribeResBody> {
        self.get_json("_cokret/self/events/describe").await
    }

    /// H1 — return a cached `events_describe` body. The first call performs
    /// the round-trip; subsequent calls return the cached reference. The
    /// `capabilities.batch_submit` flag is read off this body by
    /// [`Self::submit_events_batch`] to decide whether to send a real
    /// batch or fall back to per-envelope submits.
    pub async fn events_describe_cached(&self) -> anyhow::Result<&EventsDescribeResBody> {
        self.events_describe_cache
            .get_or_try_init(|| async { self.events_describe().await })
            .await
    }

    /// H1 — read `capabilities.batch_submit` off the cached
    /// `events_describe`. Conservative default: when the field is absent
    /// or the cache fetch fails, assume the server does NOT support batch
    /// and fall back to per-envelope submits. `EventsDescribeResBody`
    /// surfaces server capabilities under the canonical `capabilities`
    /// JSON blob on soland.
    async fn batch_submit_supported(&self) -> bool {
        let Ok(describe) = self.events_describe_cached().await else {
            return false;
        };
        describe
            .capabilities
            .get("batch_submit")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }

    /// Submit a typed [`EventEnvelope`] over `ck.events.submit`. The
    /// active-signer registry is the SINGLE source of detached JWS
    /// proofs — if no signer is installed this fails closed with
    /// `no active signer configured` rather than sending an unsigned
    /// or placeholder-signed envelope.
    ///
    /// For reducer-input event kinds, `anchor_ref` is auto-filled from
    /// the current Realm anchor (`/_cokret/self/snapshot/head`) when the
    /// caller did not supply one.
    pub async fn submit_event_envelope(
        &self,
        event: &EventEnvelope,
    ) -> anyhow::Result<SubmitEventResponse> {
        let mut signed = event.clone();

        // Real anchor_ref for reducer-input kinds. The simple heuristic
        // is: any envelope that already carries `effects[]` is a
        // reducer-input write and MUST point at the current Realm
        // anchor head. Non-reducer kinds (ck.read_cursor.advance,
        // ck.account_data.set, ck.account.blocklist, etc.) have no
        // effects and keep `anchor_ref: None`.
        if signed.anchor_ref.is_none() && !signed.effects.is_empty() {
            let anchor = self.current_anchor_for(&signed.realm_id).await?;
            signed.anchor_ref = Some(anchor);
        }

        // Single signing path. No placeholder, no fallback.
        if signed.proofs.is_empty() {
            crate::event_signer::sign_with_active(&mut signed).map_err(|err| {
                anyhow::anyhow!(
                    "no active signer configured \u{2014} cannot submit unsigned event: {err}"
                )
            })?;
        }
        if signed.proofs.is_empty() {
            anyhow::bail!("no active signer configured \u{2014} cannot submit unsigned event");
        }
        validate_outgoing_registered_payload(&signed)?;

        let idempotency_key = signed
            .local_operation_idempotency_alias()
            .map(ToOwned::to_owned)
            .unwrap_or_else(uuid_v7);
        let value = serde_json::to_value(&signed)?;
        let request = self
            .http
            .post(self.endpoint("_cokret/self/events")?)
            .json(&value);
        let request = self.with_write_request_headers(request, &idempotency_key);
        self.send_json_retryable(self.prepare_request(request), Method::POST)
            .await
    }

    /// `ck.events.submit` in batch form over typed envelopes. Spec binds
    /// events.submit to `POST /_cokret/self/events` and distinguishes the three
    /// accepted body shapes (single envelope,
    /// [`cokret_sdk::EventsSubmitBatchRequest`],
    /// [`cokret_sdk::EventsSubmitFederationRequest`]) by JSON shape, not
    /// by URL suffix. The federation shape is S2S only and yougen MUST
    /// NEVER serialise it.
    ///
    /// Envelopes MUST already be signed by the caller (typically via
    /// `event_signer::sign_with_active`) — the batch path does not
    /// auto-sign because callers commonly need an atomic anchor_ref +
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
            validate_outgoing_registered_payload(envelope)?;
        }

        // H1 — capability gate. When the server advertises
        // `capabilities.batch_submit == false` (or has not declared the
        // capability), fall back to per-envelope `submit_event_envelope`
        // so a deployment that hasn't wired the batch path still receives
        // every event. The envelopes are already signed; we just lose the
        // atomic accept/reject grouping the batch endpoint would give us.
        if !self.batch_submit_supported().await {
            for envelope in envelopes {
                self.submit_event_envelope(envelope).await?;
            }
            return Ok(json!({
                "status": "accepted",
                "fallback": "per_envelope",
                "count": envelopes.len(),
            }));
        }

        let events_value: Vec<Value> = envelopes
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<_, _>>()?;
        let body = cokret_sdk::EventsSubmitBatchRequest {
            events: events_value,
            idempotency_key: idempotency_key.map(ToOwned::to_owned),
        };
        let value = serde_json::to_value(&body)?;
        let request = self
            .http
            .post(self.endpoint("_cokret/self/events")?)
            .json(&value);
        let idem = idempotency_key
            .map(ToOwned::to_owned)
            .unwrap_or_else(uuid_v7);
        let request = self.with_write_request_headers(request, &idem);
        let response: Value = self
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
    /// signal kinds MUST NOT travel via `ck.events.submit`; this method is
    /// the single approved network path.
    pub async fn submit_ephemeral_envelope(
        &self,
        envelope: &cokret_sdk::EphemeralEnvelope,
    ) -> anyhow::Result<EphemeralSubmitResponse> {
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
        let body = serde_json::to_value(envelope)?;
        self.post_json("_cokret/self/ephemeral", body).await
    }

    /// Round R2/R3 (T02) — point-to-point to-device signals (the
    /// `ck.key.verification.*` family) MUST travel on the device-message
    /// channel, NOT through `ck.events.submit` or the broadcast ephemeral
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
    ) -> anyhow::Result<DeviceMessagesSendResBody> {
        if !message_type.starts_with("ck.key.verification.") {
            anyhow::bail!(
                "to-device ephemeral submit: message_type {message_type:?} is not in the ck.key.verification.* family"
            );
        }
        self.send_device_message_envelope(
            txn_id,
            target_actor,
            target_device_id,
            message_type,
            content,
        )
        .await
    }
}
