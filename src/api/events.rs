use super::*;

/// COR-07: hard upper bound on event-query pages walked per backfill call, so a
/// hostile / buggy server that keeps `has_more=true` (or never advances the
/// cursor) cannot turn pagination into an unbounded loop. 100 pages × 100 events
/// = 10k events is well past any realm a client backfills in one shot.
const MAX_EVENTS_QUERY_PAGES: usize = 100;

impl CokretApi {
    /// COR-07: walk EVERY page of `/_cokret/self/events` for `realm_id` until
    /// `has_more == false`, instead of returning only the first 100 events.
    ///
    /// Pagination follows `next_cursor` via `after=`. Two hardening guards keep a
    /// malicious server from hanging the client: a page-count ceiling
    /// ([`MAX_EVENTS_QUERY_PAGES`]) and a strict cursor-progress check (the
    /// server MUST advance `next_cursor`; a repeated / empty cursor while
    /// `has_more` is still true is rejected rather than looped on).
    async fn events_query_all_pages(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<cokret_sdk::EventsQueryOutcome> {
        let mut combined: cokret_sdk::EventsQueryOutcome =
            self.get_json(&events_query_path(realm_id)).await?;
        let mut pages = 1usize;
        let mut last_cursor: Option<String> = None;
        while combined.has_more {
            let Some(next) = combined
                .next_cursor
                .as_deref()
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .map(ToOwned::to_owned)
            else {
                anyhow::bail!(
                    "events query for realm {realm_id} reported has_more but no next_cursor"
                );
            };
            // Strict forward progress: refuse to re-fetch the same cursor.
            if last_cursor.as_deref() == Some(next.as_str()) {
                anyhow::bail!(
                    "events query for realm {realm_id} did not advance next_cursor ({next}); aborting to avoid a pagination loop"
                );
            }
            if pages >= MAX_EVENTS_QUERY_PAGES {
                anyhow::bail!(
                    "events query for realm {realm_id} exceeded {MAX_EVENTS_QUERY_PAGES} pages; aborting"
                );
            }
            let page: cokret_sdk::EventsQueryOutcome = self
                .get_json(&events_query_path_after(realm_id, &next))
                .await?;
            combined.events.extend(page.events);
            combined.has_more = page.has_more;
            combined.next_cursor = page.next_cursor;
            combined.range_completeness = page.range_completeness;
            last_cursor = Some(next);
            pages += 1;
        }
        Ok(combined)
    }

    /// Query durable events through the current `/_cokret/self/events` surface,
    /// following pagination to completion (COR-07).
    pub async fn backfill(&self, realm_id: &str) -> anyhow::Result<BackfillView> {
        let outcome = self.events_query_all_pages(realm_id).await?;
        Ok(outcome.into())
    }

    pub(crate) async fn find_mls_genesis_event_id(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<Option<cokret_sdk::EventId>> {
        // COR-07: the MLS genesis event may sit past the first page; paginate so
        // it is never silently judged "absent" because of front-page noise.
        let outcome = self.events_query_all_pages(realm_id).await?;
        Ok(mls_genesis_event_id_from_events(&outcome, realm_id))
    }

    /// Stream the canonical `/_cokret/self/events/subscribe` NDJSON response and
    /// invoke `on_frame` once per parsed frame.
    ///
    /// Round 4 (spec a77b995) — the parser is now typed against
    /// [`cokret_sdk::EventsSubscribeFrame`] (the `tag = "kind"`,
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
        F: FnMut(cokret_sdk::EventsSubscribeFrame) -> anyhow::Result<()>,
    {
        if let Some(token) = after {
            validate_cursor(token)?;
        }
        let request = self
            .http
            .get(self.endpoint(&events_subscribe_path(
                realm_id,
                after,
                include_history,
                None,
            ))?)
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
            // COR-01: cap the inter-newline buffer before draining. A server
            // that never delimits a frame (or sends an oversized single frame)
            // MUST NOT be able to grow this buffer without bound — fail closed
            // instead of risking OOM. Parity with the account.subscribe path.
            if pending.len() > MAX_NDJSON_STREAM_FRAME_BYTES {
                anyhow::bail!(
                    "events subscribe frame exceeded {MAX_NDJSON_STREAM_FRAME_BYTES} bytes without a newline delimiter"
                );
            }
            drain_events_subscribe_ndjson_lines(&mut pending, &mut on_frame)?;
        }

        if let Some(frame) = parse_events_subscribe_ndjson_line(&pending)? {
            on_frame(frame)?;
        }
        Ok(())
    }

    /// All-target buffered long-poll of `ck.self.events.stream.subscribe`
    /// (`GET /_cokret/self/events/subscribe`). Unlike [`Self::events_subscribe_ndjson`]
    /// it does NOT read the NDJSON body frame-by-frame (reqwest's wasm32
    /// browser-fetch backend exposes no `Response::chunk()` reader): it awaits
    /// the whole response body and parses every NDJSON line at once. The server
    /// closes the stream after `max_duration_ms`, so that window doubles as the
    /// liveness latency for this realm stream — pick it small enough to keep the
    /// board fresh and large enough to behave as a long-poll.
    ///
    /// This is the per-realm counterpart to `account_subscribe_snapshot_outcome`:
    /// it carries the realm's OWN stream cursor in `after=` (never the account
    /// cursor — they are bound to different `filter_digest`s per
    /// `encoding.md` §8.3.1, and cross-binding reuse is `cursor_integrity_invalid`).
    pub async fn events_subscribe_poll(
        &self,
        realm_id: &str,
        after: Option<&str>,
        include_history: bool,
        max_duration_ms: u64,
    ) -> anyhow::Result<Vec<cokret_sdk::EventsSubscribeFrame>> {
        if let Some(token) = after {
            validate_cursor(token)?;
        }
        let path = events_subscribe_path(
            realm_id,
            after,
            Some(include_history),
            Some(max_duration_ms),
        );
        let request = self
            .http
            .get(self.endpoint(&path)?)
            .header(ACCEPT, "application/x-ndjson");
        let response = self
            .send_with_retry(self.prepare_request(request), Method::GET, true)
            .await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            return Err(CokretApiError {
                status,
                error: decode_cokret_error(status, &bytes),
            }
            .into());
        }
        let text = String::from_utf8_lossy(&bytes);
        parse_events_subscribe_ndjson_text(&text)
    }

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
        super::ephemeral::attach_broadcast_ephemeral_proof(&mut envelope)?;
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
        super::ephemeral::attach_broadcast_ephemeral_proof(&mut envelope)?;
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
        super::ephemeral::attach_broadcast_ephemeral_proof(&mut envelope)?;
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
            .get_json(&format!(
                "_cokret/self/events/frontier?realm_id={realm_id_query}"
            ))
            .await?;
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
            .get_json(&format!(
                "_cokret/self/events/frontier?actor_id={actor_id_query}"
            ))
            .await?;
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
        if event.seal_ref.is_some() || event.seal_basis.is_some() || event.effects.is_empty() {
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
                let seal = self.current_seal_for(event.realm_id.as_str()).await?;
                event.seal_ref = Some(
                    cokret_sdk::SealId::new(seal)
                        .map_err(|err| anyhow::anyhow!("current seal id is invalid: {err}"))?,
                );
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
