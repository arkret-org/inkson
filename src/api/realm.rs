use super::*;

impl CokretApi {
    /// Build + submit the spec-canonical `ck.realm.create` event bundle
    /// (and its facet follow-ups) via `ck.self.events.submit`
    /// (`POST /_cokret/self/events`).
    ///
    /// Per spec realm-and-space.md §2.6 the create event itself is the
    /// genesis-member declaration for `created_by`. The
    /// server reducer bootstraps the member set atomically with the
    /// metadata, so the same actor's per-facet follow-ups
    /// (`ck.realm.join_rule` / `ck.realm.history_visibility` /
    /// `ck.realm.discovery` / `ck.realm.plaintext_visible_services` /
    /// invitee `ck.member.state` invites) all pass the regular
    /// `realm_has_member` authz check naturally.
    ///
    /// All five create-locked fields per spec §2.3 (`encryption_profile`,
    /// `security_class`, `federation_policy`, `anchor_profile`,
    /// `digest_algorithm`) are sent inline on the create event payload —
    /// no field is dropped at the wire, unlike a REST wrapper that
    /// might only accept a subset.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_realm(
        &self,
        actor_id: &str,
        title: &str,
        summary: Option<&str>,
        discoverability: &str,
        join_rule: &str,
        history_visibility: &str,
        encryption_profile: &str,
        security_class: &str,
        federation_policy: &str,
        anchor_profile: &str,
        digest_algorithm: &str,
        trust_domain: &str,
        invitees: Vec<String>,
        plaintext_visible_services: Vec<String>,
    ) -> anyhow::Result<RealmCreateOutcome> {
        let actor_id = actor_id.trim();
        if actor_id.is_empty() {
            return Err(anyhow::anyhow!(
                "actor_id is required for canonical ck.realm.create"
            ));
        }
        let title = title.trim();
        if title.is_empty() {
            return Err(anyhow::anyhow!("title is required for ck.realm.create"));
        }

        let realm_id = format!("ck:realm:{}", uuid_v7());
        let join_rule = canonical_space_join_rule_v1(join_rule);
        let mut envelopes = build_realm_bootstrap_events(
            &realm_id,
            actor_id,
            title,
            summary,
            discoverability,
            join_rule,
            history_visibility,
            encryption_profile,
            security_class,
            federation_policy,
            anchor_profile,
            digest_algorithm,
            trust_domain,
            &invitees,
            &plaintext_visible_services,
        )?;
        // Genesis Realm bootstrap has no prior snapshot head. The
        // `ck.realm.create` precondition asserts `head_eq null`; follow-up
        // facet events in the same batch are admitted after soland
        // materialises the creator membership from the create event.
        // Sign every envelope before they reach the wire; the batch
        // submitter takes pre-signed typed envelopes.
        let proof_context = self.event_proof_context().await?;
        for envelope in envelopes.iter_mut() {
            crate::event_signer::sign_with_active_context(envelope, proof_context.clone())
                .map_err(|err| {
                    anyhow::anyhow!(
                        "no active signer configured \u{2014} cannot submit unsigned realm bootstrap: {err}"
                    )
                })?;
        }
        let idempotency_key = format!("ck:operation:{}", uuid_v7());
        self.submit_events_batch(&envelopes, Some(&idempotency_key))
            .await?;

        let resolved_invitees = parse_realm_bootstrap_members(&invitees)?;
        let mut members = Vec::new();
        members.push(actor_id.to_owned());
        for invitee in resolved_invitees {
            if !members.iter().any(|member| member == &invitee.actor_id) {
                members.push(invitee.actor_id);
            }
        }

        Ok(RealmCreateOutcome {
            ok: true,
            realm_id,
            owner: actor_id.to_owned(),
            members,
            state: "active".to_owned(),
        })
    }

    /// Create a Space (product-structure container) inside an existing
    /// Realm. Emits `ck.space.create` per spec realm-and-space.md §3.
    /// Unlike `create_realm`, this does NOT bootstrap MLS / membership
    /// / federation — those live on the Realm and Space inherits them.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_space_under_realm(
        &self,
        realm_id: &str,
        actor_id: &str,
        title: &str,
        summary: Option<&str>,
        kind: &str,
        parent_space_id: Option<&str>,
        default_realm_id: Option<&str>,
    ) -> anyhow::Result<SpaceCreateOutcome> {
        let actor_id = actor_id.trim();
        if actor_id.is_empty() {
            return Err(anyhow::anyhow!("actor_id is required for ck.space.create"));
        }
        let title = title.trim();
        if title.is_empty() {
            return Err(anyhow::anyhow!("title is required for ck.space.create"));
        }
        let realm_id = realm_id.trim();
        if realm_id.is_empty() {
            return Err(anyhow::anyhow!(
                "realm_id is required for ck.space.create — Space must live inside a Realm"
            ));
        }
        let space_id = format!("ck:space:{}", uuid_v7());
        let event = build_space_create_event(
            &space_id,
            realm_id,
            actor_id,
            title,
            summary,
            kind,
            parent_space_id,
            default_realm_id,
        )?;
        self.submit_event_envelope(&event).await?;

        Ok(SpaceCreateOutcome {
            ok: true,
            space_id,
            owner: actor_id.to_owned(),
            members: vec![actor_id.to_owned()],
            state: "active".to_owned(),
        })
    }

    /// CKP-0007 P3B.2.6 — POST a new Circle to soland's
    /// `/_soland/self/circles` administrative surface. Circle 是 CKP-0014 §5
    /// 的候选操作,未入正式 catalog 前 MUST 走 `/_soland`(实测 `/_cokret`
    /// 端点 404),待 circle 入 catalog 后迁回 `/_cokret`。The strict-subset
    /// invariant (`Circle.members ⊆ Realm.members`) is enforced by the
    /// reducer; this client also runs
    /// [`crate::components::validate_strict_subset`] before sending so
    /// the user sees a `circle_member_must_be_realm_member` failure
    /// inline rather than as a round-tripped reducer rejection.
    ///
    /// The wire body is built from the SDK's typed
    /// [`cokret_sdk::model::circle::CircleDisplay`] struct so the
    /// enum values (`color_token`, glyph names) stay in sync with
    /// `spec/v1/artifacts/schemas/circle.schema.json` instead of being
    /// hand-rolled JSON strings.
    pub async fn create_circle(
        &self,
        realm_id: &str,
        actor_id: &str,
        title: &str,
        short_name: &str,
        color_token: &str,
        symbol_glyph: &str,
        directory_visibility: &str,
        initial_members: &[String],
    ) -> anyhow::Result<serde_json::Value> {
        use cokret_sdk::model::{
            CircleColorToken, CircleDirectoryVisibility, CircleDisplay, CircleGlyph, CircleSymbol,
        };

        let realm_id = realm_id.trim();
        let actor_id = actor_id.trim();
        let title = title.trim();
        if realm_id.is_empty() || actor_id.is_empty() || title.is_empty() {
            return Err(anyhow::anyhow!(
                "realm_id / actor_id / title are all required for ck.circle.create"
            ));
        }

        let color: CircleColorToken =
            serde_json::from_value(serde_json::Value::String(color_token.trim().to_owned()))
                .map_err(|err| {
                    anyhow::anyhow!("invalid Circle color_token `{color_token}`: {err}")
                })?;
        let glyph: CircleGlyph =
            serde_json::from_value(serde_json::Value::String(symbol_glyph.trim().to_owned()))
                .map_err(|err| {
                    anyhow::anyhow!("invalid Circle symbol glyph `{symbol_glyph}`: {err}")
                })?;
        let visibility: CircleDirectoryVisibility = serde_json::from_value(
            serde_json::Value::String(directory_visibility.trim().to_owned()),
        )
        .map_err(|err| {
            anyhow::anyhow!("invalid Circle directory_visibility `{directory_visibility}`: {err}")
        })?;

        let display = CircleDisplay {
            short_name: short_name.trim().to_owned(),
            color_token: color,
            symbol: CircleSymbol::Glyph { glyph },
        };

        let body = serde_json::json!({
            "realm_id": realm_id,
            "actor_id": actor_id,
            "title": title,
            "display": serde_json::to_value(&display)?,
            "directory_visibility": serde_json::to_value(visibility)?,
            "initial_members": initial_members,
        });
        self.post_json("/_soland/self/circles", body).await
    }

    /// CKP-0007 P3B.2.1 — fetch the Circle directory for a Realm. The
    /// projection is filtered server-side by the caller's
    /// `directory_visibility` (members-only Circles only return when
    /// the caller is a Circle member). Returns the raw JSON shape; the
    /// caller decodes into [`crate::circle::CircleSummary`].
    pub async fn list_circles(&self, realm_id: &str) -> anyhow::Result<serde_json::Value> {
        let realm_id = realm_id.trim();
        if realm_id.is_empty() {
            return Err(anyhow::anyhow!(
                "realm_id is required for /_soland/self/circles"
            ));
        }
        let path = format!("/_soland/self/circles?realm_id={}", realm_id);
        self.get_json(&path).await
    }

    /// CKP-0007 P3B.2.6 — fetch a single Circle's detail (metadata +
    /// member roster) from `GET /_soland/self/circles/{id}`. Returns the
    /// raw JSON shape; the caller decodes the summary via
    /// [`crate::circle::circle_summary_from_json`] and the roster via
    /// [`crate::circle::circle_members_from_json`].
    pub async fn get_circle(&self, circle_id: &str) -> anyhow::Result<serde_json::Value> {
        let circle_id = circle_id.trim();
        if circle_id.is_empty() {
            return Err(anyhow::anyhow!(
                "circle_id is required for /_soland/self/circles/{{id}}"
            ));
        }
        self.get_json(&format!("/_soland/self/circles/{circle_id}"))
            .await
    }

    /// CKP-0007 P3B.2.6 — add a Realm member to a Circle via
    /// `POST /_soland/self/circles/{id}/members`.
    ///
    /// This is a **one-way pull**: the added member joins the Circle
    /// immediately (`state: "active"`) with no consent / acceptance step
    /// from their side. The reducer still enforces the strict-subset
    /// invariant (`circle_member_must_be_realm_member`) — the target DID
    /// MUST already be an active member of the parent Realm.
    pub async fn add_circle_member(
        &self,
        circle_id: &str,
        actor_id: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let circle_id = circle_id.trim();
        let actor_id = actor_id.trim();
        if circle_id.is_empty() || actor_id.is_empty() {
            return Err(anyhow::anyhow!(
                "circle_id and actor_id are required to add a Circle member"
            ));
        }
        let body = json!({ "actor_id": actor_id, "state": "active" });
        self.post_json(&format!("/_soland/self/circles/{circle_id}/members"), body)
            .await
    }

    /// CKP-0007 P3B.2.6 — remove a member from a Circle via
    /// `DELETE /_soland/self/circles/{id}/members/{actor_id}`. Leaving the
    /// Circle does not affect the actor's parent-Realm membership.
    pub async fn remove_circle_member(
        &self,
        circle_id: &str,
        actor_id: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let circle_id = circle_id.trim();
        let actor_id = actor_id.trim();
        if circle_id.is_empty() || actor_id.is_empty() {
            return Err(anyhow::anyhow!(
                "circle_id and actor_id are required to remove a Circle member"
            ));
        }
        self.delete_json(&format!(
            "/_soland/self/circles/{circle_id}/members/{actor_id}"
        ))
        .await
    }

    /// Send a Space lifecycle action (`archive` / `restore` /
    /// `tombstone`) per spec realm-and-space.md §3.4. Caller MUST
    /// pass the home Realm id — the event is authorized + written
    /// inside that Realm. Server validates the state-machine
    /// (active → archived → active, any → tombstoned) and rejects
    /// invalid transitions with `space_not_active` /
    /// `space_not_archived` / `realm_already_terminal`.
    pub async fn change_space_lifecycle(
        &self,
        space_id: &str,
        realm_id: &str,
        actor_id: &str,
        kind: &str,
    ) -> anyhow::Result<()> {
        let actor_id = actor_id.trim();
        let space_id = space_id.trim();
        let realm_id = realm_id.trim();
        if actor_id.is_empty() || space_id.is_empty() || realm_id.is_empty() {
            return Err(anyhow::anyhow!(
                "actor_id, space_id and realm_id are all required for {kind}"
            ));
        }
        let event = build_space_lifecycle_event(space_id, realm_id, actor_id, kind)?;
        self.submit_event_envelope(&event).await?;
        Ok(())
    }

    /// Member-state FSM transition (kick / ban / unban / leave) on the
    /// Realm's `ck.component.member.state.v1` cell. Submits a `ck.member.state`
    /// event via `ck.self.events.submit`; deployment-local member REST shims are
    /// intentionally not used.
    pub async fn transition_member_state(
        &self,
        realm_id: &str,
        actor_id: &str,
        member: &str,
        from_state: Option<&str>,
        to_state: &str,
        reason: &str,
    ) -> anyhow::Result<SubmitEventOutcome> {
        let event = build_member_state_transition_event(
            realm_id, actor_id, member, from_state, to_state, reason,
        )?;
        self.submit_event_envelope(&event).await
    }

    /// Read the current anchorer cell value for a Realm (admin-only).
    /// Returns the raw JSON shape the server publishes — typically
    /// `{ "mode": "single_did" | "threshold" | "open_set" | "mixed",
    ///    "principals": [...], ... }`. The endpoint is being implemented
    /// in soland on a separate track (P0 M4); when it 404s the caller's
    /// `Result::Err` arm should surface a clear "endpoint unavailable"
    /// message rather than blocking the page.
    pub async fn admin_anchorer_describe(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<serde_json::Value> {
        self.get_json(&format!("_soland/admin/realms/{realm_id}/anchorer"))
            .await
    }

    pub async fn authz_check(
        &self,
        actor: &str,
        action: &str,
        realm_id: &str,
    ) -> anyhow::Result<AuthzCheckOutcome> {
        self.post_json(
            "_cokret/self/authz/check",
            json!({
                "actor_id": actor,
                "action": action,
                "resource": {"kind": "realm", "realm_id": realm_id}
            }),
        )
        .await
    }

    pub async fn authz_check_raw(
        &self,
        actor: &str,
        action: &str,
        realm_id: &str,
    ) -> anyhow::Result<Value> {
        self.post_json(
            "_cokret/self/authz/check",
            json!({
                "actor_id": actor,
                "action": action,
                "resource": {"kind": "realm", "realm_id": realm_id}
            }),
        )
        .await
    }

    pub async fn effective_grants(&self, subject: &str) -> anyhow::Result<GrantList> {
        self.get_json(&format!(
            "_cokret/self/authz/effective-grants?subject={subject}"
        ))
        .await
    }

    // ── Space / Realm Management (all writes go through ck.self.events.submit) ─

    /// Update a Realm's metadata via `ck.realm.update` event (spec-canonical).
    /// `patch` carries the merge-shape body the server reducer applies to the
    /// realm row.
    pub async fn update_realm_metadata(
        &self,
        realm_id: &str,
        actor_id: &str,
        patch: Value,
    ) -> anyhow::Result<SubmitEventOutcome> {
        if patch_touches_create_locked_encryption_profile(&patch) {
            anyhow::bail!(
                "Realm encryption_profile is locked at creation; create a new Realm to change E2EE mode."
            );
        }
        let envelope =
            crate::operation::ck_ops::realm_update_patch(realm_id, actor_id, realm_id, patch)?
                .build("yougen");
        self.submit_event_envelope(&envelope).await
    }

    /// Update a structural Space object's metadata via `ck.space.update`.
    /// The event is submitted to the Space's home Realm (`realm_id`), while
    /// `space_id` identifies the Space object being patched.
    pub async fn update_space_metadata(
        &self,
        realm_id: &str,
        space_id: &str,
        actor_id: &str,
        patch: Value,
    ) -> anyhow::Result<SubmitEventOutcome> {
        let envelope =
            crate::operation::ck_ops::space_update_patch(realm_id, actor_id, space_id, patch)?
                .build("yougen");
        self.submit_event_envelope(&envelope).await
    }

    /// Archive a Space via `ck.space.archive` event (spec-canonical).
    pub async fn archive_space(
        &self,
        space_id: &str,
        realm_id: &str,
        actor_id: &str,
    ) -> anyhow::Result<()> {
        self.change_space_lifecycle(space_id, realm_id, actor_id, "ck.space.archive")
            .await
    }

    /// Tombstone a Space via `ck.space.tombstone` event (spec-canonical).
    /// Successor of the old deployment-local Space delete REST shim.
    pub async fn delete_space(
        &self,
        space_id: &str,
        realm_id: &str,
        actor_id: &str,
    ) -> anyhow::Result<()> {
        self.change_space_lifecycle(space_id, realm_id, actor_id, "ck.space.tombstone")
            .await
    }

    /// Set Realm join_rule + history_visibility policy, optionally also
    /// emitting `ck.realm.policy_components` for Join Policy gates.
    pub async fn set_realm_policy_events(
        &self,
        realm_id: &str,
        actor_id: &str,
        join_rule: &str,
        history_visibility: &str,
        join_policy: Option<Value>,
    ) -> anyhow::Result<RealmPolicyOutcome> {
        let actor_id = actor_id.trim();
        if actor_id.is_empty() {
            return Err(anyhow::anyhow!(
                "actor_id is required for canonical Realm policy events"
            ));
        }
        if history_visibility.trim() == "restricted" {
            return Err(anyhow::anyhow!(
                "restricted history_visibility requires ck.realm.history_sharing_policy; use build_realm_history_sharing_policy_event before emitting the visibility change"
            ));
        }
        let join_rule = canonical_space_join_rule_v1(join_rule);
        let mut events = vec![
            build_realm_state_event(realm_id, actor_id, "ck.realm.join_rule", json!(join_rule))?,
            build_realm_state_event(
                realm_id,
                actor_id,
                "ck.realm.history_visibility",
                json!(history_visibility),
            )?,
        ];
        if let Some(join_policy) = join_policy {
            events.push(build_realm_state_event(
                realm_id,
                actor_id,
                "ck.realm.policy_components",
                json!({
                    "policy_revision": 1,
                    "join_policy": join_policy
                }),
            )?);
        }
        for event in events {
            self.submit_event_envelope(&event).await?;
        }
        Ok(RealmPolicyOutcome {
            ok: true,
            realm_id: realm_id.to_owned(),
            join_rule: join_rule.to_owned(),
            history_visibility: history_visibility.to_owned(),
        })
    }

    /// Create an invite via `ck.invite.create` event (spec-canonical). The
    /// `invite_id` is generated client-side so the caller can correlate
    /// optimistic UI rows with the eventual server projection.
    pub async fn invite_to_realm(
        &self,
        realm_id: &str,
        actor_id: &str,
        invite_id: &str,
        target: &str,
        role: Option<&str>,
    ) -> anyhow::Result<SubmitEventOutcome> {
        let invitee = self
            .resolve_invitee_for_invite(target, realm_id, actor_id)
            .await?;
        let envelope = crate::operation::ck_ops::invite_create_structured(
            realm_id,
            actor_id,
            invite_id,
            &invitee.did,
            role,
            invitee.invite_delivery_target,
            &invitee.introduction_evidence_digest,
        )?
        .build("yougen");
        self.submit_event_envelope(&envelope).await
    }

    /// Accept an invite via `ck.invite.accept` event (spec-canonical).
    pub async fn accept_realm_invite(
        &self,
        realm_id: &str,
        actor_id: &str,
        invite_id: &str,
    ) -> anyhow::Result<SubmitEventOutcome> {
        let envelope =
            crate::operation::ck_ops::invite_accept(realm_id, actor_id, invite_id)?.build("yougen");
        let resolved = self.resolve_realm(realm_id).await?;
        let candidate =
            select_join_candidate(&resolved, cokret_sdk::model::RealmJoinMethod::InviteAccept)?;
        self.submit_event_envelope_via_join_candidate(candidate, &envelope)
            .await
    }

    /// Join a Realm through an outstanding invite. The invite projection
    /// records are discovery state; the membership change itself is the
    /// canonical `ck.member.state` invite -> join transition.
    pub async fn join_realm_from_invite(
        &self,
        realm_id: &str,
        actor_id: &str,
        invite_id: &str,
    ) -> anyhow::Result<SubmitEventOutcome> {
        let envelope = build_member_state_invite_accept_event(realm_id, actor_id, invite_id)?;
        let resolved = self.resolve_realm(realm_id).await?;
        let candidate =
            select_join_candidate(&resolved, cokret_sdk::model::RealmJoinMethod::InviteAccept)?;
        self.submit_event_envelope_via_join_candidate(candidate, &envelope)
            .await
    }

    async fn submit_event_envelope_via_join_candidate(
        &self,
        candidate: &RealmJoinCandidate,
        event: &EventEnvelope,
    ) -> anyhow::Result<SubmitEventOutcome> {
        let Some(endpoint) = candidate
            .endpoint
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return self.submit_event_envelope(event).await;
        };
        let endpoint_url = validate_server_url(endpoint)?;
        if endpoint_url == self.base_url {
            return self.submit_event_envelope(event).await;
        }

        let mut routed = CokretApi::new(endpoint)?;
        if let Some(token) = self.access_token.as_deref() {
            routed = routed.with_bearer(token.to_owned());
        }
        if let Some(sync_token) = self.wait_for_sync_token.as_deref() {
            routed = routed.with_wait_for(sync_token.to_owned());
        }
        routed.submit_event_envelope(event).await
    }

    /// Reject an invite via `ck.invite.cancel` event (spec-canonical).
    pub async fn reject_realm_invite(
        &self,
        realm_id: &str,
        actor_id: &str,
        invite_id: &str,
        reason: Option<&str>,
    ) -> anyhow::Result<SubmitEventOutcome> {
        let envelope =
            crate::operation::ck_ops::invite_cancel(realm_id, actor_id, invite_id, reason)?
                .build("yougen");
        self.submit_event_envelope(&envelope).await
    }

    /// Leave a Realm via `ck.member.state` event (`join → leave` FSM).
    pub async fn leave_realm(
        &self,
        realm_id: &str,
        actor_id: &str,
    ) -> anyhow::Result<SubmitEventOutcome> {
        self.transition_member_state(
            realm_id,
            actor_id,
            actor_id,
            Some("join"),
            "leave",
            "self_leave",
        )
        .await
    }

    /// Archive a Realm via the reversible `ck.realm.archive` lifecycle facet.
    pub async fn archive_realm(
        &self,
        realm_id: &str,
        actor_id: &str,
    ) -> anyhow::Result<SubmitEventOutcome> {
        let envelope =
            build_realm_archive_event(realm_id, actor_id, true, Some("operator_request"))?;
        self.submit_event_envelope(&envelope).await
    }

    /// Restore a Realm by writing `ck.realm.archive{archived:false}`.
    pub async fn restore_realm(
        &self,
        realm_id: &str,
        actor_id: &str,
    ) -> anyhow::Result<SubmitEventOutcome> {
        let envelope =
            build_realm_archive_event(realm_id, actor_id, false, Some("operator_request"))?;
        self.submit_event_envelope(&envelope).await
    }

    /// Tombstone a Realm and point clients at an explicit successor Realm.
    pub async fn tombstone_realm(
        &self,
        realm_id: &str,
        actor_id: &str,
        successor_realm_id: &str,
        reason: &str,
    ) -> anyhow::Result<SubmitEventOutcome> {
        let envelope = build_realm_tombstone_event(realm_id, actor_id, successor_realm_id, reason)?;
        self.submit_event_envelope(&envelope).await
    }

    /// Permanently retire a Realm via `ck.realm.destroy`.
    pub async fn destroy_realm(
        &self,
        realm_id: &str,
        actor_id: &str,
        reason: &str,
    ) -> anyhow::Result<SubmitEventOutcome> {
        let envelope = build_realm_destroy_event(realm_id, actor_id, reason)?;
        self.submit_event_envelope(&envelope).await
    }

    /// Ban a member via `ck.member.state` event (`join → ban` FSM).
    pub async fn ban_member(
        &self,
        realm_id: &str,
        actor_id: &str,
        member: &str,
    ) -> anyhow::Result<SubmitEventOutcome> {
        self.transition_member_state(realm_id, actor_id, member, Some("join"), "ban", "admin_ban")
            .await
    }

    // ── Views — collection projection (T20) ─────────────────────────
    //
    // Pairs with cokret-rust-sdk@9d02761 + soland@1cdab88.
    // POST /_cokret/self/views/{view_id}/projection returns the typed
    // CollectionProjectionResBody defined in cokret_core::model.
    pub async fn collection_projection(
        &self,
        view_id: &str,
    ) -> anyhow::Result<cokret_sdk::CollectionProjectionResBody> {
        self.post_json(
            &format!("_cokret/self/views/{view_id}/projection"),
            json!({}),
        )
        .await
    }

    // Pull the canonical Space-container / Flow lifecycle state for a Realm so the
    // kanban view can hydrate `column.state` / `card.lifecycle` after a
    // refresh. Pairs with soland's `routing::events::projection_query`.
    pub async fn list_space_container_projections(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<LifecycleProjectionOutcome<SpaceContainerProjectionView>> {
        // `ck:realm:<uuid>` is RFC-3986-safe in query string position
        // (colon + hyphen + alpha-digit), so no percent-encoding needed.
        let realm_id = trim_realm_id(realm_id);
        let path = format!("_cokret/self/projection/spaces?realm_id={realm_id}");
        self.get_json(&path).await
    }

    pub async fn list_flow_projections(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<LifecycleProjectionOutcome<FlowProjectionView>> {
        let realm_id = trim_realm_id(realm_id);
        let path = format!("_cokret/self/projection/flows?realm_id={realm_id}");
        self.get_json(&path).await
    }

    pub async fn document_projection(&self, morph_id: &str) -> anyhow::Result<Value> {
        self.get_json(&format!("_cokret/self/projection/documents/{morph_id}"))
            .await
    }

    /// Resolve the current anchor head for `realm_id` to be stamped onto
    /// outgoing reducer-input events as `anchor_ref`.
    ///
    /// Spec resolution (2026-06-11, `renames.json` migration group
    /// `snapshot_head_returns_manifest`): `ck.self.snapshot.head` returns
    /// the full signed `ck.schema.snapshot.v1` manifest, which carries no
    /// `ck:anchor:sha256:<hex>` head — the legacy `SnapshotHeadState`
    /// pointer DTO (whose `snapshot_ref` doubled as the anchor head) is
    /// hard-rejected on current wire. Until anchor-head sourcing is
    /// re-specified for clients, fail closed instead of fabricating an
    /// `anchor_ref`. soland currently fails closed earlier with
    /// `not_implemented` on the operation, so the post-decode branch is
    /// unreachable against current servers either way.
    pub async fn current_anchor_for(&self, realm_id: &str) -> anyhow::Result<String> {
        let manifest_id = self
            .snapshot_head(realm_id)
            .await?
            .map(|manifest| manifest.id.to_string())
            .unwrap_or_else(|| "unavailable".to_owned());
        anyhow::bail!(
            "ck.self.snapshot.head for {realm_id} returned snapshot manifest `{manifest_id}`, \
             which carries no anchor head \u{2014} cannot stamp anchor_ref"
        );
    }
}
