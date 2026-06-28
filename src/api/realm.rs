use super::*;

impl CokretApi {
    /// Build + submit the spec-canonical `ck.realm.create` event bundle
    /// (and its facet follow-ups) via `ck.self.events.command.submit`
    /// (`POST /_cokret/self/events`).
    ///
    /// Per spec realm-and-space.md §2.5 the create event itself is the
    /// genesis-member declaration for `created_by`. The
    /// server reducer bootstraps the member set atomically with the
    /// metadata, so the same actor's per-facet follow-ups
    /// (`ck.realm.join_rule` / `ck.realm.history_visibility` /
    /// `ck.realm.discovery` / `ck.realm.plaintext_visible_services` /
    /// invitee `ck.member.state` invites) all pass the regular
    /// `realm_has_member` authz check naturally.
    ///
    /// All five create-locked fields per spec §2.3 (`encryption_profile`,
    /// `security_class`, `federation_policy`, `notary_profile`,
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
        notary_profile: &str,
        digest_algorithm: &str,
        trust_domain: &str,
        invitees: Vec<String>,
        plaintext_visible_services: Vec<String>,
        alias: Option<&str>,
    ) -> anyhow::Result<RealmCreateResult> {
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
        let mut events = build_realm_bootstrap_events(
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
            notary_profile,
            digest_algorithm,
            trust_domain,
            &invitees,
            &plaintext_visible_services,
            alias,
        )?;
        // Genesis Realm bootstrap has no prior snapshot head. The
        // `ck.realm.create` precondition asserts `head_eq null`; follow-up
        // facet events in the same batch are admitted after soland
        // materialises the creator membership from the create event.
        // Sign every SDK Event before it reaches the wire; the batch
        // submitter takes pre-signed typed Events.
        let proof_context = self.event_proof_context().await?;
        for event in events.iter_mut() {
            crate::event_signer::sign_sdk_event_with_active_context(event, proof_context.clone())
                .map_err(|err| {
                    anyhow::anyhow!(
                        "no active signer configured \u{2014} cannot submit unsigned realm bootstrap: {err}"
                    )
                })?;
        }
        let idempotency_key = format!("ck:operation:{}", uuid_v7());
        self.submit_signed_sdk_events_batch(&events, Some(&idempotency_key))
            .await?;

        let resolved_invitees = parse_realm_bootstrap_members(&invitees)?;
        let mut members = Vec::new();
        members.push(actor_id.to_owned());
        for invitee in resolved_invitees {
            if !members.iter().any(|member| member == &invitee.actor_id) {
                members.push(invitee.actor_id);
            }
        }

        Ok(RealmCreateResult {
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
    ) -> anyhow::Result<SpaceCreateResult> {
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
        self.submit_built_event(&event).await?;

        Ok(SpaceCreateResult {
            ok: true,
            space_id,
            owner: actor_id.to_owned(),
            members: vec![actor_id.to_owned()],
            state: "active".to_owned(),
        })
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
        kind: EventKind,
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
        self.submit_built_event(&event).await?;
        Ok(())
    }

    /// Member-state FSM transition (kick / ban / unban / leave) on the
    /// Realm's `ck.component.member.state.v1` cell. Submits a `ck.member.state`
    /// event via `ck.self.events.command.submit`; deployment-local member REST shims are
    /// intentionally not used.
    pub async fn transition_member_state(
        &self,
        realm_id: &str,
        actor_id: &str,
        member: &str,
        from_state: Option<&str>,
        to_state: &str,
        reason: &str,
    ) -> anyhow::Result<SubmitEventResult> {
        let event = build_member_state_transition_event(
            realm_id, actor_id, member, from_state, to_state, reason,
        )?;
        self.submit_built_event(&event).await
    }

    /// Read the current notary cell value for a Realm (admin-only).
    /// Returns the raw JSON shape the server publishes — typically
    /// `{ "mode": "single_did" | "threshold" | "open_set" | "mixed",
    ///    "principals": [...], ... }`. The endpoint is being implemented
    /// in soland on a separate track (P0 M4); when it 404s the caller's
    /// `Result::Err` arm should surface a clear "endpoint unavailable"
    /// message rather than blocking the page.
    pub async fn admin_notary_describe(&self, realm_id: &str) -> anyhow::Result<serde_json::Value> {
        let _ = realm_id;
        anyhow::bail!("admin notary describe has no spec-defined Cokret HTTP endpoint")
    }

    pub async fn authz_check(
        &self,
        actor: &str,
        action: &str,
        realm_id: &str,
    ) -> anyhow::Result<AuthzCheckOutcome> {
        self.authz_check_resource(
            actor,
            action,
            Some(json!({"kind": "realm", "realm_id": realm_id.trim()})),
        )
        .await
    }

    pub async fn authz_check_resource(
        &self,
        actor: &str,
        action: &str,
        resource: Option<Value>,
    ) -> anyhow::Result<AuthzCheckOutcome> {
        let body = cokret_sdk::models::AuthzCheckRequestBody {
            actor_id: cokret_sdk::Did::new(actor.trim().to_owned())?,
            action: action.trim().to_owned(),
            resource,
            context: None,
        };
        self.post_json("_cokret/self/authz/check", &body).await
    }

    pub async fn authz_check_resource_raw(
        &self,
        actor: &str,
        action: &str,
        resource: Option<Value>,
    ) -> anyhow::Result<Value> {
        let response = self.authz_check_resource(actor, action, resource).await?;
        Ok(serde_json::to_value(response)?)
    }

    pub async fn authz_check_raw(
        &self,
        actor: &str,
        action: &str,
        realm_id: &str,
    ) -> anyhow::Result<Value> {
        let response = self.authz_check(actor, action, realm_id).await?;
        Ok(serde_json::to_value(response)?)
    }

    pub async fn effective_grants(&self, subject: &str) -> anyhow::Result<GrantList> {
        self.get_json(&format!(
            "_cokret/self/authz/effective-grants?subject={subject}"
        ))
        .await
    }

    // ── Space / Realm Management (all writes go through ck.self.events.command.submit) ─

    /// Update a Realm's metadata via `ck.realm.update` event (spec-canonical).
    /// `patch` carries the merge-shape body the server reducer applies to the
    /// realm row.
    pub async fn update_realm_metadata(
        &self,
        realm_id: &str,
        actor_id: &str,
        patch: Value,
    ) -> anyhow::Result<SubmitEventResult> {
        if patch_touches_create_locked_encryption_profile(&patch) {
            anyhow::bail!(
                "Realm encryption_profile is locked at creation; create a new Realm to change E2EE mode."
            );
        }
        let event =
            crate::operation::ck_ops::realm_update_patch(realm_id, actor_id, realm_id, patch)?
                .build_sdk_event("yougen")?;
        self.submit_built_event(&event).await
    }

    /// Update the Realm plaintext-visible service facet through the
    /// dedicated `ck.realm.plaintext_visible_services` event. This is not a
    /// `ck.realm.update` metadata patch: servers enforce plaintext access from
    /// the typed facet projection.
    pub async fn update_realm_plaintext_visible_services(
        &self,
        realm_id: &str,
        actor_id: &str,
        services: Vec<String>,
    ) -> anyhow::Result<SubmitEventResult> {
        let Some(mut event) =
            build_plaintext_visible_services_event(realm_id, actor_id, &services)?
        else {
            anyhow::bail!("plaintext_visible_services update requires at least one service DID");
        };
        let seal_view = self.events_frontier_realm_seal_view(realm_id).await?;
        event.seal_basis = Some(seal_view.seal_basis());
        event.seal_ref = None;
        event.auth_context = None;
        self.submit_built_event(&event).await
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
    ) -> anyhow::Result<SubmitEventResult> {
        let event =
            crate::operation::ck_ops::space_update_patch(realm_id, actor_id, space_id, patch)?
                .build_sdk_event("yougen")?;
        self.submit_built_event(&event).await
    }

    /// Archive a Space via `ck.space.archive` event (spec-canonical).
    pub async fn archive_space(
        &self,
        space_id: &str,
        realm_id: &str,
        actor_id: &str,
    ) -> anyhow::Result<()> {
        self.change_space_lifecycle(space_id, realm_id, actor_id, EventKind::SpaceArchive)
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
        self.change_space_lifecycle(space_id, realm_id, actor_id, EventKind::SpaceTombstone)
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
        preserve_recommended_encryption_floor: bool,
    ) -> anyhow::Result<RealmPolicyResult> {
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
            build_realm_state_event(
                realm_id,
                actor_id,
                EventKind::RealmJoinRule,
                json!(join_rule),
            )?,
            build_realm_state_event(
                realm_id,
                actor_id,
                EventKind::RealmHistoryVisibility,
                json!(history_visibility),
            )?,
        ];
        if let Some(policy) = recommended_history_sharing_policy_for_visibility(history_visibility)
        {
            events.push(build_realm_history_sharing_policy_event(
                realm_id, actor_id, policy,
            )?);
        }
        if let Some(join_policy) = join_policy {
            let mut policy_components = if preserve_recommended_encryption_floor {
                recommended_realm_policy_components_value()
            } else {
                json!({
                    "policy_revision": 1,
                })
            };
            policy_components["join_policy"] = join_policy;
            events.push(build_realm_state_event(
                realm_id,
                actor_id,
                EventKind::RealmPolicyComponents,
                policy_components,
            )?);
        }
        for event in events {
            self.submit_built_event(&event).await?;
        }
        Ok(RealmPolicyResult {
            ok: true,
            realm_id: realm_id.to_owned(),
            join_rule: join_rule.to_owned(),
            history_visibility: history_visibility.to_owned(),
        })
    }

    /// Set (or clear) the Realm Recovery Key (RRK) `durability_policy` via a
    /// `ck.realm.policy_components` event (realm-and-space.md §2.3.1 write path —
    /// no new event kind; durability is a policy component).
    ///
    /// `policy` is the SDK-typed [`cokret_sdk::models::DurabilityPolicy`]
    /// so the client never re-defines the spec shape. `policy_revision` MUST be a
    /// monotonic increment of the Realm's current policy revision (the reducer
    /// rejects a stale revision). After this lands, a subsequent `ck.mls.commit`
    /// covering the membership frontier activates the new epoch's sealing
    /// obligation and triggers re-disclosure (§2.10.8) — the caller SHOULD prompt
    /// an MLS commit / self-update afterward.
    ///
    /// Pre-condition (caller-enforced): RRK durability is only effective when the
    /// Realm uses `content_scheme=mls-exporter-aead-v1`; declaring `mode != none`
    /// on a plain `mls-rfc9420` Realm is rejected server-side
    /// (`durability_scheme_incompatible`).
    pub async fn set_realm_durability_policy(
        &self,
        realm_id: &str,
        actor_id: &str,
        policy: &cokret_sdk::models::DurabilityPolicy,
        policy_revision: u64,
    ) -> anyhow::Result<()> {
        let actor_id = actor_id.trim();
        if actor_id.is_empty() {
            return Err(anyhow::anyhow!(
                "actor_id is required for ck.realm.policy_components"
            ));
        }
        let durability_value = serde_json::to_value(policy)
            .map_err(|err| anyhow::anyhow!("serialize durability_policy: {err}"))?;
        let policy_components = json!({
            "policy_revision": policy_revision,
            "durability_policy": durability_value,
        });
        let event = build_realm_state_event(
            realm_id,
            actor_id,
            EventKind::RealmPolicyComponents,
            policy_components,
        )?;
        self.submit_built_event(&event).await?;
        Ok(())
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
    ) -> anyhow::Result<SubmitEventResult> {
        let invitee = self
            .resolve_invitee_for_invite(target, realm_id, actor_id)
            .await?;
        let event = crate::operation::ck_ops::invite_create_structured(
            realm_id,
            actor_id,
            invite_id,
            &invitee.did,
            role,
            invitee.invite_delivery_target,
            &invitee.introduction_evidence_digest,
        )?
        .build_sdk_event("yougen")?;
        self.submit_built_event(&event).await
    }

    /// Accept an invite via `ck.invite.accept` event (spec-canonical).
    pub async fn accept_realm_invite(
        &self,
        realm_id: &str,
        actor_id: &str,
        invite_id: &str,
    ) -> anyhow::Result<SubmitEventResult> {
        let mut event = crate::operation::ck_ops::invite_accept(realm_id, actor_id, invite_id)?
            .build_sdk_event("yougen")?;
        let resolved = self.resolve_realm(realm_id).await?;
        let candidate =
            select_join_candidate(&resolved, cokret_sdk::models::RealmJoinMethod::InviteAccept)?;
        stamp_invite_join_seal_basis(&mut event, candidate)?;
        self.submit_built_event_via_join_candidate(candidate, &event)
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
    ) -> anyhow::Result<SubmitEventResult> {
        let mut event = build_member_state_invite_accept_event(realm_id, actor_id, invite_id)?;
        let resolved = self.resolve_realm(realm_id).await?;
        let candidate =
            select_join_candidate(&resolved, cokret_sdk::models::RealmJoinMethod::InviteAccept)?;
        stamp_invite_join_seal_basis(&mut event, candidate)?;
        self.submit_built_event_via_join_candidate(candidate, &event)
            .await
    }

    async fn submit_built_event(
        &self,
        event: &cokret_sdk::Event,
    ) -> anyhow::Result<SubmitEventResult> {
        self.submit_sdk_event(event).await
    }

    async fn submit_built_event_via_join_candidate(
        &self,
        candidate: &RealmJoinCandidate,
        event: &cokret_sdk::Event,
    ) -> anyhow::Result<SubmitEventResult> {
        let Some(endpoint) = candidate
            .endpoint
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return self.submit_sdk_event(event).await;
        };
        let endpoint_url = validate_server_url(endpoint)?;
        if endpoint_url == self.base_url {
            return self.submit_sdk_event(event).await;
        }

        let mut routed = CokretApi::new(endpoint)?;
        if let Some(token) = self.authorization_credential.as_deref() {
            routed = routed.with_bearer(token.to_owned());
        }
        if let Some(sync_token) = self.wait_for_sync_token.as_deref() {
            routed = routed.with_wait_for(sync_token.to_owned());
        }
        routed.submit_sdk_event(event).await
    }

    /// Reject an invite via `ck.invite.cancel` event (spec-canonical).
    pub async fn reject_realm_invite(
        &self,
        realm_id: &str,
        actor_id: &str,
        invite_id: &str,
        reason: Option<&str>,
    ) -> anyhow::Result<SubmitEventResult> {
        let event = crate::operation::ck_ops::invite_cancel(realm_id, actor_id, invite_id, reason)?
            .build_sdk_event("yougen")?;
        self.submit_built_event(&event).await
    }

    /// Leave a Realm via `ck.member.state` event (`join → leave` FSM).
    pub async fn leave_realm(
        &self,
        realm_id: &str,
        actor_id: &str,
    ) -> anyhow::Result<SubmitEventResult> {
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
    ) -> anyhow::Result<SubmitEventResult> {
        let event = build_realm_archive_event(realm_id, actor_id, true, Some("operator_request"))?;
        self.submit_built_event(&event).await
    }

    /// Restore a Realm by writing `ck.realm.archive{archived:false}`.
    pub async fn restore_realm(
        &self,
        realm_id: &str,
        actor_id: &str,
    ) -> anyhow::Result<SubmitEventResult> {
        let event = build_realm_archive_event(realm_id, actor_id, false, Some("operator_request"))?;
        self.submit_built_event(&event).await
    }

    /// Tombstone a Realm and point clients at an explicit successor Realm.
    pub async fn tombstone_realm(
        &self,
        realm_id: &str,
        actor_id: &str,
        successor_realm_id: &str,
        reason: &str,
    ) -> anyhow::Result<SubmitEventResult> {
        let event = build_realm_tombstone_event(realm_id, actor_id, successor_realm_id, reason)?;
        self.submit_built_event(&event).await
    }

    /// Permanently retire a Realm via `ck.realm.destroy`.
    pub async fn destroy_realm(
        &self,
        realm_id: &str,
        actor_id: &str,
        reason: &str,
    ) -> anyhow::Result<SubmitEventResult> {
        let event = build_realm_destroy_event(realm_id, actor_id, reason)?;
        self.submit_built_event(&event).await
    }

    /// Ban a member via `ck.member.state` event (`join → ban` FSM).
    pub async fn ban_member(
        &self,
        realm_id: &str,
        actor_id: &str,
        member: &str,
    ) -> anyhow::Result<SubmitEventResult> {
        self.transition_member_state(realm_id, actor_id, member, Some("join"), "ban", "admin_ban")
            .await
    }

    // ── Daily governance — protocol-event pipeline (P3) ───────────────
    //
    // Setting / revoking Realm admins, sealing moderation decisions, and
    // running the appeal loop are now self-authored protocol Moves submitted
    // via `ck.self.events.command.submit` (`POST /_cokret/self/events`) —
    // mirroring `transition_member_state` / `ban_member`. P1 (capability)
    // and P2 (moderation) projected the matching reducers in soland and the
    // sodmin-side admin write paths were retired; these are the yougen-side
    // submitters that drive them.

    /// Grant Realm admin authority to `subject` by emitting a
    /// `ck.capability.grant{actions:[ck.realm.admin], subject}` event.
    /// `grant_id` is minted client-side so the caller can correlate the
    /// optimistic row with the eventual projection. P1's `apply_capability`
    /// folds this into the soland authz index, so subsequent
    /// `ck.realm.admin` checks for `subject` pass.
    pub async fn grant_realm_admin(
        &self,
        realm_id: &str,
        actor_id: &str,
        grant_id: &str,
        subject: &str,
    ) -> anyhow::Result<SubmitEventResult> {
        let event = crate::operation::ck_ops::capability_grant_actions(
            realm_id,
            actor_id,
            grant_id,
            subject,
            &["ck.realm.admin"],
            None,
            Value::Null,
        )
        .build_sdk_event("yougen")?;
        self.submit_built_event(&event).await
    }

    /// Revoke a Realm-admin grant via `ck.capability.revoke`. `grant_id`
    /// MUST be the id of the grant established by [`grant_realm_admin`]
    /// (the soland reducer locates the cell by `grant_id`).
    pub async fn revoke_realm_admin(
        &self,
        realm_id: &str,
        actor_id: &str,
        grant_id: &str,
        reason: Option<&str>,
    ) -> anyhow::Result<SubmitEventResult> {
        let event = crate::operation::ck_ops::capability_revoke(
            realm_id,
            actor_id,
            grant_id,
            "ck.realm.admin",
            reason,
        )
        .build_sdk_event("yougen")?;
        self.submit_built_event(&event).await
    }

    /// Seal a moderation disposition via `ck.moderation.decision`.
    /// `decision_id` (cell subject) is minted client-side.
    pub async fn moderation_decide(
        &self,
        realm_id: &str,
        actor_id: &str,
        decision_id: &str,
        target_ref: &str,
        verdict: &str,
        reason_code: &str,
    ) -> anyhow::Result<SubmitEventResult> {
        let event = crate::operation::ck_ops::moderation_decision(
            realm_id,
            actor_id,
            decision_id,
            target_ref,
            verdict,
            reason_code,
        )
        .build_sdk_event("yougen")?;
        self.submit_built_event(&event).await
    }

    /// Lift a previously sealed moderation decision via
    /// `ck.moderation.decision.lift`. `decision_ref` is the lifted
    /// decision's `decision_id`.
    pub async fn moderation_lift(
        &self,
        realm_id: &str,
        actor_id: &str,
        decision_ref: &str,
        reason_code: &str,
    ) -> anyhow::Result<SubmitEventResult> {
        let event = crate::operation::ck_ops::moderation_decision_lift(
            realm_id,
            actor_id,
            decision_ref,
            reason_code,
        )
        .build_sdk_event("yougen")?;
        self.submit_built_event(&event).await
    }

    /// Take an appeal under review (`ck.moderation.appeal.review`).
    pub async fn appeal_review(
        &self,
        realm_id: &str,
        actor_id: &str,
        appeal_id: &str,
        notes_ref: Option<&str>,
    ) -> anyhow::Result<SubmitEventResult> {
        let event = crate::operation::ck_ops::moderation_appeal_review(
            realm_id, actor_id, appeal_id, notes_ref,
        )
        .build_sdk_event("yougen")?;
        self.submit_built_event(&event).await
    }

    /// Decide an appeal (`ck.moderation.appeal.decision`). For an
    /// `overturn` verdict the caller MUST also submit a matching
    /// [`Self::moderation_lift`] in the same ordered batch; for `modify`,
    /// pass the replacement decision id as `modify_decision_ref` and submit
    /// that new [`Self::moderation_decide`] in the same batch. This single
    /// call only mints the appeal-decision event.
    pub async fn appeal_decide(
        &self,
        realm_id: &str,
        actor_id: &str,
        appeal_id: &str,
        verdict: &str,
        reason_text_ref: &str,
        modify_decision_ref: Option<&str>,
    ) -> anyhow::Result<SubmitEventResult> {
        let event = crate::operation::ck_ops::moderation_appeal_decision(
            realm_id,
            actor_id,
            appeal_id,
            verdict,
            reason_text_ref,
            modify_decision_ref,
        )
        .build_sdk_event("yougen")?;
        self.submit_built_event(&event).await
    }

    /// `governance/content-moderation.md` §5.5.1.1 — atomically decide an
    /// appeal `verdict=overturn`. The reducer rejects an overturn whose
    /// matching `ck.moderation.decision.lift` (target = `decision_ref`) is not
    /// in the SAME ordered submit batch (`appeal_overturn_missing_lift`), so
    /// this helper builds BOTH events, signs them, and submits them via
    /// [`Self::submit_signed_sdk_events_batch`] as one transaction.
    ///
    /// Order matters: the appeal-decision precedes the lift it authorizes.
    pub async fn appeal_overturn_atomic(
        &self,
        realm_id: &str,
        actor_id: &str,
        appeal_id: &str,
        decision_ref: &str,
        reason_text_ref: &str,
        lift_reason_code: &str,
    ) -> anyhow::Result<cokret_sdk::EventsSubmitOutcome> {
        let appeal_event = crate::operation::ck_ops::moderation_appeal_decision(
            realm_id,
            actor_id,
            appeal_id,
            "overturn",
            reason_text_ref,
            None,
        )
        .build_sdk_event("yougen")?;
        let lift_event = crate::operation::ck_ops::moderation_decision_lift(
            realm_id,
            actor_id,
            decision_ref,
            lift_reason_code,
        )
        .build_sdk_event("yougen")?;
        self.sign_and_submit_moderation_batch(realm_id, vec![appeal_event, lift_event])
            .await
    }

    /// `governance/content-moderation.md` §5.5.1.1 — atomically decide an
    /// appeal `verdict=modify`. The reducer rejects a modify whose
    /// replacement `ck.moderation.decision` (target = original target) is not
    /// in the same batch, and cross-checks that the appeal-decision's
    /// `modify_decision_ref` equals that new decision's event id. This helper
    /// mints the replacement decision id, stamps it as `modify_decision_ref`,
    /// and submits both events as one transaction.
    ///
    /// Returns the minted replacement `decision_id` alongside the batch result
    /// so the caller can surface it.
    pub async fn appeal_modify_atomic(
        &self,
        realm_id: &str,
        actor_id: &str,
        appeal_id: &str,
        target_ref: &str,
        new_verdict: &str,
        new_reason_code: &str,
        appeal_reason_text_ref: &str,
    ) -> anyhow::Result<(String, cokret_sdk::EventsSubmitOutcome)> {
        let new_decision_id = format!("ck:event:{}", crate::operation::uuid_v7());
        let mut new_decision = crate::operation::ck_ops::moderation_decision(
            realm_id,
            actor_id,
            &new_decision_id,
            target_ref,
            new_verdict,
            new_reason_code,
        )
        .build_sdk_event("yougen")?;
        // The reducer matches `modify_decision_ref` against the new decision's
        // EVENT id, so pin the SDK Event id to the same value we report.
        new_decision.event_id = cokret_sdk::EventId::new(new_decision_id.clone())
            .map_err(|err| anyhow::anyhow!("replacement decision id is invalid: {err}"))?;
        let appeal_event = crate::operation::ck_ops::moderation_appeal_decision(
            realm_id,
            actor_id,
            appeal_id,
            "modify",
            appeal_reason_text_ref,
            Some(&new_decision_id),
        )
        .build_sdk_event("yougen")?;
        let result = self
            .sign_and_submit_moderation_batch(realm_id, vec![appeal_event, new_decision])
            .await?;
        Ok((new_decision_id, result))
    }

    /// Seal-stamp + sign each event in a moderation control transaction, then
    /// submit them atomically via [`Self::submit_signed_sdk_events_batch`]. Shared
    /// by [`Self::appeal_overturn_atomic`] / [`Self::appeal_modify_atomic`].
    /// All envelopes ride the same Realm seal head so the batch is one
    /// consistent control view.
    async fn sign_and_submit_moderation_batch(
        &self,
        _realm_id: &str,
        mut events: Vec<cokret_sdk::Event>,
    ) -> anyhow::Result<cokret_sdk::EventsSubmitOutcome> {
        for event in &mut events {
            self.stamp_cba_basis_for_sdk_event(event).await?;
        }
        let proof_context = self.event_proof_context().await?;
        for event in events.iter_mut() {
            if event.proofs.is_empty() {
                crate::event_signer::sign_sdk_event_with_active_context(
                    event,
                    proof_context.clone(),
                )
                .map_err(|err| {
                    anyhow::anyhow!(
                        "no active signer configured \u{2014} cannot submit moderation batch: {err}"
                    )
                })?;
            }
        }
        self.submit_signed_sdk_events_batch(&events, None).await
    }

    /// Close an appeal (`ck.moderation.appeal.close`). Reviewer close or
    /// appellant withdrawal (the reducer authorizes withdrawal via
    /// `closer == appellant`).
    pub async fn appeal_close(
        &self,
        realm_id: &str,
        actor_id: &str,
        appeal_id: &str,
        close_reason: Option<&str>,
    ) -> anyhow::Result<SubmitEventResult> {
        let event = crate::operation::ck_ops::moderation_appeal_close(
            realm_id,
            actor_id,
            appeal_id,
            close_reason,
        )
        .build_sdk_event("yougen")?;
        self.submit_built_event(&event).await
    }

    // ── Views — collection projection (T20 / YOU-01-009 subtask 3) ──────
    //
    // Spec-registered operation `ck.self.views.collection_projection.command.materialize`
    // (`POST /_cokret/self/views/{view_id}/projection`, spec commit
    // b0cfa89). The request body is the registered
    // `view_projection_request_body` (`{cursor?, limit?}` — an empty
    // object is valid) and the response is parsed as the registered
    // `collection_projection_view` shape (`super::CollectionProjectionView`).
    pub async fn collection_projection(
        &self,
        view_id: &str,
    ) -> anyhow::Result<super::CollectionProjectionView> {
        let body = cokret_sdk::models::ViewProjectionRequestBody::default();
        let view: cokret_sdk::CollectionProjectionView = self
            .post_json(&format!("_cokret/self/views/{view_id}/projection"), &body)
            .await?;
        Ok(view.into())
    }

    // Pull the canonical Space-container / Strand lifecycle state for a Realm so the
    // kanban view can hydrate `column.state` / `card.lifecycle` after a
    // refresh. Pairs with soland's `routing::events::projection_query`.
    pub async fn list_space_container_projections(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<LifecycleProjectionView<SpaceContainerProjectionView>> {
        // `ck:realm:<uuid>` is RFC-3986-safe in a path segment (colon, hyphen,
        // and alpha-digit are all pchar), so no percent-encoding needed.
        let realm_id = trim_realm_id(realm_id);
        let path = format!("_cokret/self/realms/{realm_id}/spaces");
        self.get_json(&path).await
    }

    pub async fn list_strand_projections(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<LifecycleProjectionView<StrandProjectionView>> {
        let realm_id = trim_realm_id(realm_id);
        let path = format!("_cokret/self/realms/{realm_id}/strands");
        self.get_json(&path).await
    }

    pub async fn document_projection(
        &self,
        realm_id: &str,
        morph_id: &str,
    ) -> anyhow::Result<Value> {
        let realm_id = trim_realm_id(realm_id);
        self.get_json(&format!("_cokret/self/realms/{realm_id}/morphs/{morph_id}"))
            .await
    }

    /// Resolve the current seal head for `realm_id` to be stamped onto
    /// outgoing reducer-input events as `seal_ref`.
    ///
    /// Spec resolution (2026-06-12, SPEC-SOL-003): the registered
    /// account-client sourcing is `ck.self.events.query.frontier?realm_id=`,
    /// whose Realm Seal view carries `{seal_id, control_event_set_root,
    /// state_root, hlc?}`. `seal_id` is the DataEvent `seal_ref`; the
    /// full view mints a single-leaf Control Move `seal_basis` (use
    /// [`Self::events_frontier_realm_seal_view`] directly for that).
    /// When the sourcing is unavailable this still fails closed — no
    /// fabricated seal heads.
    pub async fn current_seal_for(&self, realm_id: &str) -> anyhow::Result<String> {
        let view = self.events_frontier_realm_seal_view(realm_id).await?;
        Ok(view.seal_id.to_string())
    }
}

/// Stamp an invite→join Control Move's `seal_basis` from the resolve-realm
/// join candidate.
///
/// The invitee is not yet a member, so it cannot read the membership-gated
/// `GET /_cokret/self/events/frontier?realm_id=` Realm Seal view (it answers
/// `404 realm not found`). The current Seal basis is instead disclosed by
/// resolve-realm, authorized by the invite, in the join candidate. Stamp it
/// before signing so [`CokretApi::submit_built_event`] does not fall back to
/// the 404-prone frontier read or incorrectly turn the Control Move into a
/// DataEvent.
///
/// Only stamps when the event actually needs a Control Move basis: it carries
/// effects and has no CBA basis yet.
fn stamp_invite_join_seal_basis(
    event: &mut cokret_sdk::Event,
    candidate: &RealmJoinCandidate,
) -> anyhow::Result<()> {
    if event.effects.is_empty() || event.seal_basis.is_some() {
        return Ok(());
    }
    if event.seal_ref.is_some() {
        anyhow::bail!("invite join Control Move must use seal_basis, not seal_ref");
    }
    if candidate.seal_basis.leaves.is_empty() {
        anyhow::bail!("resolve_realm join candidate seal_basis has no leaves");
    }
    event.seal_basis = Some(candidate.seal_basis.clone());
    Ok(())
}
