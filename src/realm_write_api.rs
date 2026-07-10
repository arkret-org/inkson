//! E2 strangler — realm write free functions migrated out of `CokretApi`.
//!
//! These are the realm / space / member / governance event-building
//! submitters that formerly lived as inherent methods on
//! `crate::api::CokretApi`. Each takes an
//! [`crate::event_submit::EventSubmitter`] as its first argument and
//! submits through it, so call sites can drop the `CokretApi` facade in
//! favour of `with_event_submitter`. `accept_realm_invite` stays inherent
//! on `CokretApi` because its cross-endpoint join routing needs the
//! facade's base-url / credential / sync-token state.

use serde_json::{Value, json};

use crate::event_builders::{
    build_member_state_transition_event, build_plaintext_visible_services_event,
    build_realm_archive_event, build_realm_bootstrap_events, build_realm_destroy_event,
    build_realm_history_sharing_policy_event, build_realm_state_event, build_space_create_event,
    build_space_lifecycle_event, parse_realm_bootstrap_members,
    recommended_history_sharing_policy_for_visibility, recommended_realm_policy_components_value,
};
use crate::event_submit::EventSubmitter;
use crate::models::{RealmCreateResult, RealmPolicyResult, SpaceCreateResult, SubmitEventResult};
use crate::operation::{EventKind, ck_ops, uuid_v7};
use crate::realm_helpers::{
    canonical_space_join_rule_v1, patch_touches_create_locked_encryption_profile,
};

/// Build + submit the spec-canonical `ak.realm.create` event bundle
/// (and its facet follow-ups) via `ak.self.events.command.submit`
/// (`POST /_arkret/self/events`).
///
/// Per spec realm-and-space.md §2.5 the create event itself is the
/// genesis-member declaration for `created_by`. The
/// server reducer bootstraps the member set atomically with the
/// metadata, so the same actor's per-facet follow-ups
/// (`ak.realm.join_rule` / `ak.realm.history_visibility` /
/// `ak.realm.discovery` / `ak.realm.plaintext_visible_services` /
/// invitee `ak.member.state` invites) all pass the regular
/// `realm_has_member` authz check naturally.
///
/// All five create-locked fields per spec §2.3 (`encryption_profile`,
/// `security_class`, `federation_policy`, `notary_profile`,
/// `digest_algorithm`) are sent inline on the create event payload —
/// no field is dropped at the wire, unlike a REST wrapper that
/// might only accept a subset.
#[allow(clippy::too_many_arguments)]
pub async fn create_realm(
    submitter: &EventSubmitter,
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
    content_scheme: Option<&str>,
) -> anyhow::Result<RealmCreateResult> {
    let actor_id = actor_id.trim();
    if actor_id.is_empty() {
        return Err(anyhow::anyhow!(
            "actor_id is required for canonical ak.realm.create"
        ));
    }
    let title = title.trim();
    if title.is_empty() {
        return Err(anyhow::anyhow!("title is required for ak.realm.create"));
    }

    let realm_id = format!("ak:realm:{}", uuid_v7());
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
        content_scheme,
    )?;
    // Genesis Realm bootstrap has no prior snapshot head. The
    // `ak.realm.create` precondition asserts `head_eq null`; follow-up
    // facet events in the same batch are admitted after soland
    // materialises the creator membership from the create event.
    // Sign every SDK Event before it reaches the wire; the batch
    // submitter takes pre-signed typed Events.
    let proof_context = submitter.event_proof_context().await?;
    for event in events.iter_mut() {
        crate::event_signer::sign_sdk_event_with_active_context(event, proof_context.clone())
            .map_err(|err| {
                anyhow::anyhow!(
                    "no active signer configured \u{2014} cannot submit unsigned realm bootstrap: {err}"
                )
            })?;
    }
    let idempotency_key = format!("ak:operation:{}", uuid_v7());
    submitter
        .submit_signed_sdk_events_batch(&events, Some(&idempotency_key))
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
/// Realm. Emits `ak.space.create` per spec realm-and-space.md §3.
/// Unlike `create_realm`, this does NOT bootstrap MLS / membership
/// / federation — those live on the Realm and Space inherits them.
#[allow(clippy::too_many_arguments)]
pub async fn create_space_under_realm(
    submitter: &EventSubmitter,
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
        return Err(anyhow::anyhow!("actor_id is required for ak.space.create"));
    }
    let title = title.trim();
    if title.is_empty() {
        return Err(anyhow::anyhow!("title is required for ak.space.create"));
    }
    let realm_id = realm_id.trim();
    if realm_id.is_empty() {
        return Err(anyhow::anyhow!(
            "realm_id is required for ak.space.create — Space must live inside a Realm"
        ));
    }
    let space_id = format!("ak:space:{}", uuid_v7());
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
    submitter.submit_sdk_event(&event).await?;

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
    submitter: &EventSubmitter,
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
    submitter.submit_sdk_event(&event).await?;
    Ok(())
}

/// Member-state FSM transition (kick / ban / unban / leave) on the
/// Realm's `ak.component.member.state.v1` cell. Submits a `ak.member.state`
/// event via `ak.self.events.command.submit`; deployment-local member REST shims are
/// intentionally not used.
pub async fn transition_member_state(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    member: &str,
    from_state: Option<&str>,
    to_state: &str,
    reason: &str,
) -> anyhow::Result<SubmitEventResult> {
    let mut event = build_member_state_transition_event(
        realm_id, actor_id, member, from_state, to_state, reason,
    )?;
    // `ak.member.state` is CBA-exempt in the shared stamper only because the
    // Realm-bootstrap batch submits it pre-signed without a seal frontier.
    // Post-bootstrap transitions (ban / kick / leave / unban) carry effects,
    // and the server rejects effects-carrying Control Moves without
    // `seal_basis.leaves` (envelope validation). Every caller of this helper
    // is an already-joined actor, so the realm seal frontier is readable.
    let seal_view = submitter.events_frontier_realm_seal_view(realm_id).await?;
    event.seal_basis = Some(seal_view.seal_basis());
    event.seal_ref = None;
    event.auth_context = None;
    submitter.submit_sdk_event(&event).await
}

// ── Space / Realm Management (all writes go through ak.self.events.command.submit) ─

/// Update a Realm's metadata via `ak.realm.update` event (spec-canonical).
/// `patch` carries the merge-shape body the server reducer applies to the
/// realm row.
pub async fn update_realm_metadata(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    patch: Value,
) -> anyhow::Result<SubmitEventResult> {
    if patch_touches_create_locked_encryption_profile(&patch) {
        anyhow::bail!(
            "Realm encryption_profile is locked at creation; create a new Realm to change E2EE mode."
        );
    }
    let event = ck_ops::realm_update_patch(realm_id, actor_id, realm_id, patch)?
        .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}

/// Update the Realm plaintext-visible service facet through the
/// dedicated `ak.realm.plaintext_visible_services` event. This is not a
/// `ak.realm.update` metadata patch: servers enforce plaintext access from
/// the typed facet projection.
pub async fn update_realm_plaintext_visible_services(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    services: Vec<String>,
) -> anyhow::Result<SubmitEventResult> {
    let Some(mut event) = build_plaintext_visible_services_event(realm_id, actor_id, &services)?
    else {
        anyhow::bail!("plaintext_visible_services update requires at least one service DID");
    };
    let seal_view = submitter.events_frontier_realm_seal_view(realm_id).await?;
    event.seal_basis = Some(seal_view.seal_basis());
    event.seal_ref = None;
    event.auth_context = None;
    submitter.submit_sdk_event(&event).await
}

/// Update a structural Space object's metadata via `ak.space.update`.
/// The event is submitted to the Space's home Realm (`realm_id`), while
/// `space_id` identifies the Space object being patched.
pub async fn update_space_metadata(
    submitter: &EventSubmitter,
    realm_id: &str,
    space_id: &str,
    actor_id: &str,
    patch: Value,
) -> anyhow::Result<SubmitEventResult> {
    let event = ck_ops::space_update_patch(realm_id, actor_id, space_id, patch)?
        .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}

/// Set Realm join_rule + history_visibility policy, optionally also
/// emitting `ak.realm.policy_components` for Join Policy gates.
pub async fn set_realm_policy_events(
    submitter: &EventSubmitter,
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
            "restricted history_visibility requires ak.realm.history_sharing_policy; use build_realm_history_sharing_policy_event before emitting the visibility change"
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
    if let Some(policy) = recommended_history_sharing_policy_for_visibility(history_visibility) {
        events.push(build_realm_history_sharing_policy_event(
            realm_id, actor_id, policy,
        )?);
    }
    if let Some(join_policy) = join_policy {
        let mut policy_components = if preserve_recommended_encryption_floor {
            // None ⇒ the history-capable `mls-exporter-aead-v1` default. soland
            // applies a one-way content_scheme ratchet, so a policy_components
            // write MUST re-assert a scheme of rank ≥ the projected one;
            // omitting it would be rejected for exporter-aead realms.
            recommended_realm_policy_components_value(None)
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
        submitter.submit_sdk_event(&event).await?;
    }
    Ok(RealmPolicyResult {
        ok: true,
        realm_id: realm_id.to_owned(),
        join_rule: join_rule.to_owned(),
        history_visibility: history_visibility.to_owned(),
    })
}

/// Set (or clear) the Realm Recovery Key (RRK) `durability_policy` via a
/// `ak.realm.policy_components` event (realm-and-space.md §2.3.1 write path —
/// no new event kind; durability is a policy component).
///
/// `policy` is the SDK-typed [`arkret_sdk::models::DurabilityPolicy`]
/// so the client never re-defines the spec shape. `policy_revision` MUST be a
/// monotonic increment of the Realm's current policy revision (the reducer
/// rejects a stale revision). After this lands, a subsequent `ak.mls.commit`
/// covering the membership frontier activates the new epoch's sealing
/// obligation and triggers re-disclosure (§2.10.8) — the caller SHOULD prompt
/// an MLS commit / self-update afterward.
///
/// Pre-condition (caller-enforced): RRK durability is only effective when the
/// Realm uses `content_scheme=mls-exporter-aead-v1`; declaring `mode != none`
/// on a plain `mls-rfc9420` Realm is rejected server-side
/// (`durability_scheme_incompatible`).
pub async fn set_realm_durability_policy(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    policy: &arkret_sdk::models::DurabilityPolicy,
    policy_revision: u64,
) -> anyhow::Result<()> {
    let actor_id = actor_id.trim();
    if actor_id.is_empty() {
        return Err(anyhow::anyhow!(
            "actor_id is required for ak.realm.policy_components"
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
    submitter.submit_sdk_event(&event).await?;
    Ok(())
}

/// Reject an invite via `ak.invite.cancel` event (spec-canonical).
pub async fn reject_realm_invite(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    invite_id: &str,
    reason: Option<&str>,
) -> anyhow::Result<SubmitEventResult> {
    let event =
        ck_ops::invite_cancel(realm_id, actor_id, invite_id, reason)?.build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}

/// Leave a Realm via `ak.member.state` event (`join → leave` FSM).
pub async fn leave_realm(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
) -> anyhow::Result<SubmitEventResult> {
    transition_member_state(
        submitter,
        realm_id,
        actor_id,
        actor_id,
        Some("join"),
        "leave",
        "self_leave",
    )
    .await
}

/// Archive a Realm via the reversible `ak.realm.archive` lifecycle facet.
pub async fn archive_realm(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
) -> anyhow::Result<SubmitEventResult> {
    let event = build_realm_archive_event(realm_id, actor_id, true, Some("operator_request"))?;
    submitter.submit_sdk_event(&event).await
}

/// Permanently retire a Realm via `ak.realm.destroy`.
pub async fn destroy_realm(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    reason: &str,
) -> anyhow::Result<SubmitEventResult> {
    let event = build_realm_destroy_event(realm_id, actor_id, reason)?;
    submitter.submit_sdk_event(&event).await
}

/// Ban a member via `ak.member.state` event (`join → ban` FSM).
pub async fn ban_member(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    member: &str,
) -> anyhow::Result<SubmitEventResult> {
    transition_member_state(
        submitter,
        realm_id,
        actor_id,
        member,
        Some("join"),
        "ban",
        "admin_ban",
    )
    .await
}

// ── Daily governance — protocol-event pipeline (P3) ───────────────
//
// Setting / revoking Realm admins, sealing moderation decisions, and
// running the appeal loop are now self-authored protocol Moves submitted
// via `ak.self.events.command.submit` (`POST /_arkret/self/events`) —
// mirroring `transition_member_state` / `ban_member`. P1 (capability)
// and P2 (moderation) projected the matching reducers in soland and the
// sodmin-side admin write paths were retired; these are the inkson-side
// submitters that drive them.

/// Grant Realm admin authority to `subject` by emitting a
/// `ak.capability.grant{actions:[ak.realm.admin], subject}` event.
/// `grant_id` is minted client-side so the caller can correlate the
/// optimistic row with the eventual projection. P1's `apply_capability`
/// folds this into the soland authz index, so subsequent
/// `ak.realm.admin` checks for `subject` pass.
pub async fn grant_realm_admin(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    grant_id: &str,
    subject: &str,
) -> anyhow::Result<SubmitEventResult> {
    let event = ck_ops::capability_grant_actions(
        realm_id,
        actor_id,
        grant_id,
        subject,
        &["ak.realm.admin"],
        None,
        Value::Null,
    )
    .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}

/// Revoke a Realm-admin grant via `ak.capability.revoke`. `grant_id`
/// MUST be the id of the grant established by [`grant_realm_admin`]
/// (the soland reducer locates the cell by `grant_id`).
pub async fn revoke_realm_admin(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    grant_id: &str,
    reason: Option<&str>,
) -> anyhow::Result<SubmitEventResult> {
    let event = ck_ops::capability_revoke(realm_id, actor_id, grant_id, reason)?
        .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}

/// Seal a moderation disposition via `ak.moderation.decision`. The cell
/// subject is the moderated `target_ref`; the sealed decision Event's own
/// id is the reference later lift / appeal events resolve. `decision` is
/// the closed-enum runtime verb (`hard_deny` / `soft_deny` / `quarantine`
/// / `require_review`).
pub async fn moderation_decide(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    target_ref: &str,
    decision: &str,
    reason_code: &str,
) -> anyhow::Result<SubmitEventResult> {
    let event = ck_ops::moderation_decision(realm_id, actor_id, target_ref, decision, reason_code)?
        .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}

/// Lift a previously sealed moderation decision via
/// `ak.moderation.decision.lift`. `target_ref` is the moderated target
/// (the cell subject shared with the original decision); `decision_ref`
/// is the `ak:event:` id of the decision being lifted.
pub async fn moderation_lift(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    target_ref: &str,
    decision_ref: &str,
    reason_code: &str,
) -> anyhow::Result<SubmitEventResult> {
    let event = ck_ops::moderation_decision_lift(
        realm_id,
        actor_id,
        target_ref,
        decision_ref,
        reason_code,
    )?
    .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}

/// Take an appeal under review (`ak.moderation.appeal.review`).
pub async fn appeal_review(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    appeal_id: &str,
    notes_ref: Option<&str>,
) -> anyhow::Result<SubmitEventResult> {
    let event = ck_ops::moderation_appeal_review(realm_id, actor_id, appeal_id, notes_ref)
        .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}

/// Decide an appeal (`ak.moderation.appeal.decision`). For an
/// `overturn` verdict the caller MUST also submit a matching
/// [`moderation_lift`] in the same ordered batch; for `modify`,
/// pass the replacement decision id as `modify_decision_ref` and submit
/// that new [`moderation_decide`] in the same batch. This single
/// call only mints the appeal-decision event.
pub async fn appeal_decide(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    appeal_id: &str,
    verdict: &str,
    reason_text_ref: &str,
    modify_decision_ref: Option<&str>,
) -> anyhow::Result<SubmitEventResult> {
    let event = ck_ops::moderation_appeal_decision(
        realm_id,
        actor_id,
        appeal_id,
        verdict,
        reason_text_ref,
        modify_decision_ref,
    )
    .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}

/// `governance/content-moderation.md` §5.5.1.1 — atomically decide an
/// appeal `verdict=overturn`. The reducer rejects an overturn whose
/// matching `ak.moderation.decision.lift` (target = `decision_ref`) is not
/// in the SAME ordered submit batch (`appeal_overturn_missing_lift`), so
/// this helper builds BOTH events, signs them, and submits them via
/// [`EventSubmitter::submit_signed_sdk_events_batch`] as one transaction.
///
/// Order matters: the appeal-decision precedes the lift it authorizes.
pub async fn appeal_overturn_atomic(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    appeal_id: &str,
    target_ref: &str,
    decision_ref: &str,
    reason_text_ref: &str,
    lift_reason_code: &str,
) -> anyhow::Result<arkret_sdk::EventsSubmitOutcome> {
    let appeal_event = ck_ops::moderation_appeal_decision(
        realm_id,
        actor_id,
        appeal_id,
        "overturn",
        reason_text_ref,
        None,
    )
    .build_sdk_event("inkson")?;
    let lift_event = ck_ops::moderation_decision_lift(
        realm_id,
        actor_id,
        target_ref,
        decision_ref,
        lift_reason_code,
    )?
    .build_sdk_event("inkson")?;
    sign_and_submit_moderation_batch(submitter, realm_id, vec![appeal_event, lift_event]).await
}

/// `governance/content-moderation.md` §5.5.1.1 — atomically decide an
/// appeal `verdict=modify`. The reducer rejects a modify whose
/// replacement `ak.moderation.decision` (target = original target) is not
/// in the same batch, and cross-checks that the appeal-decision's
/// `modify_decision_ref` equals that new decision's event id. This helper
/// mints the replacement decision id, stamps it as `modify_decision_ref`,
/// and submits both events as one transaction.
///
/// Returns the minted replacement `decision_id` alongside the batch result
/// so the caller can surface it.
pub async fn appeal_modify_atomic(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    appeal_id: &str,
    target_ref: &str,
    new_verdict: &str,
    new_reason_code: &str,
    appeal_reason_text_ref: &str,
) -> anyhow::Result<(String, arkret_sdk::EventsSubmitOutcome)> {
    let new_decision_id = format!("ak:event:{}", crate::operation::uuid_v7());
    let mut new_decision =
        ck_ops::moderation_decision(realm_id, actor_id, target_ref, new_verdict, new_reason_code)?
            .build_sdk_event("inkson")?;
    // The reducer matches `modify_decision_ref` against the new decision's
    // EVENT id, so pin the SDK Event id to the same value we report.
    new_decision.event_id = arkret_sdk::EventId::new(new_decision_id.clone())
        .map_err(|err| anyhow::anyhow!("replacement decision id is invalid: {err}"))?;
    let appeal_event = ck_ops::moderation_appeal_decision(
        realm_id,
        actor_id,
        appeal_id,
        "modify",
        appeal_reason_text_ref,
        Some(&new_decision_id),
    )
    .build_sdk_event("inkson")?;
    let result =
        sign_and_submit_moderation_batch(submitter, realm_id, vec![appeal_event, new_decision])
            .await?;
    Ok((new_decision_id, result))
}

/// Seal-stamp + sign each event in a moderation control transaction, then
/// submit them atomically via [`EventSubmitter::submit_signed_sdk_events_batch`].
/// Shared by [`appeal_overturn_atomic`] / [`appeal_modify_atomic`].
/// All envelopes ride the same Realm seal head so the batch is one
/// consistent control view.
async fn sign_and_submit_moderation_batch(
    submitter: &EventSubmitter,
    _realm_id: &str,
    mut events: Vec<arkret_sdk::Event>,
) -> anyhow::Result<arkret_sdk::EventsSubmitOutcome> {
    for event in &mut events {
        submitter.stamp_cba_basis_for_sdk_event(event).await?;
    }
    let proof_context = submitter.event_proof_context().await?;
    for event in events.iter_mut() {
        if event.proofs.is_empty() {
            crate::event_signer::sign_sdk_event_with_active_context(event, proof_context.clone())
                .map_err(|err| {
                anyhow::anyhow!(
                    "no active signer configured \u{2014} cannot submit moderation batch: {err}"
                )
            })?;
        }
    }
    submitter
        .submit_signed_sdk_events_batch(&events, None)
        .await
}

/// Close an appeal (`ak.moderation.appeal.close`). Reviewer close or
/// appellant withdrawal (the reducer authorizes withdrawal via
/// `closer == appellant`).
pub async fn appeal_close(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    appeal_id: &str,
    close_reason: Option<&str>,
) -> anyhow::Result<SubmitEventResult> {
    let event = ck_ops::moderation_appeal_close(realm_id, actor_id, appeal_id, close_reason)
        .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}
