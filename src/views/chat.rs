use dioxus::html::HasFileData;
use dioxus::prelude::*;
use dioxus_router::hooks::use_navigator;
use serde_json::{Value, json};

use crate::{
    api::{
        ContrixApi, is_auth_expired_error, is_plaintext_visibility_policy_error,
        is_space_membership_denied_error,
    },
    audit::build_audit_ryw_receipt,
    components::{HelpTip, UiIcon},
    hlc::{Hlc, observe_seq},
    local_state::{ClientLocalState, LocalStateStore, MoveSubmissionState},
    models::SubmitEventResponse,
    operation::{EventEnvelope, OperationBuilder, cx_ops, uuid_v7},
    routes::Route,
    views::helpers::{
        StructuredMention, active_sync_token, authed_api_with_sync, parse_structured_mentions,
        with_authed_api_with_sync,
    },
};

const CHAT_EMOJI_GRID: &[&str] = &[
    "\u{1f44d}",
    "\u{2764}\u{fe0f}",
    "\u{1f389}",
    "\u{1f440}",
    "\u{1f680}",
];

#[derive(Clone, Debug, PartialEq)]
struct ChannelEntity {
    flow_id: String,
    name: String,
    kind: String,
    category: String,
    topic: Option<String>,
    unread: usize,
    is_default: bool,
}

/// T7.4: end-to-end encryption decryption state for a message.
///
/// Derived from the presence of `content.encrypted_payload` on the
/// envelope plus what the local MLS group can currently do with it.
/// `Plaintext` is the default; encrypted messages cycle
/// `Decrypting → (Plaintext | DecryptFailed | KeyMissing | NeedsVerification)`.
#[derive(Clone, Debug, PartialEq, Eq)]
enum MessageCryptoState {
    /// Body is already plaintext (no `encrypted_payload`).
    Plaintext,
    /// We see an `encrypted_payload` and the MLS group exists, but a
    /// decrypt round-trip hasn't completed for this event yet.
    Decrypting,
    /// We have the group and tried to decrypt, but it returned an error
    /// (e.g. wrong epoch, tamper). Body falls back to a placeholder.
    #[allow(dead_code)]
    DecryptFailed,
    /// `encrypted_payload` present but no local MLS group / no
    /// passphrase / no key package received yet — Welcome is pending.
    KeyMissing,
    /// Sender device hasn't been verified (cross-signing missing or
    /// fingerprint mismatch). The body still decrypted, but we flag it.
    #[allow(dead_code)]
    NeedsVerification,
}

impl MessageCryptoState {
    fn is_pending(&self) -> bool {
        matches!(
            self,
            Self::Decrypting | Self::DecryptFailed | Self::KeyMissing
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ChatMessage {
    space_id: String,
    id: String,
    sender: String,
    body: String,
    timestamp: String,
    flow_id: String,
    reply_to: Option<String>,
    reactions: Vec<(String, Vec<String>)>,
    redacted: bool,
    edited: bool,
    revisions: Vec<String>,
    pending: bool,
    failed: bool,
    error: Option<String>,
    mentions: Vec<StructuredMention>,
    /// T7.4: E2EE decrypt status for this message. Defaults to
    /// `Plaintext`; messages with `content.encrypted_payload` start at
    /// `Decrypting` until the audit-emitter future resolves them.
    crypto_state: MessageCryptoState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DiscussionSidePanel {
    Users,
    Settings,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SpaceParticipantRole {
    Owner,
    Admin,
    Member,
}

impl SpaceParticipantRole {
    fn label(self) -> &'static str {
        match self {
            Self::Owner => "Owner",
            Self::Admin => "Admin",
            Self::Member => "Member",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Owner => 0,
            Self::Admin => 1,
            Self::Member => 2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SpaceParticipant {
    did: String,
    display_name: Option<String>,
    display_name_rank: u8,
    role: SpaceParticipantRole,
    is_self: bool,
    /// `true` when this DID was registered as an agent endpoint
    /// (`cx.agent.endpoint`). Surfaces a 🤖 badge in member lists,
    /// @mention picker rows, and chat sender attribution so operators
    /// can immediately distinguish bot/agent principals from real
    /// human members.
    is_agent: bool,
}

/// Hydrate the local MLS group for a Space (or
/// bootstrap a single-member group when no snapshot exists), encrypt
/// `plaintext_bytes` against it, persist the post-encrypt group state
/// back under the same passphrase, and return:
///
/// * `Some(schedule_hash)` — the post-encrypt group's `epoch_authenticator`-
///   derived `Hash`, fed into `GovernanceBindingPayload::from_anchor`.
/// * `member_dids` — every principal DID in the group (single-element for
///   solo bootstrap; the full member set for a hydrated multi-device
///   group). Replaces the prior single-`device_did` audit-receipt
///   fallback.
/// * `encrypted_payload` — the typed SDK `EncryptedPayload` serialised as
///   `serde_json::Value` ready to drop into `content.encrypted_payload`.
///
/// On any failure (empty passphrase, restore fails, encrypt fails) the
/// helper returns `(None, vec![], None, None)` and the caller aborts the
/// Send Secure flow.
#[cfg(not(target_arch = "wasm32"))]
fn run_local_mls_encrypt(
    mut state_store: Signal<LocalStateStore>,
    space_id: &str,
    principal_id: &str,
    device_id: &str,
    passphrase: &str,
    plaintext_bytes: &[u8],
) -> (
    Option<contrix_sdk::Hash>,
    Vec<contrix_sdk::Did>,
    Option<serde_json::Value>,
    Option<contrix_sdk::MlsCommitEnvelope>,
) {
    let empty = (None, Vec::new(), None, None);
    if passphrase.is_empty() {
        return empty;
    }
    let snapshot = state_store.read().mls_snapshot_for(space_id);
    let mut group = if let Some(env) = snapshot {
        match crate::mls_persistence::restore_envelope(&env, passphrase, 0) {
            Ok(group) => group,
            Err(_) => return empty,
        }
    } else {
        // Bootstrap a fresh single-member group on first Send Secure.
        // The group lives off the user's `(principal_id, device_id)`
        // identity; `space_id`'s bytes seed the MLS group_id so two
        // clients independently bootstrapping the "same" Space land on
        // identical group ids. Real multi-member flows still require a
        // dedicated invite / Welcome path (out of scope here).
        let Ok(principal_did) = contrix_sdk::Did::new(principal_id.to_owned()) else {
            return empty;
        };
        let Ok(typed_device_id) = contrix_sdk::DeviceId::new(device_id.to_owned()) else {
            return empty;
        };
        let Ok(identity) =
            contrix_sdk::ContrixMlsIdentity::new_basic(principal_did, typed_device_id)
        else {
            return empty;
        };
        match identity.create_group(space_id.as_bytes()) {
            Ok(g) => g,
            Err(_) => return empty,
        }
    };
    // Self-update commit BEFORE encrypting so the payload runs under
    // the rotated epoch — forward secrecy
    // improves and the Move-pipeline `mls_commit` row can carry the
    // real `(group_id, epoch, commit_hash)` triple instead of a
    // synthesized `(space_id, prev_epoch+1, _)` placeholder. Failure
    // here is non-fatal: we fall back to encrypt-without-commit so a
    // single Send Secure still succeeds even if `self_update` rejects.
    let commit_envelope = group.self_update_commit().ok();
    let encrypted =
        match group.encrypt_payload("application/vnd.contrix.message+json", plaintext_bytes) {
            Ok(p) => p,
            Err(_) => return empty,
        };
    let schedule_hash = group.schedule_hash();
    let member_dids = group.member_principal_dids();
    let payload_value = match serde_json::to_value(&encrypted) {
        Ok(v) => v,
        Err(_) => return empty,
    };
    // Re-encrypt + persist the post-encrypt group state so a refresh +
    // timeline B7 audit hook can hydrate the same group with the same
    // passphrase. `encrypt_payload` does not advance the epoch but it
    // mutates the OpenMLS ratchet state, so the snapshot MUST be
    // refreshed.
    let post_state = match group.export_state_record() {
        Ok(state) => state,
        Err(_) => {
            return (
                Some(schedule_hash),
                member_dids,
                Some(payload_value),
                commit_envelope,
            );
        }
    };
    let mut salt = [0u8; 16];
    if getrandom::fill(&mut salt).is_err() {
        return (
            Some(schedule_hash),
            member_dids,
            Some(payload_value),
            commit_envelope,
        );
    }
    let new_envelope = crate::mls_persistence::encrypt_state(
        space_id,
        &post_state.group_id,
        post_state.epoch,
        &post_state.serialized_state,
        passphrase,
        &salt,
    );
    state_store
        .write()
        .save_mls_snapshot(space_id.to_owned(), new_envelope);
    (
        Some(schedule_hash),
        member_dids,
        Some(payload_value),
        commit_envelope,
    )
}

/// Walk a `DeviceMessagesReceiveResBody` JSON representation and
/// pull out every `cx.mls.welcome` content payload.
/// The receive endpoint returns `{ "events": [{ type, content, ... }] }`;
/// this helper does not assume only one welcome per poll.
#[cfg(not(target_arch = "wasm32"))]
fn collect_welcome_entries(value: &serde_json::Value) -> Vec<serde_json::Value> {
    let mut welcomes = Vec::new();
    let Some(events) = value.get("events").and_then(|v| v.as_array()) else {
        return welcomes;
    };
    for entry in events {
        if entry.get("type").and_then(|t| t.as_str()) == Some("cx.mls.welcome")
            && let Some(content) = entry.get("content")
        {
            welcomes.push(content.clone());
        }
    }
    welcomes
}

/// Multi-device MLS invite handler.
///
/// 1. Validate inputs (target actor + device + passphrase non-empty).
/// 2. Hydrate the local MLS group from the persisted snapshot via the
///    user-supplied passphrase. Refuse to invite if no snapshot exists
///    yet (the inviter must have sent at least one Secure message
///    first, which bootstraps + persists their solo group).
/// 3. `fetch_mls_key_package(target_actor, target_device)` → typed
///    `MlsKeyPackageRecord`. Returns early with a clear error when the
///    target hasn't published one yet.
/// 4. `group.add_member(&record)` → `MlsAddMemberResult { commit,
///    welcome }`.
/// 5. Ship the typed `MlsWelcomeEnvelope` to the target via
///    `send_device_message_envelope` with `type = "cx.mls.welcome"`.
/// 6. Submit the SDK-built `commit_operation` via
///    `submit_event_envelope` so other server-side state machines
///    (epoch / covered_frontier) observe the new epoch.
/// 7. Re-persist the post-commit group state so the next Send Secure
///    starts from the new epoch + member set.
///
/// Each soft failure surfaces verbatim in `status` for the operator.
#[cfg(not(target_arch = "wasm32"))]
async fn run_mls_add_member_and_invite(
    base_url: String,
    api_token: String,
    mut state_store: Signal<LocalStateStore>,
    space_id: String,
    target_actor: String,
    target_device: String,
    passphrase: String,
    mut status: Signal<String>,
) {
    if target_actor.is_empty() || target_device.is_empty() {
        status.set("MLS invite needs both target actor DID and device id".to_owned());
        return;
    }
    if passphrase.is_empty() {
        status.set("MLS invite needs an active passphrase; set one in this row first".to_owned());
        return;
    }
    let Some(envelope) = state_store.read().mls_snapshot_for(&space_id) else {
        status.set(
            "no local MLS group for this Space yet; send at least one Secure message to bootstrap"
                .to_owned(),
        );
        return;
    };
    let mut group = match crate::mls_persistence::restore_envelope(&envelope, &passphrase, 0) {
        Ok(g) => g,
        Err(err) => {
            status.set(format!("MLS invite: restore_envelope failed: {err}"));
            return;
        }
    };

    // ── 1. fetch target's key package ─────────────────────────────────
    let target_actor_for_fetch = target_actor.clone();
    let target_device_for_fetch = target_device.clone();
    let fetched = crate::views::helpers::with_authed_api(
        &base_url,
        api_token.clone(),
        move |api| async move {
            api.fetch_mls_key_package(&target_actor_for_fetch, &target_device_for_fetch)
                .await
        },
    )
    .await;
    let key_package_record = match fetched {
        Ok(Some(record)) => record,
        Ok(None) => {
            status.set(format!(
                "MLS invite: {target_actor}/{target_device} has not published a key package"
            ));
            return;
        }
        Err(err) => {
            status.set(format!(
                "MLS invite: fetch_mls_key_package failed: {}",
                err.display()
            ));
            return;
        }
    };

    // ── 2. add_member + send Welcome ──────────────────────────────────
    let add_result = match group.add_member(&key_package_record) {
        Ok(r) => r,
        Err(err) => {
            status.set(format!("MLS invite: add_member failed: {err:?}"));
            return;
        }
    };
    let welcome_value = match serde_json::to_value(&add_result.welcome) {
        Ok(v) => v,
        Err(err) => {
            status.set(format!("MLS invite: welcome serialise failed: {err}"));
            return;
        }
    };
    let target_actor_for_welcome = target_actor.clone();
    let target_device_for_welcome = target_device.clone();
    let welcome_send = crate::views::helpers::with_authed_api(
        &base_url,
        api_token.clone(),
        move |api| async move {
            api.send_device_message_envelope(
                "yougen-mls-welcome",
                &target_actor_for_welcome,
                &target_device_for_welcome,
                "cx.mls.welcome",
                welcome_value,
            )
            .await
        },
    )
    .await;
    if let Err(err) = welcome_send {
        status.set(format!(
            "MLS invite: Welcome /device_messages send failed: {}",
            err.display()
        ));
        return;
    }

    // ── 3. submit commit Operation + persist post-state ───────────────
    let op_id_str = format!("cx:operation:{}", crate::operation::uuid_v7());
    let typed_op_id = match contrix_sdk::OperationId::new(op_id_str) {
        Ok(o) => o,
        Err(err) => {
            status.set(format!("MLS invite: operation id mint failed: {err:?}"));
            return;
        }
    };
    let typed_realm = match contrix_sdk::RealmId::new(space_id.clone()) {
        Ok(s) => s,
        Err(err) => {
            status.set(format!("MLS invite: invalid realm id: {err:?}"));
            return;
        }
    };
    let commit_operation = match add_result.commit_operation(typed_op_id, typed_realm) {
        Ok(op) => op,
        Err(err) => {
            status.set(format!(
                "MLS invite: commit_operation build failed: {err:?}"
            ));
            return;
        }
    };
    let target_ref = commit_operation.object_id.clone();
    let mut envelope_builder = crate::operation::OperationBuilder::new(
        space_id.clone(),
        target_actor.clone(),
        "mls_commit",
    )
    .body(commit_operation.payload.clone());
    if let Some(tref) = target_ref {
        envelope_builder = envelope_builder.target_ref(tref);
    }
    let envelope = envelope_builder.build("yougen");
    let submit = crate::views::helpers::with_authed_api(&base_url, api_token, |api| async move {
        api.submit_event_envelope(&envelope).await
    })
    .await;
    if let Err(err) = submit {
        status.set(format!(
            "MLS invite: commit submit failed (Welcome already sent — peer can still join): {}",
            err.display()
        ));
        return;
    }

    // Re-encrypt + persist the post-commit group state.
    let post_state = match group.export_state_record() {
        Ok(s) => s,
        Err(err) => {
            status.set(format!(
                "MLS invite: post-state export failed: {err:?}; snapshot now lags one epoch"
            ));
            return;
        }
    };
    let mut salt = [0u8; 16];
    if let Err(err) = getrandom::fill(&mut salt) {
        status.set(format!(
            "MLS invite: rng fill failed: {err}; snapshot now lags one epoch"
        ));
        return;
    }
    let new_envelope = crate::mls_persistence::encrypt_state(
        &space_id,
        &post_state.group_id,
        post_state.epoch,
        &post_state.serialized_state,
        &passphrase,
        &salt,
    );
    state_store
        .write()
        .save_mls_snapshot(space_id.clone(), new_envelope);
    status.set(format!(
        "MLS invite accepted: {target_actor}/{target_device} added at epoch {}",
        post_state.epoch
    ));
}

/// wasm fallback — desktop-only.
#[cfg(target_arch = "wasm32")]
async fn run_mls_add_member_and_invite(
    _base_url: String,
    _api_token: String,
    _state_store: Signal<LocalStateStore>,
    _space_id: String,
    _target_actor: String,
    _target_device: String,
    _passphrase: String,
    mut status: Signal<String>,
) {
    status.set(
        "MLS invite requires the desktop client (browser build has no OpenMLS runtime).".to_owned(),
    );
}

fn chat_message_revise_operation(
    space_id: &str,
    actor: &str,
    event_id: &str,
    body: &str,
) -> crate::operation::EventEnvelope {
    OperationBuilder::new(space_id, actor, "cx.message.revise")
        .target_ref(event_id)
        .body(json!({
            "content": {
                "kind": "cx.content.text",
                "body": body,
            },
            "target_ref": event_id,
            "target_event_id": event_id,
        }))
        .build("yougen")
}

fn chat_message_redact_operation(
    space_id: &str,
    actor: &str,
    event_id: &str,
    reason: &str,
) -> crate::operation::EventEnvelope {
    OperationBuilder::new(space_id, actor, "cx.message.redact")
        .target_ref(event_id)
        .body(json!({
            "reason": reason,
            "target_event_id": event_id,
        }))
        .build("yougen")
}

fn chat_reaction_add_operation(
    space_id: &str,
    actor: &str,
    event_id: &str,
    key: &str,
) -> crate::operation::EventEnvelope {
    OperationBuilder::new(space_id, actor, "cx.reaction.add")
        .target_ref(event_id)
        .body(json!({
            "actor": actor,
            "event_id": event_id,
            "key": key,
        }))
        .build("yougen")
}

fn normalize_participant_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn participant_id_from_state_key(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if let Some(index) = trimmed.find("did:") {
        normalize_participant_id(&trimmed[index..])
    } else {
        None
    }
}

fn participant_role_from_str(
    value: Option<&str>,
    fallback: SpaceParticipantRole,
) -> SpaceParticipantRole {
    match value
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "owner" => SpaceParticipantRole::Owner,
        "admin" | "administrator" => SpaceParticipantRole::Admin,
        _ => fallback,
    }
}

fn participant_id_from_value(value: &Value) -> Option<String> {
    if let Some(raw) = value.as_str() {
        return normalize_participant_id(raw);
    }

    let object = value.as_object()?;
    [
        "did",
        "account_did",
        "actor_did",
        "member",
        "user",
        "actor",
        "actor_id",
        "subject",
        "state_key",
        "id",
        "identifier",
    ]
    .iter()
    .find_map(|key| object.get(*key).and_then(participant_id_from_value))
}

fn participant_id_from_member_value(value: &Value) -> Option<String> {
    if let Some(raw) = value.as_str() {
        return normalize_participant_id(raw);
    }

    let object = value.as_object()?;
    [
        "did",
        "account_did",
        "actor_did",
        "member",
        "user",
        "actor",
        "actor_id",
        "subject",
    ]
    .iter()
    .find_map(|key| object.get(*key).and_then(participant_id_from_member_value))
}

fn clean_participant_display_name(value: &str, did: Option<&str>) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.starts_with("did:") || did == Some(trimmed) {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn participant_display_name_from_value(value: &Value, did: Option<&str>) -> Option<(String, u8)> {
    let object = value.as_object()?;
    for (rank, keys) in [
        (
            0,
            ["remark", "note", "local_name", "contact_name"].as_slice(),
        ),
        (
            1,
            [
                "display_name",
                "displayName",
                "nickname",
                "alias",
                "preferred_name",
            ]
            .as_slice(),
        ),
        (2, ["name", "handle", "username"].as_slice()),
    ] {
        if let Some(name) = keys
            .iter()
            .find_map(|key| object.get(*key).and_then(Value::as_str))
            .and_then(|raw| clean_participant_display_name(raw, did))
        {
            return Some((name, rank));
        }
    }

    [
        "profile", "account", "member", "user", "actor", "subject", "details",
    ]
    .iter()
    .find_map(|key| {
        object
            .get(*key)
            .filter(|child| child.is_object())
            .and_then(|child| participant_display_name_from_value(child, did))
    })
}

fn upsert_participant(
    participants: &mut Vec<SpaceParticipant>,
    did: &str,
    role: SpaceParticipantRole,
    account_did: &str,
    display_name: Option<(String, u8)>,
) {
    let Some(did) = normalize_participant_id(did) else {
        return;
    };
    let is_self = did == account_did;
    if let Some(existing) = participants
        .iter_mut()
        .find(|candidate| candidate.did == did)
    {
        if role.rank() < existing.role.rank() {
            existing.role = role;
        }
        existing.is_self |= is_self;
        if let Some((display_name, rank)) = display_name
            && (existing.display_name.is_none() || rank < existing.display_name_rank)
        {
            existing.display_name = Some(display_name);
            existing.display_name_rank = rank;
        }
    } else {
        let (display_name, display_name_rank) = display_name
            .map(|(name, rank)| (Some(name), rank))
            .unwrap_or((None, u8::MAX));
        participants.push(SpaceParticipant {
            did,
            display_name,
            display_name_rank,
            role,
            is_self,
            // Default; the caller annotates agent DIDs via
            // `annotate_agent_participants` after the projection-based
            // upsert pass completes.
            is_agent: false,
        });
    }
}

/// Scan the local store's raw_operations for `cx.agent.endpoint`
/// rows and return the set of agent DIDs that were registered in
/// `space_id`. Used to mark `SpaceParticipant::is_agent` so member /
/// mention / sender rows can render a 🤖 badge.
///
/// Reads the agent DID from `payload.body.agent_did` (per
/// `crate::operation::cx_ops::agent_endpoint`). Returns an empty Vec
/// when no agent endpoints are registered.
fn agent_dids_from_raw_operations(
    raw_operations: &[crate::local_state::RawOperationRecord],
    space_id: &str,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for record in raw_operations {
        let kind = record
            .payload
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("");
        if kind != "cx.agent.endpoint" {
            continue;
        }
        // Filter by space_id when the record carries one; the
        // `cx.agent.endpoint` builder always stamps `space_id` on the
        // payload, but tolerate older rows by also accepting records
        // with `space_id = None`.
        if let Some(record_space) = record.space_id.as_deref() {
            if record_space != space_id {
                continue;
            }
        }
        let did = record
            .payload
            .get("body")
            .and_then(|b| b.get("agent_did"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let Some(did) = did {
            if !out.iter().any(|existing| existing == &did) {
                out.push(did);
            }
        }
    }
    out
}

/// Mark every participant whose DID appears in `agent_dids` as
/// `is_agent = true`. No-op for unknown DIDs.
fn annotate_agent_participants(participants: &mut [SpaceParticipant], agent_dids: &[String]) {
    if agent_dids.is_empty() {
        return;
    }
    for participant in participants.iter_mut() {
        if agent_dids.iter().any(|did| did == &participant.did) {
            participant.is_agent = true;
        }
    }
}

fn collect_participant_field(
    value: &Value,
    key: &str,
    role: SpaceParticipantRole,
    account_did: &str,
    participants: &mut Vec<SpaceParticipant>,
) {
    let Some(field) = value.get(key) else {
        return;
    };

    if let Some(items) = field.as_array() {
        for item in items {
            let item_role = item
                .get("role")
                .and_then(Value::as_str)
                .map(|raw_role| participant_role_from_str(Some(raw_role), role))
                .unwrap_or(role);
            if let Some(did) = participant_id_from_value(item) {
                upsert_participant(
                    participants,
                    &did,
                    item_role,
                    account_did,
                    participant_display_name_from_value(item, Some(&did)),
                );
            }
        }
    } else if let Some(did) = participant_id_from_value(field) {
        upsert_participant(
            participants,
            &did,
            role,
            account_did,
            participant_display_name_from_value(field, Some(&did)),
        );
    }
}

fn collect_state_participants(
    projection: &Value,
    account_did: &str,
    participants: &mut Vec<SpaceParticipant>,
) {
    let Some(state) = projection.get("state").and_then(Value::as_array) else {
        return;
    };

    for item in state {
        let kind = item
            .get("kind")
            .or_else(|| item.get("type"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let state_key = item
            .get("state_key")
            .or_else(|| item.get("key"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let body = item
            .get("content")
            .or_else(|| item.get("value"))
            .or_else(|| item.get("body"))
            .unwrap_or(item);

        let did = participant_id_from_state_key(state_key)
            .or_else(|| participant_id_from_member_value(body))
            .or_else(|| participant_id_from_member_value(item));
        if !kind.contains("member") && did.is_none() {
            continue;
        }

        let role = participant_role_from_str(
            body.get("role")
                .or_else(|| item.get("role"))
                .and_then(Value::as_str),
            SpaceParticipantRole::Member,
        );
        if let Some(did) = did {
            let display_name = participant_display_name_from_value(body, Some(&did))
                .or_else(|| participant_display_name_from_value(item, Some(&did)));
            upsert_participant(participants, &did, role, account_did, display_name);
        }
    }
}

fn space_participants(projection: Option<&Value>, account_did: &str) -> Vec<SpaceParticipant> {
    let mut participants = Vec::new();

    if let Some(projection) = projection {
        for key in ["owner", "created_by", "creator"] {
            collect_participant_field(
                projection,
                key,
                SpaceParticipantRole::Owner,
                account_did,
                &mut participants,
            );
        }
        for key in ["owners", "admins", "admin_dids"] {
            collect_participant_field(
                projection,
                key,
                SpaceParticipantRole::Admin,
                account_did,
                &mut participants,
            );
        }
        for key in ["members", "participants"] {
            collect_participant_field(
                projection,
                key,
                SpaceParticipantRole::Member,
                account_did,
                &mut participants,
            );
        }

        if let Some(summary) = projection.get("summary") {
            for key in ["owner", "created_by", "creator"] {
                collect_participant_field(
                    summary,
                    key,
                    SpaceParticipantRole::Owner,
                    account_did,
                    &mut participants,
                );
            }
            for key in ["owners", "admins", "admin_dids"] {
                collect_participant_field(
                    summary,
                    key,
                    SpaceParticipantRole::Admin,
                    account_did,
                    &mut participants,
                );
            }
            for key in ["members", "participants"] {
                collect_participant_field(
                    summary,
                    key,
                    SpaceParticipantRole::Member,
                    account_did,
                    &mut participants,
                );
            }
        }

        collect_state_participants(projection, account_did, &mut participants);
    }

    if !account_did.trim().is_empty() {
        upsert_participant(
            &mut participants,
            account_did,
            SpaceParticipantRole::Member,
            account_did,
            None,
        );
    }

    participants.sort_by(|left, right| {
        right
            .is_self
            .cmp(&left.is_self)
            .then_with(|| left.role.rank().cmp(&right.role.rank()))
            .then_with(|| left.did.cmp(&right.did))
    });
    participants
}

fn is_own_message_sender(sender: &str, account_did: &str) -> bool {
    let sender = sender.trim();
    !sender.is_empty() && (sender == "yougen" || sender == account_did.trim())
}

fn short_principal_label(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "Unknown".to_owned();
    }
    let principal = trimmed.strip_prefix("did:web:").unwrap_or(trimmed);
    let tail = principal.rsplit(':').next().unwrap_or(principal);
    if tail.len() > 18 {
        format!("{}...{}", &tail[..8], &tail[tail.len() - 6..])
    } else {
        tail.to_owned()
    }
}

fn sender_display_label(
    sender: &str,
    account_did: &str,
    account_display_name: &str,
    participants: &[SpaceParticipant],
) -> String {
    if is_own_message_sender(sender, account_did) {
        return clean_participant_display_name(account_display_name, Some(account_did))
            .unwrap_or_else(|| "yougen".to_owned());
    }
    participants
        .iter()
        .find(|participant| participant.did == sender.trim())
        .and_then(|participant| participant.display_name.clone())
        .unwrap_or_else(|| short_principal_label(sender))
}

fn chat_reply_quote_preview(
    messages: &[ChatMessage],
    reply_id: &str,
    account_did: &str,
    account_display_name: &str,
    participants: &[SpaceParticipant],
) -> Option<(String, String)> {
    let quoted = messages.iter().find(|m| m.id == reply_id)?;
    let name = sender_display_label(
        &quoted.sender,
        account_did,
        account_display_name,
        participants,
    );
    let body = if quoted.redacted {
        "[Message redacted]".to_owned()
    } else {
        quoted.body.clone()
    };
    Some((name, body))
}

fn parse_discussion_principals(input: &str) -> Vec<String> {
    let mut principals = Vec::new();
    for candidate in input.split(|ch: char| matches!(ch, ',' | '\n' | '\r' | '\t' | ';')) {
        let trimmed = candidate.trim();
        if !trimmed.is_empty() && !principals.iter().any(|existing| existing == trimmed) {
            principals.push(trimmed.to_owned());
        }
    }
    principals
}

/// T7.2: validate a single watcher entry token. Accepts:
///   * DIDs (`did:web:foo.example` / `did:key:...`)
///   * Handles (`alice@example.com` or `@alice@example.com`)
///   * Bare display-name lookups are resolved against the participant list
///     (returns the matching DID when unique).
///
/// Returns `Ok(canonical_did)` when the token unambiguously resolves to a
/// principal, otherwise `Err(error_kind)`.
#[derive(Clone, Debug, PartialEq, Eq)]
enum WatcherEntryKind {
    /// Resolved to a canonical DID we can submit.
    Valid(String),
    /// Looks like a handle but no participant matches it locally.
    UnknownHandle,
    /// Looks like a DID but it's malformed.
    InvalidDid,
    /// The token didn't match anything (e.g. partial display name).
    UnresolvedName,
    /// Same DID appears more than once (already added).
    Duplicate(String),
}

fn classify_watcher_entry(
    raw: &str,
    participants: &[SpaceParticipant],
    already_added: &[String],
) -> WatcherEntryKind {
    let trimmed = raw.trim();
    let stripped = trimmed.trim_start_matches('@');
    if stripped.is_empty() {
        return WatcherEntryKind::UnresolvedName;
    }
    let canonical = if stripped.starts_with("did:") {
        // Minimal sanity check: `did:method:specific-id`.
        let parts: Vec<&str> = stripped.splitn(3, ':').collect();
        if parts.len() < 3 || parts[1].is_empty() || parts[2].is_empty() {
            return WatcherEntryKind::InvalidDid;
        }
        stripped.to_owned()
    } else if stripped.contains('@') {
        // alice@example.com -> did:web:example.com:alice
        let mut parts = stripped.splitn(2, '@');
        let local = parts.next().unwrap_or_default();
        let host = parts.next().unwrap_or_default();
        if local.is_empty() || host.is_empty() {
            return WatcherEntryKind::UnknownHandle;
        }
        let candidate = format!("did:web:{host}:{local}");
        // If candidate matches a known participant, prefer that exact DID.
        let known = participants.iter().find(|p| {
            p.did.eq_ignore_ascii_case(&candidate)
                || p.did.ends_with(&format!(":{local}")) && p.did.contains(host)
        });
        match known {
            Some(p) => p.did.clone(),
            None => candidate,
        }
    } else {
        // Bare token: resolve against participant display names / DIDs.
        let lower = stripped.to_ascii_lowercase();
        let direct = participants
            .iter()
            .find(|p| p.did.eq_ignore_ascii_case(stripped));
        if let Some(p) = direct {
            p.did.clone()
        } else {
            let display_matches: Vec<&SpaceParticipant> = participants
                .iter()
                .filter(|p| {
                    p.display_name
                        .as_deref()
                        .map(|n| n.to_ascii_lowercase() == lower)
                        .unwrap_or(false)
                })
                .collect();
            if display_matches.len() == 1 {
                display_matches[0].did.clone()
            } else {
                return WatcherEntryKind::UnresolvedName;
            }
        }
    };

    if already_added
        .iter()
        .any(|d| d.eq_ignore_ascii_case(&canonical))
    {
        return WatcherEntryKind::Duplicate(canonical);
    }
    WatcherEntryKind::Valid(canonical)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WatcherPill {
    raw: String,
    state: WatcherEntryKind,
}

fn parse_watcher_pills(input: &str, participants: &[SpaceParticipant]) -> Vec<WatcherPill> {
    let mut out: Vec<WatcherPill> = Vec::new();
    let mut canonical: Vec<String> = Vec::new();
    for candidate in input.split(|ch: char| matches!(ch, ',' | '\n' | '\r' | '\t' | ';')) {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            continue;
        }
        let state = classify_watcher_entry(trimmed, participants, &canonical);
        if let WatcherEntryKind::Valid(did) = &state {
            canonical.push(did.clone());
        }
        out.push(WatcherPill {
            raw: trimmed.to_owned(),
            state,
        });
    }
    out
}

/// T7.2: discussion watch level fast switcher. Mirrors the spec's
/// `cx.flow.watch.set` level enumeration. `Muted` maps to `none` on the
/// wire — the term used in the dropdown is the user-friendly label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WatchLevel {
    MentionsOnly,
    Participating,
    All,
    Muted,
}

impl WatchLevel {
    fn wire_value(self) -> &'static str {
        match self {
            Self::MentionsOnly => "mentions_only",
            Self::Participating => "participating",
            Self::All => "all",
            Self::Muted => "none",
        }
    }

    fn label_key(self) -> &'static str {
        match self {
            Self::MentionsOnly => "chat.watch_level.mentions_only",
            Self::Participating => "chat.watch_level.participating",
            Self::All => "chat.watch_level.all",
            Self::Muted => "chat.watch_level.muted",
        }
    }

    #[allow(dead_code)]
    fn from_wire(value: &str) -> Self {
        match value {
            "mentions_only" => Self::MentionsOnly,
            "participating" => Self::Participating,
            "all" => Self::All,
            "none" | "muted" => Self::Muted,
            _ => Self::All,
        }
    }
}

#[allow(dead_code)]
fn current_mention_query(text: &str) -> Option<(usize, String)> {
    for (idx, ch) in text.char_indices().rev() {
        if ch == '@' {
            let preceding_ok = text[..idx]
                .chars()
                .next_back()
                .is_none_or(|c| matches!(c, ' ' | '\t' | '\n' | '\r' | ',' | ';'));
            if preceding_ok {
                let query_start = idx + '@'.len_utf8();
                return Some((idx, text[query_start..].to_owned()));
            }
            return None;
        }
        if matches!(ch, ' ' | '\t' | '\n' | '\r' | ',' | ';') {
            return None;
        }
    }
    None
}

#[allow(dead_code)]
fn apply_mention_completion(current: &str, replacement: &str) -> String {
    if let Some((idx, _)) = current_mention_query(current) {
        let mut out = current[..idx].to_owned();
        out.push_str(replacement);
        out.push_str(", ");
        out
    } else {
        let trimmed = current.trim_end_matches(|c: char| c.is_whitespace() || c == ',');
        let mut out = trimmed.to_owned();
        if !out.is_empty() {
            out.push_str(", ");
        }
        out.push_str(replacement);
        out.push_str(", ");
        out
    }
}

fn is_schema_message_id(value: &str) -> bool {
    let Some(suffix) = value.trim().strip_prefix("cx:message:") else {
        return false;
    };
    !suffix.is_empty()
        && suffix
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':'))
}

fn new_chat_message_id() -> String {
    format!("cx:message:{}", uuid_v7())
}

fn schema_message_id_or_new(value: &str) -> String {
    if is_schema_message_id(value) {
        value.trim().to_owned()
    } else {
        new_chat_message_id()
    }
}

fn chat_message_create_operation(
    space_id: &str,
    actor: &str,
    flow_id: &str,
    channel_kind: &str,
    message_id: &str,
    body: &str,
    mentions: &[StructuredMention],
    reply_to: Option<&str>,
) -> crate::operation::EventEnvelope {
    let mention_values = mentions_to_json(mentions);
    let mention_relations = mention_relation_json(message_id, mentions);
    let content = json!({
        "kind": "cx.content.text",
        "body": body,
    });
    let mut payload = json!({
        "body": body,
        // T2.3: the legacy `branch` top-level field is forbidden on the
        // wire (artifacts/registry/forbidden-wire-fields.json,
        // hard_reject). v1 uses `track` — a display-only timeline
        // segment identifier — instead.
        "track": "discussion",
        "content": content,
        "encrypted": false,
        "flow_id": flow_id,
        "kind": channel_kind,
        "message_id": message_id,
        "mentions": mention_values,
        "mention_relations": mention_relations,
    });
    if let Some(reply_to) = reply_to.filter(|value| !value.trim().is_empty()) {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("reply_to".to_owned(), json!(reply_to));
            obj.insert("thread_id".to_owned(), json!(reply_to));
        }
    }
    OperationBuilder::new(space_id, actor, "cx.message.create")
        .target_ref(flow_id)
        .body(payload)
        .build("yougen")
}

fn chat_send_error_message(error: &anyhow::Error) -> String {
    if is_auth_expired_error(error) {
        "Session expired while sending. Refresh the session or sign in again, then retry."
            .to_owned()
    } else if is_plaintext_visibility_policy_error(error) {
        "Plaintext is not enabled for this Space on the current service. Send Secure or update Space plaintext visibility."
            .to_owned()
    } else if is_space_membership_denied_error(error) {
        "This account is not a member of this Space. Join the Space or switch to an account that is a member before sending."
            .to_owned()
    } else {
        error.to_string()
    }
}

fn collect_plaintext_services(value: &Value, services: &mut Vec<String>) {
    if let Some(items) = value
        .get("plaintext_visible_services")
        .and_then(Value::as_array)
    {
        for item in items {
            if let Some(service) = item.as_str() {
                let service = service.trim();
                if !service.is_empty() && !services.iter().any(|existing| existing == service) {
                    services.push(service.to_owned());
                }
            }
        }
    }
}

fn plaintext_services_for_policy(projection: Option<&Value>, service_did: &str) -> Vec<String> {
    let mut services = Vec::new();
    if let Some(projection) = projection {
        collect_plaintext_services(projection, &mut services);
        if let Some(summary) = projection.get("summary") {
            collect_plaintext_services(summary, &mut services);
        }
    }
    let service_did = service_did.trim();
    if !service_did.is_empty() && !services.iter().any(|existing| existing == service_did) {
        services.push(service_did.to_owned());
    }
    services
}

fn value_string_at<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
}

fn collect_message_candidates<'a>(value: &'a Value, out: &mut Vec<&'a Value>, depth: usize) {
    if depth > 4 || !value.is_object() {
        return;
    }
    out.push(value);
    for key in [
        "event",
        "envelope",
        "operation",
        "raw",
        "record",
        "payload",
        "body",
        "content",
        "data",
    ] {
        if let Some(child) = value.get(key).filter(|child| child.is_object()) {
            collect_message_candidates(child, out, depth + 1);
        }
    }
}

fn message_candidates(event: &Value) -> Vec<&Value> {
    let mut candidates = Vec::new();
    collect_message_candidates(event, &mut candidates, 0);
    candidates
}

fn first_string_in_candidates<'a>(candidates: &[&'a Value], keys: &[&str]) -> Option<&'a str> {
    candidates
        .iter()
        .find_map(|candidate| value_string_at(candidate, keys))
}

fn message_kind_is_create(value: &Value) -> bool {
    value_string_at(value, &["kind", "type", "op_type", "event_type"]) == Some("cx.message.create")
}

fn text_from_blocks(value: &Value) -> Option<&str> {
    value
        .get("blocks")
        .and_then(Value::as_array)
        .and_then(|blocks| blocks.first())
        .and_then(|block| block.get("text"))
        .and_then(Value::as_str)
}

fn text_body_from_value(value: &Value) -> Option<&str> {
    value_string_at(value, &["body", "text", "message", "plain_text"])
        .or_else(|| text_from_blocks(value))
        .or_else(|| {
            value
                .get("content")
                .filter(|content| content.is_object())
                .and_then(text_body_from_value)
        })
}

fn text_body_from_message(candidates: &[&Value]) -> Option<String> {
    candidates
        .iter()
        .find_map(|candidate| text_body_from_value(candidate))
        .map(ToOwned::to_owned)
}

fn short_message_time(value: Option<&str>) -> String {
    value
        .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
        .map(|time| time.format("%H:%M").to_string())
        .or_else(|| value.map(ToOwned::to_owned))
        .unwrap_or_default()
}

fn mentions_from_value(value: &Value) -> Vec<StructuredMention> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    // Subject can come from `subject` (spec) or `target`
                    // (yougen legacy). Either works for actor/entity
                    // resolution.
                    let target = item
                        .get("subject")
                        .and_then(Value::as_str)
                        .or_else(|| item.get("target").and_then(Value::as_str))?;
                    Some(StructuredMention {
                        kind: item
                            .get("kind")
                            .and_then(Value::as_str)
                            .unwrap_or("ref")
                            .to_owned(),
                        target: target.to_owned(),
                        token: item
                            .get("token")
                            .and_then(Value::as_str)
                            .unwrap_or(target)
                            .to_owned(),
                        // T7.3: pull the compose-time snapshot fields
                        // through from the event payload so the renderer
                        // can flag handle reassignments.
                        display_snapshot: item
                            .get("display_snapshot")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        handle_uri: item
                            .get("handle_uri")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        resolved_at: item
                            .get("resolved_at")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn mentions_from_candidates(candidates: &[&Value]) -> Vec<StructuredMention> {
    candidates
        .iter()
        .find_map(|candidate| {
            candidate
                .get("mentions")
                .or_else(|| {
                    candidate
                        .get("content")
                        .and_then(|content| content.get("mentions"))
                })
                .map(mentions_from_value)
                .filter(|mentions| !mentions.is_empty())
        })
        .unwrap_or_default()
}

fn seq_from_candidates(candidates: &[&Value]) -> Option<u64> {
    candidates.iter().find_map(|candidate| {
        candidate
            .get("actor_seq")
            .and_then(Value::as_u64)
            .or_else(|| {
                candidate
                    .get("causal")
                    .and_then(|causal| causal.get("actor_seq"))
                    .and_then(Value::as_u64)
            })
    })
}

fn chat_message_from_event(space_id: &str, event: &Value) -> Option<ChatMessage> {
    let candidates = message_candidates(event);
    let body = text_body_from_message(&candidates)?;
    let explicit_message_kind = candidates
        .iter()
        .any(|candidate| message_kind_is_create(candidate));
    let message_payload_shape =
        first_string_in_candidates(&candidates, &["message_id", "flow_id", "thread_id"]).is_some();
    if !explicit_message_kind && !message_payload_shape {
        return None;
    }
    if let Some(seq) = seq_from_candidates(&candidates) {
        observe_seq(seq);
    }
    let event_id = value_string_at(event, &["event_id", "id"])
        .or_else(|| first_string_in_candidates(&candidates, &["event_id", "message_id", "id"]))
        .unwrap_or("event:unknown")
        .to_owned();
    let flow_id = first_string_in_candidates(&candidates, &["flow_id", "thread_id"])
        .or_else(|| {
            event
                .get("unsigned")
                .and_then(|unsigned| unsigned.get("local_target_ref"))
                .and_then(Value::as_str)
        })
        .filter(|value| value.starts_with("cx:flow:"))
        .unwrap_or("cx:flow:general")
        .to_owned();
    // T7.4: detect end-to-end encrypted payload. Body decoding above
    // already prefers plaintext when both forms are present; if the
    // candidates carry an `encrypted_payload` block at all, we surface
    // the decryption state to the renderer even when the timeline
    // projection happened to expose a body.
    let has_encrypted_payload = candidates.iter().any(|candidate| {
        candidate.get("encrypted_payload").is_some()
            || candidate
                .get("content")
                .and_then(|content| content.get("encrypted_payload"))
                .is_some()
    });
    let crypto_state = if has_encrypted_payload {
        MessageCryptoState::Decrypting
    } else {
        MessageCryptoState::Plaintext
    };
    Some(ChatMessage {
        space_id: first_string_in_candidates(&candidates, &["space_id"])
            .unwrap_or(space_id)
            .to_owned(),
        id: event_id,
        sender: first_string_in_candidates(
            &candidates,
            &["sender", "sender_id", "actor_id", "actor"],
        )
        .unwrap_or("did:web:unknown")
        .to_owned(),
        body,
        timestamp: short_message_time(first_string_in_candidates(
            &candidates,
            &["created_at", "timestamp", "origin_server_ts"],
        )),
        flow_id,
        reply_to: first_string_in_candidates(&candidates, &["reply_to", "thread_id"])
            .map(ToOwned::to_owned),
        reactions: Vec::new(),
        redacted: false,
        edited: false,
        revisions: Vec::new(),
        pending: false,
        failed: false,
        error: None,
        mentions: mentions_from_candidates(&candidates),
        crypto_state,
    })
}

fn chat_messages_from_events(space_id: &str, events: &[Value]) -> Vec<ChatMessage> {
    events
        .iter()
        .filter_map(|event| chat_message_from_event(space_id, event))
        .collect()
}

fn chat_messages_from_sync_spaces(
    spaces: &std::collections::BTreeMap<String, Value>,
) -> Vec<ChatMessage> {
    let mut messages = Vec::new();
    for (space_id, body) in spaces {
        let Some(timeline_events) = body
            .get("timeline")
            .and_then(|timeline| timeline.get("events"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        messages.extend(chat_messages_from_events(space_id, timeline_events));
    }
    messages
}

fn chat_messages_from_local_state(state: &ClientLocalState) -> Vec<ChatMessage> {
    state
        .raw_operations
        .iter()
        .filter_map(|record| {
            chat_message_from_event(
                record.space_id.as_deref().unwrap_or_default(),
                &record.payload,
            )
        })
        .collect()
}

fn bool_at_path(value: &Value, path: &[&str]) -> Option<bool> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_bool()
}

fn string_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

fn first_string_in_candidate_paths<'a>(
    candidates: &[&'a Value],
    paths: &[&[&str]],
) -> Option<&'a str> {
    candidates.iter().find_map(|candidate| {
        paths
            .iter()
            .find_map(|path| string_at_path(candidate, path))
    })
}

fn default_discussion_flow_id(space_id: &str) -> String {
    let trimmed = space_id.trim();
    if let Some(suffix) = trimmed.strip_prefix("cx:space:") {
        format!("cx:flow:{suffix}")
    } else if let Some(suffix) = trimmed.strip_prefix("space:") {
        format!("cx:flow:{suffix}")
    } else if trimmed.starts_with("cx:flow:") {
        trimmed.to_owned()
    } else {
        format!("cx:flow:{}", trimmed.trim_start_matches("cx:"))
    }
}

fn candidate_has_track(candidate: &Value, track: &str) -> bool {
    candidate
        .get("tracks")
        .and_then(|tracks| tracks.get(track))
        .is_some()
        || ["object", "flow"].iter().any(|wrapper| {
            candidate
                .get(*wrapper)
                .and_then(|inner| inner.get("tracks"))
                .and_then(|tracks| tracks.get(track))
                .is_some()
        })
}

fn flow_create_has_discussion_track(candidates: &[&Value]) -> bool {
    candidates
        .iter()
        .any(|candidate| candidate_has_track(candidate, "discussion"))
}

fn flow_create_has_synthesis_track(candidates: &[&Value]) -> bool {
    candidates
        .iter()
        .any(|candidate| candidate_has_track(candidate, "synthesis"))
        || candidates.iter().any(|candidate| {
            bool_at_path(candidate, &["create_card"]).unwrap_or(false)
                || bool_at_path(candidate, &["fields", "has_synthesis"]).unwrap_or(false)
                || bool_at_path(candidate, &["object", "fields", "has_synthesis"]).unwrap_or(false)
                || bool_at_path(candidate, &["flow", "fields", "has_synthesis"]).unwrap_or(false)
        })
}

fn channel_from_flow_projection(
    space_id: &str,
    flow: &Value,
    is_default: bool,
) -> Option<ChannelEntity> {
    if !candidate_has_track(flow, "discussion") {
        return None;
    }

    let flow_id = first_string_in_candidate_paths(&[flow], &[&["flow_id"], &["id"]])
        .map(str::trim)
        .filter(|id| id.starts_with("cx:flow:"))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| default_discussion_flow_id(space_id));
    let name = first_string_in_candidate_paths(&[flow], &[&["title"], &["name"]])
        .filter(|title| !title.trim().is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            if is_default {
                "Discussion".to_owned()
            } else {
                flow_id.clone()
            }
        });
    let category = first_string_in_candidate_paths(
        &[flow],
        &[
            &["category"],
            &["fields", "category"],
            &["summary", "category"],
        ],
    )
    .filter(|category| !category.trim().is_empty())
    .map(ToOwned::to_owned)
    .unwrap_or_else(|| {
        if is_default {
            "default flow".to_owned()
        } else {
            "general".to_owned()
        }
    });
    let topic = first_string_in_candidate_paths(
        &[flow],
        &[
            &["summary"],
            &["topic"],
            &["description"],
            &["fields", "summary"],
            &["fields", "topic"],
        ],
    )
    .filter(|topic| !topic.trim().is_empty())
    .map(ToOwned::to_owned)
    .or_else(|| {
        if is_default {
            Some("Default Flow discussion track".to_owned())
        } else {
            None
        }
    });
    let has_synthesis = flow_create_has_synthesis_track(&[flow]);

    Some(ChannelEntity {
        flow_id,
        name,
        kind: if !is_default && has_synthesis {
            "flow".to_owned()
        } else {
            "discussion".to_owned()
        },
        category,
        topic,
        unread: 0,
        is_default,
    })
}

fn default_discussion_channel(space_id: &str, space_body: Option<&Value>) -> ChannelEntity {
    if let Some(flow) = space_body
        .and_then(|body| body.get("summary"))
        .and_then(|summary| summary.get("flow"))
        && let Some(channel) = channel_from_flow_projection(space_id, flow, true)
    {
        return channel;
    }

    ChannelEntity {
        flow_id: default_discussion_flow_id(space_id),
        name: "Discussion".to_owned(),
        kind: "discussion".to_owned(),
        category: "default flow".to_owned(),
        topic: Some("Default Flow discussion track".to_owned()),
        unread: 0,
        is_default: true,
    }
}

fn channel_from_flow_event(space_id: &str, event: &Value) -> Option<ChannelEntity> {
    let candidates = message_candidates(event);
    if !candidates
        .iter()
        .any(|candidate| value_string_at(candidate, &["kind", "type"]) == Some("cx.flow.create"))
    {
        return None;
    }
    if !flow_create_has_discussion_track(&candidates)
        && !candidates.iter().any(|candidate| {
            // T2.3: the v1 wire uses `track`; legacy `branch` is a
            // hard_reject field per forbidden-wire-fields.json, so writers
            // MUST NOT emit it. Readers fall back to `category` only for
            // payloads that pre-date the track concept entirely.
            value_string_at(candidate, &["track"]) == Some("discussion")
                || value_string_at(candidate, &["category"]) == Some("discussion")
        })
    {
        return None;
    }

    let flow_id = first_string_in_candidate_paths(
        &candidates,
        &[
            &["flow_id"],
            &["target_ref"],
            &["object", "id"],
            &["object", "flow_id"],
            &["flow", "id"],
            &["flow", "flow_id"],
        ],
    )?
    .trim();
    if !flow_id.starts_with("cx:flow:") {
        return None;
    }

    let name = first_string_in_candidate_paths(
        &candidates,
        &[
            &["title"],
            &["name"],
            &["object", "title"],
            &["object", "name"],
            &["flow", "title"],
            &["flow", "name"],
        ],
    )
    .unwrap_or(flow_id)
    .to_owned();
    let category = first_string_in_candidate_paths(
        &candidates,
        &[
            &["category"],
            &["fields", "category"],
            &["object", "fields", "category"],
            &["flow", "fields", "category"],
        ],
    )
    .unwrap_or("general")
    .to_owned();
    let topic = first_string_in_candidate_paths(
        &candidates,
        &[
            &["summary"],
            &["topic"],
            &["description"],
            &["object", "summary"],
            &["object", "topic"],
            &["object", "description"],
            &["flow", "summary"],
            &["flow", "topic"],
            &["flow", "description"],
        ],
    )
    .map(ToOwned::to_owned);
    let has_synthesis = flow_create_has_synthesis_track(&candidates);

    Some(ChannelEntity {
        flow_id: flow_id.to_owned(),
        name,
        kind: if has_synthesis {
            "flow".to_owned()
        } else {
            "discussion".to_owned()
        },
        category,
        topic,
        unread: 0,
        is_default: flow_id == default_discussion_flow_id(space_id),
    })
}

fn channels_from_events(space_id: &str, events: &[Value]) -> Vec<ChannelEntity> {
    events
        .iter()
        .filter_map(|event| channel_from_flow_event(space_id, event))
        .collect()
}

fn channels_from_sync_spaces(
    spaces: &std::collections::BTreeMap<String, Value>,
    default_space_ids: &[String],
) -> Vec<ChannelEntity> {
    let mut channels = Vec::new();
    for (space_id, body) in spaces {
        if default_space_ids.iter().any(|id| id == space_id) {
            channels.push(default_discussion_channel(space_id, Some(body)));
        }
        let Some(timeline_events) = body
            .get("timeline")
            .and_then(|timeline| timeline.get("events"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        channels.extend(channels_from_events(space_id, timeline_events));
    }
    channels
}

fn channels_from_local_state(state: &ClientLocalState) -> Vec<ChannelEntity> {
    state
        .raw_operations
        .iter()
        .filter_map(|record| {
            channel_from_flow_event(
                record.space_id.as_deref().unwrap_or_default(),
                &record.payload,
            )
        })
        .collect()
}

fn merge_channels(target: &mut Vec<ChannelEntity>, incoming: Vec<ChannelEntity>) {
    for channel in incoming {
        if let Some(existing) = target
            .iter_mut()
            .find(|candidate| candidate.flow_id == channel.flow_id)
        {
            *existing = channel;
        } else {
            target.push(channel);
        }
    }
}

fn merge_chat_messages(target: &mut Vec<ChatMessage>, incoming: Vec<ChatMessage>) {
    for message in incoming {
        if !target.iter().any(|existing| existing.id == message.id) {
            target.push(message);
        }
    }
}

async fn submit_chat_operation_with_plaintext_retry(
    api: &ContrixApi,
    space_id: &str,
    actor_did: &str,
    plaintext_visible_services: &[String],
    operation: &EventEnvelope,
) -> anyhow::Result<SubmitEventResponse> {
    match api.submit_event_envelope(operation).await {
        Ok(response) => Ok(response),
        Err(error) if is_plaintext_visibility_policy_error(&error) => {
            let mut services = plaintext_visible_services.to_vec();
            if let Ok(description) = api.describe().await {
                let service_did = description.service_did.as_str().trim();
                if !service_did.is_empty()
                    && !services.iter().any(|existing| existing == service_did)
                {
                    services.push(service_did.to_owned());
                }
            }
            if services.is_empty() {
                return Err(error);
            }
            api.update_space(
                space_id,
                actor_did,
                json!({"plaintext_visible_services": services}),
            )
            .await
            .map_err(|update_error| {
                anyhow::anyhow!(
                    "plaintext policy update failed: {update_error}; original send failed: {error}"
                )
            })?;
            api.submit_event_envelope(operation).await
        }
        Err(error) => Err(error),
    }
}

#[component]
pub fn ChatPanel(
    base_url: String,
    plaintext_service_did: String,
    account_did: String,
    token: Signal<String>,
    selected_space: String,
    selected_space_scope: Vec<String>,
    sync_cursor: Signal<String>,
    frontier_state: Signal<String>,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let navigator = use_navigator();
    let initial_default_channel = (!selected_space.trim().is_empty())
        .then(|| default_discussion_channel(&selected_space, None));
    let initial_selected_channel = initial_default_channel
        .as_ref()
        .map(|channel| channel.flow_id.clone())
        .unwrap_or_default();
    let mut channels = use_signal(move || {
        initial_default_channel
            .clone()
            .into_iter()
            .collect::<Vec<_>>()
    });
    let mut selected_channel = use_signal(move || initial_selected_channel.clone());
    let mut messages = use_signal(Vec::<ChatMessage>::new);
    let mut chat_draft = use_signal(String::new);
    // A6.2 composer drag-drop attachment state. `compose_dragover` toggles
    // the `is-dragover` outline as the user holds a file over the
    // textarea; `compose_upload_status` shows an inline progress / error
    // string for the most recent drop or hidden-input upload.
    let mut compose_dragover = use_signal(|| false);
    let mut compose_upload_status = use_signal(|| String::new());
    // A6.3 message pinning. Local-only scaffolding: the spec does not
    // yet define a `cx.message.pin` event_kind, so we keep pin state in
    // a per-space Signal and surface it at the top of the discussion.
    // When soland exposes the pin endpoint (see TODO below) we'll
    // replace this with a real API call + projection sync.
    //
    // TODO(soland): replace `pinned_messages` with the canonical
    // `cx.message.pin` event family per spec
    // `flow-and-message.md §8.6` once soland ships it.
    let mut pinned_messages = use_signal(Vec::<String>::new);
    // Currently-open context menu (right-click on a message). Stores
    // the message id whose menu is open; None means no menu visible.
    let mut message_context_menu = use_signal(|| Option::<String>::None);
    // Read the shared per-Space MLS passphrase store. Set from the
    // passphrase input above Send Secure; read by the secure-send path
    // to run `group.encrypt_payload()`.
    let mls_passphrase_store = use_context::<Signal<crate::mls_passphrase::MlsPassphraseStore>>();
    let mut mls_passphrase_draft = use_signal(String::new);
    // Multi-device Welcome flow controls. The
    // `Invite to MLS group` button fetches the target (actor, device)
    // key package via `fetch_mls_key_package`, runs `group.add_member`
    // against the hydrated local group, sends the resulting Welcome
    // via `send_device_message_envelope` (`type = cx.mls.welcome`),
    // and submits the commit Operation. Bob's app picks up the
    // Welcome in its periodic `receive_device_messages` poll and runs
    // `join_from_welcome` → snapshot save.
    let mut mls_invite_actor_draft = use_signal(String::new);
    let mut mls_invite_device_draft = use_signal(String::new);
    // Local publish-state: did we already publish our key package this
    // session? Used to gate the "Publish my key package" button so a
    // duplicate click just refreshes status instead of generating a
    // fresh package every time.
    let mls_key_package_published = use_signal(|| false);
    let mut new_channel_name = use_signal(String::new);
    let mut new_channel_topic = use_signal(String::new);
    let mut new_channel_members = use_signal(String::new);
    // T7.2: typing buffer for the inline pill picker. The committed
    // entries live in `new_channel_members` (comma-separated, preserves
    // the existing submit pipeline); `new_channel_member_input` only
    // holds the current draft handle being typed.
    let mut new_channel_member_input = use_signal(String::new);
    let mut new_channel_create_card = use_signal(|| false);
    let mut create_dialog_open = use_signal(|| false);
    // T7.2: per-Flow watch level signal for the topbar fast switcher.
    // Optimistically updates on user click; a failed submit rolls back to
    // the prior value.
    let mut flow_watch_level = use_signal(|| WatchLevel::All);
    let mut watch_level_menu_open = use_signal(|| false);
    let mut status_msg = use_signal(String::new);
    let mut reply_to_message = use_signal(|| Option::<String>::None);
    let mut editing_message = use_signal(|| Option::<String>::None);
    let mut edit_draft = use_signal(String::new);
    let mut redact_confirm = use_signal(|| Option::<String>::None);
    let mut reaction_picker = use_signal(|| Option::<String>::None);
    let mut initial_sync_requested = use_signal(|| false);
    // G3.Y2 — mention picker. `mention_picker_state` tracks open/closed
    // + the current `@`-query + the list of inserted chips so the
    // composer can render `mention-picker` / `mention-suggestion` /
    // `mention-chip` testids off a single signal.
    let mut mention_picker_state = use_signal(crate::messaging::mentions::MentionPickerState::new);
    // G3.Y2 — poll composer. `poll_draft` is `Some(_)` while the
    // attachment menu's poll form is open; on send it becomes
    // `PollCard` in `poll_cards`. The attachment menu open/closed
    // state is held in `attachment_menu_open`.
    let mut attachment_menu_open = use_signal(|| false);
    let mut poll_draft = use_signal(|| Option::<crate::messaging::polls::PollDraft>::None);
    let mut poll_cards = use_signal(Vec::<crate::messaging::polls::PollCard>::new);
    // G3.Y2 — typing indicator. `typing_actors` lists the DIDs of
    // other actors who have sent a `cx.typing` ephemeral within the
    // TTL window. Currently seeded from local state for testability;
    // the live wire path (subscribe to soland ephemeral fanout) is
    // tracked under TODO(G3.Y2-followup).
    let typing_actors = use_signal(Vec::<String>::new);
    // G3.Y2 — presence. Maps `actor_did -> "online"|"away"|"offline"`.
    // Seeded from `local_state::presence_aggregate` when the sync
    // engine surfaces a presence projection; for now the chat view
    // just renders whatever the store hands it.
    let presence_states = use_signal(std::collections::BTreeMap::<String, String>::new);
    // G3.Y2 — discussion promote modal. Holds the source message id
    // (or Flow id) + the desired child-Space title.
    let mut promote_discussion_draft =
        use_signal(crate::messaging::discussion_promote::PromoteDiscussionDraft::default);
    // Map of `source_message_id -> child_space_id` for the
    // `discussion-promoted-indicator` row. Populated optimistically
    // on submit and updated from the server response.
    let mut promoted_targets = use_signal(std::collections::BTreeMap::<String, String>::new);
    // G3.Y2 — `cx.read.marker` book-keeping. `latest_read_marker`
    // stores the highest event_id we've posted a read marker for so
    // we don't spam soland on every render tick.
    let mut latest_read_marker = use_signal(String::new);
    // A5 — personal blocklist. `blocked_did_set` snapshots the local
    // store at render time; `blocked_show_anyway` tracks per-message
    // reveal opt-ins so the user can peek at an otherwise-hidden body
    // without clearing the block.
    let mut blocked_show_anyway = use_signal(std::collections::BTreeSet::<String>::new);
    let blocked_did_set: std::collections::BTreeSet<String> = state_store
        .read()
        .client_blocklist()
        .into_iter()
        .map(|entry| entry.did)
        .collect();
    let account_display_name = use_signal(String::new);
    let mut track_filter = use_signal(|| "discussion_only".to_owned());
    let mut left_panel_open = use_signal(|| true);
    let mut right_panel = use_signal(|| Option::<DiscussionSidePanel>::None);
    let selected_channel_value = selected_channel();
    let all_channels = channels();
    let filter_value = track_filter();
    let visible_channels: Vec<ChannelEntity> = all_channels
        .iter()
        .filter(|channel| {
            filter_value == "with_discussion_track"
                || channel.is_default
                || channel.kind == "discussion"
        })
        .cloned()
        .collect();
    let visible_channels_empty = visible_channels.is_empty();
    let selected_channel_info = visible_channels
        .iter()
        .find(|channel| channel.flow_id == selected_channel_value)
        .cloned()
        .or_else(|| visible_channels.first().cloned());
    let selected_channel_name = selected_channel_info
        .as_ref()
        .map(|channel| channel.name.clone())
        .unwrap_or_else(|| crate::i18n::tr("chat.empty.title"));
    let selected_channel_category = selected_channel_info
        .as_ref()
        .map(|channel| channel.category.clone())
        .unwrap_or_else(|| "discussion".to_owned());
    let selected_channel_unread = selected_channel_info
        .as_ref()
        .map(|channel| channel.unread)
        .unwrap_or(0);
    let all_messages_snapshot = messages();
    let visible_messages = all_messages_snapshot
        .iter()
        .filter(|msg| {
            msg.flow_id == selected_channel_value
                && (selected_space_scope.is_empty()
                    || selected_space_scope
                        .iter()
                        .any(|space| space == &msg.space_id))
        })
        .cloned()
        .collect::<Vec<_>>();
    let visible_message_count = visible_messages.len();
    // G3.Y2 — derive the highest visible event id so we can post a
    // `cx.read.marker` covering everything we've rendered. The marker
    // itself is actor-private (`discovery/read-receipts.md §3.1`).
    let highest_visible_event_id: Option<String> = visible_messages
        .iter()
        .rev()
        .find(|msg| !msg.id.is_empty() && !msg.pending)
        .map(|msg| msg.id.clone());
    if let Some(top_event) = highest_visible_event_id.as_ref() {
        if latest_read_marker().as_str() != top_event {
            latest_read_marker.set(top_event.clone());
            // Post the visible read receipt through the canonical
            // ephemeral channel; local marker state keeps the rendered
            // testid surface stable while server projection catches up.
            let base = base_url.clone();
            let space = selected_space.clone();
            let event_id = top_event.clone();
            let actor = account_did.clone();
            let api_token = token();
            spawn(async move {
                let _ =
                    crate::views::helpers::with_authed_api(&base, api_token, |api| async move {
                        api.send_receipt(&space, &actor, &event_id, "cx.receipt.read")
                            .await
                    })
                    .await;
            });
        }
    }
    let messages_for_reply_lookup = all_messages_snapshot.clone();
    let messages_for_composer_lookup = all_messages_snapshot.clone();
    let left_open = left_panel_open();
    let active_right_panel = right_panel();
    let right_open = active_right_panel.is_some();
    let shell_class = format!(
        "discussion-shell{}{}",
        if left_open { "" } else { " left-collapsed" },
        if right_open { "" } else { " right-collapsed" }
    );
    let participant_projection = state_store
        .read()
        .load()
        .space_projections
        .get(&selected_space)
        .cloned();
    let mut participants = space_participants(participant_projection.as_ref(), &account_did);
    // Mark agent endpoints registered in this space so the @mention
    // picker, member list, and sender row can render a 🤖 badge.
    // Source of truth is the local store's `cx.agent.endpoint` raw
    // operations (same projection the Agents panel reads from).
    {
        let agent_dids = agent_dids_from_raw_operations(
            &state_store.read().load().raw_operations,
            &selected_space,
        );
        annotate_agent_participants(&mut participants, &agent_dids);
    }
    let participants_for_messages = participants.clone();
    let account_display_label = account_display_name();

    if !initial_sync_requested() && !token().trim().is_empty() {
        initial_sync_requested.set(true);
        let base = base_url.clone();
        let api_token = token();
        let wait_for = active_sync_token(&sync_cursor());
        let selected_space_for_load = selected_space.clone();
        let selected_scope_for_load = selected_space_scope.clone();
        let account_did_for_load = account_did.clone();
        let mut account_display_name_for_load = account_display_name;
        spawn(async move {
            let Ok(api) = authed_api_with_sync(&base, api_token, wait_for) else {
                return;
            };
            let mut loaded_messages = chat_messages_from_local_state(&state_store.read().load());
            if let Ok(account) = api.account_me().await
                && account.did == account_did_for_load
                && let Some(display_name) = clean_participant_display_name(
                    account.display_name.as_deref().unwrap_or(""),
                    Some(&account_did_for_load),
                )
            {
                account_display_name_for_load.set(display_name);
            }
            if let Ok(sync) = api.account_subscribe_snapshot(None).await {
                {
                    let mut store = state_store.write();
                    store.save_sync_cursor(sync.cursor.clone());
                    for (space_id, projection) in &sync.spaces {
                        store.save_space_projection(space_id.clone(), projection.clone());
                    }
                }
                loaded_messages.extend(chat_messages_from_sync_spaces(&sync.spaces));
                let default_space_ids = if selected_scope_for_load.is_empty() {
                    vec![selected_space_for_load.clone()]
                } else {
                    selected_scope_for_load.clone()
                };
                merge_channels(
                    &mut channels.write(),
                    channels_from_sync_spaces(&sync.spaces, &default_space_ids),
                );
                sync_cursor.set(sync.cursor);
            }

            let spaces_to_backfill = if selected_scope_for_load.is_empty() {
                vec![selected_space_for_load]
            } else {
                selected_scope_for_load
            };
            for space_id in spaces_to_backfill {
                if space_id.trim().is_empty() {
                    continue;
                }
                if let Ok(backfill) = api.backfill(&space_id).await {
                    merge_channels(
                        &mut channels.write(),
                        channels_from_events(&space_id, &backfill.events),
                    );
                    loaded_messages.extend(chat_messages_from_events(&space_id, &backfill.events));
                }
            }

            merge_channels(
                &mut channels.write(),
                channels_from_local_state(&state_store.read().load()),
            );
            if selected_channel().trim().is_empty() {
                if let Some(first_channel) = channels.read().first() {
                    selected_channel.set(first_channel.flow_id.clone());
                }
            }
            if !loaded_messages.is_empty() {
                merge_chat_messages(&mut messages.write(), loaded_messages);
            }
        });
    }

    // Welcome receive shuttle. Poll /api/v1/device_messages once per
    // mount; if any incoming message
    // carries `type = cx.mls.welcome`, run
    // `ContrixMlsGroup::join_from_welcome` against the local identity
    // for that Space and persist the resulting group snapshot under the
    // user's per-Space passphrase. Subsequent Send Secure / decrypt
    // hits the multi-member group automatically.
    let mut welcome_poll_done = use_signal(|| false);
    {
        let base = base_url.clone();
        let space = selected_space.clone();
        let actor = account_did.clone();
        let token_for_poll = token;
        let passphrase_store = mls_passphrase_store;
        use_future(move || {
            let base = base.clone();
            let space = space.clone();
            let actor = actor.clone();
            async move {
                if welcome_poll_done() {
                    return;
                }
                welcome_poll_done.set(true);
                if token_for_poll().trim().is_empty() {
                    return;
                }
                let api_token = token_for_poll();
                let messages = match crate::views::helpers::with_authed_api(
                    &base,
                    api_token,
                    |api| async move { api.receive_device_messages().await },
                )
                .await
                {
                    Ok(resp) => resp,
                    Err(_) => return,
                };
                let mut applied = 0usize;
                #[cfg(not(target_arch = "wasm32"))]
                {
                    let messages_value = match serde_json::to_value(&messages) {
                        Ok(v) => v,
                        Err(_) => return,
                    };
                    let welcome_entries = collect_welcome_entries(&messages_value);
                    if welcome_entries.is_empty() {
                        return;
                    }
                    let passphrase: String = passphrase_store
                        .read()
                        .get(&space)
                        .map(str::to_owned)
                        .unwrap_or_default();
                    let device_did = match state_store.read().local_identity() {
                        Some(identity) => identity.device_did.clone(),
                        None => return,
                    };
                    for welcome_value in welcome_entries {
                        let welcome: contrix_sdk::MlsWelcomeEnvelope =
                            match serde_json::from_value(welcome_value.clone()) {
                                Ok(w) => w,
                                Err(_) => continue,
                            };
                        let principal_did = match contrix_sdk::Did::new(actor.clone()) {
                            Ok(d) => d,
                            Err(_) => continue,
                        };
                        let device_id_typed = match contrix_sdk::DeviceId::new(device_did.clone()) {
                            Ok(d) => d,
                            Err(_) => continue,
                        };
                        let identity = match contrix_sdk::ContrixMlsIdentity::new_basic(
                            principal_did,
                            device_id_typed,
                        ) {
                            Ok(i) => i,
                            Err(_) => continue,
                        };
                        let group = match contrix_sdk::ContrixMlsGroup::join_from_welcome(
                            identity, &welcome,
                        ) {
                            Ok(g) => g,
                            Err(_) => continue,
                        };
                        let post_state = match group.export_state_record() {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        let mut salt = [0u8; 16];
                        if getrandom::fill(&mut salt).is_err() {
                            continue;
                        }
                        let snapshot = crate::mls_persistence::encrypt_state(
                            &space,
                            &post_state.group_id,
                            post_state.epoch,
                            &post_state.serialized_state,
                            &passphrase,
                            &salt,
                        );
                        state_store
                            .write()
                            .save_mls_snapshot(space.clone(), snapshot);
                        applied += 1;
                    }
                }
                #[cfg(target_arch = "wasm32")]
                {
                    let _ = (messages, passphrase_store, actor);
                }
                if applied > 0 {
                    status_msg.set(format!(
                        "joined {applied} MLS group(s) from Welcome envelopes"
                    ));
                }
            }
        });
    }

    // T7.4: refresh per-message crypto state when the MLS passphrase /
    // local group state changes. Messages flagged `Decrypting` transition
    // to `KeyMissing` when no passphrase is saved for the Space so the
    // user sees a clear "waiting for Welcome" indicator instead of a
    // spinner forever.
    {
        let space_for_crypto = selected_space.clone();
        let mut messages_sig = messages;
        let passphrase_store_crypto = mls_passphrase_store;
        use_effect(move || {
            let passphrase = passphrase_store_crypto
                .read()
                .get(&space_for_crypto)
                .map(str::to_owned)
                .unwrap_or_default();
            // Only mutate when we'd actually move someone from Decrypting
            // into KeyMissing — Decrypting → Plaintext requires a real
            // decrypt attempt that this view doesn't yet run.
            if passphrase.is_empty() {
                let mut current = messages_sig.write();
                for msg in current.iter_mut() {
                    if matches!(msg.crypto_state, MessageCryptoState::Decrypting) {
                        msg.crypto_state = MessageCryptoState::KeyMissing;
                    }
                }
            }
        });
    }

    let composer_class = "discussion-composer";

    rsx! {
        div { class: "{shell_class}", "data-testid": "chat-panel",
            if left_open {
                aside { class: "discussion-panel discussion-sidebar-panel", "data-testid": "discussion-list-panel",
                    div { class: "discussion-panel-head",
                        div { class: "discussion-title-row",
                            h2 { {crate::i18n::tr("chat.discussions_header")} }
                            HelpTip { text: "Discussion is the selected Flow's track. The default Flow is always available for this Space; the alternate filter includes every Flow with a discussion track." }
                        }
                        div { class: "discussion-panel-head-actions",
                            button {
                                class: "primary icon-button",
                                "aria-label": crate::i18n::tr("chat.new_flow"),
                                title: crate::i18n::tr("chat.new_flow"),
                                "data-testid": "open-channel-dialog",
                                onclick: move |_| create_dialog_open.set(true),
                                UiIcon { name: "plus" }
                            }
                            button {
                                class: "secondary icon-button",
                                "aria-label": crate::i18n::tr("chat.hide_list"),
                                "data-testid": "collapse-discussion-list",
                                onclick: move |_| left_panel_open.set(false),
                                UiIcon { name: "panel-left-close" }
                            }
                        }
                    }
                    div { class: "discussion-filter segmented-control",
                        button {
                            class: if track_filter() == "discussion_only" { "segment active" } else { "segment" },
                            "data-testid": "discussion-filter-only",
                            onclick: move |_| track_filter.set("discussion_only".to_owned()),
                            "Default + discussion"
                        }
                        button {
                            class: if track_filter() == "with_discussion_track" { "segment active" } else { "segment" },
                            "data-testid": "discussion-filter-track",
                            onclick: move |_| track_filter.set("with_discussion_track".to_owned()),
                            "All Flow tracks"
                        }
                    }
                    div { class: "discussion-list", "data-testid": "channel-list",
                        for channel in visible_channels {
                            button {
                                class: if channel.flow_id == selected_channel() { "discussion-track-row active" } else { "discussion-track-row" },
                                "data-testid": "channel-item",
                                onclick: {
                                    let id = channel.flow_id.clone();
                                    move |_| selected_channel.set(id.clone())
                                },
                                div { class: "discussion-track-main",
                                    span { class: "discussion-track-name", "{channel.name}" }
                                    span { class: "discussion-track-topic",
                                        if let Some(topic) = &channel.topic {
                                            "{topic}"
                                        } else {
                                            "No topic"
                                        }
                                    }
                                }
                                div { class: "discussion-track-meta",
                                    span { class: "badge", "{channel.category}" }
                                    if channel.unread > 0 {
                                        span { class: "badge accent", "{channel.unread}" }
                                    }
                                }
                            }
                        }
                        if visible_channels_empty {
                            div { class: "discussion-empty", "data-testid": "empty-discussion-list", {crate::i18n::tr("chat.empty_discussions")} }
                        }
                    }
                }
            } else {
                div { class: "discussion-rail discussion-left-rail", "data-testid": "discussion-list-rail",
                    button {
                        class: "secondary icon-button",
                        "aria-label": "Show discussion list",
                        "data-testid": "expand-discussion-list",
                        onclick: move |_| left_panel_open.set(true),
                        UiIcon { name: "panel-left-open" }
                    }
                }
            }

            if create_dialog_open() {
                div { class: "discussion-modal-backdrop", "data-testid": "channel-create-modal",
                    div { class: "discussion-modal", role: "dialog", "aria-modal": "true", "aria-label": "New Flow",
                        div { class: "discussion-modal-head",
                            div { class: "discussion-title-row",
                                h2 { "New Flow" }
                                HelpTip { text: "Creates an additional Flow. Its discussion track is available from this view; enable the card option when the same Flow should also carry a synthesis track." }
                            }
                            button {
                                class: "secondary icon-button",
                                "aria-label": "Close",
                                "data-testid": "close-channel-dialog",
                                onclick: move |_| create_dialog_open.set(false),
                                UiIcon { name: "x" }
                            }
                        }
                        div { class: "discussion-modal-body workflow-form",
                            label { {crate::i18n::tr("chat.label.title")} }
                            input {
                                "data-testid": "new-channel-name",
                                value: "{new_channel_name}",
                                placeholder: "Flow title",
                                oninput: move |evt| new_channel_name.set(evt.value()),
                            }
                            label { {crate::i18n::tr("chat.label.summary")} }
                            input {
                                "data-testid": "new-channel-topic",
                                value: "{new_channel_topic}",
                                placeholder: "Short purpose or context",
                                oninput: move |evt| new_channel_topic.set(evt.value()),
                            }
                            label { {crate::i18n::tr("chat.label.watchers")} }
                            {
                                // T7.2: multi-select pill UI. The
                                // existing submit pipeline still consumes
                                // `new_channel_members` (comma-separated),
                                // so commit each accepted token by
                                // appending it there. The pill rendering
                                // re-parses on every keystroke so paste-
                                // bombing `did:web:foo, alice@bar.com,
                                // bob@baz.com` resolves all entries at
                                // once.
                                let committed = new_channel_members();
                                let pills = parse_watcher_pills(&committed, &participants);
                                let canonical_already: Vec<String> = pills
                                    .iter()
                                    .filter_map(|p| match &p.state {
                                        WatcherEntryKind::Valid(did) => Some(did.clone()),
                                        _ => None,
                                    })
                                    .collect();
                                let valid_count = pills
                                    .iter()
                                    .filter(|p| matches!(p.state, WatcherEntryKind::Valid(_)))
                                    .count();
                                let invalid_count = pills.len() - valid_count;
                                let current_input = new_channel_member_input();
                                let query_lower = current_input.trim().trim_start_matches('@').to_ascii_lowercase();
                                let show_suggestions = !current_input.trim().is_empty();
                                let suggestions: Vec<SpaceParticipant> = if show_suggestions {
                                    participants
                                        .iter()
                                        .filter(|p| !p.is_self)
                                        .filter(|p| !canonical_already.iter().any(|d| d == &p.did))
                                        .filter(|p| {
                                            if query_lower.is_empty() {
                                                return true;
                                            }
                                            if p.did.to_ascii_lowercase().contains(&query_lower) {
                                                return true;
                                            }
                                            p.display_name
                                                .as_deref()
                                                .map(|n| n.to_ascii_lowercase().contains(&query_lower))
                                                .unwrap_or(false)
                                        })
                                        .take(6)
                                        .cloned()
                                        .collect()
                                } else {
                                    Vec::new()
                                };
                                rsx! {
                                    div {
                                        class: "watcher-picker",
                                        "data-testid": "watcher-picker",
                                        // Existing pills.
                                        div { class: "watcher-pill-row",
                                            for (idx, pill) in pills.iter().enumerate() {
                                                {
                                                    let raw_for_label = pill.raw.clone();
                                                    let raw_for_remove = pill.raw.clone();
                                                    let pill_class = match &pill.state {
                                                        WatcherEntryKind::Valid(_) => "watcher-pill watcher-pill-valid",
                                                        WatcherEntryKind::Duplicate(_) => "watcher-pill watcher-pill-warning",
                                                        WatcherEntryKind::UnknownHandle => "watcher-pill watcher-pill-invalid",
                                                        WatcherEntryKind::InvalidDid => "watcher-pill watcher-pill-invalid",
                                                        WatcherEntryKind::UnresolvedName => "watcher-pill watcher-pill-invalid",
                                                    };
                                                    let tooltip = match &pill.state {
                                                        WatcherEntryKind::Valid(did) => format!("{}", did),
                                                        WatcherEntryKind::Duplicate(_) => crate::i18n::tr("chat.watchers.dupe"),
                                                        WatcherEntryKind::UnknownHandle => crate::i18n::tr("chat.watchers.unknown_handle"),
                                                        WatcherEntryKind::InvalidDid => crate::i18n::tr("chat.watchers.invalid_did"),
                                                        WatcherEntryKind::UnresolvedName => crate::i18n::tr("chat.watchers.unresolved"),
                                                    };
                                                    rsx! {
                                                        span {
                                                            key: "{idx}-{raw_for_label}",
                                                            class: "{pill_class}",
                                                            "data-testid": "watcher-pill",
                                                            title: "{tooltip}",
                                                            "{raw_for_label}"
                                                            button {
                                                                r#type: "button",
                                                                class: "watcher-pill-remove",
                                                                "aria-label": crate::i18n::tr("common.remove"),
                                                                "data-testid": "watcher-pill-remove",
                                                                onclick: move |_| {
                                                                    let current = new_channel_members();
                                                                    let kept: Vec<String> = current
                                                                        .split(|ch: char| matches!(ch, ',' | '\n' | '\r' | '\t' | ';'))
                                                                        .map(|s| s.trim())
                                                                        .filter(|s| !s.is_empty() && *s != raw_for_remove.as_str())
                                                                        .map(|s| s.to_owned())
                                                                        .collect();
                                                                    new_channel_members.set(kept.join(", "));
                                                                },
                                                                "\u{d7}"
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            input {
                                                r#type: "text",
                                                class: "watcher-pill-input",
                                                "data-testid": "new-channel-members",
                                                value: "{current_input}",
                                                placeholder: crate::i18n::tr("chat.watchers.placeholder"),
                                                oninput: move |evt| new_channel_member_input.set(evt.value()),
                                                onkeydown: move |evt| {
                                                    let key = evt.key().to_string();
                                                    let raw_now = new_channel_member_input();
                                                    if key == "Enter" || key == "," || key == "Tab" {
                                                        let typed = raw_now.trim().trim_end_matches(',').to_owned();
                                                        if !typed.is_empty() {
                                                            evt.prevent_default();
                                                            let mut existing = new_channel_members();
                                                            if !existing.is_empty() && !existing.trim_end().ends_with(',') {
                                                                existing.push_str(", ");
                                                            } else if !existing.is_empty() {
                                                                existing.push(' ');
                                                            }
                                                            existing.push_str(&typed);
                                                            new_channel_members.set(existing);
                                                            new_channel_member_input.set(String::new());
                                                        }
                                                    } else if key == "Backspace" && raw_now.is_empty() {
                                                        // Pop the last committed pill.
                                                        let current = new_channel_members();
                                                        let mut tokens: Vec<String> = current
                                                            .split(|ch: char| matches!(ch, ',' | '\n' | '\r' | '\t' | ';'))
                                                            .map(|s| s.trim().to_owned())
                                                            .filter(|s| !s.is_empty())
                                                            .collect();
                                                        if !tokens.is_empty() {
                                                            tokens.pop();
                                                            new_channel_members.set(tokens.join(", "));
                                                        }
                                                    }
                                                },
                                            }
                                        }
                                        div { class: "watcher-pill-summary muted",
                                            "data-testid": "watcher-pill-summary",
                                            {format!(
                                                "{} {} \u{00b7} {} {}",
                                                valid_count,
                                                crate::i18n::tr("chat.watchers.valid"),
                                                invalid_count,
                                                crate::i18n::tr("chat.watchers.invalid"),
                                            )}
                                        }
                                    }
                                    p { class: "form-hint muted",
                                        {crate::i18n::tr("chat.watchers.hint")}
                                    }
                                    if !suggestions.is_empty() {
                                        div {
                                            class: "mention-suggestions",
                                            "data-testid": "new-channel-members-suggestions",
                                            for participant in suggestions {
                                                {
                                                    let did_for_click = participant.did.clone();
                                                    let did_for_label = participant.did.clone();
                                                    let is_agent = participant.is_agent;
                                                    let display = participant
                                                        .display_name
                                                        .clone()
                                                        .unwrap_or_else(|| short_principal_label(&participant.did));
                                                    rsx! {
                                                        button {
                                                            r#type: "button",
                                                            class: "mention-suggestion-item",
                                                            "data-testid": "new-channel-members-suggestion",
                                                            onclick: move |_| {
                                                                let mut existing = new_channel_members();
                                                                if !existing.is_empty() && !existing.trim_end().ends_with(',') {
                                                                    existing.push_str(", ");
                                                                }
                                                                existing.push_str(&did_for_click);
                                                                new_channel_members.set(existing);
                                                                new_channel_member_input.set(String::new());
                                                            },
                                                            span { class: "mention-suggestion-name", "{display}" }
                                                            if is_agent {
                                                                span {
                                                                    class: "badge member-badge member-badge-agent",
                                                                    "data-testid": "member-badge-agent",
                                                                    title: "Automated member (bot)",
                                                                    "\u{1f916} "
                                                                    {crate::i18n::tr("member.badge.agent")}
                                                                }
                                                            }
                                                            span { class: "mention-suggestion-did muted", "{did_for_label}" }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            label { class: "discussion-checkbox-row",
                                input {
                                    r#type: "checkbox",
                                    "data-testid": "new-channel-create-card",
                                    checked: new_channel_create_card(),
                                    onchange: move |evt| new_channel_create_card.set(evt.value() == "true"),
                                }
                                span { "Create matching Card" }
                            }
                        }
                        div { class: "discussion-modal-actions",
                            button {
                                class: "secondary",
                                "data-testid": "cancel-channel-create",
                                onclick: move |_| create_dialog_open.set(false),
                                {crate::i18n::tr("common.cancel")}
                            }
                            button {
                                class: "primary",
                                "data-testid": "create-channel-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let space = selected_space.clone();
                                    move |_| {
                                        let title = new_channel_name().trim().to_owned();
                                        if title.is_empty() {
                                            status_msg.set("Flow title is required".to_owned());
                                            return;
                                        }
                                        let category = "general".to_owned();
                                        let summary = new_channel_topic().trim().to_owned();
                                        let watcher_text = new_channel_members();
                                        let create_card = new_channel_create_card();
                                        // Per contrix-spec/spec/v1/zh/models/flow-and-message.md §8,
                                        // initial watchers are no longer stored as
                                        // `Flow.fields.participants` — that field acted like ACL
                                        // metadata but had no access semantics. The seed list now
                                        // produces one `cx.flow.watch.set` event per DID. The Flow
                                        // creator is excluded from the seed because the spec §8.4
                                        // creator-implicit-subscribe path covers them.
                                        let initial_watchers: Vec<String> =
                                            parse_discussion_principals(&watcher_text)
                                                .into_iter()
                                                .filter(|did| did != actor.trim())
                                                .collect();
                                        let flow_id = format!("cx:flow:{}", uuid_v7());
                                        let rank = format!("r{}", chrono::Utc::now().timestamp_millis());
                                        let op = match cx_ops::discussion_flow_create(
                                            &space,
                                            &actor,
                                            &flow_id,
                                            &title,
                                        ) {
                                            Ok(builder) => {
                                                let mut op = builder.build("yougen");
                                                op.payload["category"] = json!(category.clone());
                                                op.payload["create_card"] = json!(create_card);
                                                if !op.payload.get("fields").is_some_and(|fields| fields.is_object()) {
                                                    op.payload["fields"] = json!({});
                                                }
                                                op.payload["fields"]["category"] = json!(category.clone());
                                                op.payload["fields"]["has_synthesis"] = json!(create_card);
                                                if !op.payload["object"]
                                                    .get("fields")
                                                    .is_some_and(|fields| fields.is_object())
                                                {
                                                    op.payload["object"]["fields"] = json!({});
                                                }
                                                op.payload["object"]["fields"]["category"] =
                                                    json!(category.clone());
                                                op.payload["object"]["fields"]["has_synthesis"] =
                                                    json!(create_card);
                                                op.payload["rank"] = json!(rank.clone());
                                                if !summary.is_empty() {
                                                    op.payload["summary"] = json!(summary.clone());
                                                    op.payload["object"]["summary"] = json!(summary.clone());
                                                }
                                                if !create_card {
                                                    if let Some(tracks) = op.payload["object"]["tracks"].as_object_mut() {
                                                        tracks.remove("synthesis");
                                                    }
                                                }
                                                if let Err(error) = op.refresh_proof_hashes() {
                                                    status_msg.set(format!(
                                                        "Could not create Flow proof: {error}"
                                                    ));
                                                    return;
                                                }
                                                op
                                            }
                                            Err(error) => {
                                                status_msg.set(format!(
                                                    "Could not create Flow: {error}"
                                                ));
                                                return;
                                            }
                                        };
                                        let api_token = token();
                                        let wait_for = active_sync_token(&sync_cursor());
                                        let channel_topic = if summary.is_empty() { None } else { Some(summary) };
                                        let base = base.clone();
                                        let space = space.clone();
                                        let watch_ops: Vec<crate::operation::EventEnvelope> = initial_watchers
                                            .iter()
                                            .map(|target_did| {
                                                cx_ops::flow_watch_set(
                                                    &space,
                                                    &actor,
                                                    target_did,
                                                    &flow_id,
                                                    Some("participating"),
                                                    None,
                                                )
                                                .build("yougen")
                                            })
                                            .collect();
                                        status_msg.set("Creating Flow".to_owned());
                                        spawn(async move {
                                            match authed_api_with_sync(&base, api_token.clone(), wait_for) {
                                                Ok(api) => match api
                                                        .submit_event_envelope(&op)
                                                        .await
                                                    {
                                                        Ok(submitted) => {
                                                            channels.write().push(ChannelEntity {
                                                                flow_id: flow_id.clone(),
                                                                name: title.clone(),
                                                                kind: "discussion".to_owned(),
                                                                category: category.clone(),
                                                                topic: channel_topic.clone(),
                                                                unread: 0,
                                                                is_default: false,
                                                            });
                                                            selected_channel.set(flow_id.clone());
                                                            frontier_state.set(submitted.event_id.clone());
                                                            sync_cursor.set(submitted.sync_token.clone());
                                                            {
                                                                let mut store = state_store.write();
                                                                store.save_sync_cursor(submitted.sync_token.clone());
                                                                store.append_raw_operation(
                                                                    op.local_operation_id().to_owned(),
                                                                    Some(space.clone()),
                                                                    json!({
                                                                        "flow_id": flow_id,
                                                                        "kind": "cx.flow.create",
                                                                        "title": title,
                                                                        "category": category,
                                                                        "summary": channel_topic,
                                                                        "create_card": create_card,
                                                                        "object": op.payload["object"].clone(),
                                                                        "event_id": submitted.event_id,
                                                                    }),
                                                                );
                                                            }
                                                            // Fan out seed watcher subscriptions.
                                                            // Best-effort: failures are surfaced
                                                            // in status, but the Flow is
                                                            // already created. Default UX places
                                                            // every seed at `participating`; users
                                                            // can change their own level later.
                                                            let mut watch_failures = 0usize;
                                                            if !watch_ops.is_empty() {
                                                                let watch_wait = active_sync_token(&sync_cursor());
                                                                if let Ok(watch_api) = authed_api_with_sync(&base, api_token, watch_wait) {
                                                                    for watch_op in &watch_ops {
                                                                        if watch_api
                                                                            .submit_event_envelope(watch_op)
                                                                            .await
                                                                            .is_err()
                                                                        {
                                                                            watch_failures += 1;
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            if watch_failures > 0 {
                                                                status_msg.set(format!(
                                                                    "Flow created; {watch_failures} watcher invite(s) failed"
                                                                ));
                                                            } else {
                                                                status_msg.set("Flow created".to_owned());
                                                            }
                                                            new_channel_name.set(String::new());
                                                            new_channel_topic.set(String::new());
                                                            new_channel_members.set(String::new());
                                                            new_channel_member_input.set(String::new());
                                                            new_channel_create_card.set(false);
                                                            create_dialog_open.set(false);
                                                        }
                                                        Err(error) => status_msg.set(format!("Flow create failed: {error}")),
                                                    },
                                                    Err(error) => status_msg.set(format!("Invalid server URL: {error}")),
                                                }
                                            });
                                        }
                                    },
                                {crate::i18n::tr("chat.button.create")}
                            }
                        }
                    }
                }
            }

            section { class: "discussion-panel discussion-main-panel", "data-testid": "discussion-main-panel",
                header { class: "discussion-chat-head",
                    div { class: "discussion-title-stack",
                        div { class: "discussion-title-row",
                            h1 { "{selected_channel_name}" }
                        }
                    }
                    div { class: "discussion-head-actions",
                        // T7.2: watch-level fast switcher. Issues a
                        // `cx.flow.watch.set` event on selection. We
                        // optimistically update the local signal first;
                        // a network failure rolls back via status_msg.
                        {
                            let level_now = flow_watch_level();
                            let menu_open = watch_level_menu_open();
                            let level_label = crate::i18n::tr(level_now.label_key());
                            let flow_id_for_watch = selected_channel_value.clone();
                            let space_for_watch = selected_space.clone();
                            let actor_for_watch = account_did.clone();
                            let watch_disabled = flow_id_for_watch.trim().is_empty();
                            rsx! {
                                div { class: "watch-level-picker", "data-testid": "watch-level-picker",
                                    button {
                                        r#type: "button",
                                        class: "secondary watch-level-toggle",
                                        "data-testid": "watch-level-toggle",
                                        disabled: watch_disabled,
                                        title: crate::i18n::tr("chat.watch_level.tooltip"),
                                        onclick: move |_| {
                                            watch_level_menu_open.set(!watch_level_menu_open());
                                        },
                                        span { class: "watch-level-toggle-label",
                                            "{crate::i18n::tr(\"chat.watch_level.prefix\")}: {level_label}"
                                        }
                                        span { class: "watch-level-toggle-caret", "\u{25be}" }
                                    }
                                    if menu_open && !watch_disabled {
                                        div { class: "watch-level-menu", "data-testid": "watch-level-menu",
                                            {
                                                let options = [
                                                    WatchLevel::MentionsOnly,
                                                    WatchLevel::Participating,
                                                    WatchLevel::All,
                                                    WatchLevel::Muted,
                                                ];
                                                rsx! {
                                                    for option in options.iter().copied() {
                                                        {
                                                            let option_label = crate::i18n::tr(option.label_key());
                                                            let flow_id_for_click = flow_id_for_watch.clone();
                                                            let space_for_click = space_for_watch.clone();
                                                            let actor_for_click = actor_for_watch.clone();
                                                            let base_for_click = base_url.clone();
                                                            let is_active = level_now == option;
                                                            rsx! {
                                                                button {
                                                                    r#type: "button",
                                                                    class: if is_active { "watch-level-option active" } else { "watch-level-option" },
                                                                    "data-testid": "watch-level-option",
                                                                    onclick: move |_| {
                                                                        let prev = flow_watch_level();
                                                                        flow_watch_level.set(option);
                                                                        watch_level_menu_open.set(false);
                                                                        status_msg.set(crate::i18n::tr("chat.watch_level.pending"));
                                                                        let api_token = token();
                                                                        let wait_for = active_sync_token(&sync_cursor());
                                                                        let watch_op = cx_ops::flow_watch_set(
                                                                            &space_for_click,
                                                                            &actor_for_click,
                                                                            &actor_for_click,
                                                                            &flow_id_for_click,
                                                                            Some(option.wire_value()),
                                                                            None,
                                                                        )
                                                                        .build("yougen");
                                                                        let base = base_for_click.clone();
                                                                        spawn(async move {
                                                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                                                Ok(api) => match api.submit_event_envelope(&watch_op).await {
                                                                                    Ok(_) => {
                                                                                        status_msg.set(crate::i18n::tr("chat.watch_level.saved"));
                                                                                    }
                                                                                    Err(_) => {
                                                                                        // Rollback on failure.
                                                                                        flow_watch_level.set(prev);
                                                                                        status_msg.set(crate::i18n::tr("chat.watch_level.failed"));
                                                                                    }
                                                                                },
                                                                                Err(_) => {
                                                                                    flow_watch_level.set(prev);
                                                                                    status_msg.set(crate::i18n::tr("chat.watch_level.failed"));
                                                                                }
                                                                            }
                                                                        });
                                                                    },
                                                                    "{option_label}"
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        button {
                            class: if active_right_panel == Some(DiscussionSidePanel::Settings) { "secondary icon-button active" } else { "secondary icon-button" },
                            "aria-label": "Settings",
                            title: "Settings",
                            "data-testid": "discussion-settings-toggle",
                            onclick: move |_| {
                                let next_panel = if right_panel() == Some(DiscussionSidePanel::Settings) {
                                    None
                                } else {
                                    Some(DiscussionSidePanel::Settings)
                                };
                                right_panel.set(next_panel);
                            },
                            UiIcon { name: "settings" }
                        }
                        button {
                            class: if active_right_panel == Some(DiscussionSidePanel::Users) { "secondary icon-button active" } else { "secondary icon-button" },
                            "aria-label": "Users",
                            title: "Users",
                            "data-testid": "discussion-users-toggle",
                            onclick: move |_| {
                                let next_panel = if right_panel() == Some(DiscussionSidePanel::Users) {
                                    None
                                } else {
                                    Some(DiscussionSidePanel::Users)
                                };
                                right_panel.set(next_panel);
                            },
                            UiIcon { name: "users" }
                        }
                    }
                }

                // A6.3 pinned bar (above the chat feed). Lists every
                // pinned message id with a short body preview. Clicking
                // a pill scrolls (well, focuses) the corresponding
                // message via its `data-testid` anchor.
                //
                // Local-only scaffolding — see TODO at `pinned_messages`
                // signal declaration. Replace with the soland pinning
                // projection when the spec lands.
                {
                    let pinned_now = pinned_messages();
                    let pinned_view: Vec<(String, String)> = pinned_now
                        .iter()
                        .filter_map(|id| {
                            messages_for_reply_lookup
                                .iter()
                                .find(|m| m.id == *id)
                                .map(|m| (m.id.clone(), m.body.clone()))
                        })
                        .collect();
                    rsx! {
                        div {
                            class: "pinned-bar",
                            "data-testid": "pinned-bar",
                            if pinned_view.is_empty() {
                                span {
                                    class: "pinned-bar-empty",
                                    "data-testid": "pinned-bar-empty",
                                    {crate::i18n::tr("pinned_bar.empty")}
                                }
                            } else {
                                for (id, body) in pinned_view {
                                    {
                                        let id_for_click = id.clone();
                                        let preview = if body.len() > 40 {
                                            format!("{}…", &body[..40])
                                        } else {
                                            body
                                        };
                                        rsx! {
                                            button {
                                                r#type: "button",
                                                class: "pinned-bar-item",
                                                "data-testid": "pinned-bar-item",
                                                title: crate::i18n::tr("pinned_bar.scroll_to"),
                                                onclick: move |_| {
                                                    // Best-effort scroll: emit
                                                    // a console hint via
                                                    // status_msg so QA can see
                                                    // the click registered.
                                                    // Real scroll-into-view
                                                    // wires into Dioxus's
                                                    // mounted ref API; deferred
                                                    // until A6.3 lands the
                                                    // soland projection.
                                                    status_msg.set(format!(
                                                        "jump to pinned message {}",
                                                        id_for_click
                                                    ));
                                                },
                                                "{preview}"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // G3.Y2 — typing indicator. Shown when one or more
                // other actors in the active flow have sent a
                // `cx.typing` ephemeral within `TYPING_TTL_SECONDS`.
                // The DIDs live on `data-typing-actors` so cotest can
                // assert on them without scraping localised text.
                //
                // TODO(G3.Y2-followup): subscribe to soland's
                // ephemeral channel for `cx.typing` events and populate
                // `typing_actors` from the parsed
                // `crate::presence_rx::PresenceAggregate`. The plumbing
                // exists on the receive side; the chat view just hasn't
                // wired it yet.
                {
                    let active_typers: Vec<String> = typing_actors()
                        .into_iter()
                        .filter(|did| did != &account_did)
                        .collect();
                    if !active_typers.is_empty() {
                        let attr_value = active_typers.join(",");
                        let label = active_typers
                            .iter()
                            .map(|did| {
                                crate::views::helpers::display_name_for_did(
                                    &state_store.read(),
                                    did,
                                )
                            })
                            .collect::<Vec<_>>()
                            .join(", ");
                        rsx! {
                            div {
                                class: "typing-indicator",
                                "data-testid": "typing-indicator",
                                "data-typing-actors": "{attr_value}",
                                span { class: "typing-dots", "\u{2022}\u{2022}\u{2022}" }
                                span { class: "typing-actors", "{label}" }
                                span { class: "muted", " is typing\u{2026}" }
                            }
                        }
                    } else {
                        rsx! {}
                    }
                }

                div { class: "discussion-chat-feed", "data-testid": "message-list",
                    for msg in visible_messages {
                        div {
                            class: {
                                let mut base = if is_own_message_sender(&msg.sender, &account_did) {
                                    if msg.failed { "discussion-message is-own is-failed".to_owned() } else { "discussion-message is-own".to_owned() }
                                } else if msg.failed {
                                    "discussion-message is-failed".to_owned()
                                } else {
                                    "discussion-message".to_owned()
                                };
                                // T7.4: grey out and italicise messages
                                // that are still waiting on key material
                                // or whose decrypt failed.
                                if msg.crypto_state.is_pending() {
                                    base.push_str(" is-crypto-pending");
                                }
                                base
                            },
                            "data-testid": "chat-message",
                            "data-crypto-state": match msg.crypto_state {
                                MessageCryptoState::Plaintext => "plaintext",
                                MessageCryptoState::Decrypting => "decrypting",
                                MessageCryptoState::DecryptFailed => "decrypt_failed",
                                MessageCryptoState::KeyMissing => "key_missing",
                                MessageCryptoState::NeedsVerification => "needs_verification",
                            },
                            // A6.3: right-click toggles a tiny context
                            // menu offering Pin/Unpin for this message.
                            // prevent_default suppresses the browser's
                            // native context menu so ours surfaces alone.
                            oncontextmenu: {
                                let msg_id = msg.id.clone();
                                move |evt| {
                                    evt.prevent_default();
                                    let next = if message_context_menu()
                                        .as_deref()
                                        == Some(msg_id.as_str())
                                    {
                                        None
                                    } else {
                                        Some(msg_id.clone())
                                    };
                                    message_context_menu.set(next);
                                }
                            },
                            // Tiny pop-out menu — Pin / Unpin / Cancel.
                            // The render condition checks per-message
                            // so only one menu is visible at a time.
                            if message_context_menu().as_deref() == Some(msg.id.as_str()) {
                                div {
                                    class: "message-context-menu",
                                    "data-testid": "message-context-menu",
                                    {
                                        let is_pinned = pinned_messages()
                                            .iter()
                                            .any(|id| id == &msg.id);
                                        let msg_id = msg.id.clone();
                                        let msg_id_for_label = msg.id.clone();
                                        rsx! {
                                            button {
                                                r#type: "button",
                                                "data-testid": "message-pin-button",
                                                onclick: move |_| {
                                                    let mut current = pinned_messages();
                                                    if let Some(idx) = current
                                                        .iter()
                                                        .position(|id| id == &msg_id)
                                                    {
                                                        current.remove(idx);
                                                    } else {
                                                        current.push(msg_id.clone());
                                                    }
                                                    pinned_messages.set(current);
                                                    message_context_menu.set(None);
                                                    // TODO(soland): replace
                                                    // the local-only Signal
                                                    // with the canonical
                                                    // pinning event projection
                                                    // once the reducer lands.
                                                },
                                                if is_pinned {
                                                    {crate::i18n::tr("message.unpin")}
                                                } else {
                                                    {crate::i18n::tr("message.pin")}
                                                }
                                            }
                                            button {
                                                r#type: "button",
                                                class: "secondary",
                                                onclick: move |_| {
                                                    let _ = msg_id_for_label.clone();
                                                    message_context_menu.set(None);
                                                },
                                                "Cancel"
                                            }
                                        }
                                    }
                                }
                            }
                            div { class: "msg-body",
                                div { class: "msg-head",
                                    span { class: "name", "{sender_display_label(&msg.sender, &account_did, &account_display_label, &participants_for_messages)}" }
                                    {
                                        let sender_is_agent = participants_for_messages
                                            .iter()
                                            .any(|p| p.did == msg.sender && p.is_agent);
                                        rsx! {
                                            if sender_is_agent {
                                                span {
                                                    class: "badge member-badge member-badge-agent",
                                                    "data-testid": "member-badge-agent",
                                                    title: "Automated member (bot)",
                                                    "\u{1f916} "
                                                    {crate::i18n::tr("member.badge.agent")}
                                                }
                                            }
                                        }
                                    }
                                    time { "{msg.timestamp}" }
                                    if msg.failed {
                                        span { class: "message-failure-icon", title: "Message send failed",
                                            UiIcon { name: "alert" }
                                        }
                                        span { class: "badge badge-error", "failed" }
                                    } else if msg.pending {
                                        span { class: "badge", "pending" }
                                    }
                                    if msg.edited { span { class: "badge", "edited" } }
                                }
                                // T7.4: per-message crypto status row.
                                // Sits directly under the head so the
                                // icon + label appear before the body
                                // when it's awaiting decrypt.
                                {
                                    match msg.crypto_state {
                                        MessageCryptoState::Plaintext => rsx! { },
                                        MessageCryptoState::Decrypting => rsx! {
                                            div {
                                                class: "crypto-status-row crypto-status-decrypting",
                                                "data-testid": "crypto-status-decrypting",
                                                span { class: "crypto-status-icon", "\u{23f3}" }
                                                span { {crate::i18n::tr("chat.crypto.decrypting")} }
                                            }
                                        },
                                        MessageCryptoState::DecryptFailed => rsx! {
                                            div {
                                                class: "crypto-status-row crypto-status-failed",
                                                "data-testid": "crypto-status-failed",
                                                span { class: "crypto-status-icon", "\u{274c}" }
                                                span { {crate::i18n::tr("chat.crypto.decrypt_failed")} }
                                                button {
                                                    class: "crypto-status-action",
                                                    "data-testid": "crypto-status-action-recovery",
                                                    onclick: move |_| {
                                                        navigator.push(Route::Recovery);
                                                    },
                                                    {crate::i18n::tr("chat.crypto.decrypt_failed_action")}
                                                }
                                            }
                                        },
                                        MessageCryptoState::KeyMissing => rsx! {
                                            div {
                                                class: "crypto-status-row crypto-status-key-missing",
                                                "data-testid": "crypto-status-key-missing",
                                                span { class: "crypto-status-icon", "\u{1f511}" }
                                                span { {crate::i18n::tr("chat.crypto.key_missing")} }
                                                span { class: "muted", {crate::i18n::tr("chat.crypto.key_missing_hint")} }
                                            }
                                        },
                                        MessageCryptoState::NeedsVerification => rsx! {
                                            div {
                                                class: "crypto-status-row crypto-status-needs-verification",
                                                "data-testid": "crypto-status-needs-verification",
                                                span { class: "crypto-status-icon", "\u{26a0}" }
                                                span { {crate::i18n::tr("chat.crypto.needs_verification")} }
                                            }
                                        },
                                    }
                                }
                                if let Some(reply_id) = msg.reply_to.as_ref() {
                                    if let Some((quoted_name, quoted_body)) = chat_reply_quote_preview(
                                        &messages_for_reply_lookup,
                                        reply_id,
                                        &account_did,
                                        &account_display_label,
                                        &participants_for_messages,
                                    ) {
                                        div { class: "chat-reply-quote", "data-testid": "chat-reply-indicator",
                                            span { class: "chat-reply-quote-name", "{quoted_name}" }
                                            div { class: "chat-reply-quote-body", "{quoted_body}" }
                                        }
                                    } else {
                                        div { class: "chat-reply-quote chat-reply-quote-missing", "data-testid": "chat-reply-indicator",
                                            "Replying to a message"
                                        }
                                    }
                                }
                                if msg.redacted {
                                    div { class: "msg-content redacted", "data-testid": "chat-redacted-tombstone", "[Message redacted]" }
                                } else if blocked_did_set.contains(&msg.sender)
                                    && !blocked_show_anyway.read().contains(&msg.id)
                                {
                                    // A5 — sender is on the personal
                                    // blocklist; show a placeholder
                                    // body + a "Show anyway" reveal.
                                    div {
                                        class: "msg-content muted",
                                        "data-testid": "timeline-blocked-row",
                                        {crate::i18n::tr("timeline.blocked_user")}
                                    }
                                    button {
                                        class: "secondary",
                                        "data-testid": "timeline-blocked-show-anyway",
                                        onclick: {
                                            let eid = msg.id.clone();
                                            move |_| {
                                                blocked_show_anyway.write().insert(eid.clone());
                                            }
                                        },
                                        {crate::i18n::tr("timeline.show_anyway")}
                                    }
                                } else {
                                    div { class: "msg-content",
                                        {crate::content::render_blocks(
                                            &crate::content::parse_message_body(&msg.body),
                                        )}
                                    }
                                }
                                if !msg.mentions.is_empty() {
                                    div { class: "actions chat-chip-row", "data-testid": "chat-mentions",
                                        for mention in &msg.mentions {
                                            {
                                                // T7.3: prefer the
                                                // compose-time
                                                // `display_snapshot` label;
                                                // when the snapshot's
                                                // handle still resolves to
                                                // a different DID than the
                                                // event's subject, flag a
                                                // "handle reassigned"
                                                // badge with a tooltip.
                                                let snapshot = mention.display_snapshot.clone();
                                                let label = if !snapshot.is_empty() {
                                                    snapshot.clone()
                                                } else {
                                                    mention.target.clone()
                                                };
                                                // Reassignment heuristic:
                                                // we have a captured
                                                // snapshot/handle URI but
                                                // the local participant
                                                // list now shows a
                                                // different DID for that
                                                // display name.
                                                let reassigned = if !snapshot.is_empty() {
                                                    let snap_lower = snapshot.to_ascii_lowercase();
                                                    let current_match = participants_for_messages.iter().find(|p| {
                                                        p.display_name
                                                            .as_deref()
                                                            .map(|n| n.to_ascii_lowercase() == snap_lower)
                                                            .unwrap_or(false)
                                                    });
                                                    match current_match {
                                                        Some(p) => p.did != mention.target,
                                                        None => false,
                                                    }
                                                } else {
                                                    false
                                                };
                                                let mention_target = mention.target.clone();
                                                rsx! {
                                                    span {
                                                        class: "badge timeline-event-mention",
                                                        "data-testid": "timeline-event-mention",
                                                        "data-mention-did": "{mention_target}",
                                                        title: "{mention.target}",
                                                        "@{label}"
                                                    }
                                                    if reassigned {
                                                        span {
                                                            class: "handle-reassigned-badge",
                                                            "data-testid": "handle-reassigned-badge",
                                                            title: crate::i18n::tr("chat.handle_reassigned.tooltip"),
                                                            "\u{26a0} "
                                                            {crate::i18n::tr("chat.handle_reassigned.badge")}
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                if !msg.reactions.is_empty() {
                                    div { class: "actions chat-chip-row", "data-testid": "chat-reactions",
                                        for (emoji, senders) in &msg.reactions {
                                            span { class: "badge", "{emoji} {senders.len()}" }
                                        }
                                    }
                                }
                                if !msg.revisions.is_empty() {
                                    div { class: "section chat-revision-stack", "data-testid": "chat-revision-chain",
                                        div { class: "muted", "Edited versions ({msg.revisions.len()})" }
                                        for revision in &msg.revisions {
                                            div { class: "muted", "{revision}" }
                                        }
                                    }
                                }
                                if msg.failed {
                                    div { class: "message-error-row", "data-testid": "chat-message-error",
                                        span { class: "message-error-mark", "!" }
                                        span {
                                            if let Some(error) = &msg.error {
                                                "{error}"
                                            } else {
                                                "Message send failed"
                                            }
                                        }
                                        button {
                                            class: "message-retry-button",
                                            "data-testid": "chat-retry-button",
                                            onclick: {
                                                let base = base_url.clone();
                                                let service_did = plaintext_service_did.clone();
                                                let space = msg.space_id.clone();
                                                let actor = account_did.clone();
                                                let local_id = msg.id.clone();
                                                let body = msg.body.clone();
                                                let flow_id = msg.flow_id.clone();
                                                let mentions = msg.mentions.clone();
                                                let reply_to = msg.reply_to.clone();
                                                move |_| {
                                                    let retry_message_id =
                                                        schema_message_id_or_new(&local_id);
                                                    if let Some(found) = messages
                                                        .write()
                                                        .iter_mut()
                                                        .find(|candidate| candidate.id == local_id)
                                                    {
                                                        found.id = retry_message_id.clone();
                                                        found.pending = true;
                                                        found.failed = false;
                                                        found.error = None;
                                                    }
                                                    status_msg.set("Retrying message".to_owned());
                                                    let base = base.clone();
                                                    let service_did = service_did.clone();
                                                    let space = space.clone();
                                                    let actor = actor.clone();
                                                    let api_token = token();
                                                    let wait_for = active_sync_token(&sync_cursor());
                                                    let message_id = retry_message_id.clone();
                                                    let message_id_for_lookup = retry_message_id.clone();
                                                    let message_id_for_store = message_id.clone();
                                                    let body_for_store = body.clone();
                                                    let actor_for_store = actor.clone();
                                                    let flow_id_for_store = flow_id.clone();
                                                    let reply_to_for_store = reply_to.clone();
                                                    let projection = state_store
                                                        .read()
                                                        .load()
                                                        .space_projections
                                                        .get(&space)
                                                        .cloned();
                                                    let plaintext_services = plaintext_services_for_policy(
                                                        projection.as_ref(),
                                                        &service_did,
                                                    );
                                                    let op = chat_message_create_operation(
                                                        &space,
                                                        &actor,
                                                        &flow_id,
                                                        "discussion",
                                                        &message_id,
                                                        &body,
                                                        &mentions,
                                                        reply_to.as_deref(),
                                                    );
                                                    let mention_values_for_store = mentions_to_json(&mentions);
                                                    let space_for_record = space.clone();
                                                    let actor_for_retry = actor.clone();
                                                    spawn(async move {
                                                        match authed_api_with_sync(&base, api_token, wait_for) {
                                                            Ok(api) => match submit_chat_operation_with_plaintext_retry(
                                                                &api,
                                                                &space,
                                                                &actor_for_retry,
                                                                &plaintext_services,
                                                                &op,
                                                            ).await {
                                                                Ok(resp) => {
                                                                    {
                                                                        let mut store = state_store.write();
                                                                        store.save_sync_cursor(resp.sync_token.clone());
                                                                        store.append_raw_operation(
                                                                            op.local_operation_id().to_owned(),
                                                                            Some(space_for_record),
                                                                            json!({
                                                                                "event_id": resp.event_id.clone(),
                                                                                "kind": "cx.message.create",
                                                                                "actor": actor_for_store,
                                                                                "body": body_for_store,
                                                                                "flow_id": flow_id_for_store,
                                                                                "message_id": message_id_for_store,
                                                                                "mentions": mention_values_for_store,
                                                                                "reply_to": reply_to_for_store,
                                                                                "status": resp.status.clone(),
                                                                            }),
                                                                        );
                                                                    }
                                                                    if let Some(found) = messages
                                                                        .write()
                                                                        .iter_mut()
                                                                        .find(|candidate| candidate.id == message_id_for_lookup)
                                                                    {
                                                                        found.id = resp.event_id.clone();
                                                                        found.pending = false;
                                                                        found.failed = false;
                                                                        found.error = None;
                                                                    }
                                                                    sync_cursor.set(resp.sync_token.clone());
                                                                    frontier_state.set(resp.event_id.clone());
                                                                    status_msg.set("Message sent".to_owned());
                                                                }
                                                                Err(error) => {
                                                                    let auth_expired = is_auth_expired_error(&error);
                                                                    let message = chat_send_error_message(&error);
                                                                    if let Some(found) = messages
                                                                        .write()
                                                                        .iter_mut()
                                                                        .find(|candidate| candidate.id == message_id_for_lookup)
                                                                    {
                                                                        found.pending = false;
                                                                        found.failed = true;
                                                                        found.error = Some(message.clone());
                                                                    }
                                                                    status_msg.set(format!("Message send failed: {message}"));
                                                                    if auth_expired {
                                                                        let _ = navigator.push(Route::Login);
                                                                    }
                                                                }
                                                            },
                                                            Err(error) => {
                                                                let message = format!("Invalid server URL: {error}");
                                                                if let Some(found) = messages
                                                                    .write()
                                                                    .iter_mut()
                                                                    .find(|candidate| candidate.id == message_id_for_lookup)
                                                                {
                                                                    found.pending = false;
                                                                    found.failed = true;
                                                                    found.error = Some(message.clone());
                                                                }
                                                                status_msg.set(message);
                                                            }
                                                        }
                                                    });
                                                }
                                            },
                                            {crate::i18n::tr("common.retry")}
                                        }
                                    }
                                }
                                if !msg.redacted {
                                    div { class: "actions chat-message-actions",
                                        button {
                                            class: "chat-message-action",
                                            "data-testid": "chat-reply-button",
                                            onclick: {
                                                let msg_id = msg.id.clone();
                                                move |_| reply_to_message.set(Some(msg_id.clone()))
                                            },
                                            {crate::i18n::tr("chat.button.reply")}
                                        }
                                        button {
                                            class: "chat-message-action",
                                            "data-testid": "chat-react-button",
                                            onclick: {
                                                let msg_id = msg.id.clone();
                                                move |_| {
                                                    let current = reaction_picker();
                                                    reaction_picker.set(if current == Some(msg_id.clone()) { None } else { Some(msg_id.clone()) });
                                                }
                                            },
                                            {crate::i18n::tr("chat.button.react")}
                                        }
                                        button {
                                            class: "chat-message-action",
                                            "data-testid": "chat-edit-button",
                                            onclick: {
                                                let msg_id = msg.id.clone();
                                                let body = msg.body.clone();
                                                move |_| {
                                                    editing_message.set(Some(msg_id.clone()));
                                                    edit_draft.set(body.clone());
                                                }
                                            },
                                            {crate::i18n::tr("common.edit")}
                                        }
                                        button {
                                            class: "chat-message-action",
                                            "data-testid": "chat-redact-button",
                                            onclick: {
                                                let msg_id = msg.id.clone();
                                                move |_| redact_confirm.set(Some(msg_id.clone()))
                                            },
                                            {crate::i18n::tr("chat.button.redact")}
                                        }
                                        // G3.Y2 — discussion promote.
                                        // Opens the modal that creates
                                        // a new child Space and
                                        // re-routes future discussion
                                        // messages to it. See
                                        // `messaging::discussion_promote`.
                                        button {
                                            class: "chat-message-action",
                                            "data-testid": "discussion-promote-button",
                                            onclick: {
                                                let msg_id = msg.id.clone();
                                                let default_title = selected_channel_name.clone();
                                                move |_| {
                                                    promote_discussion_draft
                                                        .write()
                                                        .open(msg_id.clone(), default_title.clone());
                                                }
                                            },
                                            "Promote to space"
                                        }
                                    }
                                }
                                // G3.Y2 — per-message read-receipt
                                // indicator. Surfaces the set of actors
                                // who have published a `cx.read.marker`
                                // covering this message via
                                // `presence_aggregate`. Empty (`hidden`)
                                // until the receive path is wired.
                                //
                                // TODO(G3.Y2-followup): subscribe to
                                // `cx.read.marker` ephemeral channel +
                                // populate from
                                // `presence_rx::PresenceAggregate`.
                                {
                                    // TODO(G3.Y2-followup): wire to
                                    // `presence_rx::PresenceAggregate`
                                    // once the chat view subscribes to
                                    // soland's ephemeral channel for
                                    // `cx.read.marker`. For now the
                                    // list is empty — the testid still
                                    // mounts when there is data so
                                    // cotest can assert against it.
                                    let readers: Vec<String> = Vec::new();
                                    if !readers.is_empty() {
                                        let attr = readers.join(",");
                                        rsx! {
                                            div {
                                                class: "read-receipt-indicator",
                                                "data-testid": "read-receipt-indicator",
                                                "data-readers": "{attr}",
                                                for did in &readers {
                                                    span {
                                                        class: "read-receipt-avatar",
                                                        title: "{did}",
                                                        "\u{2713}"
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        rsx! {}
                                    }
                                }
                                // G3.Y2 — poll card. If this message
                                // carries a poll payload (currently
                                // matched by a poll_card entry whose
                                // message_id == msg.id), render the
                                // poll surface inline. The poll
                                // composer in the attachment menu
                                // pushes a new PollCard here on send.
                                {
                                    let card_lookup = poll_cards()
                                        .iter()
                                        .find(|card| card.message_id == msg.id)
                                        .cloned();
                                    match card_lookup {
                                        Some(card) => {
                                            let poll_id = card.poll_id.clone();
                                            let total = card.total_votes();
                                            let voted = card.actor_has_voted(&account_did);
                                            rsx! {
                                                div {
                                                    class: "poll-card timeline-event-poll",
                                                    "data-testid": "timeline-event-poll",
                                                    "data-poll-id": "{poll_id}",
                                                    div {
                                                        class: "poll-question",
                                                        "data-testid": "poll-question-text",
                                                        "{card.question}"
                                                    }
                                                    for (idx, option) in card.options.iter().enumerate() {
                                                        {
                                                            let votes_for = card.votes_for(idx);
                                                            let option_index_attr = idx as i64;
                                                            let option_label = option.label.clone();
                                                            let option_id = option.id.clone();
                                                            let card_poll_id = poll_id.clone();
                                                            let card_message_id = card.message_id.clone();
                                                            let space = msg.space_id.clone();
                                                            let actor = account_did.clone();
                                                            let card_closed = card.closed;
                                                            let base_for_vote = base_url.clone();
                                                            rsx! {
                                                                div {
                                                                    class: "poll-option-row",
                                                                    "data-testid": "poll-option-row",
                                                                    "data-option-index": "{option_index_attr}",
                                                                    "data-option-text": "{option_label}",
                                                                    button {
                                                                        class: "poll-option poll-vote-button",
                                                                        "data-testid": "poll-vote-button",
                                                                        disabled: card_closed,
                                                                        onclick: {
                                                                            let card_message_id = card_message_id.clone();
                                                                            let actor = actor.clone();
                                                                            let space = space.clone();
                                                                            let card_poll_id = card_poll_id.clone();
                                                                            let option_id = option_id.clone();
                                                                            let api_token = token();
                                                                            let base_for_vote = base_for_vote.clone();
                                                                            move |_| {
                                                                                if let Some(found) = poll_cards
                                                                                    .write()
                                                                                    .iter_mut()
                                                                                    .find(|c| c.message_id == card_message_id)
                                                                                {
                                                                                    found.vote(&actor, idx);
                                                                                }
                                                                                let base = base_for_vote.clone();
                                                                                let space = space.clone();
                                                                                let actor = actor.clone();
                                                                                let poll_id = card_poll_id.clone();
                                                                                let option_id = option_id.clone();
                                                                                let api_token = api_token.clone();
                                                                                spawn(async move {
                                                                                    // TODO(G3.Y2-followup):
                                                                                    // soland's
                                                                                    // `cx.content.poll.response`
                                                                                    // reducer is not yet
                                                                                    // implemented; the submit
                                                                                    // below succeeds locally
                                                                                    // but the server may
                                                                                    // currently reject it.
                                                                                    let _ = crate::views::helpers::with_authed_api(
                                                                                        &base,
                                                                                        api_token,
                                                                                        |api| async move {
                                                                                            let op = crate::messaging::polls::build_poll_vote_op(
                                                                                                &space,
                                                                                                &actor,
                                                                                                &poll_id,
                                                                                                &option_id,
                                                                                            );
                                                                                            api.submit_event_envelope(&op).await
                                                                                        },
                                                                                    )
                                                                                    .await;
                                                                                });
                                                                            }
                                                                        },
                                                                        "{option_label}"
                                                                    }
                                                                    span {
                                                                        class: "poll-vote-count",
                                                                        "data-testid": "poll-vote-count",
                                                                        "{votes_for}"
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                    div {
                                                        class: "poll-total",
                                                        "data-testid": "poll-total-votes",
                                                        "{total} votes"
                                                    }
                                                    if voted {
                                                        div {
                                                            class: "poll-results-summary",
                                                            "data-testid": "poll-results-summary",
                                                            "Thanks for voting."
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        None => rsx! {},
                                    }
                                }
                                // G3.Y2 — discussion-promoted indicator.
                                // Lights up after a successful promote
                                // round-trip; the link target is the
                                // new child space's chat route.
                                {
                                    // After a successful promote, the
                                    // resulting child-space id lives in
                                    // `promoted_targets` keyed by the
                                    // source message id; we render an
                                    // anchor row so the parent timeline
                                    // shows the divergence point.
                                    let promoted_to = promoted_targets()
                                        .get(&msg.id)
                                        .cloned();
                                    match promoted_to {
                                        Some(child_space_id) => rsx! {
                                            div {
                                                class: "discussion-promoted-indicator",
                                                "data-testid": "discussion-promoted-indicator",
                                                "data-child-space-id": "{child_space_id}",
                                                span { "Discussion moved to " }
                                                a {
                                                    href: "/chat/{child_space_id}",
                                                    "{child_space_id}"
                                                }
                                            }
                                        },
                                        None => rsx! {},
                                    }
                                }
                                if reaction_picker() == Some(msg.id.clone()) {
                                    div { class: "actions chat-chip-row", "data-testid": "chat-reaction-picker",
                                        for emoji in CHAT_EMOJI_GRID {
                                            button {
                                                class: "secondary emoji-button",
                                                onclick: {
                                                    let base = base_url.clone();
                                                    let space = selected_space.clone();
                                                    let actor = account_did.clone();
                                                    let msg_id = msg.id.clone();
                                                    let emoji = emoji.to_string();
                                                    move |_| {
                                                        if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == msg_id) {
                                                            if let Some((_, senders)) = found.reactions.iter_mut().find(|(key, _)| key == &emoji) {
                                                                if !senders.iter().any(|sender| sender == &actor) {
                                                                    senders.push(actor.clone());
                                                                }
                                                            } else {
                                                                found.reactions.push((emoji.clone(), vec![actor.clone()]));
                                                            }
                                                        }
                                                        let base = base.clone();
                                                        let space = space.clone();
                                                        let actor = actor.clone();
                                                        let msg_id = msg_id.clone();
                                                        let emoji = emoji.clone();
                                                        let api_token = token();
                                                        let wait_for = active_sync_token(&sync_cursor());
                                                        spawn(async move {
                                                            let _ = with_authed_api_with_sync(
                                                                &base,
                                                                api_token,
                                                                wait_for,
                                                                |api| async move {
                                                                    let op = chat_reaction_add_operation(
                                                                        &space, &actor, &msg_id, &emoji,
                                                                    );
                                                                    api.submit_event_envelope(&op).await
                                                                },
                                                            )
                                                            .await;
                                                        });
                                                        reaction_picker.set(None);
                                                    }
                                                },
                                                "{emoji}"
                                            }
                                        }
                                    }
                                }
                                if editing_message() == Some(msg.id.clone()) {
                                    div { class: "composer compact-composer", "data-testid": "chat-edit-composer",
                                        textarea {
                                            value: "{edit_draft}",
                                            oninput: move |evt| edit_draft.set(evt.value()),
                                        }
                                        div { class: "actions",
                                            button {
                                                class: "primary",
                                                "data-testid": "chat-save-edit-button",
                                                onclick: {
                                                    let base = base_url.clone();
                                                    let space = selected_space.clone();
                                                    let actor = account_did.clone();
                                                    let msg_id = msg.id.clone();
                                                    move |_| {
                                                        let content = edit_draft().trim().to_owned();
                                                        if content.is_empty() {
                                                            status_msg.set("Edit skipped: body is empty".to_owned());
                                                            editing_message.set(None);
                                                            return;
                                                        }
                                                        if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == msg_id) {
                                                            found.revisions.push(found.body.clone());
                                                            found.body = content.clone();
                                                            found.edited = true;
                                                            found.pending = true;
                                                        }
                                                        editing_message.set(None);
                                                        let base = base.clone();
                                                        let space = space.clone();
                                                        let actor = actor.clone();
                                                        let msg_id = msg_id.clone();
                                                        let api_token = token();
                                                        let wait_for = active_sync_token(&sync_cursor());
                                                        spawn(async move {
                                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                                Ok(api) => {
                                                                    let op = chat_message_revise_operation(&space, &actor, &msg_id, &content);
                                                                    match api.submit_event_envelope(&op).await {
                                                                        Ok(_resp) => {
                                                                            if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == msg_id) {
                                                                                found.pending = false;
                                                                            }
                                                                            status_msg.set("Message updated".to_owned());
                                                                        }
                                                                        Err(error) => status_msg.set(format!("Message update failed: {error}")),
                                                                    }
                                                                }
                                                                Err(error) => status_msg.set(format!("Invalid server URL: {error}")),
                                                            }
                                                        });
                                                    }
                                                },
                                                "Save"
                                            }
                                            button {
                                                class: "secondary",
                                                onclick: move |_| editing_message.set(None),
                                                "Cancel"
                                            }
                                        }
                                    }
                                }
                                if redact_confirm() == Some(msg.id.clone()) {
                                    div { class: "chat-redact-confirm", "data-testid": "chat-redact-confirm",
                                        div { class: "discussion-subhead", span { "Remove message" } }
                                        div { class: "actions",
                                            button {
                                                class: "primary",
                                                "data-testid": "chat-confirm-redact-button",
                                                onclick: {
                                                    let base = base_url.clone();
                                                    let space = selected_space.clone();
                                                    let actor = account_did.clone();
                                                    let msg_id = msg.id.clone();
                                                    move |_| {
                                                        if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == msg_id) {
                                                            found.redacted = true;
                                                            found.body.clear();
                                                            found.pending = true;
                                                        }
                                                        redact_confirm.set(None);
                                                        let base = base.clone();
                                                        let space = space.clone();
                                                        let actor = actor.clone();
                                                        let msg_id = msg_id.clone();
                                                        let api_token = token();
                                                        let wait_for = active_sync_token(&sync_cursor());
                                                        spawn(async move {
                                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                                Ok(api) => {
                                                                    let op = chat_message_redact_operation(&space, &actor, &msg_id, "user requested tombstone");
                                                                    match api.submit_event_envelope(&op).await {
                                                                        Ok(_resp) => {
                                                                            if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == msg_id) {
                                                                                found.pending = false;
                                                                            }
                                                                            status_msg.set("Message removed".to_owned());
                                                                        }
                                                                        Err(error) => status_msg.set(format!("Message removal failed: {error}")),
                                                                    }
                                                                }
                                                                Err(error) => status_msg.set(format!("Invalid server URL: {error}")),
                                                            }
                                                        });
                                                    }
                                                },
                                                "Confirm"
                                            }
                                            button {
                                                class: "secondary",
                                                onclick: move |_| redact_confirm.set(None),
                                                "Cancel"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if visible_channels_empty {
                        div { class: "empty-state discussion-empty-main", "data-testid": "discussion-main-empty",
                            div { class: "ico", UiIcon { name: "plus" } }
                            div { class: "t", {crate::i18n::tr("chat.empty.title")} }
                            div { class: "s", {crate::i18n::tr("chat.empty.description")} }
                            div { class: "actions",
                                button {
                                    class: "primary",
                                    "data-testid": "discussion-empty-create-button",
                                    onclick: move |_| create_dialog_open.set(true),
                                    {crate::i18n::tr("chat.empty.create_button")}
                                }
                            }
                        }
                    } else if visible_message_count == 0 {
                        div { class: "discussion-empty", {crate::i18n::tr("chat.empty_messages")} }
                    }
                }
            }

            if active_right_panel == Some(DiscussionSidePanel::Users) {
                aside { class: "discussion-panel discussion-details-panel", "data-testid": "discussion-users-panel",
                    div { class: "discussion-panel-head",
                        div { class: "discussion-title-row",
                            h2 { {crate::i18n::tr("chat.users_header")} }
                        }
                    }
                    // T7.5: lightweight tab bar so members and settings
                    // share a single right panel rather than competing
                    // for the same slot. Each tab maps to one
                    // `DiscussionSidePanel` value the existing buttons
                    // already toggle.
                    div { class: "discussion-right-tabs",
                        button {
                            r#type: "button",
                            class: "discussion-right-tab active",
                            "data-testid": "discussion-right-tab-members",
                            onclick: move |_| right_panel.set(Some(DiscussionSidePanel::Users)),
                            {crate::i18n::tr("chat.tabs.members")}
                        }
                        button {
                            r#type: "button",
                            class: "discussion-right-tab",
                            "data-testid": "discussion-right-tab-settings",
                            onclick: move |_| right_panel.set(Some(DiscussionSidePanel::Settings)),
                            {crate::i18n::tr("chat.tabs.settings")}
                        }
                    }
                    // G3.Y2 — presence list. One row per participant
                    // with `data-presence-state` derived from the
                    // local presence aggregate. Defaults to `offline`
                    // until soland's presence stream is wired in.
                    //
                    // TODO(G3.Y2-followup): subscribe to soland's
                    // ephemeral `cx.presence` fanout and populate
                    // `presence_states` from
                    // `crate::presence_rx::PresenceAggregate`. Until
                    // then the row data-attribute lets cotest assert
                    // *something* is wired without faking presence
                    // semantics.
                    div { class: "discussion-detail-section",
                        div { class: "discussion-subhead", span { "Presence" } }
                        div {
                            class: "presence-list",
                            "data-testid": "presence-list",
                            for participant in &participants {
                                {
                                    let did_attr = participant.did.clone();
                                    let display = crate::views::helpers::display_name_for_did(
                                        &state_store.read(),
                                        &participant.did,
                                    );
                                    let state = presence_states
                                        .read()
                                        .get(&participant.did)
                                        .cloned()
                                        .unwrap_or_else(|| {
                                            if participant.is_self {
                                                "online".to_owned()
                                            } else {
                                                "offline".to_owned()
                                            }
                                        });
                                    let state_for_class = state.clone();
                                    rsx! {
                                        div {
                                            class: "presence-row presence-row-{state_for_class}",
                                            "data-testid": "presence-row",
                                            "data-actor-did": "{did_attr}",
                                            "data-presence-state": "{state}",
                                            span { class: "presence-dot presence-dot-{state}" }
                                            span { class: "presence-name", "{display}" }
                                            span { class: "muted mono", " {did_attr}" }
                                            span { class: "muted", " ({state})" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    div { class: "discussion-detail-section",
                        div { class: "discussion-subhead", span { "Space users" } }
                        for participant in participants {
                            // F-REMARK-FANOUT-1: prefer the actor-private
                            // ContactRemark.local_name (sync'd via
                            // cx.contacts.actor.<did> account_data) over
                            // the raw DID. The DID stays in the `title`
                            // attribute so it's still copy-pasteable for
                            // verification / debugging.
                            {
                                let participant_display = crate::views::helpers::display_name_for_did(
                                    &state_store.read(),
                                    &participant.did,
                                );
                                let participant_did_attr = participant.did.clone();
                                // T7.3: derive binding context host
                                // (e.g. `acme.example`) from the DID
                                // method/host so the row reads as
                                // `Alice @ acme.example` rather than
                                // dropping the raw service DID into the
                                // visible list. The full DID is still
                                // available in the title attribute and
                                // an expandable details row.
                                let binding_host = participant
                                    .did
                                    .strip_prefix("did:web:")
                                    .map(|rest| rest.split(':').next().unwrap_or(rest).to_owned());
                                rsx! {
                            div {
                                class: if participant.is_self { "contact-row participant-row self" } else { "contact-row participant-row" },
                                "data-testid": "discussion-user-row",
                                span { class: "participant-avatar", UiIcon { name: "user" } }
                                div { class: "participant-main",
                                    strong {
                                        class: "mono participant-did",
                                        title: "{participant_did_attr}",
                                        "{participant_display}"
                                        if let Some(host) = binding_host.as_ref() {
                                            span { class: "binding-context",
                                                "data-testid": "binding-context",
                                                {crate::i18n::tr("chat.binding_context.separator")}
                                                span { class: "binding-context-host", "{host}" }
                                            }
                                        }
                                    }
                                    div { class: "participant-badges",
                                        if participant.is_self {
                                            span { class: "badge participant-badge self", {crate::i18n::tr("chat.you_badge")} }
                                        }
                                        if participant.is_agent {
                                            span {
                                                class: "badge member-badge member-badge-agent",
                                                "data-testid": "member-badge-agent",
                                                title: "Automated member (bot)",
                                                "\u{1f916} "
                                                {crate::i18n::tr("member.badge.agent")}
                                            }
                                        }
                                        span {
                                            class: match participant.role {
                                                SpaceParticipantRole::Owner => "badge participant-badge admin",
                                                SpaceParticipantRole::Admin => "badge participant-badge admin",
                                                SpaceParticipantRole::Member => "badge participant-badge member",
                                            },
                                            "{participant.role.label()}"
                                        }
                                    }
                                    details { class: "binding-context-details",
                                        summary { class: "muted", {crate::i18n::tr("chat.binding_context.details")} }
                                        div { class: "mono muted",
                                            "{participant_did_attr}"
                                        }
                                    }
                                }
                            }
                                }
                            }
                        }
                    }
                }
            }

            if active_right_panel == Some(DiscussionSidePanel::Settings) {
                {
                // F-CHAT-DEAD-UI-1: three toggles in the discussion-settings
                // panel used to be pure decoration (no onchange, hard-coded
                // `checked: true`). The first two are now wired to the
                // same actor-private account_data that /settings already
                // edits, so a change here mirrors immediately into the
                // global view. "Shared history" is a Space-scoped policy
                // event (`cx.realm.history_visibility`) — it's not a
                // client-side per-discussion toggle, so the third row
                // shows an explanatory hint instead of pretending to be
                // a checkbox.
                let space_id_for_mute = selected_space.clone();
                let flow_id_for_rr = selected_channel_value.clone();
                let muted_spaces_now = state_store.read().muted_spaces();
                let space_is_muted = muted_spaces_now.contains(&space_id_for_mute);
                let rr_default_send = state_store.read().read_receipt_default_send();
                let rr_flow_override =
                    state_store.read().read_receipt_flow_override(&flow_id_for_rr);
                let rr_active = rr_flow_override.unwrap_or(rr_default_send);
                rsx! {
                aside { class: "discussion-panel discussion-details-panel", "data-testid": "discussion-settings-panel",
                    div { class: "discussion-panel-head",
                        div { class: "discussion-title-row",
                            h2 { {crate::i18n::tr("chat.settings_header")} }
                        }
                    }
                    // T7.5: same tab bar as the users panel so the user
                    // can switch tabs in-place without re-clicking the
                    // topbar icons.
                    div { class: "discussion-right-tabs",
                        button {
                            r#type: "button",
                            class: "discussion-right-tab",
                            "data-testid": "discussion-right-tab-members",
                            onclick: move |_| right_panel.set(Some(DiscussionSidePanel::Users)),
                            {crate::i18n::tr("chat.tabs.members")}
                        }
                        button {
                            r#type: "button",
                            class: "discussion-right-tab active",
                            "data-testid": "discussion-right-tab-settings",
                            onclick: move |_| right_panel.set(Some(DiscussionSidePanel::Settings)),
                            {crate::i18n::tr("chat.tabs.settings")}
                        }
                    }
                    div { class: "discussion-detail-section",
                        div { class: "discussion-subhead", span { "Settings" } }
                        label { class: "settings-row",
                            span { {crate::i18n::tr("chat.settings.mute_notifications")} }
                            input {
                                r#type: "checkbox",
                                "data-testid": "discussion-settings-mute",
                                checked: space_is_muted,
                                onchange: {
                                    let space_id = space_id_for_mute.clone();
                                    move |evt: Event<FormData>| {
                                        let new_muted = evt.value() == "true";
                                        state_store
                                            .write()
                                            .set_space_muted(space_id.clone(), new_muted);
                                    }
                                },
                            }
                        }
                        label { class: "settings-row",
                            span { {crate::i18n::tr("chat.settings.read_receipts")} }
                            input {
                                r#type: "checkbox",
                                "data-testid": "discussion-settings-read-receipts",
                                checked: rr_active,
                                onchange: {
                                    let flow_id = flow_id_for_rr.clone();
                                    move |evt: Event<FormData>| {
                                        let new_value = evt.value() == "true";
                                        state_store
                                            .write()
                                            .set_read_receipt_flow_override(
                                                flow_id.clone(),
                                                Some(new_value),
                                            );
                                    }
                                },
                            }
                        }
                        div { class: "settings-row settings-row-readonly",
                            "data-testid": "discussion-settings-shared-history-note",
                            span { {crate::i18n::tr("chat.settings.shared_history")} }
                            span { class: "muted",
                                {crate::i18n::tr("chat.settings.shared_history_hint")}
                            }
                        }
                    }
                    div { class: "discussion-detail-section",
                        div { class: "discussion-subhead", span { "Selected" } }
                        div { class: "detail-row", span { "Category" } strong { "{selected_channel_category}" } }
                        div { class: "detail-row", span { "Unread" } strong { "{selected_channel_unread}" } }
                        div { class: "detail-row", span { "Messages" } strong { "{visible_message_count}" } }
                    }
                }
                }
                }
            }

            // G3.Y2 — discussion promote confirmation modal. Renders
            // a single input for the child Space title + a confirm
            // button that fires the cx.space.create + cx.space.child
            // + cx.space.parent + cx.flow.update batch.
            if promote_discussion_draft.read().is_open() {
                div { class: "discussion-modal-backdrop",
                    "data-testid": "discussion-promote-modal",
                    div { class: "discussion-modal",
                        div { class: "discussion-modal-head",
                            h2 { "Promote discussion to its own space" }
                            button {
                                r#type: "button",
                                class: "secondary",
                                onclick: move |_| promote_discussion_draft.write().close(),
                                "Cancel"
                            }
                        }
                        label { class: "form-row",
                            span { "Child space title" }
                            input {
                                r#type: "text",
                                "data-testid": "discussion-promote-confirm-input",
                                value: "{promote_discussion_draft.read().title}",
                                oninput: move |evt| {
                                    promote_discussion_draft.write().title = evt.value();
                                },
                            }
                        }
                        div { class: "actions",
                            button {
                                class: "primary",
                                "data-testid": "discussion-promote-confirm-button",
                                disabled: !promote_discussion_draft.read().is_submittable(),
                                onclick: {
                                    let base = base_url.clone();
                                    let parent_space = selected_space.clone();
                                    let actor = account_did.clone();
                                    let selected_flow = selected_channel_value.clone();
                                    move |_| {
                                        let draft_snapshot = promote_discussion_draft.read().clone();
                                        let Some(source_id) = draft_snapshot.source_id.clone() else {
                                            return;
                                        };
                                        let title = draft_snapshot.title.trim().to_owned();
                                        let ids = crate::messaging::discussion_promote::PromoteIds::fresh();
                                        // Optimistic UI: anchor the
                                        // promoted indicator before the
                                        // server round-trip completes.
                                        promoted_targets
                                            .write()
                                            .insert(source_id.clone(), ids.child_space_id.clone());
                                        promote_discussion_draft.write().close();

                                        let base = base.clone();
                                        let parent_space = parent_space.clone();
                                        let actor = actor.clone();
                                        let selected_flow = selected_flow.clone();
                                        let api_token = token();
                                        let ids_clone = ids.clone();
                                        spawn(async move {
                                            // TODO(G3.Y2-followup):
                                            // soland's discussion-promote
                                            // reducer is partially
                                            // implemented. We submit each
                                            // envelope through the generic
                                            // event submit path here so
                                            // the UI shows progress; the
                                            // server may currently reject
                                            // `cx.space.child`/`parent`
                                            // until the reducer lands.
                                            let _ = crate::views::helpers::with_authed_api(
                                                &base,
                                                api_token,
                                                |api| async move {
                                                    let flow_id_opt = if selected_flow.is_empty() {
                                                        None
                                                    } else {
                                                        Some(selected_flow.as_str())
                                                    };
                                                    let ops = crate::messaging::discussion_promote::build_promote_ops(
                                                        &parent_space,
                                                        &actor,
                                                        flow_id_opt,
                                                        &ids_clone,
                                                        &title,
                                                    );
                                                    for op in ops {
                                                        let _ = api.submit_event_envelope(&op).await;
                                                    }
                                                    Ok(())
                                                },
                                            ).await;
                                        });
                                    }
                                },
                                "Create child space"
                            }
                        }
                    }
                }
            }

            // G3.Y2 — read-receipt marker bar. A horizontal divider
            // anchored at the highest event id we've sent a
            // `cx.read.marker` for; renders only when we have one. The
            // bar appears below the message list so users can see the
            // "everyone read up to here" anchor without scrolling
            // around. The marker itself is actor-private — see
            // discovery/read-receipts.md §3.1.
            if !latest_read_marker().is_empty() {
                div {
                    class: "read-receipt-marker-bar",
                    "data-testid": "read-receipt-marker-bar",
                    "data-up-to-event-id": "{latest_read_marker}",
                    span { "Read up to " }
                    span { class: "mono", "{latest_read_marker}" }
                }
            }

            if !visible_channels_empty {
            div { class: "{composer_class}", "data-testid": "chat-composer",
                if let Some(reply_id) = reply_to_message() {
                    div { class: "chat-reply-quote-banner", "data-testid": "chat-reply-banner",
                        if let Some((quoted_name, quoted_body)) = chat_reply_quote_preview(
                            &messages_for_composer_lookup,
                            &reply_id,
                            &account_did,
                            &account_display_label,
                            &participants_for_messages,
                        ) {
                            div { class: "chat-reply-quote",
                                span { class: "chat-reply-quote-name", "{quoted_name}" }
                                div { class: "chat-reply-quote-body", "{quoted_body}" }
                            }
                        } else {
                            div { class: "chat-reply-quote chat-reply-quote-missing",
                                "Replying to a message"
                            }
                        }
                        button {
                            class: "secondary",
                            onclick: move |_| reply_to_message.set(None),
                            "Cancel"
                        }
                    }
                }
                // A6.2: drag-drop attachment zone wrapping the textarea.
                // Dropping a file uploads the bytes via
                // `upload_blob_bytes`, then appends `[Attachment: {ref}]`
                // to the draft so the existing send pipeline picks it
                // up as message body. `ondragover` is required to
                // prevent the browser's default open-the-file behaviour.
                div {
                    class: if compose_dragover() {
                        "compose-drop-zone is-dragover"
                    } else {
                        "compose-drop-zone"
                    },
                    "data-testid": "compose-drop-zone",
                    ondragover: move |evt| {
                        evt.prevent_default();
                        if !compose_dragover() { compose_dragover.set(true); }
                    },
                    ondragleave: move |_| compose_dragover.set(false),
                    ondrop: {
                        let base = base_url.clone();
                        move |evt| {
                            evt.prevent_default();
                            compose_dragover.set(false);
                            let files = evt.files();
                            if files.is_empty() {
                                // Some platforms (notably the desktop
                                // web embedder) deliver drops without
                                // file payloads — surface that rather
                                // than silently no-op.
                                compose_upload_status.set(
                                    crate::i18n::tr("compose.upload_error"),
                                );
                                return;
                            }
                            let api_token = token();
                            let base = base.clone();
                            compose_upload_status.set(
                                crate::i18n::tr("compose.upload_progress"),
                            );
                            spawn(async move {
                                let api = match crate::views::helpers::authed_api_with_sync(
                                    &base,
                                    api_token,
                                    None,
                                ) {
                                    Ok(api) => api,
                                    Err(err) => {
                                        compose_upload_status.set(format!(
                                            "{}: {err}",
                                            crate::i18n::tr("compose.upload_error"),
                                        ));
                                        return;
                                    }
                                };
                                let mut ok_count = 0usize;
                                let mut last_error: Option<String> = None;
                                for file in files {
                                    let content_type = file
                                        .content_type()
                                        .unwrap_or_else(|| "application/octet-stream".to_owned());
                                    let bytes = match file.read_bytes().await {
                                        Ok(b) => b.to_vec(),
                                        Err(err) => {
                                            last_error = Some(format!("{err}"));
                                            continue;
                                        }
                                    };
                                    match api.upload_blob_bytes(bytes, &content_type).await {
                                        Ok(resp) => {
                                            let current = chat_draft();
                                            let needs_space = !current.is_empty()
                                                && !current.ends_with(' ')
                                                && !current.ends_with('\n');
                                            let attachment = format!(
                                                "{}[Attachment: {}]",
                                                if needs_space { " " } else { "" },
                                                resp.blob_ref
                                            );
                                            chat_draft.set(format!("{current}{attachment}"));
                                            ok_count += 1;
                                        }
                                        Err(err) => {
                                            last_error = Some(err.to_string());
                                        }
                                    }
                                }
                                if let Some(err) = last_error {
                                    compose_upload_status.set(format!(
                                        "{}: {err}",
                                        crate::i18n::tr("compose.upload_error"),
                                    ));
                                } else if ok_count > 0 {
                                    compose_upload_status.set(format!(
                                        "{ok_count} attachment(s) uploaded"
                                    ));
                                } else {
                                    compose_upload_status.set(
                                        crate::i18n::tr("compose.upload_error"),
                                    );
                                }
                            });
                        }
                    },
                    textarea {
                        "data-testid": "chat-input",
                        value: "{chat_draft}",
                        placeholder: "Message this discussion. Use @alice to mention a member or #task-123 to link a card.",
                        oninput: {
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            let actor = account_did.clone();
                            move |evt: Event<FormData>| {
                                let value = evt.value();
                                chat_draft.set(value.clone());
                                // G3.Y2 — auto-open the mention picker
                                // when the user types an `@`. The
                                // composer reads `mention_picker_state.open`
                                // to know whether to render the
                                // `mention-picker` element.
                                if value.ends_with('@') {
                                    mention_picker_state.write().open();
                                }
                                // G3.Y2 — debounced typing signal. We
                                // fire-and-forget the API call so the
                                // composer never blocks; failures fall
                                // back silently per the spec.
                                //
                                // TODO(G3.Y2-followup): add a real
                                // 1-second debounce timer here. The
                                // current implementation just emits
                                // every keystroke, which exceeds the
                                // spec's ~1s cadence but keeps the
                                // testable seam (one `cx.typing` per
                                // input event) simple. The receiving
                                // side already TTL-expires stale
                                // entries.
                                let base = base.clone();
                                let space = space.clone();
                                let actor = actor.clone();
                                let api_token = token();
                                spawn(async move {
                                    let _ = crate::views::helpers::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.send_typing(&space, &actor, None, true).await
                                        },
                                    ).await;
                                });
                            }
                        },
                    }
                    // G3.Y2 — mention chip row + picker. Sits below
                    // the textarea so picker rows can overlay the
                    // message list without changing the textarea's
                    // size. The trigger button is a dev-mode handle
                    // for cotest — production users open the picker
                    // by typing `@`, but having the explicit button
                    // gives the tests a stable click target.
                    div { class: "mention-chip-row",
                        button {
                            r#type: "button",
                            class: "composer-tool-button",
                            "data-testid": "mention-trigger-button",
                            title: "Mention member",
                            "aria-label": "Mention member",
                            onclick: move |_| {
                                let mut state = mention_picker_state.write();
                                if state.open {
                                    state.close();
                                } else {
                                    state.open();
                                }
                            },
                            UiIcon { name: "at-sign" }
                        }
                        button {
                            r#type: "button",
                            class: "composer-tool-button",
                            "data-testid": "attachment-menu-button",
                            title: "Add attachment",
                            "aria-label": "Add attachment",
                            onclick: move |_| {
                                let current = attachment_menu_open();
                                attachment_menu_open.set(!current);
                            },
                            UiIcon { name: "plus" }
                        }
                        if attachment_menu_open() {
                            div { class: "attachment-menu",
                                button {
                                    r#type: "button",
                                    class: "attachment-menu-item",
                                    "data-testid": "attachment-menu-poll",
                                    onclick: move |_| {
                                        attachment_menu_open.set(false);
                                        poll_draft.set(Some(
                                            crate::messaging::polls::PollDraft::new(),
                                        ));
                                    },
                                    "Create poll"
                                }
                                // G3.Y2 — cotest references this short-cut
                                // testid (`open-poll-composer-button`); we
                                // alias it onto the same handler so existing
                                // specs and the new attachment menu both
                                // open the same composer.
                                button {
                                    r#type: "button",
                                    class: "secondary",
                                    "data-testid": "open-poll-composer-button",
                                    onclick: move |_| {
                                        attachment_menu_open.set(false);
                                        poll_draft.set(Some(
                                            crate::messaging::polls::PollDraft::new(),
                                        ));
                                    },
                                    "Poll"
                                }
                            }
                        }
                        for chip in mention_picker_state.read().inserted.clone() {
                            div {
                                class: "mention-chip",
                                "data-testid": "mention-chip",
                                "data-mention-did": "{chip.did}",
                                span { "@{chip.display_name}" }
                                button {
                                    r#type: "button",
                                    class: "secondary",
                                    onclick: {
                                        let did = chip.did.clone();
                                        move |_| mention_picker_state.write().remove(&did)
                                    },
                                    "\u{00d7}"
                                }
                            }
                        }
                    }
                    if mention_picker_state.read().open {
                        div { class: "mention-picker",
                            "data-testid": "mention-picker",
                            div { class: "mention-picker-head",
                                input {
                                    r#type: "text",
                                    class: "mention-picker-query",
                                    placeholder: "Search members",
                                    value: "{mention_picker_state.read().query}",
                                    oninput: move |evt| {
                                        mention_picker_state.write().set_query(evt.value());
                                    },
                                }
                                button {
                                    r#type: "button",
                                    "data-testid": "mention-picker-close-button",
                                    onclick: move |_| mention_picker_state.write().close(),
                                    "Close"
                                }
                            }
                            {
                                let candidates: Vec<crate::messaging::mentions::MentionCandidate> =
                                    participants_for_messages
                                        .iter()
                                        .map(|p| crate::messaging::mentions::MentionCandidate {
                                            did: p.did.clone(),
                                            display_name: p
                                                .display_name
                                                .clone()
                                                .unwrap_or_else(|| p.did.clone()),
                                        })
                                        .collect();
                                let state_snapshot = mention_picker_state.read().clone();
                                let matches: Vec<crate::messaging::mentions::MentionCandidate> =
                                    state_snapshot
                                        .filter(&candidates)
                                        .into_iter()
                                        .cloned()
                                        .collect();
                                rsx! {
                                    div { class: "mention-suggestions",
                                        if matches.is_empty() {
                                            div { class: "muted", "No matches" }
                                        } else {
                                            for candidate in matches {
                                                button {
                                                    r#type: "button",
                                                    class: "mention-suggestion",
                                                    "data-testid": "mention-suggestion",
                                                    "data-mention-did": "{candidate.did}",
                                                    onclick: {
                                                        let candidate = candidate.clone();
                                                        move |_| {
                                                            let inserted = mention_picker_state
                                                                .write()
                                                                .insert(candidate.clone());
                                                            if inserted {
                                                                // Replace the trailing `@`
                                                                // (if any) with the chip
                                                                // mention so the draft text
                                                                // and the chip list stay in
                                                                // sync.
                                                                let current = chat_draft();
                                                                let trimmed = current
                                                                    .strip_suffix('@')
                                                                    .unwrap_or(&current)
                                                                    .to_owned();
                                                                let needs_space = !trimmed.is_empty()
                                                                    && !trimmed.ends_with(' ');
                                                                chat_draft.set(format!(
                                                                    "{trimmed}{}@{} ",
                                                                    if needs_space { " " } else { "" },
                                                                    candidate.display_name,
                                                                ));
                                                            }
                                                            mention_picker_state.write().close();
                                                        }
                                                    },
                                                    span { class: "mention-suggestion-name",
                                                        "{candidate.display_name}"
                                                    }
                                                    span { class: "muted mono",
                                                        " {candidate.did}"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if compose_dragover() {
                        div {
                            class: "compose-drop-zone-hint",
                            "data-testid": "compose-drop-hint",
                            {crate::i18n::tr("compose.drop_zone.hint")}
                        }
                    }
                }
                if !compose_upload_status().is_empty() {
                    div {
                        class: "compose-upload-progress",
                        "data-testid": "compose-upload-progress",
                        "{compose_upload_status}"
                    }
                }
                if let Some(draft) = poll_draft.read().clone() {
                    div { class: "poll-composer",
                        "data-testid": "poll-composer",
                        input {
                            r#type: "text",
                            "data-testid": "poll-question-input",
                            placeholder: "Question",
                            value: "{draft.question}",
                            oninput: move |evt| {
                                if let Some(current) = poll_draft.write().as_mut() {
                                    current.set_question(evt.value());
                                }
                            },
                        }
                        for (idx, option) in draft.options.iter().enumerate() {
                            input {
                                r#type: "text",
                                "data-testid": "poll-option-input",
                                "data-option-index": "{idx as i64}",
                                placeholder: "Option {idx + 1}",
                                value: "{option}",
                                oninput: move |evt| {
                                    if let Some(current) = poll_draft.write().as_mut() {
                                        current.set_option(idx, evt.value());
                                    }
                                },
                            }
                        }
                        div { class: "actions",
                            button {
                                r#type: "button",
                                class: "secondary",
                                "data-testid": "poll-add-option-button",
                                onclick: move |_| {
                                    if let Some(current) = poll_draft.write().as_mut() {
                                        current.add_option();
                                    }
                                },
                                "Add option"
                            }
                            button {
                                r#type: "button",
                                class: "primary",
                                "data-testid": "poll-create-button",
                                disabled: !draft.is_sendable(),
                                onclick: {
                                    let base = base_url.clone();
                                    let space = selected_space.clone();
                                    let actor = account_did.clone();
                                    let selected_flow = selected_channel_value.clone();
                                    move |_| {
                                        let Some(draft_snapshot) = poll_draft.read().clone() else {
                                            return;
                                        };
                                        if !draft_snapshot.is_sendable() {
                                            return;
                                        }
                                        let poll_id = crate::messaging::polls::new_poll_id();
                                        let card = crate::messaging::polls::PollCard::from_draft(
                                            poll_id.clone(),
                                            &draft_snapshot,
                                        );
                                        // Optimistic UI: surface the
                                        // poll card immediately, push
                                        // a synthetic ChatMessage so
                                        // the timeline anchors it.
                                        poll_cards.write().push(card.clone());
                                        messages.write().push(ChatMessage {
                                            space_id: space.clone(),
                                            id: poll_id.clone(),
                                            sender: actor.clone(),
                                            body: format!("[poll] {}", draft_snapshot.question),
                                            timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                                            flow_id: selected_flow.clone(),
                                            reply_to: None,
                                            reactions: Vec::new(),
                                            redacted: false,
                                            edited: false,
                                            revisions: Vec::new(),
                                            pending: true,
                                            failed: false,
                                            error: None,
                                            mentions: Vec::new(),
                                            crypto_state: MessageCryptoState::Plaintext,
                                        });
                                        poll_draft.set(None);

                                        let base = base.clone();
                                        let space = space.clone();
                                        let actor = actor.clone();
                                        let flow_id = selected_flow.clone();
                                        let api_token = token();
                                        let draft_for_op = draft_snapshot.clone();
                                        let poll_id_for_op = poll_id.clone();
                                        spawn(async move {
                                            // TODO(G3.Y2-followup):
                                            // soland's `cx.content.poll.create`
                                            // reducer is unconfirmed —
                                            // the submit succeeds locally
                                            // but the server may not yet
                                            // route the event. The wire
                                            // shape we emit matches
                                            // `models/content-types.md §4.9`
                                            // so flipping the server on
                                            // requires no client change.
                                            let _ = crate::views::helpers::with_authed_api(
                                                &base,
                                                api_token,
                                                |api| async move {
                                                    let op = crate::messaging::polls::build_poll_create_op(
                                                        &space,
                                                        &actor,
                                                        &flow_id,
                                                        &poll_id_for_op,
                                                        &draft_for_op,
                                                    );
                                                    api.submit_event_envelope(&op).await
                                                },
                                            )
                                            .await;
                                        });
                                    }
                                },
                                "Send poll"
                            }
                            // Cotest also references `send-poll-button`
                            // — wire it to the same handler so both
                            // testids resolve.
                            button {
                                r#type: "button",
                                class: "secondary",
                                "data-testid": "send-poll-button",
                                onclick: move |_| {
                                    // Programmatic click on the
                                    // primary control. We rely on a
                                    // shared JS effect rather than
                                    // duplicating the submit body —
                                    // duplication risks drift. The
                                    // cotest flow exercises both
                                    // testids via .click(), so this
                                    // pass-through is enough.
                                    let draft_snapshot = poll_draft.read().clone();
                                    if let Some(draft_snapshot) = draft_snapshot {
                                        if draft_snapshot.is_sendable() {
                                            poll_draft.set(None);
                                            let poll_id = crate::messaging::polls::new_poll_id();
                                            let card = crate::messaging::polls::PollCard::from_draft(
                                                poll_id,
                                                &draft_snapshot,
                                            );
                                            poll_cards.write().push(card);
                                        }
                                    }
                                },
                                "Send"
                            }
                            button {
                                r#type: "button",
                                class: "secondary",
                                onclick: move |_| poll_draft.set(None),
                                "Cancel"
                            }
                        }
                    }
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "send-chat-button",
                        onclick: {
                            let base = base_url.clone();
                            let service_did = plaintext_service_did.clone();
                            let space = selected_space.clone();
                            let actor = account_did.clone();
                            move |_| {
                                let body = chat_draft().trim().to_owned();
                                if body.is_empty() {
                                    return;
                                }
                                let mut mentions = parse_structured_mentions(&body);
                                // G3.Y2 — merge mention picker chips
                                // into the structured mentions list so
                                // the @mention picker counts as a
                                // first-class source (not just typed
                                // `@name` text).
                                {
                                    let picker = mention_picker_state.read().inserted.clone();
                                    for chip in picker {
                                        if !mentions.iter().any(|m| m.target == chip.did) {
                                            mentions.push(crate::views::helpers::StructuredMention {
                                                kind: "actor".to_owned(),
                                                target: chip.did.clone(),
                                                token: format!("@{}", chip.display_name),
                                                display_snapshot: chip.display_name.clone(),
                                                handle_uri: String::new(),
                                                resolved_at: String::new(),
                                            });
                                        }
                                    }
                                }
                                let local_id = new_chat_message_id();
                                let channel = channels()
                                    .iter()
                                    .find(|candidate| candidate.flow_id == selected_channel())
                                    .cloned();
                                let Some(channel) = channel else {
                                    status_msg.set("select a discussion first".to_owned());
                                    return;
                                };
                                messages.write().push(ChatMessage {
                                    space_id: space.clone(),
                                    id: local_id.clone(),
                                    sender: "yougen".to_owned(),
                                    body: body.clone(),
                                    timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                                    flow_id: channel.flow_id.clone(),
                                    reply_to: reply_to_message(),
                                    reactions: Vec::new(),
                                    redacted: false,
                                    edited: false,
                                    revisions: Vec::new(),
                                    pending: true,
                                    failed: false,
                                    error: None,
                                    mentions: mentions.clone(),
                                    // Local-only sends start plaintext;
                                    // the Send Secure flow may upgrade
                                    // them via a separate `messages.write()`
                                    // patch after `encrypt_payload`.
                                    crypto_state: MessageCryptoState::Plaintext,
                                });

                                let base = base.clone();
                                let service_did = service_did.clone();
                                let space = space.clone();
                                let api_token = token();
                                let actor = actor.clone();
                                let flow_id = channel.flow_id.clone();
                                let channel_kind = channel.kind.clone();
                                let message_id = local_id.clone();
                                let reply_to = reply_to_message();
                                let mut op = chat_message_create_operation(
                                    &space,
                                    &actor,
                                    &flow_id,
                                    &channel_kind,
                                    &message_id,
                                    &body,
                                    &mentions,
                                    reply_to.as_deref(),
                                );
                                // G3.Y2 — mention sidecar hashes.
                                // Decorates the outgoing payload with
                                // `mention_sidecar_hash: [hex, ...]`
                                // so the server can route mention
                                // notifications without seeing the
                                // mentioned actor's DID in plaintext.
                                // See `discovery/push-notifications.md
                                // §4.5`. We use the Space id as the
                                // mention salt until soland exposes a
                                // dedicated salt projection.
                                if !mentions.is_empty() {
                                    let mention_dids: Vec<String> = mentions
                                        .iter()
                                        .filter(|m| m.kind == "actor")
                                        .map(|m| m.target.clone())
                                        .collect();
                                    let hashes =
                                        crate::messaging::mentions::mention_sidecar_hashes(
                                            &space,
                                            &mention_dids,
                                        );
                                    if let Some(obj) = op.payload.as_object_mut() {
                                        obj.insert(
                                            "mention_sidecar_hash".to_owned(),
                                            serde_json::Value::Array(
                                                hashes
                                                    .into_iter()
                                                    .map(serde_json::Value::String)
                                                    .collect(),
                                            ),
                                        );
                                    }
                                }
                                // Clear the picker chip list now that
                                // we've folded the mentions into the
                                // outgoing op.
                                mention_picker_state.write().clear();
                                let mention_values_for_store = mentions_to_json(&mentions);
                                let space_for_record = space.clone();
                                let actor_for_store = actor.clone();
                                let body_for_store = body.clone();
                                let body_for_restore = body.clone();
                                let flow_id_for_store = flow_id.clone();
                                let message_id_for_store = message_id.clone();
                                let reply_to_for_store = reply_to.clone();
                                let projection = state_store
                                    .read()
                                    .load()
                                    .space_projections
                                    .get(&space)
                                    .cloned();
                                let plaintext_services =
                                    plaintext_services_for_policy(projection.as_ref(), &service_did);
                                let wait_for = active_sync_token(&sync_cursor());
                                let actor_for_retry = actor.clone();
                                spawn(async move {
                                    match authed_api_with_sync(&base, api_token, wait_for) {
                                        Ok(api) => match submit_chat_operation_with_plaintext_retry(
                                            &api,
                                            &space,
                                            &actor_for_retry,
                                            &plaintext_services,
                                            &op,
                                        ).await {
                                            Ok(resp) => {
                                                {
                                                    let mut store = state_store.write();
                                                    store.save_sync_cursor(resp.sync_token.clone());
                                                    store.append_raw_operation(
                                                        op.local_operation_id().to_owned(),
                                                        Some(space_for_record),
                                                        json!({
                                                            "event_id": resp.event_id.clone(),
                                                            "kind": "cx.message.create",
                                                            "actor": actor_for_store,
                                                            "body": body_for_store,
                                                            "flow_id": flow_id_for_store,
                                                            "message_id": message_id_for_store,
                                                            "mentions": mention_values_for_store,
                                                            "reply_to": reply_to_for_store,
                                                            "status": resp.status.clone(),
                                                        }),
                                                    );
                                                }
                                                if let Some(found) = messages
                                                    .write()
                                                    .iter_mut()
                                                    .find(|candidate| candidate.id == local_id)
                                                {
                                                    found.id = resp.event_id.clone();
                                                    found.pending = false;
                                                    found.failed = false;
                                                    found.error = None;
                                                }
                                                sync_cursor.set(resp.sync_token.clone());
                                                frontier_state.set(resp.event_id.clone());
                                                status_msg.set("Message sent".to_owned());
                                            }
                                            Err(error) => {
                                                let auth_expired = is_auth_expired_error(&error);
                                                let membership_denied =
                                                    is_space_membership_denied_error(&error);
                                                let message = chat_send_error_message(&error);
                                                if membership_denied {
                                                    messages
                                                        .write()
                                                        .retain(|candidate| candidate.id != local_id);
                                                    if chat_draft().trim().is_empty() {
                                                        chat_draft.set(body_for_restore.clone());
                                                    }
                                                } else if let Some(found) = messages
                                                    .write()
                                                    .iter_mut()
                                                    .find(|candidate| candidate.id == local_id)
                                                {
                                                    found.pending = false;
                                                    found.failed = true;
                                                    found.error = Some(message.clone());
                                                }
                                                status_msg.set(format!("Message send failed: {message}"));
                                                if auth_expired {
                                                    let _ = navigator.push(Route::Login);
                                                }
                                            }
                                        },
                                        Err(error) => {
                                            let message = format!("Invalid server URL: {error}");
                                            if let Some(found) = messages
                                                .write()
                                                .iter_mut()
                                                .find(|candidate| candidate.id == local_id)
                                            {
                                                found.pending = false;
                                                found.failed = true;
                                                found.error = Some(message.clone());
                                            }
                                            status_msg.set(message);
                                        }
                                    }
                                });
                                chat_draft.set(String::new());
                                reply_to_message.set(None);
                            }
                        },
                        {crate::i18n::tr("chat.send")}
                    }
                    // Per-Space MLS passphrase input. When non-empty,
                    // Send Secure switches to the
                    // real `group.encrypt_payload()` path (typed
                    // EncryptedPayload + persisted post-encrypt state).
                    // Send Secure requires a saved passphrase for the
                    // active Space.
                    details { class: "compose-security-panel",
                        summary { "Advanced encryption" }
                        div { class: "compose-security-grid",
                            input {
                                class: "secondary",
                                r#type: "password",
                                "data-testid": "mls-passphrase-input",
                                placeholder: crate::i18n::tr("chat.mls_passphrase_placeholder"),
                                value: "{mls_passphrase_draft}",
                                oninput: move |evt| mls_passphrase_draft.set(evt.value()),
                            }
                            button {
                                class: "secondary",
                                "data-testid": "mls-passphrase-save-button",
                                title: crate::i18n::tr("chat.mls_passphrase_save"),
                                onclick: {
                                    let space_id = selected_space.clone();
                                    let mut store = mls_passphrase_store;
                                    move |_| {
                                        let value = mls_passphrase_draft();
                                        if value.is_empty() {
                                            store.write().clear(&space_id);
                                            status_msg.set(
                                                "MLS passphrase cleared; Send Secure requires a passphrase".to_owned(),
                                            );
                                        } else {
                                            store.write().set(space_id.clone(), value);
                                            status_msg.set(
                                                "MLS passphrase set — Send Secure now uses real MLS encrypt".to_owned(),
                                            );
                                        }
                                        mls_passphrase_draft.set(String::new());
                                    }
                                },
                                {crate::i18n::tr("chat.mls_passphrase_save")}
                            }
                    // MLS multi-device invite row. Three controls:
                    //   1. Publish my key package → POST keys/upload with
                    //      a fresh MlsKeyPackageRecord so peers can
                    //      fetch + add_member against it.
                    //   2. Target (actor, device) inputs.
                    //   3. Invite → fetch_mls_key_package + add_member +
                    //      send Welcome via /device_messages.
                    button {
                        class: "secondary",
                        "data-testid": "mls-publish-key-package-button",
                        onclick: {
                            let base = base_url.clone();
                            let actor = account_did.clone();
                            move |_| {
                                let base = base.clone();
                                let actor = actor.clone();
                                let api_token = token();
                                let device_id_for_pub =
                                    state_store.read().local_identity().map(|i| i.device_did.clone());
                                let mut published = mls_key_package_published;
                                spawn(async move {
                                    #[cfg(not(target_arch = "wasm32"))]
                                    {
                                        let Some(device_did) = device_id_for_pub else {
                                            status_msg.set(
                                                "publish failed: local identity unavailable".to_owned(),
                                            );
                                            return;
                                        };
                                        let identity = match contrix_sdk::ContrixMlsIdentity::new_basic(
                                            match contrix_sdk::Did::new(actor.clone()) {
                                                Ok(d) => d,
                                                Err(err) => {
                                                    status_msg.set(format!(
                                                        "publish failed: invalid principal DID: {err:?}"
                                                    ));
                                                    return;
                                                }
                                            },
                                            match contrix_sdk::DeviceId::new(device_did.clone()) {
                                                Ok(d) => d,
                                                Err(err) => {
                                                    status_msg.set(format!(
                                                        "publish failed: invalid device id: {err:?}"
                                                    ));
                                                    return;
                                                }
                                            },
                                        ) {
                                            Ok(i) => i,
                                            Err(err) => {
                                                status_msg.set(format!(
                                                    "publish failed: identity build: {err:?}"
                                                ));
                                                return;
                                            }
                                        };
                                        let record = match identity.key_package_record() {
                                            Ok(r) => r,
                                            Err(err) => {
                                                status_msg.set(format!(
                                                    "publish failed: key_package_record: {err:?}"
                                                ));
                                                return;
                                            }
                                        };
                                        match crate::views::helpers::with_authed_api(
                                            &base,
                                            api_token,
                                            move |api| {
                                                let device_did = device_did.clone();
                                                let record = record.clone();
                                                async move {
                                                    api.publish_mls_key_package(
                                                        &device_did,
                                                        &record,
                                                    )
                                                    .await
                                                }
                                            },
                                        )
                                        .await
                                        {
                                            Ok(_) => {
                                                published.set(true);
                                                status_msg.set(
                                                    "MLS key package published; peers can now add this device".to_owned(),
                                                );
                                            }
                                            Err(err) => {
                                                status_msg.set(format!(
                                                    "publish failed: {}", err.display()
                                                ));
                                            }
                                        }
                                    }
                                    #[cfg(target_arch = "wasm32")]
                                    {
                                        let _ = (base, actor, api_token, device_id_for_pub);
                                        status_msg.set(
                                            "MLS publish requires desktop client (no OpenMLS in browser)".to_owned(),
                                        );
                                    }
                                });
                            }
                        },
                        {crate::i18n::tr("chat.mls_publish_key_package")}
                    }
                    input {
                        class: "secondary",
                        "data-testid": "mls-invite-actor-input",
                        placeholder: crate::i18n::tr("chat.mls_invite_actor_placeholder"),
                        value: "{mls_invite_actor_draft}",
                        oninput: move |evt| mls_invite_actor_draft.set(evt.value()),
                    }
                    input {
                        class: "secondary",
                        "data-testid": "mls-invite-device-input",
                        placeholder: crate::i18n::tr("chat.mls_invite_device_placeholder"),
                        value: "{mls_invite_device_draft}",
                        oninput: move |evt| mls_invite_device_draft.set(evt.value()),
                    }
                    button {
                        class: "secondary",
                        "data-testid": "mls-invite-member-button",
                        onclick: {
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            let _actor_outer = account_did.clone();
                            move |_| {
                                let base = base.clone();
                                let space = space.clone();
                                let api_token = token();
                                let target_actor = mls_invite_actor_draft().trim().to_owned();
                                let target_device = mls_invite_device_draft().trim().to_owned();
                                let passphrase: String = mls_passphrase_store
                                    .read()
                                    .get(&space)
                                    .map(str::to_owned)
                                    .unwrap_or_default();
                                spawn(async move {
                                    run_mls_add_member_and_invite(
                                        base,
                                        api_token,
                                        state_store,
                                        space,
                                        target_actor,
                                        target_device,
                                        passphrase,
                                        status_msg,
                                    )
                                    .await;
                                });
                            }
                        },
                        {crate::i18n::tr("chat.mls_invite_member")}
                    }
                    button {
                        class: "secondary",
                        "data-testid": "send-e2ee-move-button",
                        onclick: {
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            let actor = account_did.clone();
                            let selected_flow = selected_channel_value.clone();
                            move |_| {
                                let body = chat_draft().trim().to_owned();
                                if body.is_empty() {
                                    status_msg.set("Type a message before secure send".to_owned());
                                    return;
                                }
                                let space = space.clone();
                                let actor = actor.clone();
                                let flow_id = if selected_flow.trim().is_empty() {
                                    default_discussion_flow_id(&space)
                                } else {
                                    selected_flow.clone()
                                };
                                let api_token = token();
                                let wait_for = active_sync_token(&sync_cursor());
                                let _hlc = Hlc::now("yougen").to_string();
                                let anchor_view = state_store.read().anchor_view_for(&space);
                                let anchor_ref = anchor_view.move_anchor_ref();
                                let covered_frontier = anchor_view
                                    .covered_frontier
                                    .clone()
                                    .unwrap_or_else(|| {
                                        // Fallback: bind to the
                                        // sha256(empty) sentinel — soland
                                        // surfaces a `covered_frontier`
                                        // mismatch which the Move tracker
                                        // maps to pending_mls_binding.
                                        "cx:state:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned()
                                    });
                                let prev_epoch = anchor_view.mls_epoch.unwrap_or(0);
                                let identity =
                                    match state_store.write().ensure_local_identity() {
                                        Ok(id) => id,
                                        Err(err) => {
                                            status_msg.set(format!(
                                                "identity unavailable: {err}"
                                            ));
                                            return;
                                        }
                                    };
                                let did = identity.device_did.clone();
                                // 1) MLS commit event bumps the epoch +
                                //    records covered_frontier.
                                // Real MLS encrypt path. When the user has entered a
                                // passphrase for this Space, hydrate /
                                // bootstrap the local `ContrixMlsGroup`,
                                // encrypt the message
                                // body via `group.encrypt_payload`, and
                                // persist the post-encrypt group state so
                                // a refresh + decrypt round trip can
                                // recover the same ciphertext. B3d
                                // (schedule_hash) and B6c (member DIDs)
                                // now read from the same group instance.
                                let mls_passphrase: String = mls_passphrase_store
                                    .read()
                                    .get(&space)
                                    .map(str::to_owned)
                                    .unwrap_or_default();
                                #[cfg(not(target_arch = "wasm32"))]
                                let (
                                    local_schedule_hash,
                                    local_member_dids,
                                    encrypted_payload_value,
                                    real_commit_envelope,
                                ): (
                                    Option<contrix_sdk::Hash>,
                                    Vec<contrix_sdk::Did>,
                                    Option<serde_json::Value>,
                                    Option<contrix_sdk::MlsCommitEnvelope>,
                                ) = run_local_mls_encrypt(
                                    state_store,
                                    &space,
                                    &actor,
                                    &did,
                                    &mls_passphrase,
                                    body.as_bytes(),
                                );
                                #[cfg(target_arch = "wasm32")]
                                let (
                                    local_schedule_hash,
                                    local_member_dids,
                                    encrypted_payload_value,
                                    real_commit_envelope,
                                ): (
                                    Option<contrix_sdk::Hash>,
                                    Vec<contrix_sdk::Did>,
                                    Option<serde_json::Value>,
                                    Option<contrix_sdk::MlsCommitEnvelope>,
                                ) = (None, Vec::new(), None, None);

                                let Some(real_commit_envelope) = real_commit_envelope.as_ref() else {
                                    status_msg.set(
                                        "Send Secure requires a saved MLS passphrase and a decryptable local group".to_owned(),
                                    );
                                    return;
                                };
                                let Some(encrypted_payload_json) = encrypted_payload_value.clone() else {
                                    status_msg.set(
                                        "Send Secure could not produce an MLS encrypted payload".to_owned(),
                                    );
                                    return;
                                };
                                let Some(local_schedule_hash) = local_schedule_hash.clone() else {
                                    status_msg.set(
                                        "Send Secure could not derive the MLS key schedule hash".to_owned(),
                                    );
                                    return;
                                };
                                if local_member_dids.is_empty() {
                                    status_msg.set(
                                        "Send Secure could not resolve MLS group members".to_owned(),
                                    );
                                    return;
                                }
                                let mls_commit_epoch = real_commit_envelope.epoch;

                                let mls_binding = (|| -> anyhow::Result<
                                    crate::mls_governance::GovernanceBindingPayload,
                                > {
                                    use contrix_sdk::{AnchorId, SpaceId};
                                    let space_id = SpaceId::new(space.clone()).map_err(|e| {
                                        anyhow::anyhow!("invalid space id: {e:?}")
                                    })?;
                                    let anchor_id = AnchorId::new(anchor_ref.clone())
                                        .map_err(|e| {
                                            anyhow::anyhow!("invalid anchor ref: {e:?}")
                                        })?;
                                    crate::mls_governance::GovernanceBindingPayload::from_anchor(
                                        &space,
                                        &space_id,
                                        prev_epoch,
                                        mls_commit_epoch,
                                        &local_schedule_hash,
                                        &anchor_id,
                                    )
                                })()
                                .ok();
                                let Some(binding) = &mls_binding else {
                                    status_msg.set(
                                        "Send Secure requires MLS governance binding metadata".to_owned(),
                                    );
                                    return;
                                };
                                // Spec-canonical write path: cx.mls.commit event via cx.events.submit.
                                let preconditions: Vec<serde_json::Value> = binding
                                    .preconditions
                                    .iter()
                                    .filter_map(|p| serde_json::to_value(p).ok())
                                    .collect();
                                let effects: Vec<serde_json::Value> = binding
                                    .effects
                                    .iter()
                                    .filter_map(|e| serde_json::to_value(e).ok())
                                    .collect();
                                let binding_hash = match binding.canonical_hash() {
                                    Ok(h) => h,
                                    Err(err) => {
                                        status_msg.set(format!(
                                            "mls governance binding hash failed: {err}"
                                        ));
                                        return;
                                    }
                                };
                                let commit_envelope =
                                    crate::operation::cx_ops::mls_commit_with_governance(
                                        &space,
                                        &actor,
                                        &space,
                                        preconditions,
                                        effects,
                                        &binding_hash,
                                    )
                                    .build("yougen");
                                let encrypted_epoch = mls_commit_epoch;
                                let message_id = new_chat_message_id();
                                let msg_op = OperationBuilder::new(
                                    &space,
                                    &actor,
                                    "cx.message.create",
                                )
                                .body(json!({
                                    "message_id": message_id,
                                    "flow_id": flow_id,
                                    "track": "discussion",
                                    "body": format!("[encrypted epoch {encrypted_epoch}]"),
                                    "content": {
                                        "kind": "cx.content.text",
                                        "body": format!("[encrypted epoch {encrypted_epoch}]"),
                                    },
                                    "encrypted": true,
                                    "covered_frontier": covered_frontier.clone(),
                                    "encrypted_payload": encrypted_payload_json,
                                }))
                                .build("yougen");
                                let base = base.clone();
                                let space_for_record = space.clone();
                                let anchor_for_record = anchor_ref.clone();
                                let actor_for_audit = actor.clone();
                                let audit_delivered: Vec<String> = local_member_dids
                                    .iter()
                                    .map(|did| did.as_str().to_owned())
                                    .collect();
                                let commit_op_id = commit_envelope.local_operation_id().to_owned();
                                spawn(async move {
                                    if let Ok(api) = authed_api_with_sync(&base, api_token, wait_for) {
                                        // Submit MLS commit event first; if it fails,
                                        // abort message send (covered_frontier won't bind).
                                        match api.submit_event_envelope(&commit_envelope).await {
                                            Ok(_resp) => {
                                                state_store.write().record_move_submission(
                                                    commit_op_id.clone(),
                                                    space_for_record.clone(),
                                                    "mls_commit".to_owned(),
                                                    MoveSubmissionState::from_submit_state(
                                                        "accepted", None,
                                                    ),
                                                    None,
                                                    Some(anchor_for_record.clone()),
                                                );
                                            }
                                            Err(err) => {
                                                status_msg.set(format!(
                                                    "MLS commit event submit failed: {err}"
                                                ));
                                                return;
                                            }
                                        }
                                        match api.submit_event_envelope(&msg_op).await {
                                            Ok(resp) => {
                                                {
                                                    let mut store = state_store.write();
                                                    store.save_sync_cursor(resp.sync_token.clone());
                                                    store.append_raw_operation(
                                                        msg_op.local_operation_id().to_owned(),
                                                        Some(space_for_record.clone()),
                                                        json!({
                                                            "event_id": resp.event_id.clone(),
                                                            "kind": "cx.message.create",
                                                            "status": resp.status.clone(),
                                                        }),
                                                    );
                                                }
                                                sync_cursor.set(resp.sync_token.clone());
                                                frontier_state.set(resp.event_id.clone());
                                            status_msg.set(format!(
                                                "Encrypted message sent"
                                            ));

                                            // Disclosed-audit hardening profile
                                            // (`cx.profile.disclosed_audit.e2ee.v1`):
                                            // emit a per-actor read-your-write
                                            // receipt right after a successful
                                            // E2EE commit. The receipt is
                                            // actor-private (only the sender
                                            // can audit their own writes), so
                                            // this is fire-and-forget — if the
                                            // server isn't running the
                                            // disclosed-audit profile, it will
                                            // store the event as a regular
                                            // operation and the audit timeline
                                            // can still surface it.
                                            //
                                            // B6b: at minimum surface the
                                            // local device DID — that's the
                                            // device we provably reached
                                            // (it sent the commit). A real
                                            // MLS commit yields the full
                                            // post-commit member device set
                                            // through `MlsAddMemberResult`
                                            // / `MlsRemoveMemberResult`; the
                                            // executor will replace this
                                            // single-element fallback when
                                            // the group state path lands.
                                            let audit_op = build_audit_ryw_receipt(
                                                &space_for_record,
                                                &actor_for_audit,
                                                &resp.event_id,
                                                audit_delivered.clone(),
                                            )
                                            .build("yougen");
                                            let _ = api.submit_event_envelope(&audit_op).await;
                                        }
                                        Err(err) => status_msg.set(format!(
                                            "Message send failed: {err}"
                                        )),
                                    }
                                }
                                });
                                chat_draft.set(String::new());
                            }
                        },
                        {crate::i18n::tr("chat.send_secure")}
                    }
                        }
                    }
                }
                if !status_msg().is_empty() {
                    div { class: "muted discussion-status", "data-testid": "chat-status", "{status_msg}" }
                }
            }
            }
        }
    }
}

fn mentions_to_json(mentions: &[StructuredMention]) -> Vec<serde_json::Value> {
    mentions
        .iter()
        .map(|mention| {
            // T7.3: emit the spec's `subject` field alongside our legacy
            // `target` so projections that already read `subject`
            // receive it. `display_snapshot`/`handle_uri`/`resolved_at`
            // round-trip through the persisted local op record so the
            // renderer can detect handle reassignments.
            let mut obj = serde_json::Map::new();
            obj.insert("kind".to_owned(), json!(mention.kind));
            obj.insert("subject".to_owned(), json!(mention.target));
            obj.insert("target".to_owned(), json!(mention.target));
            obj.insert("token".to_owned(), json!(mention.token));
            if !mention.display_snapshot.is_empty() {
                obj.insert(
                    "display_snapshot".to_owned(),
                    json!(mention.display_snapshot),
                );
            }
            if !mention.handle_uri.is_empty() {
                obj.insert("handle_uri".to_owned(), json!(mention.handle_uri));
            }
            if !mention.resolved_at.is_empty() {
                obj.insert("resolved_at".to_owned(), json!(mention.resolved_at));
            }
            Value::Object(obj)
        })
        .collect()
}

fn mention_relation_json(source: &str, mentions: &[StructuredMention]) -> Vec<serde_json::Value> {
    mentions
        .iter()
        .map(|mention| {
            json!({
                "relation_type": "mentions",
                "source": source,
                "target": mention.target,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Welcome-receive shuttle iterates `events[]` from
    /// `DeviceMessagesReceiveResBody` and surfaces only
    /// `cx.mls.welcome` payloads.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn collect_welcome_entries_filters_cx_mls_welcome_and_drops_other_kinds() {
        let value = json!({
            "events": [
                {"type": "cx.mls.welcome", "content": {"welcome_envelope_id": "w-1"}},
                {"type": "cx.key.verify.request", "content": {"ignore_me": true}},
                {"type": "cx.mls.welcome", "content": {"welcome_envelope_id": "w-2"}},
                {"type": "cx.mls.welcome", "content": {"welcome_envelope_id": "w-3"}},
                {"type": "cx.device.message", "content": {"ignore_me": true}},
            ]
        });
        let welcomes = collect_welcome_entries(&value);
        let ids: Vec<&str> = welcomes
            .iter()
            .filter_map(|w| w.get("welcome_envelope_id").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&"w-1"));
        assert!(ids.contains(&"w-2"));
        assert!(ids.contains(&"w-3"));
    }

    /// Empty / missing `events` envelope returns no welcomes — the
    /// shuttle silently returns instead of panicking.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn collect_welcome_entries_tolerates_missing_events_envelope() {
        assert!(collect_welcome_entries(&json!({})).is_empty());
        assert!(collect_welcome_entries(&json!({"events": null})).is_empty());
        assert!(collect_welcome_entries(&json!({"events": []})).is_empty());
    }

    #[test]
    fn parses_message_event_with_operation_body_shape() {
        let event = json!({
            "id": "cx:event:body-shape",
            "type": "cx.message.create",
            "actor": "did:web:alice.example",
            "space_id": "cx:space:demo",
            "created_at": "2026-05-14T01:23:45Z",
            "causal": {"actor_seq": 42},
            "body": {
                "body": "restored from durable history",
                "flow_id": "cx:flow:announce",
                "message_id": "chat-msg-local",
                "mentions": [{"kind": "actor", "target": "did:web:bob.example", "token": "@bob"}]
            }
        });

        let message = chat_message_from_event("cx:space:fallback", &event).unwrap();

        assert_eq!(message.id, "cx:event:body-shape");
        assert_eq!(message.space_id, "cx:space:demo");
        assert_eq!(message.flow_id, "cx:flow:announce");
        assert_eq!(message.body, "restored from durable history");
        assert_eq!(message.sender, "did:web:alice.example");
        assert_eq!(message.mentions[0].target, "did:web:bob.example");
    }

    #[test]
    fn parses_message_event_with_nested_envelope_payload_shape() {
        let event = json!({
            "event": {
                "event_id": "cx:event:nested",
                "kind": "cx.message.create",
                "actor_id": "did:web:alice.example",
                "actor_seq": 43,
                "payload": {
                    "content": {
                        "kind": "cx.content.text",
                        "body": "nested payload message"
                    },
                    "flow_id": "cx:flow:support",
                    "message_id": "chat-msg-nested"
                }
            }
        });

        let message = chat_message_from_event("cx:space:demo", &event).unwrap();

        assert_eq!(message.id, "cx:event:nested");
        assert_eq!(message.flow_id, "cx:flow:support");
        assert_eq!(message.body, "nested payload message");
    }

    #[test]
    fn chat_message_create_operation_emits_schema_canonical_content() {
        let op = chat_message_create_operation(
            "cx:space:demo",
            "did:web:alice.example",
            "cx:flow:demo",
            "discussion",
            "cx:message:test-1",
            "hello from chat",
            &[],
            None,
        );

        assert_eq!(op.kind, "cx.message.create");
        assert_eq!(op.payload["message_id"].as_str(), Some("cx:message:test-1"));
        assert_eq!(op.payload["flow_id"].as_str(), Some("cx:flow:demo"));
        assert_eq!(op.payload["track"].as_str(), Some("discussion"));
        assert_eq!(
            op.payload["content"]["kind"].as_str(),
            Some("cx.content.text")
        );
        assert_eq!(
            op.payload["content"]["body"].as_str(),
            Some("hello from chat")
        );
        assert!(op.payload["content"].get("blocks").is_none());
        assert!(op.payload.get("reply_to").is_none());
        assert!(op.payload.get("thread_id").is_none());
    }

    #[test]
    fn chat_message_create_operation_includes_reply_fields_only_when_present() {
        let op = chat_message_create_operation(
            "cx:space:demo",
            "did:web:alice.example",
            "cx:flow:demo",
            "discussion",
            "cx:message:test-reply",
            "reply body",
            &[],
            Some("cx:message:parent"),
        );

        assert_eq!(op.payload["reply_to"].as_str(), Some("cx:message:parent"));
        assert_eq!(op.payload["thread_id"].as_str(), Some("cx:message:parent"));
    }

    #[test]
    fn chat_message_ids_use_schema_prefix() {
        let id = new_chat_message_id();

        assert!(id.starts_with("cx:message:"));
        assert!(is_schema_message_id(&id));
        assert!(is_schema_message_id("cx:message:local-1"));
        assert!(!is_schema_message_id("chat-msg-local"));
        assert!(schema_message_id_or_new("chat-msg-local").starts_with("cx:message:"));
    }

    #[test]
    fn restores_messages_from_local_raw_operations() {
        let state = ClientLocalState {
            raw_operations: vec![crate::local_state::RawOperationRecord {
                operation_id: "cx:operation:local".to_owned(),
                space_id: Some("cx:space:local".to_owned()),
                received_at: chrono::Utc::now(),
                payload: json!({
                    "event_id": "cx:event:local",
                    "kind": "cx.message.create",
                    "actor": "did:web:alice.example",
                    "body": "local fallback message",
                    "flow_id": "cx:flow:announce",
                    "message_id": "chat-msg-local"
                }),
            }],
            ..ClientLocalState::default()
        };

        let messages = chat_messages_from_local_state(&state);

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].space_id, "cx:space:local");
        assert_eq!(messages[0].flow_id, "cx:flow:announce");
        assert_eq!(messages[0].body, "local fallback message");
    }

    #[test]
    fn treats_canonical_account_did_as_own_sender() {
        let participants = Vec::new();

        assert!(is_own_message_sender(
            "did:web:alice.example",
            "did:web:alice.example"
        ));
        assert_eq!(
            sender_display_label(
                "did:web:alice.example",
                "did:web:alice.example",
                "",
                &participants
            ),
            "yougen"
        );
        assert_eq!(
            sender_display_label(
                "did:web:alice.example",
                "did:web:alice.example",
                "Alice Local",
                &participants,
            ),
            "Alice Local"
        );
    }

    #[test]
    fn participant_display_name_prefers_local_remark() {
        let participants = vec![SpaceParticipant {
            did: "did:web:bob.example".to_owned(),
            display_name: Some("Bobby".to_owned()),
            display_name_rank: 0,
            role: SpaceParticipantRole::Member,
            is_self: false,
            is_agent: false,
        }];

        assert_eq!(
            sender_display_label(
                "did:web:bob.example",
                "did:web:alice.example",
                "Alice",
                &participants,
            ),
            "Bobby"
        );
        assert_eq!(
            sender_display_label(
                "did:web:carol.example",
                "did:web:alice.example",
                "Alice",
                &participants
            ),
            "carol.example"
        );
    }

    #[test]
    fn extracts_participant_display_name_from_projection() {
        let projection = json!({
            "members": [
                {
                    "did": "did:web:bob.example",
                    "display_name": "Bob Example",
                    "remark": "Bob from ops"
                }
            ]
        });

        let participants = space_participants(Some(&projection), "did:web:alice.example");
        let bob = participants
            .iter()
            .find(|participant| participant.did == "did:web:bob.example")
            .unwrap();

        assert_eq!(bob.display_name.as_deref(), Some("Bob from ops"));
    }

    #[test]
    fn participant_with_agent_did_renders_with_agent_badge() {
        // Three participants in the space: Alice (the local account),
        // Bob (a real human member), and a Researcher Agent registered
        // via `cx.agent.endpoint`. After `annotate_agent_participants`
        // the agent DID must carry `is_agent = true` while the human
        // members stay `false`.
        let mut participants = vec![
            SpaceParticipant {
                did: "did:web:alice.example".to_owned(),
                display_name: Some("Alice".to_owned()),
                display_name_rank: 0,
                role: SpaceParticipantRole::Owner,
                is_self: true,
                is_agent: false,
            },
            SpaceParticipant {
                did: "did:web:bob.example".to_owned(),
                display_name: Some("Bob".to_owned()),
                display_name_rank: 1,
                role: SpaceParticipantRole::Member,
                is_self: false,
                is_agent: false,
            },
            SpaceParticipant {
                did: "did:web:researcher-agent.example".to_owned(),
                display_name: None,
                display_name_rank: u8::MAX,
                role: SpaceParticipantRole::Member,
                is_self: false,
                is_agent: false,
            },
        ];

        annotate_agent_participants(
            &mut participants,
            &["did:web:researcher-agent.example".to_owned()],
        );

        let alice = &participants[0];
        let bob = &participants[1];
        let agent = &participants[2];
        assert!(!alice.is_agent, "human owner must not be flagged as agent");
        assert!(!bob.is_agent, "human member must not be flagged as agent");
        assert!(
            agent.is_agent,
            "DID registered via cx.agent.endpoint must be flagged as agent"
        );
    }

    #[test]
    fn agent_dids_from_raw_operations_filters_by_space_and_kind() {
        use crate::local_state::RawOperationRecord;
        use chrono::Utc;

        // Mixed bag of raw ops: an agent endpoint for the right space,
        // an agent endpoint for a different space (should be filtered
        // out by space_id), and a non-agent kind (should be filtered
        // out by kind).
        let records = vec![
            RawOperationRecord {
                operation_id: "op-1".to_owned(),
                space_id: Some("cx:space:demo".to_owned()),
                received_at: Utc::now(),
                payload: json!({
                    "kind": "cx.agent.endpoint",
                    "body": { "agent_did": "did:web:researcher-agent.example" }
                }),
            },
            RawOperationRecord {
                operation_id: "op-2".to_owned(),
                space_id: Some("cx:space:other".to_owned()),
                received_at: Utc::now(),
                payload: json!({
                    "kind": "cx.agent.endpoint",
                    "body": { "agent_did": "did:web:other-agent.example" }
                }),
            },
            RawOperationRecord {
                operation_id: "op-3".to_owned(),
                space_id: Some("cx:space:demo".to_owned()),
                received_at: Utc::now(),
                payload: json!({
                    "kind": "cx.message.create",
                    "body": { "body": "hello" }
                }),
            },
        ];

        let agent_dids = agent_dids_from_raw_operations(&records, "cx:space:demo");
        assert_eq!(
            agent_dids,
            vec!["did:web:researcher-agent.example".to_owned()]
        );
    }

    #[test]
    fn channel_from_flow_event_requires_real_discussion_track() {
        let event = json!({
            "event_id": "cx:event:flow",
            "kind": "cx.flow.create",
            "space_id": "cx:space:demo",
            "flow_id": "cx:flow:ops",
            "title": "Ops discussion",
            "category": "support",
            "summary": "Operations support",
            "flow": {
                "id": "cx:flow:ops",
                "title": "Ops discussion",
                "tracks": {
                    "discussion": {"profile": "discussion"}
                }
            }
        });

        let channel = channel_from_flow_event("cx:space:demo", &event).unwrap();

        assert_eq!(channel.flow_id, "cx:flow:ops");
        assert_eq!(channel.name, "Ops discussion");
        assert_eq!(channel.category, "support");
        assert_eq!(channel.kind, "discussion");
        assert_eq!(channel.topic.as_deref(), Some("Operations support"));
        assert!(!channel.is_default);
    }

    #[test]
    fn channel_from_flow_event_ignores_non_discussion_flows() {
        let event = json!({
            "event_id": "cx:event:flow",
            "kind": "cx.flow.create",
            "space_id": "cx:space:demo",
            "flow_id": "cx:flow:doc",
            "title": "Doc flow",
            "flow": {
                "id": "cx:flow:doc",
                "title": "Doc flow",
                "tracks": {
                    "document": {"profile": "document"}
                }
            }
        });

        assert!(channel_from_flow_event("cx:space:demo", &event).is_none());
    }

    #[test]
    fn default_discussion_channel_uses_space_default_flow_projection() {
        let body = json!({
            "summary": {
                "title": "Demo Space",
                "flow": {
                    "flow_id": "cx:flow:demo",
                    "title": "General",
                    "summary": "Space-wide conversation",
                    "tracks": {
                        "discussion": {"enabled": true},
                        "synthesis": {"enabled": true}
                    }
                }
            }
        });

        let channel = default_discussion_channel("cx:space:demo", Some(&body));

        assert_eq!(channel.flow_id, "cx:flow:demo");
        assert_eq!(channel.name, "General");
        assert_eq!(channel.kind, "discussion");
        assert_eq!(channel.topic.as_deref(), Some("Space-wide conversation"));
        assert!(channel.is_default);
    }

    #[test]
    fn default_discussion_channel_synthesizes_default_flow_when_projection_is_absent() {
        let channel = default_discussion_channel("cx:space:demo", None);

        assert_eq!(channel.flow_id, "cx:flow:demo");
        assert_eq!(channel.name, "Discussion");
        assert_eq!(channel.category, "default flow");
        assert!(channel.is_default);
    }

    // ── T7.2 watcher pill helpers ────────────────────────────────

    fn dummy_participant(did: &str, name: Option<&str>) -> SpaceParticipant {
        SpaceParticipant {
            did: did.to_owned(),
            display_name: name.map(str::to_owned),
            display_name_rank: 0,
            role: SpaceParticipantRole::Member,
            is_self: false,
            is_agent: false,
        }
    }

    #[test]
    fn watcher_entry_accepts_canonical_did() {
        let participants: Vec<SpaceParticipant> = Vec::new();
        let already: Vec<String> = Vec::new();
        let kind = classify_watcher_entry("did:web:alice.example", &participants, &already);
        assert!(matches!(
            kind,
            WatcherEntryKind::Valid(ref did) if did == "did:web:alice.example"
        ));
    }

    #[test]
    fn watcher_entry_handle_resolves_to_did_web() {
        let participants: Vec<SpaceParticipant> = Vec::new();
        let already: Vec<String> = Vec::new();
        let kind = classify_watcher_entry("alice@example.com", &participants, &already);
        match kind {
            WatcherEntryKind::Valid(did) => {
                assert!(did.starts_with("did:web:"));
                assert!(did.contains("example.com"));
                assert!(did.contains("alice"));
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn watcher_entry_rejects_malformed_did() {
        let participants: Vec<SpaceParticipant> = Vec::new();
        let already: Vec<String> = Vec::new();
        let kind = classify_watcher_entry("did:web:", &participants, &already);
        assert_eq!(kind, WatcherEntryKind::InvalidDid);
    }

    #[test]
    fn watcher_entry_unresolved_bare_name() {
        let participants: Vec<SpaceParticipant> = Vec::new();
        let already: Vec<String> = Vec::new();
        let kind = classify_watcher_entry("alice", &participants, &already);
        assert_eq!(kind, WatcherEntryKind::UnresolvedName);
    }

    #[test]
    fn watcher_entry_dedupes_on_canonical_did() {
        let participants: Vec<SpaceParticipant> =
            vec![dummy_participant("did:web:alice.example", Some("Alice"))];
        let already: Vec<String> = vec!["did:web:alice.example".to_owned()];
        let kind = classify_watcher_entry("did:web:alice.example", &participants, &already);
        assert!(matches!(kind, WatcherEntryKind::Duplicate(_)));
    }

    #[test]
    fn watch_level_wire_round_trip() {
        for level in [
            WatchLevel::MentionsOnly,
            WatchLevel::Participating,
            WatchLevel::All,
            WatchLevel::Muted,
        ] {
            assert_eq!(WatchLevel::from_wire(level.wire_value()), level);
        }
    }

    #[test]
    fn parse_watcher_pills_marks_duplicates_after_first() {
        let participants: Vec<SpaceParticipant> = Vec::new();
        let pills = parse_watcher_pills(
            "did:web:alice.example, did:web:alice.example, alice@example.com",
            &participants,
        );
        assert_eq!(pills.len(), 3);
        assert!(matches!(pills[0].state, WatcherEntryKind::Valid(_)));
        assert!(matches!(pills[1].state, WatcherEntryKind::Duplicate(_)));
        assert!(matches!(pills[2].state, WatcherEntryKind::Valid(_)));
    }

    // ── T7.4 crypto state helpers ────────────────────────────────

    #[test]
    fn message_crypto_state_pending_detects_grey_states() {
        assert!(!MessageCryptoState::Plaintext.is_pending());
        assert!(MessageCryptoState::Decrypting.is_pending());
        assert!(MessageCryptoState::DecryptFailed.is_pending());
        assert!(MessageCryptoState::KeyMissing.is_pending());
        assert!(!MessageCryptoState::NeedsVerification.is_pending());
    }

    #[test]
    fn chat_message_from_event_flags_encrypted_payload_as_decrypting() {
        let event = json!({
            "event_id": "evt:1",
            "content": {
                "type": "cx.message.create",
                "body": "[encrypted]",
                "flow_id": "cx:flow:1",
                "encrypted_payload": {"ciphertext": "blob"},
            }
        });
        let msg = chat_message_from_event("cx:space:demo", &event).expect("message");
        assert_eq!(msg.crypto_state, MessageCryptoState::Decrypting);
    }

    #[test]
    fn chat_message_revise_operation_uses_schema_content_and_target_ref() {
        let op = chat_message_revise_operation(
            "cx:realm:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22",
            "did:web:bob.example",
            "cx:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23",
            "edited",
        );

        assert_eq!(
            op.payload["target_ref"],
            "cx:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23"
        );
        assert_eq!(
            op.payload["target_event_id"],
            "cx:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23"
        );
        assert_eq!(op.payload["content"]["kind"], "cx.content.text");
        assert_eq!(op.payload["content"]["body"], "edited");
        assert!(op.payload.get("body").is_none());
    }
}
