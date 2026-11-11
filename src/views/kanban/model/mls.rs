use arkret_sdk::EventPayloadExt as _;

use super::*;

/// Borrowed decrypt context for retained signed originals and the author's
/// local plaintext cache. Projected ciphertext stays opaque until its exact
/// verified outer Event and retained content root are available.
#[derive(Clone, Copy)]
pub(crate) struct MlsDecryptCtx<'a> {
    pub(crate) state_store: &'a LocalStateStore,
    pub(crate) realm_id: &'a str,
    pub(crate) identity: Option<(&'a arkret_sdk::AccountId, &'a str)>,
}

/// Build a context for the active Account. Original content reads use retained
/// roots and verified public history; the old private checkpoint and its
/// account-secret wrapper are not prerequisites or sources of read authority.
pub(crate) fn mls_decrypt_ctx_if_ready<'a>(
    state_store: &'a LocalStateStore,
    realm_id: &'a str,
    authority: &'a arkret_sdk::AccountId,
    device_id: &'a str,
) -> Option<MlsDecryptCtx<'a>> {
    if state_store.active_authority().as_ref() != Some(authority)
        || state_store.current_reset_required()
        || arkret_sdk::DeviceId::new(device_id.to_owned()).is_err()
    {
        return None;
    }
    Some(MlsDecryptCtx {
        state_store,
        realm_id,
        identity: Some((authority, device_id)),
    })
}

/// A remote patch must be decrypted using its original signed Event, never a
/// projection's claimed sender or an unrelated author-side field cache.
pub(crate) fn private_strand_event_field_text(
    ctx: &MlsDecryptCtx<'_>,
    event_value: &Value,
    strand_id: &str,
    field_path: &str,
    value: &Value,
) -> Option<String> {
    let plaintext =
        private_strand_event_field_value(ctx, event_value, strand_id, field_path, value)?;
    Some(strand_body_display_text(Some(&plaintext)))
}

pub(crate) fn private_strand_event_field_value(
    ctx: &MlsDecryptCtx<'_>,
    event_value: &Value,
    strand_id: &str,
    field_path: &str,
    value: &Value,
) -> Option<Value> {
    let (authority, device_id) = ctx.identity?;
    let device_id = arkret_sdk::DeviceId::new(device_id.to_owned()).ok()?;
    let event: arkret_sdk::Event = serde_json::from_value(event_value.clone()).ok()?;
    if !original_selects_private_field(ctx, &event, strand_id, field_path, value) {
        return None;
    }
    let warn_pending = |reason: &str| {
        crate::mls::runtime::warn_mls_decrypt_once(
            ctx.realm_id,
            event.event_id.event_digest().as_str(),
            value
                .pointer("/encryption_context/epoch")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
            ctx.state_store
                .mls_checkpoint_for_scope(&event.scope_ref)
                .map(|snapshot| snapshot.epoch),
            reason,
        )
    };
    let sender = crate::views::chat::verified_chat_sender_domain_for_realm(
        ctx.realm_id,
        event_value,
        Some(ctx.state_store),
        Some((authority, authority.principal_id.as_str(), &device_id)),
    )
    .or_else(|| {
        let verdict = crate::views::chat::verify_chat_envelope_proof_for_realm(
            ctx.realm_id,
            event_value,
            Some(ctx.state_store),
            Some((authority, authority.principal_id.as_str(), &device_id)),
        );
        warn_pending(&format!("Strand sender proof is {verdict:?}"));
        None
    })?;
    let plaintext = crate::state::projection::try_local_mls_decrypt_from_verified_original(
        ctx.state_store,
        ctx.realm_id,
        authority,
        &device_id,
        value,
        &event,
        &sender,
    )
    .or_else(|| {
        warn_pending("Strand verified envelope or receive state is unavailable");
        None
    })?;
    serde_json::from_slice(&plaintext).ok()
}

fn original_selects_private_field(
    ctx: &MlsDecryptCtx<'_>,
    event: &arkret_sdk::Event,
    strand_id: &str,
    field_path: &str,
    value: &Value,
) -> bool {
    if event.realm_id.as_str() != ctx.realm_id
        || event.scope_ref.realm_id_opt() != Some(&event.realm_id)
    {
        return false;
    }
    match event.kind {
        arkret_sdk::EventKind::StrandCreate => {
            arkret_sdk::StrandId::from_event_id(&event.event_id).as_str() == strand_id
                && event.payload.get("object").and_then(|object| {
                    object.pointer(&format!("/{}", field_path.replace('.', "/")))
                }) == Some(value)
        }
        arkret_sdk::EventKind::StrandUpdate => {
            let Ok(payload) = event.as_strand_update() else {
                return false;
            };
            if payload.strand_id.as_str() != strand_id {
                return false;
            }
            let Ok(patch) = serde_json::to_value(&payload.patch) else {
                return false;
            };
            let Some(patch) = patch.as_object() else {
                return false;
            };
            let Some(op) = patch_op_for_private_path(patch, field_path) else {
                return false;
            };
            let Ok(op) = serde_json::from_value::<arkret_wire::patch::PatchOp>(op.into_owned())
            else {
                return false;
            };
            op.op() == arkret_wire::patch::PatchOpKind::Set && op.value() == Some(value)
        }
        _ => false,
    }
}

fn retained_private_strand_field_text(
    ctx: &MlsDecryptCtx<'_>,
    strand_id: &str,
    field_path: &str,
    value: &Value,
) -> Option<String> {
    let mut originals = ctx
        .state_store
        .encrypted_originals_for(ctx.realm_id)
        .into_iter()
        .filter(|event| original_selects_private_field(ctx, event, strand_id, field_path, value));
    let original = originals.next()?;
    // The ciphertext alone cannot choose between different signed outer Events.
    if originals.next().is_some() {
        return None;
    }
    private_strand_event_field_text(
        ctx,
        &serde_json::to_value(original).ok()?,
        strand_id,
        field_path,
        value,
    )
}

/// Cheap key-only check for the raw encrypted payload/envelope shape. Projection and
/// patch wrappers are handled by [`mls_envelope_value`].
pub(crate) fn value_is_raw_mls_envelope(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.contains_key("ciphertext") && object.contains_key("content_type")
}

/// Extract a canonical MLS envelope from the value shapes the reducer/projection
/// can hand back to the board UI:
///
/// - raw `EncryptedPayload` / `EncryptedEnvelope`
/// - `{ "encrypted_content": <envelope> }`
/// - patch/set wrappers such as `{ "$op": "set", "value": <envelope> }`
///
/// This intentionally does not recurse through arbitrary object fields, so a
/// plaintext business object containing unrelated keys is not treated as E2EE.
pub(crate) fn mls_envelope_value(value: &Value) -> Option<&Value> {
    if value_is_raw_mls_envelope(value) {
        return Some(value);
    }
    let object = value.as_object()?;
    for key in ["encrypted_content", "encrypted_payload", "value"] {
        if let Some(child) = object.get(key)
            && let Some(envelope) = mls_envelope_value(child)
        {
            return Some(envelope);
        }
    }
    None
}

/// Cheap key-only check: is `value` an MLS-encrypted envelope, possibly wrapped
/// by a projection or patch operation?
pub(crate) fn value_is_mls_envelope(value: &Value) -> bool {
    mls_envelope_value(value).is_some()
}

/// Render `value` as display text, transparently decrypting it first when
/// it is plaintext. Projected encrypted values stay opaque because they do
/// not carry the verified outer Event context required to reconstruct the
/// authenticated header. The author-side plaintext cache is handled by
/// [`private_strand_field_text`].
pub(crate) fn private_strand_display_text(
    _ctx: Option<&MlsDecryptCtx<'_>>,
    value: Option<&Value>,
) -> String {
    let Some(value) = value else {
        return String::new();
    };
    if value_is_mls_envelope(value) {
        return String::new();
    }
    strand_body_display_text(Some(value))
}

pub(crate) fn private_plaintext_display_text(plaintext: &str) -> String {
    if let Ok(parsed) = serde_json::from_str::<Value>(plaintext) {
        return strand_body_display_text(Some(&parsed));
    }
    plaintext.to_owned()
}

/// X10.2 — true when a private field IS an MLS envelope that this device
/// cannot currently read: no local plaintext sidecar AND decryption is not
/// possible (author's own ciphertext / fresh browser before MLS unlock).
/// The display layer renders [`MLS_LOCKED_FIELD_PLACEHOLDER`] in this case so
/// the user can tell "encrypted, unlock to view" apart from "no content" —
/// WITHOUT putting the placeholder text into `card.synthesis` (which the editor
/// copies and could re-save, corrupting the real encrypted content).
pub(crate) fn private_strand_field_locked(
    ctx: Option<&MlsDecryptCtx<'_>>,
    strand_id: &str,
    field_path: &str,
    value: Option<&Value>,
) -> bool {
    let Some(value) = value else {
        return false;
    };
    if !value_is_mls_envelope(value) {
        return false;
    }
    if ctx.is_some_and(|ctx| {
        retained_private_strand_field_text(ctx, strand_id, field_path, value).is_some()
    }) {
        return false;
    }
    // Non-empty sidecar hit → readable, not locked. Empty sidecars are not
    // useful for an encrypted `set` value; treat them as missing so the UI
    // does not confuse encrypted-but-unreadable content with "no content".
    if let Some(ctx) = ctx
        && let Some(plaintext) =
            ctx.state_store
                .private_plaintext_for(ctx.realm_id, strand_id, field_path)
        && !private_plaintext_display_text(&plaintext).trim().is_empty()
    {
        return false;
    }
    // Envelope with no author-side plaintext is locked until its verified
    // outer Event context is available to the projection.
    true
}

/// Resolve a projected private Strand field using retained original provenance.
///
/// 1. **Retained original** — bind the exact target, field and ciphertext, then verify the producer
///    and decrypt with the original Event's content root.
/// 2. **Local plaintext sidecar** (`save_private_plaintext`) — stored as the JSON-serialized patch
///    value, parsed through `strand_body_display_text` to keep write/read symmetric. Event overlays
///    independently try verified decryption, including for the same Account.
/// 3. **Blank** — encrypted content without its verified outer Event context; never leaks the raw
///    envelope.
///
/// `field_path` MUST match the token the writer stored under — the ENCRYPTED
/// patch key (`kanban_encrypted_patch_path`): `"encrypted_content"` for the
/// Strand Description, or `"tracks.synthesis.encrypted_content"` for the
/// Synthesis track.
pub(crate) fn private_strand_field_text(
    ctx: Option<&MlsDecryptCtx<'_>>,
    strand_id: &str,
    field_path: &str,
    value: Option<&Value>,
) -> String {
    if let (Some(ctx), Some(value)) = (ctx, value)
        && value_is_mls_envelope(value)
        && let Some(text) = retained_private_strand_field_text(ctx, strand_id, field_path, value)
    {
        return text;
    }
    // The author's own plaintext sidecar is a local-only fallback.
    if let Some(ctx) = ctx
        && let Some(plaintext) =
            ctx.state_store
                .private_plaintext_for(ctx.realm_id, strand_id, field_path)
    {
        let text = private_plaintext_display_text(&plaintext);
        if !text.trim().is_empty() {
            return text;
        }
    }
    // Encrypted content remains opaque without verified Event context.
    private_strand_display_text(ctx, value)
}
