//! C10.D (2026-05-09 十六轮): client-side helpers to construct + sign
//! `contrix_sdk::Move` values for the cell-driven write paths.
//!
//! # When to use a Move (vs a direct event)
//!
//! Per spec event-kind-registry, only events that declare a `cell_family`
//! belong on the Move/Anchor pipeline. Examples:
//!
//! - **Yes**: `cx.consent.grant` / `revoke`, `cx.capability.*`,
//!   `cx.member.state`, `cx.space.{create,update,destroy,...}`,
//!   `cx.flow.position`, `cx.anchorer.*`, `cx.mls.epoch`
//! - **No**: `cx.message.*`, `cx.reaction.*`, `cx.read.marker`,
//!   `cx.entity.*`, `cx.relation.*`, `cx.redaction` — these stay on
//!   their durable-event endpoints (`/api/v1/messages/send`, etc.)
//!   per spec.
//!
//! # Signing model
//!
//! Each Move's body is canonicalized (RFC 8785 JCS) and a SHA-256 digest
//! over those bytes serves as the content-addressed `id`. The `sig` field
//! carries an Ed25519 detached JWS (RFC 7515 §3.2) over the same
//! canonical bytes. Production yougen would resolve the issuer DID
//! (the local actor) to a private signing key via OS keychain / WebAuthn
//! / HSM; this module provides only the canonicalization + JWS shaping
//! helpers.
//!
//! # Builders provided
//!
//! - [`build_consent_grant_move`] — `cx.consent.grant` over the
//!   `cx.component.consent.grant.v1` OrSet cell
//! - [`build_member_state_transition_move`] — `cx.member.state` FSM
//!   transition (`invited` → `join`, etc.) over
//!   `cx.component.member.state.v1`
//! - [`build_space_organization_update_move`] — `cx.space.update` over
//!   `cx.component.space.organization.v1` (cas-register)

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use contrix_sdk::{
    AnchorId, CellRef, Did, Effect, Hash, Hlc, LatticeOp, Move, MoveId, MoveSignature, SpaceId,
    canonical,
};
#[cfg(test)]
use contrix_sdk::LatticeOpType;

/// Output of a builder: an unsigned [`Move`] body together with its
/// canonical bytes (so the signer can sign exactly the bytes the server
/// will rehash for `id` validation).
pub struct UnsignedMove {
    pub move_obj: Move,
    pub canonical_bytes: Vec<u8>,
}

/// Construct a `cx.consent.grant` Move that adds a tag to the consent
/// OrSet cell. The cell subject is the `consent_id` (one cell per
/// distinct consent grant). `tag` is what gets added to the OrSet —
/// typically a stable identifier the issuer wants to record (e.g.
/// the granted scope or capability id).
pub fn build_consent_grant_move(
    issuer: &str,
    space_id: &str,
    consent_id: &str,
    tag: &str,
    anchor_ref: &str,
    hlc: &str,
) -> Result<UnsignedMove> {
    let cell_id = format!("cx:cell:cx.component.consent.grant.v1:{consent_id}");
    let effect = serde_json::json!({
        "cell": cell_id,
        "op": { "type": "add", "tag": tag }
    });
    build_move_inner(issuer, space_id, vec![effect], anchor_ref, hlc)
}

/// Construct a `cx.consent.revoke` Move that removes a tag from the
/// consent OrSet cell. The cell subject is the same `consent_id` used by
/// [`build_consent_grant_move`]; soland's OrSet semantics enforce causal
/// remove (only tags previously added by an observed grant can be
/// removed). `reason` is optional but recommended — it surfaces in the
/// audit trail and can drive UI confirmation copy.
pub fn build_consent_revoke_move(
    issuer: &str,
    space_id: &str,
    consent_id: &str,
    tag: &str,
    reason: Option<&str>,
    anchor_ref: &str,
    hlc: &str,
) -> Result<UnsignedMove> {
    let cell_id = format!("cx:cell:cx.component.consent.grant.v1:{consent_id}");
    let mut op = serde_json::json!({ "type": "remove", "tag": tag });
    if let Some(reason) = reason {
        op["reason"] = serde_json::Value::String(reason.to_owned());
    }
    let effect = serde_json::json!({ "cell": cell_id, "op": op });
    build_move_inner(issuer, space_id, vec![effect], anchor_ref, hlc)
}

/// Construct a `cx.capability.grant` Move that adds a capability tag to
/// the capability OrSet cell. Mirrors [`build_consent_grant_move`] —
/// the cell family (`cx.component.capability.grant.v1`) is OrSet too,
/// so the wire shape is identical save for the cell prefix. `grant_id`
/// is the cell subject (per-grant cell), `tag` is what the OrSet records
/// (typically the granted action / scope / capability identifier).
pub fn build_capability_grant_move(
    issuer: &str,
    space_id: &str,
    grant_id: &str,
    tag: &str,
    anchor_ref: &str,
    hlc: &str,
) -> Result<UnsignedMove> {
    let cell_id = format!("cx:cell:cx.component.capability.grant.v1:{grant_id}");
    let effect = serde_json::json!({
        "cell": cell_id,
        "op": { "type": "add", "tag": tag }
    });
    build_move_inner(issuer, space_id, vec![effect], anchor_ref, hlc)
}

/// Construct a `cx.capability.revoke` Move that removes a capability tag
/// from the capability OrSet cell. Mirrors [`build_consent_revoke_move`].
/// `reason` is optional but encouraged — it surfaces in the audit trail
/// and lets the UI explain why the capability was dropped.
pub fn build_capability_revoke_move(
    issuer: &str,
    space_id: &str,
    grant_id: &str,
    tag: &str,
    reason: Option<&str>,
    anchor_ref: &str,
    hlc: &str,
) -> Result<UnsignedMove> {
    let cell_id = format!("cx:cell:cx.component.capability.grant.v1:{grant_id}");
    let mut op = serde_json::json!({ "type": "remove", "tag": tag });
    if let Some(reason) = reason {
        op["reason"] = serde_json::Value::String(reason.to_owned());
    }
    let effect = serde_json::json!({ "cell": cell_id, "op": op });
    build_move_inner(issuer, space_id, vec![effect], anchor_ref, hlc)
}

/// Construct a `cx.member.state` Move that transitions an actor's
/// membership FSM. The cell subject is the `actor_id` (per-actor cell
/// across the whole protocol; soland's CellStore is space-scoped so
/// different Spaces have independent records of the same actor's state).
pub fn build_member_state_transition_move(
    issuer: &str,
    space_id: &str,
    actor_id: &str,
    from_state: &str,
    to_state: &str,
    anchor_ref: &str,
    hlc: &str,
) -> Result<UnsignedMove> {
    let cell_id = format!("cx:cell:cx.component.member.state.v1:{actor_id}");
    let effect = serde_json::json!({
        "cell": cell_id,
        "op": { "type": "transition", "from": from_state, "to": to_state }
    });
    build_move_inner(issuer, space_id, vec![effect], anchor_ref, hlc)
}

/// Construct a `cx.space.update` Move that writes the
/// `cx.component.space.organization.v1` cas-register cell with the
/// provided organization metadata. `value` should be a JSON object
/// (typically `{title, owner, ...}`); soland's reducer mirrors the
/// fields it knows about and ignores the rest.
pub fn build_space_organization_update_move(
    issuer: &str,
    space_id: &str,
    value: serde_json::Value,
    anchor_ref: &str,
    hlc: &str,
) -> Result<UnsignedMove> {
    let cell_id = format!("cx:cell:cx.component.space.organization.v1:{space_id}");
    let effect = serde_json::json!({
        "cell": cell_id,
        "op": { "type": "set", "value": value }
    });
    build_move_inner(issuer, space_id, vec![effect], anchor_ref, hlc)
}

/// Common Move-construction tail: take the typed pieces, build the
/// canonical body JSON, derive the Move id from `sha256(canonical_bytes)`,
/// stub the `sig` field with placeholder values, and return the unsigned
/// Move + the bytes that need signing. Callers run
/// [`sign_unsigned_move`] (or equivalent) before submitting.
fn build_move_inner(
    issuer: &str,
    space_id: &str,
    effects: Vec<serde_json::Value>,
    anchor_ref: &str,
    hlc: &str,
) -> Result<UnsignedMove> {
    let body = serde_json::json!({
        "issuer": issuer,
        "space_id": space_id,
        "preconditions": [],
        "effects": effects,
        "anchor_ref": anchor_ref,
        "refs": [],
        "hlc": hlc,
    });
    let canonical_bytes =
        canonical::canonical_json_bytes(&body).context("canonicalize move body")?;
    let payload_hash_str = canonical::sha256_digest(&canonical_bytes);
    let id_hex: String = Sha256::digest(&canonical_bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let move_id = MoveId::new(format!("cx:move:sha256:{id_hex}"))
        .map_err(|e| anyhow::anyhow!("derive move id: {e}"))?;
    // Build typed Move with placeholder signature; the canonical_bytes
    // remain stable because `id` and `sig` are NOT part of the canonical
    // body (per `Move::canonical_bytes_for_id`).
    let move_obj = Move {
        id: move_id.clone(),
        issuer: Did::new(issuer.to_owned())
            .map_err(|e| anyhow::anyhow!("invalid issuer DID: {e}"))?,
        space_id: SpaceId::new(space_id.to_owned())
            .map_err(|e| anyhow::anyhow!("invalid space id: {e}"))?,
        preconditions: vec![],
        effects: parse_effects(&effects)?,
        anchor_ref: AnchorId::new(anchor_ref.to_owned())
            .map_err(|e| anyhow::anyhow!("invalid anchor_ref: {e}"))?,
        refs: vec![],
        hlc: Hlc::new(hlc.to_owned()).map_err(|e| anyhow::anyhow!("invalid hlc: {e}"))?,
        sig: MoveSignature {
            alg: "EdDSA".to_owned(),
            verification_method: format!("{issuer}#unsigned"),
            payload_hash: Hash::new(payload_hash_str)
                .map_err(|e| anyhow::anyhow!("payload hash: {e}"))?,
            created_at: chrono::Utc::now(),
            jws: String::new(), // filled in by sign_unsigned_move
        },
    };
    Ok(UnsignedMove { move_obj, canonical_bytes })
}

/// Re-parse the effects JSON array into typed `Effect` records. The
/// builders construct effects as JSON for ergonomic shape composition;
/// this converts to the SDK type for the typed `Move.effects` field.
fn parse_effects(effects: &[serde_json::Value]) -> Result<Vec<Effect>> {
    effects
        .iter()
        .map(|e| {
            let cell_str = e
                .get("cell")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("effect missing `cell`"))?;
            let cell = CellRef::new(cell_str.to_owned())
                .map_err(|e| anyhow::anyhow!("invalid cell ref: {e}"))?;
            let op_value = e
                .get("op")
                .ok_or_else(|| anyhow::anyhow!("effect missing `op`"))?
                .clone();
            let op: LatticeOp = serde_json::from_value(op_value)
                .map_err(|e| anyhow::anyhow!("invalid lattice op: {e}"))?;
            Ok(Effect { cell, op })
        })
        .collect()
}

/// Sign an [`UnsignedMove`] with an Ed25519 [`SigningKey`], producing a
/// detached JWS (RFC 7515 §3.2) over the canonical bytes. `verification_method`
/// is the DID URL fragment that resolves to the corresponding public key
/// (for `did:key:z<multibase>` the URL is `did:key:z<multibase>#z<multibase>`).
pub fn sign_unsigned_move(
    mut unsigned: UnsignedMove,
    signing_key: &SigningKey,
    verification_method: &str,
) -> Move {
    let header_json = br#"{"alg":"EdDSA"}"#;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&unsigned.canonical_bytes);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signing_key.sign(signing_input.as_bytes()).to_bytes();
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature);
    let jws = format!("{header_b64}..{sig_b64}");
    unsigned.move_obj.sig.jws = jws;
    unsigned.move_obj.sig.verification_method = verification_method.to_owned();
    unsigned.move_obj
}

/// Encode an Ed25519 public key as the multibase form did:key DID URLs
/// + DID Document `verificationMethod` entries use:
/// `z<base58btc(0xed 0x01 || pubkey32)>`. Mirrors the SDK's internal
/// helper so yougen can build did:key DIDs locally.
pub fn encode_ed25519_did_key_multibase(verifying_key: &VerifyingKey) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.push(0xed);
    bytes.push(0x01);
    bytes.extend_from_slice(verifying_key.as_bytes());
    format!("z{}", bs58::encode(bytes).into_string())
}

/// Compose a did:key DID URL from a verifying key (`did:key:z<...>`).
pub fn did_key_from_verifying_key(verifying_key: &VerifyingKey) -> String {
    format!("did:key:{}", encode_ed25519_did_key_multibase(verifying_key))
}

/// Compose the verification_method DID URL for a did:key keypair
/// (`did:key:z<...>#z<...>`).
pub fn did_key_verification_method(verifying_key: &VerifyingKey) -> String {
    let mb = encode_ed25519_did_key_multibase(verifying_key);
    format!("did:key:{mb}#{mb}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_anchor_ref() -> &'static str {
        // SHA-256 of empty bytes — used as a "no predecessor" placeholder
        // for tests; production callers thread in the latest known
        // anchor frontier ref.
        "cx:anchor:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }

    fn fixed_hlc() -> &'static str {
        // Some 30-char HLC; tests don't enforce wall-clock here.
        "0189c4d2af00-00000000-aabbccdd"
    }

    #[test]
    fn consent_grant_builder_produces_or_set_add_effect() {
        let did = "did:web:alice.example";
        let space = "cx:space:0196419b-0000-7000-8000-000000000000";
        let unsigned = build_consent_grant_move(
            did,
            space,
            "cnt.01abc",
            "scope:contacts",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        assert_eq!(unsigned.move_obj.issuer.as_str(), did);
        assert_eq!(unsigned.move_obj.space_id.as_str(), space);
        assert_eq!(unsigned.move_obj.effects.len(), 1);
        let effect = &unsigned.move_obj.effects[0];
        assert!(effect
            .cell
            .as_str()
            .starts_with("cx:cell:cx.component.consent.grant.v1:"));
        assert_eq!(effect.op.op_type, LatticeOpType::Add);
        assert_eq!(effect.op.tag.as_deref(), Some("scope:contacts"));
    }

    #[test]
    fn consent_revoke_builder_produces_or_set_remove_with_reason() {
        let unsigned = build_consent_revoke_move(
            "did:web:alice.example",
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cnt.01abc",
            "scope:contacts",
            Some("user revoked from settings UI"),
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &unsigned.move_obj.effects[0];
        assert!(effect
            .cell
            .as_str()
            .starts_with("cx:cell:cx.component.consent.grant.v1:"));
        assert_eq!(effect.op.op_type, LatticeOpType::Remove);
        assert_eq!(effect.op.tag.as_deref(), Some("scope:contacts"));
        assert_eq!(
            effect.op.reason.as_deref(),
            Some("user revoked from settings UI")
        );
    }

    #[test]
    fn consent_revoke_builder_omits_reason_when_none() {
        let unsigned = build_consent_revoke_move(
            "did:web:alice.example",
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cnt.01abc",
            "scope:contacts",
            None,
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &unsigned.move_obj.effects[0];
        assert_eq!(effect.op.op_type, LatticeOpType::Remove);
        assert_eq!(effect.op.reason, None);
    }

    #[test]
    fn capability_grant_builder_produces_or_set_add_effect() {
        let unsigned = build_capability_grant_move(
            "did:web:admin.example",
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cap.01abc",
            "discussion.message.create",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &unsigned.move_obj.effects[0];
        assert!(effect
            .cell
            .as_str()
            .starts_with("cx:cell:cx.component.capability.grant.v1:"));
        assert_eq!(effect.op.op_type, LatticeOpType::Add);
        assert_eq!(effect.op.tag.as_deref(), Some("discussion.message.create"));
    }

    #[test]
    fn capability_revoke_builder_produces_or_set_remove_with_reason() {
        let unsigned = build_capability_revoke_move(
            "did:web:admin.example",
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cap.01abc",
            "discussion.message.create",
            Some("rotation policy quarterly"),
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &unsigned.move_obj.effects[0];
        assert!(effect
            .cell
            .as_str()
            .starts_with("cx:cell:cx.component.capability.grant.v1:"));
        assert_eq!(effect.op.op_type, LatticeOpType::Remove);
        assert_eq!(effect.op.tag.as_deref(), Some("discussion.message.create"));
        assert_eq!(
            effect.op.reason.as_deref(),
            Some("rotation policy quarterly")
        );
    }

    #[test]
    fn capability_grant_and_revoke_target_same_cell_family() {
        let space = "cx:space:0196419b-0000-7000-8000-000000000000";
        let granted = build_capability_grant_move(
            "did:web:admin.example",
            space,
            "cap.01abc",
            "discussion.message.create",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let revoked = build_capability_revoke_move(
            "did:web:admin.example",
            space,
            "cap.01abc",
            "discussion.message.create",
            None,
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        // Same cell subject — OrSet causal remove demands it.
        assert_eq!(
            granted.move_obj.effects[0].cell.as_str(),
            revoked.move_obj.effects[0].cell.as_str()
        );
        // Different op_type → different content-addressed move id.
        assert_ne!(
            granted.move_obj.id.as_str(),
            revoked.move_obj.id.as_str()
        );
    }

    #[test]
    fn member_state_builder_produces_fsm_transition() {
        let unsigned = build_member_state_transition_move(
            "did:web:admin.example",
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "did.web.alice.example",
            "invited",
            "join",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &unsigned.move_obj.effects[0];
        assert!(effect
            .cell
            .as_str()
            .starts_with("cx:cell:cx.component.member.state.v1:"));
        assert_eq!(effect.op.op_type, LatticeOpType::Transition);
        assert_eq!(
            effect.op.from.as_ref().and_then(|v| v.as_str()),
            Some("invited")
        );
        assert_eq!(
            effect.op.to.as_ref().and_then(|v| v.as_str()),
            Some("join")
        );
    }

    #[test]
    fn space_organization_builder_produces_cas_register_set() {
        let unsigned = build_space_organization_update_move(
            "did:web:admin.example",
            "cx:space:0196419b-0000-7000-8000-000000000000",
            serde_json::json!({"title": "Renamed", "owner": "did:web:admin.example"}),
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let effect = &unsigned.move_obj.effects[0];
        assert!(effect
            .cell
            .as_str()
            .starts_with("cx:cell:cx.component.space.organization.v1:"));
        assert_eq!(effect.op.op_type, LatticeOpType::Set);
        let value = effect.op.value.as_ref().expect("set op carries a value");
        assert_eq!(value.get("title").and_then(|v| v.as_str()), Some("Renamed"));
    }

    #[test]
    fn move_id_is_content_addressed_sha256_of_canonical_bytes() {
        let unsigned = build_consent_grant_move(
            "did:web:alice.example",
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cnt.01abc",
            "scope:contacts",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let recomputed: String = Sha256::digest(&unsigned.canonical_bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            unsigned.move_obj.id.as_str(),
            format!("cx:move:sha256:{recomputed}")
        );
    }

    #[test]
    fn signed_move_round_trip_verifies_with_dalek() {
        use ed25519_dalek::Verifier;
        let signing = SigningKey::from_bytes(&[19u8; 32]);
        let verifying = signing.verifying_key();
        let did = did_key_from_verifying_key(&verifying);
        let vm = did_key_verification_method(&verifying);

        let unsigned = build_consent_grant_move(
            &did,
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cnt.01abc",
            "scope:contacts",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let canonical_bytes = unsigned.canonical_bytes.clone();
        let signed = sign_unsigned_move(unsigned, &signing, &vm);
        // Reconstruct the JWS signing input the way a verifier would.
        let parts: Vec<&str> = signed.sig.jws.split('.').collect();
        assert_eq!(parts.len(), 3, "detached JWS has 3 segments");
        assert!(parts[1].is_empty(), "detached payload segment is empty");
        let header_b64 = parts[0];
        let signature_b64 = parts[2];
        let payload_b64 = URL_SAFE_NO_PAD.encode(&canonical_bytes);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature_bytes = URL_SAFE_NO_PAD.decode(signature_b64).unwrap();
        let signature_arr: [u8; 64] = signature_bytes.try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&signature_arr);
        // Real Ed25519 verify: must succeed for the matching public key.
        verifying
            .verify(signing_input.as_bytes(), &signature)
            .expect("signature should verify under matching pubkey");
    }

    #[test]
    fn did_key_verification_method_round_trips() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let verifying = signing.verifying_key();
        let did = did_key_from_verifying_key(&verifying);
        let vm = did_key_verification_method(&verifying);
        // verification_method should be `<did>#<multibase>`; the `#`
        // suffix matches the DID itself per did:key §3.
        let (prefix, frag) = vm.split_once('#').unwrap();
        assert_eq!(prefix, did);
        assert!(frag.starts_with('z'));
        assert_eq!(format!("{prefix}#{frag}"), vm);
    }
}
