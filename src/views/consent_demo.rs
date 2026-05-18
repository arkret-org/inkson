//! First end-to-end UI Move-flow PoC.
//!
//! Wires a single user-facing button — "Grant consent" — to the
//! `move_builder` + `api::submit_move` infrastructure.
//! The flow is:
//!
//! 1. user types `consent_id` + `tag` in the form;
//! 2. on click, build a `cx.consent.grant` Move via
//!    [`crate::move_builder::build_consent_grant_move`];
//! 3. sign with a deterministic placeholder ed25519 key (yougen does
//!    not yet have OS keychain / WebAuthn / HSM key management — see
//!    `TODO(real-key-management)` below);
//! 4. POST to soland via [`crate::api::ContrixApi::submit_move`];
//! 5. render the response (`pending` / `rejected` + reason) in the UI.
//!
//! This view intentionally does NOT replace yougen's direct-event
//! endpoints for messages / reactions / read markers / entities /
//! relations / redactions — per spec event-kind-registry, only events
//! that declare a `cell_family` use the Move/Anchor path. The demo's
//! purpose is to prove the wire path works for ONE such event
//! (`cx.consent.grant`); follow-up tasks port member admin / space
//! organization / capability / etc. UIs to the same pattern.

use dioxus::prelude::*;
#[cfg(test)]
use ed25519_dalek::SigningKey;

use crate::{
    hlc::Hlc,
    local_state::{LocalIdentity, LocalStateStore},
    models::SubmitMoveResponse,
    move_builder::{
        UnsignedMove, build_consent_grant_move, build_consent_revoke_move,
        did_key_verification_method, sign_unsigned_move,
    },
    views::helpers::with_authed_api,
};

/// Sentinel anchor reference used when the local store hasn't seen any
/// Anchor view yet (`/sync` projection didn't carry an `anchor_view`
/// field). SHA-256 of empty bytes — soland's MoveStore accepts this as
/// the "no predecessor" tag for tests / first-Move-in-Space scenarios.
///
/// Kept as a public constant for tests; production UI callers now pull the
/// resolved anchor_ref from [`LocalStateStore::anchor_ref_for_move`], which
/// threads in the latest frontier head when sync has surfaced one.
#[cfg(test)]
pub(crate) const PLACEHOLDER_ANCHOR_REF: &str =
    "cx:anchor:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Test-only deterministic signing key used by unit tests so vectors stay
/// reproducible across runs. UI builders load the persisted
/// [`LocalIdentity`] from the local state store instead; tests still want
/// a stable key so per-content-address assertions don't depend on
/// `getrandom`.
#[cfg(test)]
pub(crate) fn demo_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

/// Adapter for tests: build an in-memory [`LocalIdentity`] from a fixed
/// signing key. Production UI uses
/// [`LocalStateStore::ensure_local_identity`] to load+persist the
/// per-device key; this helper centralises the verifying-key → did:key
/// derivation so callers don't have to reach back into `move_builder`.
#[cfg(test)]
fn identity_from_signing_key(signing_key: SigningKey) -> LocalIdentity {
    let verifying = signing_key.verifying_key();
    let device_did = crate::move_builder::did_key_from_verifying_key(&verifying);
    LocalIdentity {
        device_did,
        signing_key,
    }
}

/// Pure helper: turn the form values into a signed `Move` ready for
/// submission. Splitting this out keeps the Dioxus closure tiny and
/// — crucially — makes it unit-testable without spawning an event loop
/// or HTTP client.
///
/// Takes a [`LocalIdentity`] borrow. UI callers thread in the result of
/// `state_store.write().ensure_local_identity()`; tests pass an
/// `identity_from_signing_key(demo_signing_key())` so vectors stay stable.
pub(crate) fn build_signed_consent_grant(
    identity: &LocalIdentity,
    space_id: &str,
    consent_id: &str,
    tag: &str,
    anchor_ref: &str,
    hlc: &str,
) -> anyhow::Result<contrix_sdk::Move> {
    let did = identity.device_did.as_str();
    let vm = did_key_verification_method(&identity.signing_key.verifying_key());
    let unsigned: UnsignedMove =
        build_consent_grant_move(did, space_id, consent_id, tag, anchor_ref, hlc)?;
    Ok(sign_unsigned_move(unsigned, &identity.signing_key, &vm))
}

/// Pure helper: build + sign a `cx.consent.revoke` Move (OrSet remove).
/// Mirror of [`build_signed_consent_grant`] for the revoke path. Splitting
/// it out keeps the Dioxus closure tiny and unit-testable.
pub(crate) fn build_signed_consent_revoke(
    identity: &LocalIdentity,
    space_id: &str,
    consent_id: &str,
    tag: &str,
    reason: Option<&str>,
    anchor_ref: &str,
    hlc: &str,
) -> anyhow::Result<contrix_sdk::Move> {
    let did = identity.device_did.as_str();
    let vm = did_key_verification_method(&identity.signing_key.verifying_key());
    let unsigned: UnsignedMove =
        build_consent_revoke_move(did, space_id, consent_id, tag, reason, anchor_ref, hlc)?;
    Ok(sign_unsigned_move(unsigned, &identity.signing_key, &vm))
}

/// Pure helper: format a `SubmitMoveResponse` for the status-line UI.
/// Tested independently so we can lock the wording without booting
/// Dioxus.
pub(crate) fn format_submit_response(response: &SubmitMoveResponse) -> String {
    match response.reason.as_deref() {
        Some(reason) if !reason.is_empty() => format!(
            "Move {}: state={} reason={}",
            response.move_id, response.state, reason
        ),
        _ => format!("Move {}: state={}", response.move_id, response.state),
    }
}

/// The consent-grant demo card. Rendered inside the Privacy section of
/// the SettingsPanel. Self-contained: owns its own form state + status
/// signal, only needs `base_url` / `token` / `space_id` from the parent.
#[component]
pub fn ConsentGrantDemoCard(
    base_url: Signal<String>,
    token: Signal<String>,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let mut consent_id = use_signal(|| "cnt.demo-01".to_owned());
    let mut tag = use_signal(|| "scope:contacts".to_owned());
    let mut space_id = use_signal(|| String::new());
    let mut status = use_signal(|| String::new());
    let mut last_move_id = use_signal(|| String::new());

    rsx! {
        div { class: "event", "data-testid": "consent-grant-demo",
            div { class: "event-head",
                span { "Grant consent (Move PoC)" }
                span { "cx.consent.grant · cell-driven" }
            }
            div { class: "muted",
                "Constructs a cx.consent.grant Move on the cx.component.consent.grant.v1 OrSet cell, signs it with a deterministic demo ed25519 key (TODO real-key-management), and POSTs /api/v1/moves. Non-cell writes such as messages and reactions use /api/v1/events."
            }
            label { "Space ID" }
            input {
                "data-testid": "consent-grant-space-id",
                placeholder: "cx:space:...",
                value: "{space_id}",
                oninput: move |evt| space_id.set(evt.value()),
            }
            label { "Consent ID (cell subject)" }
            input {
                "data-testid": "consent-grant-consent-id",
                value: "{consent_id}",
                oninput: move |evt| consent_id.set(evt.value()),
            }
            label { "Tag (OrSet add)" }
            input {
                "data-testid": "consent-grant-tag",
                value: "{tag}",
                oninput: move |evt| tag.set(evt.value()),
            }
            div { class: "actions",
                button {
                    class: "primary",
                    "data-testid": "consent-grant-submit",
                    onclick: move |_| {
                        let base = base_url();
                        let api_token = token();
                        let space_val = space_id().trim().to_owned();
                        let consent_val = consent_id().trim().to_owned();
                        let tag_val = tag().trim().to_owned();
                        if space_val.is_empty() || consent_val.is_empty() || tag_val.is_empty() {
                            status.set(
                                "Fill space_id / consent_id / tag before submitting".to_owned(),
                            );
                            return;
                        }
                        let hlc = Hlc::now("yougen").to_string();
                        let anchor_ref = state_store.read().anchor_ref_for_move(&space_val);
                        let identity = match state_store.write().ensure_local_identity() {
                            Ok(id) => id,
                            Err(err) => {
                                status.set(format!("Identity unavailable: {err}"));
                                return;
                            }
                        };
                        let signed = match build_signed_consent_grant(
                            &identity,
                            &space_val,
                            &consent_val,
                            &tag_val,
                            &anchor_ref,
                            &hlc,
                        ) {
                            Ok(m) => m,
                            Err(error) => {
                                status.set(format!("Build move failed: {error}"));
                                return;
                            }
                        };
                        let move_id = signed.id.as_str().to_owned();
                        last_move_id.set(move_id.clone());
                        spawn(async move {
                            match with_authed_api(&base, api_token, |api| async move {
                                api.submit_move(&signed).await
                            })
                            .await
                            {
                                Ok(response) => status.set(format_submit_response(&response)),
                                Err(err) => status
                                    .set(format!("submit_move {move_id}: {}", err.display())),
                            }
                        });
                    },
                    "Grant consent (build + sign + POST)"
                }
                button {
                    class: "secondary",
                    "data-testid": "consent-revoke-submit",
                    onclick: move |_| {
                        let base = base_url();
                        let api_token = token();
                        let space_val = space_id().trim().to_owned();
                        let consent_val = consent_id().trim().to_owned();
                        let tag_val = tag().trim().to_owned();
                        if space_val.is_empty() || consent_val.is_empty() || tag_val.is_empty() {
                            status.set(
                                "Fill space_id / consent_id / tag before submitting".to_owned(),
                            );
                            return;
                        }
                        let hlc = Hlc::now("yougen").to_string();
                        let anchor_ref = state_store.read().anchor_ref_for_move(&space_val);
                        let identity = match state_store.write().ensure_local_identity() {
                            Ok(id) => id,
                            Err(err) => {
                                status.set(format!("Identity unavailable: {err}"));
                                return;
                            }
                        };
                        let signed = match build_signed_consent_revoke(
                            &identity,
                            &space_val,
                            &consent_val,
                            &tag_val,
                            Some("user revoked from settings UI"),
                            &anchor_ref,
                            &hlc,
                        ) {
                            Ok(m) => m,
                            Err(error) => {
                                status.set(format!("Build revoke move failed: {error}"));
                                return;
                            }
                        };
                        let move_id = signed.id.as_str().to_owned();
                        last_move_id.set(move_id.clone());
                        spawn(async move {
                            match with_authed_api(&base, api_token, |api| async move {
                                api.submit_move(&signed).await
                            })
                            .await
                            {
                                Ok(response) => status.set(format_submit_response(&response)),
                                Err(err) => status.set(format!(
                                    "submit_move (revoke) {move_id}: {}",
                                    err.display()
                                )),
                            }
                        });
                    },
                    "Revoke consent (OrSet remove)"
                }
            }
            if !last_move_id().is_empty() {
                div { class: "muted", "data-testid": "consent-grant-last-move-id",
                    "Last move id: {last_move_id}"
                }
            }
            if !status().is_empty() {
                div { class: "muted", "data-testid": "consent-grant-status",
                    "{status}"
                }
            }
            div { class: "muted",
                "Signing key is the per-device ed25519 key persisted in local_state (LocalIdentity). TODO(secure-key-store-handoff): production deploys must move this seed into OS keychain / WebAuthn / HSM. TODO(anchor-frontier-from-sync): plumb the latest Anchor head from sync.rs."
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::move_builder::did_key_from_verifying_key;
    use contrix_sdk::LatticeOpType;

    fn fixed_anchor_ref() -> &'static str {
        PLACEHOLDER_ANCHOR_REF
    }

    fn fixed_hlc() -> &'static str {
        "0189c4d2af00-00000000-aabbccdd"
    }

    /// Test-only stable identity built from `demo_signing_key()`. Used by
    /// per-content-address assertions that need bit-identical move ids
    /// across runs — production callers thread in
    /// `state_store.write().ensure_local_identity()` instead.
    fn fixed_identity() -> LocalIdentity {
        identity_from_signing_key(demo_signing_key())
    }

    /// The form-to-Move helper builds a Move with exactly the consent
    /// OrSet add effect the spec requires: cell prefix
    /// `cx:cell:cx.component.consent.grant.v1:`, op type `add`, op tag
    /// matching the form's tag input.
    #[test]
    fn build_signed_consent_grant_produces_consent_or_set_add() {
        let space = "cx:space:0196419b-0000-7000-8000-000000000000";
        let identity = fixed_identity();
        let signed = build_signed_consent_grant(
            &identity,
            space,
            "cnt.demo-01",
            "scope:contacts",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        assert_eq!(signed.space_id.as_str(), space);
        assert_eq!(signed.effects.len(), 1);
        let effect = &signed.effects[0];
        assert!(
            effect
                .cell
                .as_str()
                .starts_with("cx:cell:cx.component.consent.grant.v1:"),
            "consent grant must target the consent.grant.v1 cell family"
        );
        assert_eq!(effect.op.op_type, LatticeOpType::Add);
        assert_eq!(effect.op.tag.as_deref(), Some("scope:contacts"));
        // Issuer DID matches the identity's device_did (round-tripped from
        // the verifying key).
        let expected_did = did_key_from_verifying_key(&identity.signing_key.verifying_key());
        assert_eq!(signed.issuer.as_str(), expected_did);
        assert_eq!(signed.issuer.as_str(), identity.device_did);
    }

    /// The signed Move's `sig.jws` is a non-empty detached JWS with the
    /// expected three-segment shape (`<header>..<sig>` with empty
    /// payload), and the verification_method points at the demo did:key.
    #[test]
    fn build_signed_consent_grant_attaches_detached_jws_with_demo_did_key() {
        let identity = fixed_identity();
        let signed = build_signed_consent_grant(
            &identity,
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cnt.demo-01",
            "scope:contacts",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let jws = &signed.sig.jws;
        assert!(!jws.is_empty(), "sign_unsigned_move must populate jws");
        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3, "detached JWS has 3 segments");
        assert!(
            parts[1].is_empty(),
            "middle (payload) segment must be empty for detached JWS"
        );
        let expected_vm = did_key_verification_method(&identity.signing_key.verifying_key());
        assert_eq!(signed.sig.verification_method, expected_vm);
        assert_eq!(signed.sig.alg, "EdDSA");
    }

    /// Status-line formatter: bare state when no reason, state + reason
    /// when soland rejected the Move with a structural reason.
    #[test]
    fn format_submit_response_renders_state_and_optional_reason() {
        let pending = SubmitMoveResponse {
            move_id: "sha256:abc".to_owned(),
            state: "pending".to_owned(),
            reason: None,
        };
        assert_eq!(
            format_submit_response(&pending),
            "Move sha256:abc: state=pending"
        );
        let rejected = SubmitMoveResponse {
            move_id: "sha256:def".to_owned(),
            state: "rejected".to_owned(),
            reason: Some("anchor_ref unknown".to_owned()),
        };
        assert_eq!(
            format_submit_response(&rejected),
            "Move sha256:def: state=rejected reason=anchor_ref unknown"
        );
        // Empty-string reason should be treated as None — soland's DTO
        // skips serializing None but a defensive client must still cope
        // if a deployment emits "" for "no reason".
        let rejected_blank = SubmitMoveResponse {
            move_id: "sha256:ghi".to_owned(),
            state: "rejected".to_owned(),
            reason: Some(String::new()),
        };
        assert_eq!(
            format_submit_response(&rejected_blank),
            "Move sha256:ghi: state=rejected"
        );
    }

    /// Revoke helper builds a `cx.consent.revoke`-shaped Move on the
    /// SAME OrSet cell as the grant, with op_type=Remove and the given
    /// reason. This is the second user-facing button on the Move/Anchor
    /// pipeline — a counterpart to the grant button so users can drop a
    /// consent without touching server admin UIs.
    #[test]
    fn build_signed_consent_revoke_produces_consent_or_set_remove() {
        let space = "cx:space:0196419b-0000-7000-8000-000000000000";
        let identity = fixed_identity();
        let signed = build_signed_consent_revoke(
            &identity,
            space,
            "cnt.demo-01",
            "scope:contacts",
            Some("user revoked from settings UI"),
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        assert_eq!(signed.space_id.as_str(), space);
        assert_eq!(signed.effects.len(), 1);
        let effect = &signed.effects[0];
        // Same cell family / subject as the grant — OrSet causal remove
        // requires it.
        assert!(
            effect
                .cell
                .as_str()
                .starts_with("cx:cell:cx.component.consent.grant.v1:"),
            "consent revoke targets the same OrSet cell as the grant"
        );
        assert_eq!(effect.op.op_type, LatticeOpType::Remove);
        assert_eq!(effect.op.tag.as_deref(), Some("scope:contacts"));
        assert_eq!(
            effect.op.reason.as_deref(),
            Some("user revoked from settings UI")
        );
        // Issuer matches the identity's device_did.
        assert_eq!(signed.issuer.as_str(), identity.device_did);
    }

    /// Grant + revoke on the same form values produce DIFFERENT move ids
    /// (the canonical effect op_type differs). This is the property soland
    /// uses to distinguish OrSet add from OrSet remove on the same tag.
    #[test]
    fn grant_and_revoke_have_distinct_content_addresses() {
        let space = "cx:space:0196419b-0000-7000-8000-000000000000";
        let identity = fixed_identity();
        let granted = build_signed_consent_grant(
            &identity,
            space,
            "cnt.demo-01",
            "scope:contacts",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let revoked = build_signed_consent_revoke(
            &identity,
            space,
            "cnt.demo-01",
            "scope:contacts",
            None,
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        assert_ne!(granted.id.as_str(), revoked.id.as_str());
    }

    /// Move id is content-addressed: building twice with the same form
    /// values + anchor_ref + hlc yields the same `sha256:...`
    /// id. This is the property soland's idempotency relies on.
    #[test]
    fn build_signed_consent_grant_is_content_addressed_by_canonical_bytes() {
        let space = "cx:space:0196419b-0000-7000-8000-000000000000";
        let identity = fixed_identity();
        let one = build_signed_consent_grant(
            &identity,
            space,
            "cnt.demo-01",
            "scope:contacts",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let two = build_signed_consent_grant(
            &identity,
            space,
            "cnt.demo-01",
            "scope:contacts",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        assert_eq!(one.id.as_str(), two.id.as_str());
        assert!(one.id.as_str().starts_with("sha256:"));
    }

    /// Two freshly-generated identities sign the same form values and the
    /// resulting Move ids differ — proves the per-device key actually
    /// participates in the canonical hash (round-trip via `getrandom::fill`).
    /// This is the property a real key store needs to preserve: rotating a
    /// device's key changes the issuer, which changes the content address.
    #[test]
    fn distinct_identities_produce_distinct_move_ids() {
        let id_a = LocalIdentity::generate().unwrap();
        let id_b = LocalIdentity::generate().unwrap();
        assert_ne!(id_a.device_did, id_b.device_did);
        let space = "cx:space:0196419b-0000-7000-8000-000000000000";
        let move_a = build_signed_consent_grant(
            &id_a,
            space,
            "cnt.demo-01",
            "scope:contacts",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        let move_b = build_signed_consent_grant(
            &id_b,
            space,
            "cnt.demo-01",
            "scope:contacts",
            fixed_anchor_ref(),
            fixed_hlc(),
        )
        .unwrap();
        assert_ne!(move_a.id.as_str(), move_b.id.as_str());
        assert_eq!(move_a.issuer.as_str(), id_a.device_did);
        assert_eq!(move_b.issuer.as_str(), id_b.device_did);
    }
}
