//! First end-to-end UI Move-flow PoC.
//!
//! Wires a single user-facing button — "Grant consent" — to the
//! `move_builder` + `api::submit_move` infrastructure.
//! The flow is:
//!
//! 1. user types `consent_id` + `tag` in the form;
//! 2. on click, build a `cx.consent.grant` Move via
//!    [`crate::move_builder::build_consent_grant_move`];
//! 3. sign with a deterministic placeholder ed25519 key (yougen does not yet have OS keychain /
//!    WebAuthn / HSM key management — see `TODO(real-key-management)` below);
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

use crate::local_state::LocalStateStore;
use crate::views::helpers::{short_protocol_id, with_authed_api};

// NOTE: build_signed_consent_grant / build_signed_consent_revoke /
// build_signed_consent_revoke_v2 / format_submit_response and their
// helpers have been removed — the consent demo card now builds
// cx.consent.{grant,revoke} events via cx_ops::consent_grant / consent_revoke
// and submits them through cx.events.submit. The original Move-based
// helpers + their wire-shape tests are preserved in git history.

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
    let mut space_id = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut last_move_id = use_signal(String::new);

    rsx! {
        div { class: "event", "data-testid": "consent-grant-demo",
            div { class: "event-head",
                span { "Grant consent (Move PoC)" }
                span { "cx.consent.grant · cell-driven" }
            }
            div { class: "muted",
                "Submits a cx.consent.grant event via cx.events.submit; soland's reducer folds the OrSet add into the cx.component.consent.grant.v1 cell."
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
                        let actor_did = match state_store.write().ensure_local_identity() {
                            Ok(id) => id.device_did.as_str().to_owned(),
                            Err(err) => {
                                status.set(format!("Identity unavailable: {err}"));
                                return;
                            }
                        };
                        let envelope = crate::operation::cx_ops::consent_grant(
                            &space_val,
                            &actor_did,
                            &consent_val,
                            &tag_val,
                        )
                        .build("yougen");
                        let op_id = envelope.local_operation_id().to_owned();
                        last_move_id.set(op_id.clone());
                        spawn(async move {
                            match with_authed_api(&base, api_token, |api| async move {
                                api.submit_event_envelope(&envelope).await
                            })
                            .await
                            {
                                Ok(response) => status.set(format!(
                                    "cx.consent.grant event {} state=accepted",
                                    short_protocol_id(&response.event_id)
                                )),
                                Err(err) => status
                                    .set(format!(
                                        "submit {}: {}",
                                        short_protocol_id(&op_id),
                                        err.display()
                                    )),
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
                        let actor_did = match state_store.write().ensure_local_identity() {
                            Ok(id) => id.device_did.as_str().to_owned(),
                            Err(err) => {
                                status.set(format!("Identity unavailable: {err}"));
                                return;
                            }
                        };
                        let envelope = crate::operation::cx_ops::consent_revoke(
                            &space_val,
                            &actor_did,
                            &consent_val,
                            &tag_val,
                            Some("user revoked from settings UI"),
                            &[],
                        )
                        .build("yougen");
                        let op_id = envelope.local_operation_id().to_owned();
                        last_move_id.set(op_id.clone());
                        spawn(async move {
                            match with_authed_api(&base, api_token, |api| async move {
                                api.submit_event_envelope(&envelope).await
                            })
                            .await
                            {
                                Ok(response) => status.set(format!(
                                    "cx.consent.revoke event {} state=accepted",
                                    short_protocol_id(&response.event_id)
                                )),
                                Err(err) => status.set(format!(
                                    "submit revoke {}: {}",
                                    short_protocol_id(&op_id),
                                    err.display()
                                )),
                            }
                        });
                    },
                    "Revoke consent (OrSet remove)"
                }
            }
            if !last_move_id().is_empty() {
                {
                    let last_move_id_value = last_move_id();
                    let last_move_id_label = short_protocol_id(&last_move_id_value);
                    rsx! {
                        div { class: "muted", "data-testid": "consent-grant-last-move-id",
                            title: "{last_move_id_value}",
                            "Last move id: {last_move_id_label}"
                        }
                    }
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

            // Round R2/R3 (T17) — one-click "Revoke all consent"
            // (scope=any). Mounts a cascade view that enumerates every
            // subscope that will be cleared and a confirmation modal
            // that re-prints the cascade before the user commits.
            RevokeAllConsentCard {
                base_url: base_url,
                token: token,
                state_store: state_store,
            }
        }
    }
}

/// Round 4 (spec a77b995) — parse `observed_dots` from a textarea
/// (one `<actor_did>:<actor_seq>` per line). Lines where the suffix
/// after the last `:` does not parse as a `u64` are skipped. Returns
/// an empty Vec when the input has no parseable lines — the caller
/// MUST refuse to submit a cascade revoke in that case.
pub fn parse_observed_dots(raw: &str) -> Vec<contrix_sdk::Dot> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Split from the right because DIDs themselves contain `:`.
        let Some((did_part, seq_part)) = line.rsplit_once(':') else {
            continue;
        };
        let Ok(actor_seq) = seq_part.trim().parse::<u64>() else {
            continue;
        };
        let Ok(actor_id) = contrix_sdk::Did::new(did_part.trim()) else {
            continue;
        };
        out.push(contrix_sdk::Dot {
            actor_id,
            actor_seq,
        });
    }
    out
}

/// Convenience: count of parseable observed_dots for the UI badge.
/// Returns `None` when the input is empty so the caller can hide the
/// count chip.
pub fn parse_observed_dots_count(raw: &str) -> Option<usize> {
    if raw.trim().is_empty() {
        return None;
    }
    Some(parse_observed_dots(raw).len())
}

/// Round R2/R3 (T17) — known top-level consent subscopes the
/// `scope=any` revoke MUST cascade through. The list mirrors the
/// `consent_scope_registry.json` enum from the spec (Round R2/R3 add);
/// any subscope listed here is cleared in a single fanout when the
/// user confirms.
pub const CONSENT_REVOKE_CASCADE_SUBSCOPES: &[&str] = &[
    "scope:contacts",
    "scope:presence",
    "scope:typing",
    "scope:profile_public",
    "scope:read_receipts",
    "scope:media_thumbnails",
    "scope:applets",
    "scope:agents",
    "scope:federation_out",
    "scope:directory_listing",
];

/// Round R2/R3 (T17) — one-click "Revoke all consent" card with cascade
/// preview + confirmation modal. The card is rendered inside the consent
/// settings panel; activating the button shows the full subscope list
/// before the user can commit.
#[component]
pub fn RevokeAllConsentCard(
    base_url: Signal<String>,
    token: Signal<String>,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let mut confirming = use_signal(|| false);
    let mut status = use_signal(String::new);
    let mut consent_id = use_signal(|| "cnt.demo-01".to_owned());
    let mut space_id = use_signal(String::new);
    // Round 4 (spec a77b995) — observed_dots input. The user pastes
    // `actor_id:actor_seq` lines (one per dot) so the cascade revoke
    // tells the reducer exactly which observations it covers. Without
    // a populated list the reducer rejects the envelope with
    // `schema_violation`.
    let mut observed_dots_raw = use_signal(String::new);

    rsx! {
        div { class: "event", "data-testid": "revoke-all-consent-card",
            div { class: "event-head",
                span { "Revoke all consent (scope=any)" }
                span { class: "badge red", title: "cx.consent.revoke", "scope=any" }
            }
            div { class: "muted",
                "Revoking with scope=any submits one cx.consent.revoke event per subscope; soland's reducer collapses them into a single OrSet remove fanout. This is irreversible — the recipient must re-issue consent if you change your mind."
            }
            label { "Space ID" }
            input {
                "data-testid": "revoke-all-space-id",
                placeholder: "cx:space:...",
                value: "{space_id}",
                oninput: move |evt| space_id.set(evt.value()),
            }
            label { "Consent ID (cell subject)" }
            input {
                "data-testid": "revoke-all-consent-id",
                value: "{consent_id}",
                oninput: move |evt| consent_id.set(evt.value()),
            }
            div { class: "muted", "data-testid": "revoke-all-cascade-list",
                strong { "Subscopes that will be cleared:" }
                ul {
                    for scope in CONSENT_REVOKE_CASCADE_SUBSCOPES {
                        li { "{scope}" }
                    }
                }
            }
            // Round 4 — observed_dots input. The reducer rejects an
            // empty list with `schema_violation` so the user MUST
            // surface the observations they are revoking. One
            // `actor_id:actor_seq` per line; rendered straight into the
            // wire payload by `build_signed_consent_revoke_v2`.
            label {
                {crate::i18n::tr("consent.revoke.dot_list_header")}
            }
            textarea {
                "data-testid": "revoke-all-observed-dots",
                placeholder: "did:web:peer.example:42",
                value: "{observed_dots_raw}",
                oninput: move |evt| observed_dots_raw.set(evt.value()),
            }
            if let Some(parsed_count) = parse_observed_dots_count(&observed_dots_raw()) {
                div { class: "muted", "data-testid": "revoke-all-observed-dots-count",
                    "{parsed_count} observed dot(s) parsed"
                }
            }
            if confirming() {
                div {
                    class: "event",
                    "data-testid": "revoke-all-confirm-modal",
                    role: "alertdialog",
                    "aria-modal": "true",
                    div { class: "event-head",
                        span { "Confirm: revoke ALL consent" }
                    }
                    div { class: "muted",
                        "The following subscopes will be cleared (irreversible):"
                    }
                    ul { "data-testid": "revoke-all-confirm-cascade",
                        for scope in CONSENT_REVOKE_CASCADE_SUBSCOPES {
                            li { "{scope}" }
                        }
                    }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "revoke-all-confirm-submit",
                            onclick: move |_| {
                                let base = base_url();
                                let api_token = token();
                                let space_val = space_id().trim().to_owned();
                                let consent_val = consent_id().trim().to_owned();
                                if space_val.is_empty() || consent_val.is_empty() {
                                    status.set("Fill space_id and consent_id first".to_owned());
                                    return;
                                }
                                let actor_did = match state_store.write().ensure_local_identity() {
                                    Ok(id) => id.device_did.as_str().to_owned(),
                                    Err(err) => {
                                        status.set(format!("Identity unavailable: {err}"));
                                        return;
                                    }
                                };
                                // Build one cx.consent.revoke event per
                                // subscope. The server-side reducer collapses
                                // these into a single OrSet fanout under
                                // scope=any. TODO(round23-T17): once the SDK
                                // exposes a single scope=any revoke event,
                                // collapse the per-scope loop into one event.
                                let scopes: Vec<String> = CONSENT_REVOKE_CASCADE_SUBSCOPES
                                    .iter()
                                    .map(|s| (*s).to_owned())
                                    .collect();
                                let scope_count = scopes.len();
                                let observed_dots = parse_observed_dots(&observed_dots_raw());
                                if observed_dots.is_empty() {
                                    status.set(
                                        "Cascade revoke needs at least one observed dot \
                                         (round 4 schema_violation if omitted)."
                                            .to_owned(),
                                    );
                                    confirming.set(false);
                                    return;
                                }
                                spawn(async move {
                                    let mut succeeded = 0usize;
                                    for scope in &scopes {
                                        let envelope = crate::operation::cx_ops::consent_revoke(
                                            &space_val,
                                            &actor_did,
                                            &consent_val,
                                            scope,
                                            Some("scope=any cascade revoke"),
                                            &observed_dots,
                                        )
                                        .build("yougen");
                                        let base = base.clone();
                                        let api_token = api_token.clone();
                                        let outcome = with_authed_api(
                                            &base,
                                            api_token,
                                            |api| async move {
                                                api.submit_event_envelope(&envelope).await
                                            },
                                        )
                                        .await;
                                        if outcome.is_ok() {
                                            succeeded += 1;
                                        }
                                    }
                                    status.set(format!(
                                        "scope=any revoke submitted: {succeeded}/{scope_count} subscopes accepted"
                                    ));
                                });
                                confirming.set(false);
                            },
                            "Yes, revoke everything"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "revoke-all-confirm-cancel",
                            onclick: move |_| confirming.set(false),
                            "Cancel"
                        }
                    }
                }
            } else {
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "revoke-all-button",
                        onclick: move |_| confirming.set(true),
                        "Revoke ALL consent (scope=any)"
                    }
                }
            }
            if !status().is_empty() {
                div { class: "muted", "data-testid": "revoke-all-status", "{status}" }
            }
        }
    }
}

// (Move-flow test module removed; the OrSet/CAS wire shapes are now covered by soland's
// events.submit handler tests and the contrix-spec fixtures.)
