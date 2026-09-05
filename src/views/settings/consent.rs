//! Holder-private consent settings surface (`/settings/consent`).
//!
//! Spec `identity/consent-model.md` §2-§4. Consent is a holder-private
//! decision, orthogonal to capability + membership: the holder grants or
//! revokes scoped permission for a peer to initiate a contact action
//! (`direct_message` / `invite` / `voice_call`). The cells are read from the
//! holder-private projection at `/_arkret/self/consent/cells` and mutated via
//! the `grant` / `revoke` / `request` self-plane commands.
//!
//! Surfaces (testids consumed by `cotest/e2e/.../consent-grant.spec.ts`):
//! - `consent-settings-panel` wrapper
//! - `consent-grant-empty` empty state
//! - direct grant form: `consent-new-grant-button` toggle, `consent-new-grant-scope-input`,
//!   `consent-new-grant-grantee-input`, `consent-new-grant-grantee-station-input`,
//!   `consent-new-grant-ttl-input`, `consent-new-grant-submit-button`
//! - opaque outbound request: `consent-request-button`, `consent-request-scope-input`,
//!   `consent-request-holder-input`, `consent-request-submit-button`
//! - pending list: `consent-pending-row`, `consent-detail-button`, `consent-pending-detail`,
//!   `consent-scope-select`, `consent-valid-until-input`, `grant-consent-button`
//! - granted list: `consent-granted-row`, `revoke-consent-button`
//! - `write-status` shared write feedback line.

use dioxus::prelude::*;

use crate::i18n::tr;
use crate::transport::auth::with_authed_sdk_client;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::select::{Select, SelectOption};

/// One consent cell row distilled from the holder-private projection.
#[derive(Clone, Debug, PartialEq)]
struct ConsentRow {
    holder: String,
    /// The exact closed `consent_peer` this cell froze, kept typed.
    ///
    /// Spec `zh/identity/consent-model.md` section 6.1 query step 1: the two
    /// kinds are separate identities that never match each other, and an
    /// ordinary Account peer is identified by its complete ActorId. Flattening
    /// a row to a bare DID would collide a Realm-local pairwise peer with an
    /// Account that happens to share its principal core, and would make every
    /// later grant / revoke this row drives address the wrong cell.
    peer: arkret_sdk::ConsentPeer,
    /// Kind-qualified row key: the exact wire form of [`ConsentRow::peer`].
    peer_key: String,
    /// Human label. Always contains the peer principal, plus the rest of the
    /// identity that makes it exact.
    peer_label: String,
    /// Wire scope (`direct_message` / `invite` / `voice_call` / ...).
    scope: String,
    /// Effective state: `active` / `pending` / `revoked`.
    state: String,
    expires_at: Option<String>,
}

/// Readable, kind-qualified label for one consent peer.
fn consent_peer_label(peer: &arkret_sdk::ConsentPeer) -> String {
    match peer {
        arkret_sdk::ConsentPeer::Actor { actor_id } => match actor_id {
            arkret_sdk::ActorId::Account { account_id } => format!(
                "{} @ {}",
                account_id.principal_id.as_str(),
                account_id.station_id.as_str()
            ),
            arkret_sdk::ActorId::Service { service_id } => {
                format!("service {}", service_id.as_str())
            }
        },
        arkret_sdk::ConsentPeer::PairwisePrincipal {
            realm_id,
            principal_id,
        } => format!(
            "pairwise {} in realm {}",
            principal_id.as_str(),
            realm_id.as_str()
        ),
    }
}

/// Whether this peer is the holder itself, per kind.
///
/// A Realm-local ephemeral pairwise actor is never the holder Account, so the
/// question only has an answer on the actor branch.
fn consent_peer_is_holder(peer: &arkret_sdk::ConsentPeer, holder_principal_id: &str) -> bool {
    match peer {
        arkret_sdk::ConsentPeer::Actor { actor_id } => {
            actor_id.signing_principal_id().as_str() == holder_principal_id
        }
        arkret_sdk::ConsentPeer::PairwisePrincipal { .. } => false,
    }
}

/// Map a wire scope to the UI scope token used by the scope `Select`
/// (`message` ↔ `direct_message`, `call` ↔ `voice_call`).
fn wire_scope_to_ui(scope: &str) -> &'static str {
    match scope {
        "direct_message" => "message",
        "voice_call" => "call",
        "invite" => "invite",
        "video_call" => "video_call",
        "presence" => "presence",
        _ => "message",
    }
}

/// Map a UI scope token back to its wire scope.
fn ui_scope_to_wire(scope: &str) -> &'static str {
    match scope {
        "message" => "direct_message",
        "call" => "voice_call",
        "invite" => "invite",
        "video_call" => "video_call",
        "presence" => "presence",
        _ => "direct_message",
    }
}

/// Human label for a wire scope.
fn scope_label(scope: &str) -> &'static str {
    match scope {
        "direct_message" => "Direct messages",
        "invite" => "Group invites",
        "voice_call" => "Voice calls",
        "video_call" => "Video calls",
        "presence" => "Presence",
        _ => "Contact",
    }
}

/// Parse a TTL token such as `30d` / `12h` / `90m` / `5s` into a duration. Returns
/// `None` for an empty / unparseable value (treated as no expiry window).
fn parse_ttl(raw: &str) -> Option<chrono::Duration> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let (digits, unit) = raw.split_at(raw.find(|c: char| !c.is_ascii_digit()).unwrap_or(raw.len()));
    let amount: i64 = digits.parse().ok()?;
    match unit.trim() {
        "" | "d" | "D" => Some(chrono::Duration::days(amount)),
        "h" | "H" => Some(chrono::Duration::hours(amount)),
        "m" | "M" => Some(chrono::Duration::minutes(amount)),
        "s" | "S" => Some(chrono::Duration::seconds(amount)),
        "w" | "W" => Some(chrono::Duration::weeks(amount)),
        _ => None,
    }
}

/// Parse an absolute RFC 3339 `valid_until` timestamp into a UTC datetime.
fn parse_valid_until(raw: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

fn parse_consent_rows(value: &arkret_sdk::ConsentCellList, holder: &str) -> Vec<ConsentRow> {
    value
        .consent_cell_views
        .iter()
        .map(|cell| ConsentRow {
            // The self list endpoint is holder-scoped; ConsentCellView
            // deliberately does not mirror that authenticated holder.
            holder: holder.to_owned(),
            peer: cell.peer.clone(),
            peer_key: serde_json::to_string(&cell.peer).unwrap_or_default(),
            peer_label: consent_peer_label(&cell.peer),
            scope: cell.consent_scope.as_str().to_owned(),
            state: match cell.state {
                arkret_sdk::ConsentState::Active => "active",
                arkret_sdk::ConsentState::NoConsent if !cell.revoked_dots.is_empty() => "revoked",
                arkret_sdk::ConsentState::NoConsent => "pending",
            }
            .to_owned(),
            expires_at: cell
                .expires_at
                .map(arkret_sdk::canonical::format_timestamp_canonical),
        })
        .collect()
}

#[component]
pub fn ConsentSettingsPanel(principal_id: Signal<String>, token: Signal<String>) -> Element {
    // A4 — base_url from session context instead of a prop.
    let active_account = crate::app::SessionContext::get().active_account;
    let base_url = use_signal(move || {
        active_account()
            .map(|account| account.server_url.to_string())
            .unwrap_or_default()
    });
    let mut rows = use_signal(Vec::<ConsentRow>::new);
    let mut load_error = use_signal(|| Option::<String>::None);
    let mut reload = use_signal(|| 0_u32);
    let mut loaded_generation = use_signal(|| u32::MAX);
    let mut write_status = use_signal(String::new);

    // Direct-grant form state.
    let mut grant_form_open = use_signal(|| false);
    let mut grant_scope = use_signal(|| "message".to_owned());
    let grant_scope_selected = use_memo(move || Some(grant_scope()));
    let mut grant_grantee = use_signal(String::new);
    // The actor branch is matched on the complete ActorId, so the grantee's
    // own Station is part of what is being granted, not an implicit local
    // default. Blank means "hosted by this Station".
    let mut grant_grantee_station = use_signal(String::new);
    let mut grant_ttl = use_signal(|| "30d".to_owned());

    // Outbound-request form state.
    let mut request_form_open = use_signal(|| false);
    let mut request_scope = use_signal(|| "message".to_owned());
    let request_scope_selected = use_memo(move || Some(request_scope()));
    let mut request_holder = use_signal(String::new);

    // Open pending-detail editor, keyed by `(peer_key, scope)` — the exact
    // wire peer, so two kinds sharing a principal core never share a row.
    let mut detail_open = use_signal(|| Option::<(String, String)>::None);
    let mut detail_scope = use_signal(|| "message".to_owned());
    let detail_scope_selected = use_memo(move || Some(detail_scope()));
    let mut detail_valid_until = use_signal(String::new);

    let mut busy = use_signal(|| false);

    // Load consent cells on mount and whenever `reload` ticks.
    {
        let base = base_url();
        use_effect(move || {
            let generation = reload();
            if loaded_generation() == generation {
                return;
            }
            let api_token = token();
            if api_token.trim().is_empty() {
                return;
            }
            loaded_generation.set(generation);
            let base = base.clone();
            let holder = principal_id();
            load_error.set(None);
            spawn(async move {
                match with_authed_sdk_client(&base, api_token, |http| async move {
                    crate::transport::account::consent_cells(&http).await
                })
                .await
                {
                    Ok(list) => {
                        rows.set(parse_consent_rows(&list, &holder));
                    }
                    Err(err) => {
                        load_error.set(Some(err.display()));
                    }
                }
            });
        });
    }

    let me = principal_id();
    let all_rows = rows.read().clone();
    let pending_rows: Vec<ConsentRow> = all_rows
        .iter()
        .filter(|row| {
            row.holder == me && !consent_peer_is_holder(&row.peer, &me) && row.state == "pending"
        })
        .cloned()
        .collect();
    let granted_rows: Vec<ConsentRow> = all_rows
        .iter()
        .filter(|row| row.holder == me && row.state == "active")
        .cloned()
        .collect();
    let show_empty = !grant_form_open() && pending_rows.is_empty() && granted_rows.is_empty();

    let grant_submit_disabled = grant_grantee.read().trim().is_empty() || busy();
    let request_submit_disabled = request_holder.read().trim().is_empty() || busy();

    rsx! {
        div { class: "settings", "data-testid": "consent-settings-panel",
            div { class: "settings-shell",
                section { class: "settings-content-stack",
                    div { class: "event",
                        div { class: "event-head",
                            span { "Consent" }
                            div { class: "actions",
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "consent-new-grant-button",
                                    onclick: move |_| {
                                        let next = !grant_form_open();
                                        grant_form_open.set(next);
                                    },
                                    "Grant consent"
                                }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "consent-request-button",
                                    onclick: move |_| {
                                        let next = !request_form_open();
                                        request_form_open.set(next);
                                    },
                                    "Request consent"
                                }
                            }
                        }
                        div { class: "muted",
                            "Decide who may message, invite, or call you. Consent is a "
                            "private decision — it does not grant any group membership."
                        }

                        if let Some(message) = load_error.read().clone() {
                            div {
                                class: "event error-banner",
                                "data-testid": "consent-load-error",
                                div { class: "muted", "Couldn't load consent: {message}" }
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "consent-retry-button",
                                        onclick: move |_| reload.set(reload() + 1),
                                        "Retry"
                                    }
                                }
                            }
                        }

                        if show_empty {
                            div {
                                class: "members-empty",
                                "data-testid": "consent-grant-empty",
                                div { class: "members-empty-title", "No consent decisions yet" }
                                div { class: "muted members-empty-hint",
                                    "Grant consent directly, or ask someone for consent."
                                }
                            }
                        }
                    }

                    // ── Direct grant form ───────────────────────────────────
                    if grant_form_open() {
                        div { class: "event", "data-testid": "consent-new-grant-form",
                            div { class: "event-head", span { "Grant consent" } }
                            div { class: "field",
                                Label { html_for: "consent-new-grant-scope", "Scope" }
                                Select::<String> {
                                    id: "consent-new-grant-scope",
                                    "data-testid": "consent-new-grant-scope-input",
                                    value: Some(grant_scope_selected.into()),
                                    on_value_change: move |v: Option<String>| {
                                        if let Some(v) = v {
                                            grant_scope.set(v);
                                        }
                                    },
                                    SelectOption::<String> { index: 0usize, value: "message".to_string(), text_value: "Direct messages", "Direct messages" }
                                    SelectOption::<String> { index: 1usize, value: "invite".to_string(), text_value: "Group invites", "Group invites" }
                                    SelectOption::<String> { index: 2usize, value: "call".to_string(), text_value: "Calls", "Calls" }
                                }
                            }
                            div { class: "field",
                                Label { html_for: "consent-new-grant-grantee-input-input", "Grantee DID" }
                                Input {
                                    id: "consent-new-grant-grantee-input-input",
                                    "data-testid": "consent-new-grant-grantee-input",
                                    value: "{grant_grantee}",
                                    placeholder: "did:web:bob.example",
                                    oninput: move |event: FormEvent| grant_grantee.set(event.value()),
                                }
                            }
                            div { class: "field",
                                Label { html_for: "consent-new-grant-grantee-station-input-input", {tr("consent.grant.grantee_station_label")} }
                                Input {
                                    id: "consent-new-grant-grantee-station-input-input",
                                    "data-testid": "consent-new-grant-grantee-station-input",
                                    value: "{grant_grantee_station}",
                                    placeholder: "did:web:soland.example",
                                    oninput: move |event: FormEvent| grant_grantee_station.set(event.value()),
                                }
                            }
                            div { class: "field",
                                Label { html_for: "consent-new-grant-ttl-input-input", "Valid for (e.g. 30d)" }
                                Input {
                                    id: "consent-new-grant-ttl-input-input",
                                    "data-testid": "consent-new-grant-ttl-input",
                                    value: "{grant_ttl}",
                                    placeholder: "30d",
                                    oninput: move |event: FormEvent| grant_ttl.set(event.value()),
                                }
                            }
                            div { class: "actions",
                                Button {
                                    variant: ButtonVariant::Primary,
                                    "data-testid": "consent-new-grant-submit-button",
                                    disabled: grant_submit_disabled,
                                    onclick: {
                                        let base = base_url();
                                        let holder = me.clone();
                                        move |_| {
                                            let base = base.clone();
                                            let api_token = token();
                                            let holder = holder.clone();
                                            let grantee = grant_grantee().trim().to_owned();
                                            let grantee_station = grant_grantee_station().trim().to_owned();
                                            let scope = ui_scope_to_wire(&grant_scope()).to_owned();
                                            let expires_at = parse_ttl(&grant_ttl())
                                                .map(|d| chrono::Utc::now() + d);
                                            if grantee.is_empty() {
                                                return;
                                            }
                                            // The form only ever authors the ordinary Account
                                            // branch. A Realm-local ephemeral pairwise peer is
                                            // never inferred from a typed DID; it reaches this
                                            // surface only as an existing cell's own peer.
                                            let peer = match crate::operation::ak_ops::consent_actor_peer(
                                                &grantee,
                                                Some(grantee_station.as_str()),
                                            ) {
                                                Ok(peer) => peer,
                                                Err(err) => {
                                                    write_status.set(format!("grant failed: {err}"));
                                                    return;
                                                }
                                            };
                                            busy.set(true);
                                            write_status.set("granting…".to_owned());
                                            spawn(async move {
                                                match with_authed_sdk_client(&base, api_token, |http| async move {
                                                    crate::transport::account::grant_consent(
                                                        &crate::event_submit::EventSubmitter::from_current_session(http),
                                                        &holder, &peer, &scope, expires_at,
                                                    ).await
                                                })
                                                .await
                                                {
                                                    Ok(_) => {
                                                        write_status.set("consent granted".to_owned());
                                                        grant_form_open.set(false);
                                                        grant_grantee.set(String::new());
                                                        grant_grantee_station.set(String::new());
                                                        reload.set(reload() + 1);
                                                    }
                                                    Err(err) => {
                                                        write_status.set(format!("grant failed: {}", err.display()));
                                                    }
                                                }
                                                busy.set(false);
                                            });
                                        }
                                    },
                                    "Grant"
                                }
                            }
                        }
                    }

                    // ── Outbound request form ───────────────────────────────
                    if request_form_open() {
                        div { class: "event", "data-testid": "consent-request-form",
                            div { class: "event-head", span { "Request consent" } }
                            div { class: "field",
                                Label { html_for: "consent-request-scope", "Scope" }
                                Select::<String> {
                                    id: "consent-request-scope",
                                    "data-testid": "consent-request-scope-input",
                                    value: Some(request_scope_selected.into()),
                                    on_value_change: move |v: Option<String>| {
                                        if let Some(v) = v {
                                            request_scope.set(v);
                                        }
                                    },
                                    // `consent_request_request_body.consent_scope` is the
                                    // section 4 enum minus `invite`: an invite-scope
                                    // request would have to become a holder_quarantine
                                    // entry whose surface_kind is consent_request, and
                                    // that branch pins the scope away from invite. The
                                    // grant form above still offers it, because a grant
                                    // may cover the invite scope.
                                    SelectOption::<String> { index: 0usize, value: "message".to_string(), text_value: "Direct messages", "Direct messages" }
                                    SelectOption::<String> { index: 1usize, value: "call".to_string(), text_value: "Calls", "Calls" }
                                    SelectOption::<String> { index: 2usize, value: "presence".to_string(), text_value: "Presence", "Presence" }
                                }
                            }
                            div { class: "field",
                                Label { html_for: "consent-request-holder-input-input", "Holder DID" }
                                Input {
                                    id: "consent-request-holder-input-input",
                                    "data-testid": "consent-request-holder-input",
                                    value: "{request_holder}",
                                    placeholder: "did:web:bob.example",
                                    oninput: move |event: FormEvent| request_holder.set(event.value()),
                                }
                            }
                            div { class: "actions",
                                Button {
                                    variant: ButtonVariant::Primary,
                                    "data-testid": "consent-request-submit-button",
                                    disabled: request_submit_disabled,
                                    onclick: {
                                        let base = base_url();
                                        move |_| {
                                            let base = base.clone();
                                            let api_token = token();
                                            let holder = request_holder().trim().to_owned();
                                            let scope = ui_scope_to_wire(&request_scope()).to_owned();
                                            if holder.is_empty() {
                                                return;
                                            }
                                            busy.set(true);
                                            write_status.set("requesting…".to_owned());
                                            spawn(async move {
                                                match with_authed_sdk_client(&base, api_token, |http| async move {
                                                    crate::transport::account::request_consent(&http, &holder, &scope).await
                                                })
                                                .await
                                                {
                                                    Ok(_) => {
                                                        request_form_open.set(false);
                                                        request_holder.set(String::new());
                                                        write_status.set(
                                                            "consent request accepted for processing"
                                                                .to_owned(),
                                                        );
                                                    }
                                                    Err(err) => {
                                                        write_status.set(format!("request failed: {}", err.display()));
                                                    }
                                                }
                                                busy.set(false);
                                            });
                                        }
                                    },
                                    "Send request"
                                }
                            }
                        }
                    }

                    // ── Pending (inbound) requests ──────────────────────────
                    if !pending_rows.is_empty() {
                        div { class: "event",
                            div { class: "event-head", span { "Pending requests" } }
                            ul { class: "settings-list",
                                for row in pending_rows.iter().cloned() {
                                    {
                                        let peer = row.peer.clone();
                                        let peer_key = row.peer_key.clone();
                                        let peer_label = row.peer_label.clone();
                                        let scope = row.scope.clone();
                                        let detail_key = (peer_key.clone(), scope.clone());
                                        let is_open = detail_open() == Some(detail_key.clone());
                                        rsx! {
                                            li {
                                                class: "event",
                                                "data-testid": "consent-pending-row",
                                                "data-peer": "{peer_key}",
                                                "data-scope": "{scope}",
                                                div { class: "event-head",
                                                    span { "{scope_label(&scope)}" }
                                                    span { class: "mono", title: "{peer_key}", "{peer_label}" }
                                                }
                                                div { class: "actions",
                                                    Button {
                                                        variant: ButtonVariant::Secondary,
                                                        "data-testid": "consent-detail-button",
                                                        onclick: {
                                                            let peer_key = peer_key.clone();
                                                            let scope = scope.clone();
                                                            move |_| {
                                                                detail_scope.set(wire_scope_to_ui(&scope).to_owned());
                                                                detail_valid_until.set(String::new());
                                                                detail_open.set(Some((peer_key.clone(), scope.clone())));
                                                            }
                                                        },
                                                        "Review"
                                                    }
                                                }

                                                if is_open {
                                                    div {
                                                        class: "event",
                                                        "data-testid": "consent-pending-detail",
                                                        div { class: "muted", title: "{peer_key}", "Request from {peer_label}" }
                                                        div { class: "field",
                                                            Label { html_for: "consent-scope-select", "Scope" }
                                                            Select::<String> {
                                                                id: "consent-scope-select",
                                                                "data-testid": "consent-scope-select",
                                                                value: Some(detail_scope_selected.into()),
                                                                on_value_change: move |v: Option<String>| {
                                                                    if let Some(v) = v {
                                                                        detail_scope.set(v);
                                                                    }
                                                                },
                                                                SelectOption::<String> { index: 0usize, value: "message".to_string(), text_value: "Direct messages", "Direct messages" }
                                                                SelectOption::<String> { index: 1usize, value: "invite".to_string(), text_value: "Group invites", "Group invites" }
                                                                SelectOption::<String> { index: 2usize, value: "call".to_string(), text_value: "Calls", "Calls" }
                                                            }
                                                        }
                                                        div { class: "field",
                                                            Label { html_for: "consent-valid-until-input-input", "Valid until (optional, RFC 3339)" }
                                                            Input {
                                                                id: "consent-valid-until-input-input",
                                                                "data-testid": "consent-valid-until-input",
                                                                value: "{detail_valid_until}",
                                                                placeholder: "2026-12-31T00:00:00.000Z",
                                                                oninput: move |event: FormEvent| detail_valid_until.set(event.value()),
                                                            }
                                                        }
                                                        div { class: "actions",
                                                            Button {
                                                                variant: ButtonVariant::Primary,
                                                                "data-testid": "grant-consent-button",
                                                                disabled: busy(),
                                                                onclick: {
                                                                    let base = base_url();
                                                                    let peer = peer.clone();
                                                                    let me_did = me.clone();
                                                                    move |_| {
                                                                        let base = base.clone();
                                                                        let api_token = token();
                                                                        let holder = me_did.clone();
                                                                        let peer = peer.clone();
                                                                        let scope = ui_scope_to_wire(&detail_scope()).to_owned();
                                                                        let expires_at = parse_valid_until(&detail_valid_until());
                                                                        busy.set(true);
                                                                        write_status.set("granting…".to_owned());
                                                                        spawn(async move {
                                                                            match with_authed_sdk_client(&base, api_token, |http| async move {
                                                                                crate::transport::account::grant_consent(
                                                        &crate::event_submit::EventSubmitter::from_current_session(http),
                                                        &holder, &peer, &scope, expires_at,
                                                    ).await
                                                                            })
                                                                            .await
                                                                            {
                                                                                Ok(_) => {
                                                                                    write_status.set("consent granted".to_owned());
                                                                                    detail_open.set(None);
                                                                                    reload.set(reload() + 1);
                                                                                }
                                                                                Err(err) => {
                                                                                    write_status.set(format!("grant failed: {}", err.display()));
                                                                                }
                                                                            }
                                                                            busy.set(false);
                                                                        });
                                                                    }
                                                                },
                                                                "Grant consent"
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

                    // ── Granted consents ────────────────────────────────────
                    if !granted_rows.is_empty() {
                        div { class: "event",
                            div { class: "event-head", span { "Granted" } }
                            ul { class: "settings-list",
                                for row in granted_rows.iter().cloned() {
                                    {
                                        let peer = row.peer.clone();
                                        let peer_key = row.peer_key.clone();
                                        let peer_label = row.peer_label.clone();
                                        let scope = row.scope.clone();
                                        let expires = row.expires_at.clone();
                                        rsx! {
                                            li {
                                                class: "event",
                                                "data-testid": "consent-granted-row",
                                                "data-peer": "{peer_key}",
                                                "data-scope": "{scope}",
                                                div { class: "event-head",
                                                    span { "{scope_label(&scope)}" }
                                                    span { class: "mono", title: "{peer_key}", "{peer_label}" }
                                                }
                                                if let Some(expires) = &expires {
                                                    div { class: "muted", "Expires: {expires}" }
                                                }
                                                div { class: "actions",
                                                    Button {
                                                        variant: ButtonVariant::Secondary,
                                                        "data-testid": "revoke-consent-button",
                                                        disabled: busy(),
                                                        onclick: {
                                                            let base = base_url();
                                                            let peer = peer.clone();
                                                            let scope = scope.clone();
                                                            let me_did = me.clone();
                                                            move |_| {
                                                                let base = base.clone();
                                                                let api_token = token();
                                                                let holder = me_did.clone();
                                                                let peer = peer.clone();
                                                                let scope = scope.clone();
                                                                busy.set(true);
                                                                write_status.set("revoking…".to_owned());
                                                                spawn(async move {
                                                                    match with_authed_sdk_client(&base, api_token, |http| async move {
                                                                        crate::transport::account::revoke_consent(
                                                        &crate::event_submit::EventSubmitter::from_current_session(http),
                                                        &holder, &peer, &scope,
                                                    ).await
                                                                    })
                                                                    .await
                                                                    {
                                                                        Ok(_) => {
                                                                            write_status.set("consent revoked".to_owned());
                                                                            reload.set(reload() + 1);
                                                                        }
                                                                        Err(err) => {
                                                                            write_status.set(format!("revoke failed: {}", err.display()));
                                                                        }
                                                                    }
                                                                    busy.set(false);
                                                                });
                                                            }
                                                        },
                                                        "Revoke"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if !write_status.read().is_empty() {
                        div {
                            class: "muted",
                            "data-testid": "write-status",
                            "{write_status}"
                        }
                    }
                }
            }
        }
    }
}
