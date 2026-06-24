//! Holder-private consent settings surface (`/settings/consent`).
//!
//! Spec `identity/consent-model.md` §2-§4. Consent is a holder-private
//! decision, orthogonal to capability + membership: the holder grants or
//! revokes scoped permission for a peer to initiate a contact action
//! (`direct_message` / `invite` / `voice_call`). The cells are read from the
//! holder-private projection at `/_cokret/self/consent/cells` and mutated via
//! the `grant` / `revoke` / `request` self-plane commands.
//!
//! Surfaces (testids consumed by `cotest/e2e/.../consent-grant.spec.ts`):
//! - `consent-settings-panel` wrapper
//! - `consent-grant-empty` empty state
//! - direct grant form: `consent-new-grant-button` toggle, `consent-new-grant-scope-input`,
//!   `consent-new-grant-grantee-input`, `consent-new-grant-ttl-input`,
//!   `consent-new-grant-submit-button`
//! - outbound request: `consent-request-button`, `consent-request-scope-input`,
//!   `consent-request-holder-input`, `consent-request-submit-button`,
//!   `consent-outgoing-request-row`
//! - pending list: `consent-pending-row`, `consent-detail-button`, `consent-pending-detail`,
//!   `consent-scope-select`, `consent-valid-until-input`, `grant-consent-button`
//! - granted list: `consent-granted-row`, `revoke-consent-button`
//! - `write-status` shared write feedback line.

use dioxus::prelude::*;

use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::select::{Select, SelectOption};
use crate::views::helpers::with_authed_api;

/// One consent cell row distilled from the holder-private projection.
#[derive(Clone, Debug, PartialEq)]
struct ConsentRow {
    holder: String,
    peer: String,
    /// Wire scope (`direct_message` / `invite` / `voice_call` / ...).
    scope: String,
    /// Effective state: `active` / `pending` / `revoked`.
    state: String,
    expires_at: Option<String>,
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

/// Parse a TTL token such as `30d` / `12h` / `90m` into a duration. Returns
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

fn parse_consent_rows(value: &cokret_sdk::ConsentCellList) -> Vec<ConsentRow> {
    value
        .cells
        .iter()
        .map(|cell| ConsentRow {
            holder: cell.holder_did.to_string(),
            peer: cell.peer_did.to_string(),
            scope: cell.consent_scope.clone(),
            state: serde_json::to_value(cell.state)
                .ok()
                .and_then(|v| v.as_str().map(ToOwned::to_owned))
                .unwrap_or_else(|| "pending".to_owned()),
            expires_at: cell.expires_at.map(|dt| dt.to_rfc3339()),
        })
        .collect()
}

#[component]
pub fn ConsentSettingsPanel(
    base_url: Signal<String>,
    account_did: Signal<String>,
    token: Signal<String>,
) -> Element {
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
    let mut grant_ttl = use_signal(|| "30d".to_owned());

    // Outbound-request form state.
    let mut request_form_open = use_signal(|| false);
    let mut request_scope = use_signal(|| "message".to_owned());
    let request_scope_selected = use_memo(move || Some(request_scope()));
    let mut request_holder = use_signal(String::new);

    // Open pending-detail editor, keyed by `(peer, scope)`.
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
            load_error.set(None);
            spawn(async move {
                match with_authed_api(
                    &base,
                    api_token,
                    |api| async move { api.consent_cells().await },
                )
                .await
                {
                    Ok(list) => {
                        rows.set(parse_consent_rows(&list));
                    }
                    Err(err) => {
                        load_error.set(Some(err.display()));
                    }
                }
            });
        });
    }

    let me = account_did();
    let all_rows = rows.read().clone();
    let pending_rows: Vec<ConsentRow> = all_rows
        .iter()
        .filter(|row| row.holder == me && row.peer != me && row.state == "pending")
        .cloned()
        .collect();
    let granted_rows: Vec<ConsentRow> = all_rows
        .iter()
        .filter(|row| row.holder == me && row.state == "active")
        .cloned()
        .collect();
    let outgoing_rows: Vec<ConsentRow> = all_rows
        .iter()
        .filter(|row| row.holder != me && row.peer == me && row.state == "pending")
        .cloned()
        .collect();

    let show_empty = !grant_form_open()
        && pending_rows.is_empty()
        && granted_rows.is_empty()
        && outgoing_rows.is_empty();

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
                                            let peer = grant_grantee().trim().to_owned();
                                            let scope = ui_scope_to_wire(&grant_scope()).to_owned();
                                            let expires_at = parse_ttl(&grant_ttl())
                                                .map(|d| chrono::Utc::now() + d);
                                            if peer.is_empty() {
                                                return;
                                            }
                                            busy.set(true);
                                            write_status.set("granting…".to_owned());
                                            spawn(async move {
                                                match with_authed_api(&base, api_token, |api| async move {
                                                    api.grant_consent(&holder, &peer, &scope, expires_at).await
                                                })
                                                .await
                                                {
                                                    Ok(_) => {
                                                        write_status.set("consent granted".to_owned());
                                                        grant_form_open.set(false);
                                                        grant_grantee.set(String::new());
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
                                    SelectOption::<String> { index: 0usize, value: "message".to_string(), text_value: "Direct messages", "Direct messages" }
                                    SelectOption::<String> { index: 1usize, value: "invite".to_string(), text_value: "Group invites", "Group invites" }
                                    SelectOption::<String> { index: 2usize, value: "call".to_string(), text_value: "Calls", "Calls" }
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
                                        let me_did = me.clone();
                                        move |_| {
                                            let base = base.clone();
                                            let api_token = token();
                                            let me_did = me_did.clone();
                                            let holder = request_holder().trim().to_owned();
                                            let scope = ui_scope_to_wire(&request_scope()).to_owned();
                                            if holder.is_empty() {
                                                return;
                                            }
                                            busy.set(true);
                                            write_status.set("requesting…".to_owned());
                                            spawn(async move {
                                                match with_authed_api(&base, api_token, |api| async move {
                                                    api.request_consent(&holder, &me_did, &scope).await
                                                })
                                                .await
                                                {
                                                    Ok(_) => {
                                                        write_status.set("consent requested".to_owned());
                                                        request_form_open.set(false);
                                                        request_holder.set(String::new());
                                                        reload.set(reload() + 1);
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

                    // ── Outgoing requests ───────────────────────────────────
                    if !outgoing_rows.is_empty() {
                        div { class: "event",
                            div { class: "event-head", span { "Outgoing requests" } }
                            ul { class: "settings-list",
                                for row in outgoing_rows.iter().cloned() {
                                    li {
                                        class: "event",
                                        "data-testid": "consent-outgoing-request-row",
                                        "data-peer": "{row.holder}",
                                        "data-scope": "{row.scope}",
                                        div { class: "event-head",
                                            span { "{scope_label(&row.scope)}" }
                                            span { class: "mono", title: "{row.holder}", "{row.holder}" }
                                        }
                                        div { class: "muted", "Waiting for them to grant consent." }
                                    }
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
                                        let scope = row.scope.clone();
                                        let detail_key = (peer.clone(), scope.clone());
                                        let is_open = detail_open() == Some(detail_key.clone());
                                        rsx! {
                                            li {
                                                class: "event",
                                                "data-testid": "consent-pending-row",
                                                "data-peer": "{peer}",
                                                "data-scope": "{scope}",
                                                div { class: "event-head",
                                                    span { "{scope_label(&scope)}" }
                                                    span { class: "mono", title: "{peer}", "{peer}" }
                                                }
                                                div { class: "actions",
                                                    Button {
                                                        variant: ButtonVariant::Secondary,
                                                        "data-testid": "consent-detail-button",
                                                        onclick: {
                                                            let peer = peer.clone();
                                                            let scope = scope.clone();
                                                            move |_| {
                                                                detail_scope.set(wire_scope_to_ui(&scope).to_owned());
                                                                detail_valid_until.set(String::new());
                                                                detail_open.set(Some((peer.clone(), scope.clone())));
                                                            }
                                                        },
                                                        "Review"
                                                    }
                                                }

                                                if is_open {
                                                    div {
                                                        class: "event",
                                                        "data-testid": "consent-pending-detail",
                                                        div { class: "muted", title: "{peer}", "Request from {peer}" }
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
                                                                placeholder: "2026-12-31T00:00:00Z",
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
                                                                            match with_authed_api(&base, api_token, |api| async move {
                                                                                api.grant_consent(&holder, &peer, &scope, expires_at).await
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
                                        let scope = row.scope.clone();
                                        let expires = row.expires_at.clone();
                                        rsx! {
                                            li {
                                                class: "event",
                                                "data-testid": "consent-granted-row",
                                                "data-peer": "{peer}",
                                                "data-scope": "{scope}",
                                                div { class: "event-head",
                                                    span { "{scope_label(&scope)}" }
                                                    span { class: "mono", title: "{peer}", "{peer}" }
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
                                                                    match with_authed_api(&base, api_token, |api| async move {
                                                                        api.revoke_consent(&holder, &peer, &scope).await
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
