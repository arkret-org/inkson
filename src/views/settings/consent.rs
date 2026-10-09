//! Holder-private consent settings surface (`/settings/consent`).
//!
//! Spec `identity/consent-model.md` §2-§4. Consent is a holder-private
//! decision, orthogonal to capability + membership: the holder grants or
//! revokes scoped permission for a peer to initiate a contact action
//! (`invite` / `voice_call` / `presence`). The cells are read from the
//! holder-private projection at `/_arkret/self/consent` and mutated via
//! the `grant` / `revoke` / `request` self-plane commands.
//!
//! Surfaces (testids consumed by `cotest/e2e/.../consent-grant.spec.ts`):
//! - `consent-settings-panel` wrapper
//! - `consent-grant-empty` empty state
//! - direct grant form: `consent-new-grant-button` toggle, `consent-new-grant-scope-input`,
//!   `consent-new-grant-grantee-input`, `consent-new-grant-grantee-station-input`,
//!   `consent-new-grant-ttl-input`, `consent-new-grant-submit-button`
//! - opaque outbound request: `consent-request-button`, `consent-request-scope-input`,
//!   `consent-request-holder-input`, `consent-request-holder-station-input`,
//!   `consent-request-submit-button`
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
    consent_id: arkret_sdk::ConsentId,
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
    /// Wire scope (`invite` / `voice_call` / `presence` / ...).
    scope: String,
    /// Materialized current state, with `expired` derived from the read clock.
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
            arkret_sdk::ActorId::Service { service_id } => crate::i18n::tr_args(
                "consent.peer_service",
                &[("service", service_id.to_string())],
            ),
        },
    }
}

/// Human label for a wire scope.
fn scope_label(scope: &str) -> String {
    tr(match scope {
        "invite" => "consent.scope.invite",
        "voice_call" => "consent.scope.voice_call",
        "video_call" => "consent.scope.video_call",
        "presence" => "consent.scope.presence",
        "any" => "consent.scope.any",
        _ => "consent.scope.unknown",
    })
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

fn parse_consent_rows(value: &arkret_sdk::ConsentList, holder: &str) -> Vec<ConsentRow> {
    let now = crate::clock::now_utc();
    value
        .consents
        .iter()
        .map(|cell| ConsentRow {
            consent_id: cell.consent_id.clone(),
            // The self list endpoint is holder-scoped; ConsentView
            // deliberately does not mirror that authenticated holder.
            holder: holder.to_owned(),
            peer: cell.peer.clone(),
            peer_key: serde_json::to_string(&cell.peer).unwrap_or_default(),
            scope: cell.consent_scope.as_str().to_owned(),
            state: match cell.state {
                arkret_sdk::ConsentState::Active
                    if cell.expires_at.is_some_and(|expires_at| expires_at <= now) =>
                {
                    "expired"
                }
                arkret_sdk::ConsentState::Active => "active",
                arkret_sdk::ConsentState::Revoked => "revoked",
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
    let mut load_error = use_signal(|| Option::<Vec<(&'static str, String)>>::None);
    let mut reload = use_signal(|| 0_u32);
    let mut loaded_generation = use_signal(|| u32::MAX);
    let mut write_status = use_signal(|| ("", Vec::<(&'static str, String)>::new()));

    // Direct-grant form state.
    let mut grant_form_open = use_signal(|| false);
    let mut grant_scope = use_signal(String::new);
    let grant_scope_selected = use_memo(move || (!grant_scope().is_empty()).then(|| grant_scope()));
    let mut grant_grantee = use_signal(String::new);
    // The actor branch is matched on the complete ActorId, so the grantee's
    // own Station is part of what is being granted, never an implicit local
    // default: either the grantee field carries the canonical account selector
    // or this field names the Station (account-lifecycle.md §156).
    let mut grant_grantee_station = use_signal(String::new);
    let mut grant_ttl = use_signal(|| "30d".to_owned());

    // Outbound-request form state. The holder is a remote account and is
    // closed the same way as the grantee above.
    let mut request_form_open = use_signal(|| false);
    let mut request_scope = use_signal(String::new);
    let request_scope_selected =
        use_memo(move || (!request_scope().is_empty()).then(|| request_scope()));
    let mut request_holder = use_signal(String::new);
    let mut request_holder_station = use_signal(String::new);

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
                        load_error.set(Some(super::capabilities::api_error_feedback_args(&err)));
                    }
                }
            });
        });
    }

    let me = principal_id();
    let all_rows = rows.read().clone();
    let granted_rows: Vec<ConsentRow> = all_rows
        .iter()
        .filter(|row| row.holder == me && row.state == "active")
        .cloned()
        .collect();
    let revoked_rows: Vec<ConsentRow> = all_rows
        .iter()
        .filter(|row| row.holder == me && row.state == "revoked")
        .cloned()
        .collect();
    let expired_rows: Vec<ConsentRow> = all_rows
        .iter()
        .filter(|row| row.holder == me && row.state == "expired")
        .cloned()
        .collect();
    let show_empty = !grant_form_open() && all_rows.is_empty();

    let grant_submit_disabled = grant_grantee.read().trim().is_empty()
        || grant_scope().parse::<arkret_wire::ConsentScope>().is_err()
        || busy();
    let request_submit_disabled = request_holder.read().trim().is_empty()
        || request_scope()
            .parse::<arkret_wire::ConsentRequestScope>()
            .is_err()
        || busy();

    rsx! {
        div { class: "settings", "data-testid": "consent-settings-panel",
            div { class: "settings-shell",
                section { class: "settings-content-stack",
                    div { class: "event",
                        div { class: "event-head",
                            span { {tr("consent.title")} }
                            div { class: "actions",
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "consent-new-grant-button",
                                    onclick: move |_| {
                                        let next = !grant_form_open();
                                        grant_form_open.set(next);
                                    },
                                    {tr("consent.grant")}
                                }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "consent-request-button",
                                    onclick: move |_| {
                                        let next = !request_form_open();
                                        request_form_open.set(next);
                                    },
                                    {tr("consent.request")}
                                }
                            }
                        }
                        div { class: "muted",
                            {tr("consent.intro")}
                        }

                        if let Some(message) = load_error.read().clone() {
                            div {
                                class: "event error-banner",
                                "data-testid": "consent-load-error",
                                div { class: "muted", {crate::i18n::tr_args("consent.load_failed", &super::capabilities::localized_feedback_args(&message))} }
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "consent-retry-button",
                                        onclick: move |_| reload.set(reload() + 1),
                                        {tr("common.retry")}
                                    }
                                }
                            }
                        }

                        if show_empty {
                            div {
                                class: "members-empty",
                                "data-testid": "consent-grant-empty",
                                div { class: "members-empty-title", {tr("consent.empty")} }
                                div { class: "muted members-empty-hint",
                                    {tr("consent.empty_hint")}
                                }
                            }
                        }
                    }

                    // ── Direct grant form ───────────────────────────────────
                    if grant_form_open() {
                        div { class: "event", "data-testid": "consent-new-grant-form",
                            div { class: "event-head", span { {tr("consent.grant")} } }
                            div { class: "field",
                                Label { html_for: "consent-new-grant-scope", {tr("consent.scope")} }
                                Select::<String> {
                                    id: "consent-new-grant-scope",
                                    "data-testid": "consent-new-grant-scope-input",
                                    value: Some(grant_scope_selected.into()),
                                    on_value_change: move |v: Option<String>| {
                                        if let Some(v) = v {
                                            grant_scope.set(v);
                                        }
                                    },
                                    SelectOption::<String> { index: 0usize, value: "invite".to_string(), text_value: tr("consent.scope.invite"), {tr("consent.scope.invite")} }
                                    SelectOption::<String> { index: 1usize, value: "voice_call".to_string(), text_value: tr("consent.scope.voice_call"), {tr("consent.scope.voice_call")} }
                                    SelectOption::<String> { index: 2usize, value: "video_call".to_string(), text_value: tr("consent.scope.video_call"), {tr("consent.scope.video_call")} }
                                    SelectOption::<String> { index: 3usize, value: "presence".to_string(), text_value: tr("consent.scope.presence"), {tr("consent.scope.presence")} }
                                    SelectOption::<String> { index: 4usize, value: "any".to_string(), text_value: tr("consent.scope.any"), {tr("consent.scope.any")} }
                                }
                            }
                            div { class: "field",
                                Label { html_for: "consent-new-grant-grantee-input-input", {tr("consent.grantee")} }
                                Input {
                                    id: "consent-new-grant-grantee-input-input",
                                    "data-testid": "consent-new-grant-grantee-input",
                                    value: "{grant_grantee}",
                                    placeholder: tr("consent.account_example"),
                                    oninput: move |event: FormEvent| grant_grantee.set(event.value()),
                                }
                            }
                            div { class: "field",
                                Label { html_for: "consent-new-grant-grantee-station-input-input", {tr("consent.grant.grantee_station_label")} }
                                Input {
                                    id: "consent-new-grant-grantee-station-input-input",
                                    "data-testid": "consent-new-grant-grantee-station-input",
                                    value: "{grant_grantee_station}",
                                    placeholder: tr("consent.station_example"),
                                    oninput: move |event: FormEvent| grant_grantee_station.set(event.value()),
                                }
                            }
                            div { class: "field",
                                Label { html_for: "consent-new-grant-ttl-input-input", {tr("consent.ttl")} }
                                Input {
                                    id: "consent-new-grant-ttl-input-input",
                                    "data-testid": "consent-new-grant-ttl-input",
                                    value: "{grant_ttl}",
                                    placeholder: tr("consent.ttl_example"),
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
                                            let scope = grant_scope();
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
                                                    write_status.set(("consent.grant_failed", vec![("error", err.to_string())]));
                                                    return;
                                                }
                                            };
                                            busy.set(true);
                                            write_status.set(("consent.grant_busy", vec![]));
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
                                                        write_status.set(("consent.grant_success", vec![]));
                                                        grant_form_open.set(false);
                                                        grant_grantee.set(String::new());
                                                        grant_grantee_station.set(String::new());
                                                        reload.set(reload() + 1);
                                                    }
                                                    Err(err) => {
                                                        write_status.set(("consent.grant_failed", super::capabilities::api_error_feedback_args(&err)));
                                                    }
                                                }
                                                busy.set(false);
                                            });
                                        }
                                    },
                                    {tr("consent.grant_submit")}
                                }
                            }
                        }
                    }

                    // ── Outbound request form ───────────────────────────────
                    if request_form_open() {
                        div { class: "event", "data-testid": "consent-request-form",
                            div { class: "event-head", span { {tr("consent.request")} } }
                            div { class: "field",
                                Label { html_for: "consent-request-scope", {tr("consent.scope")} }
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
                                    SelectOption::<String> { index: 0usize, value: "voice_call".to_string(), text_value: tr("consent.scope.voice_call"), {tr("consent.scope.voice_call")} }
                                    SelectOption::<String> { index: 1usize, value: "video_call".to_string(), text_value: tr("consent.scope.video_call"), {tr("consent.scope.video_call")} }
                                    SelectOption::<String> { index: 2usize, value: "presence".to_string(), text_value: tr("consent.scope.presence"), {tr("consent.scope.presence")} }
                                    SelectOption::<String> { index: 3usize, value: "any".to_string(), text_value: tr("consent.scope.any"), {tr("consent.scope.any")} }
                                }
                            }
                            div { class: "field",
                                Label { html_for: "consent-request-holder-input-input", {tr("consent.holder")} }
                                Input {
                                    id: "consent-request-holder-input-input",
                                    "data-testid": "consent-request-holder-input",
                                    value: "{request_holder}",
                                    placeholder: tr("consent.account_example"),
                                    oninput: move |event: FormEvent| request_holder.set(event.value()),
                                }
                            }
                            div { class: "field",
                                Label { html_for: "consent-request-holder-station-input-input", {tr("consent.request.holder_station_label")} }
                                Input {
                                    id: "consent-request-holder-station-input-input",
                                    "data-testid": "consent-request-holder-station-input",
                                    value: "{request_holder_station}",
                                    placeholder: tr("consent.station_core_example"),
                                    oninput: move |event: FormEvent| request_holder_station.set(event.value()),
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
                                            let holder_station = request_holder_station().trim().to_owned();
                                            let scope = request_scope();
                                            if holder.is_empty() {
                                                return;
                                            }
                                            // The holder is a remote account; a bare DID
                                            // has no Station and fails closed here rather
                                            // than being completed with this Station.
                                            let holder = match crate::mls_api_helpers::closed_account_id_input(
                                                &holder,
                                                Some(holder_station.as_str()),
                                            ) {
                                                Ok(holder) => holder,
                                                Err(err) => {
                                                    write_status.set(("consent.request_failed", vec![("error", err.to_string())]));
                                                    return;
                                                }
                                            };
                                            busy.set(true);
                                            write_status.set(("consent.request_busy", vec![]));
                                            spawn(async move {
                                                match with_authed_sdk_client(&base, api_token, |http| async move {
                                                    crate::transport::account::request_consent(&http, &holder, &scope).await
                                                })
                                                .await
                                                {
                                                    Ok(_) => {
                                                        request_form_open.set(false);
                                                        request_holder.set(String::new());
                                                        request_holder_station.set(String::new());
                                                        write_status.set(("consent.request_success", vec![]));
                                                    }
                                                    Err(err) => {
                                                        write_status.set(("consent.request_failed", super::capabilities::api_error_feedback_args(&err)));
                                                    }
                                                }
                                                busy.set(false);
                                            });
                                        }
                                    },
                                    {tr("consent.request_submit")}
                                }
                            }
                        }
                    }

                    // ── Granted consents ────────────────────────────────────
                    if !granted_rows.is_empty() {
                        div { class: "event",
                            div { class: "event-head", span { {tr("consent.granted")} } }
                            ul { class: "settings-list",
                                for row in granted_rows.iter().cloned() {
                                    {
                                        let consent_id = row.consent_id.clone();
                                        let peer = row.peer.clone();
                                        let peer_key = row.peer_key.clone();
                                        let peer_label = consent_peer_label(&row.peer);
                                        let scope = row.scope.clone();
                                        let expires = row.expires_at.clone();
                                        rsx! {
                                            li {
                                                class: "event",
                                                "data-testid": "consent-granted-row",
                                                "data-consent-id": "{consent_id}",
                                                "data-peer": "{peer_key}",
                                                "data-scope": "{scope}",
                                                div { class: "event-head",
                                                    span { "{scope_label(&scope)}" }
                                                    span { class: "mono", title: "{peer_key}", "{peer_label}" }
                                                }
                                                if let Some(expires) = &expires {
                                                    div { class: "muted", {crate::i18n::tr_args("consent.expires", &[("time", expires.clone())])} }
                                                }
                                                div { class: "actions",
                                                    Button {
                                                        variant: ButtonVariant::Secondary,
                                                        "data-testid": "revoke-consent-button",
                                                        disabled: busy(),
                                                        onclick: {
                                                            let base = base_url();
                                                            let consent_id = consent_id.clone();
                                                            let peer = peer.clone();
                                                            let scope = scope.clone();
                                                            let me_did = me.clone();
                                                            move |_| {
                                                                let base = base.clone();
                                                                let consent_id = consent_id.clone();
                                                                let api_token = token();
                                                                let holder = me_did.clone();
                                                                let peer = peer.clone();
                                                                let scope = scope.clone();
                                                                busy.set(true);
                                                                write_status.set(("consent.revoke_busy", vec![]));
                                                                spawn(async move {
                                                                    match with_authed_sdk_client(&base, api_token, |http| async move {
                                                                        crate::transport::account::revoke_consent(
                                                        &crate::event_submit::EventSubmitter::from_current_session(http),
                                                        &holder, &consent_id, &peer, &scope,
                                                    ).await
                                                                    })
                                                                    .await
                                                                    {
                                                                        Ok(_) => {
                                                                            write_status.set(("consent.revoke_success", vec![]));
                                                                            reload.set(reload() + 1);
                                                                        }
                                                                        Err(err) => {
                                                                            write_status.set(("consent.revoke_failed", super::capabilities::api_error_feedback_args(&err)));
                                                                        }
                                                                    }
                                                                    busy.set(false);
                                                                });
                                                            }
                                                        },
                                                        {tr("consent.revoke")}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if !revoked_rows.is_empty() {
                        div { class: "event",
                            div { class: "event-head", span { {tr("consent.revoked")} } }
                            ul { class: "settings-list",
                                for row in revoked_rows.iter() {
                                    li {
                                        class: "event",
                                        "data-testid": "consent-revoked-row",
                                        "data-peer": "{row.peer_key}",
                                        "data-scope": "{row.scope}",
                                        span { "{scope_label(&row.scope)}" }
                                        span { class: "mono", title: "{row.peer_key}", "{consent_peer_label(&row.peer)}" }
                                    }
                                }
                            }
                        }
                    }

                    if !expired_rows.is_empty() {
                        div { class: "event",
                            div { class: "event-head", span { {tr("consent.expired")} } }
                            ul { class: "settings-list",
                                for row in expired_rows.iter() {
                                    li {
                                        class: "event",
                                        "data-testid": "consent-expired-row",
                                        "data-peer": "{row.peer_key}",
                                        "data-scope": "{row.scope}",
                                        span { "{scope_label(&row.scope)}" }
                                        span { class: "mono", title: "{row.peer_key}", "{consent_peer_label(&row.peer)}" }
                                    }
                                }
                            }
                        }
                    }

                    if !write_status.read().0.is_empty() {
                        div {
                            class: "muted",
                            "data-testid": "write-status",
                            {crate::i18n::tr_args(write_status.read().0, &super::capabilities::localized_feedback_args(&write_status.read().1))}
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consent_scope_and_exact_service_peer_retranslate_without_changing_identity() {
        let peer = arkret_sdk::ConsentPeer::Actor {
            actor_id: arkret_sdk::ActorId::service(
                arkret_sdk::DidCoreId::new("ak:did_core:web:service.example").unwrap(),
            ),
        };
        let original = serde_json::to_string(&peer).unwrap();
        let mut dom = VirtualDom::new(|| rsx! {});
        dom.rebuild_in_place();
        dom.in_scope(ScopeId::ROOT, || {
            let mut locale = provide_context(crate::i18n::init_i18n_with_locale(
                crate::i18n::UiLocale::En,
            ));
            for (language, scope, prefix) in [
                (crate::i18n::UiLocale::En, "Group invites", "service "),
                (crate::i18n::UiLocale::Zh, "群组邀请", "服务 "),
                (crate::i18n::UiLocale::En, "Group invites", "service "),
            ] {
                crate::i18n::set_locale(&mut locale, language);
                assert_eq!(
                    scope_label(arkret_wire::ConsentScope::Invite.as_str()),
                    scope
                );
                assert_eq!(
                    consent_peer_label(&peer),
                    format!("{prefix}ak:did_core:web:service.example")
                );
                assert_eq!(serde_json::to_string(&peer).unwrap(), original);
            }
        });
    }
}
