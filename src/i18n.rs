use std::collections::HashMap;

use chrono::{DateTime, Utc};
use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

/// Supported locales.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Locale {
    #[default]
    En,
    Zh,
    Ar,
    /// Phase D.2 #8: Spanish.
    Es,
    /// Phase D.2 #8: Japanese.
    Ja,
    /// Phase D.2 #8: French.
    Fr,
}

impl Locale {
    pub fn code(&self) -> &'static str {
        match self {
            Locale::En => "en",
            Locale::Zh => "zh",
            Locale::Ar => "ar",
            Locale::Es => "es",
            Locale::Ja => "ja",
            Locale::Fr => "fr",
        }
    }

    /// Parse a BCP 47 locale string. The match recognises both the base
    /// tag (e.g. `"ar"`) and common region variants (`"ar-SA"`, `"ar-EG"`,
    /// `"zh-CN"`, `"zh-TW"`, `"es-MX"`, `"fr-CA"`, `"ja-JP"`). Region
    /// variants always fall through to the base locale dictionary.
    pub fn from_code(code: &str) -> Self {
        // Normalise on the base subtag so `ar-SA` and `ar-EG` both pick
        // the Arabic dictionary, which is the entry-point of the
        // ar-SA → ar → en fallback chain defined in [`translate`].
        let base = code
            .split(['-', '_'])
            .next()
            .unwrap_or(code)
            .to_ascii_lowercase();
        match base.as_str() {
            "zh" => Locale::Zh,
            "ar" => Locale::Ar,
            "es" => Locale::Es,
            "ja" => Locale::Ja,
            "fr" => Locale::Fr,
            _ => Locale::En,
        }
    }

    pub fn direction(&self) -> TextDirection {
        match self {
            Locale::Ar => TextDirection::Rtl,
            Locale::En | Locale::Zh | Locale::Es | Locale::Ja | Locale::Fr => TextDirection::Ltr,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextDirection {
    Ltr,
    Rtl,
}

impl TextDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ltr => "ltr",
            Self::Rtl => "rtl",
        }
    }
}

/// Translation dictionary for a single locale.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TranslationDict {
    pub locale: Locale,
    pub strings: HashMap<String, String>,
}

impl TranslationDict {
    pub fn new(locale: Locale) -> Self {
        Self {
            locale,
            strings: HashMap::new(),
        }
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.strings.insert(key.into(), value.into());
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.strings.get(key).map(|s| s.as_str())
    }
}

/// Global i18n state managed as a Dioxus signal.
pub type I18nSignal = Signal<(Locale, HashMap<String, TranslationDict>)>;

/// Get a translated string by key. Falls back to English, then to the key itself.
pub fn t(signal: &I18nSignal, key: &str) -> String {
    let (locale, dicts) = signal.read().clone();
    translate(locale, &dicts, key)
}

/// Lookup a translated string without requiring a Dioxus runtime.
///
/// Phase D.2 #8: extends the fallback chain so a region variant like
/// `ar-SA` walks `ar-SA → ar → en → key` even though the
/// [`Locale`] enum collapses region tags at parse time. Callers that
/// keep a raw BCP 47 tag around can call [`translate_chain`] instead;
/// this helper is the simple "I already have a `Locale`" entrypoint.
pub fn translate(locale: Locale, dicts: &HashMap<String, TranslationDict>, key: &str) -> String {
    translate_chain(locale.code(), dicts, key)
}

/// Phase D.2 #8: translate against an explicit BCP 47 chain. The
/// `requested_tag` may carry a region suffix (e.g. `"ar-SA"`). The
/// lookup tries the full tag, then strips each `-region` segment, then
/// falls back to English. Missing keys are reported via
/// [`record_missing_translation`] before returning the key itself.
pub fn translate_chain(
    requested_tag: &str,
    dicts: &HashMap<String, TranslationDict>,
    key: &str,
) -> String {
    // Build the lookup chain: `ar-SA → ar → en`.
    let mut chain: Vec<String> = Vec::new();
    let mut current = requested_tag.to_owned();
    chain.push(current.clone());
    while let Some(idx) = current.rfind('-') {
        current.truncate(idx);
        if !current.is_empty() {
            chain.push(current.clone());
        }
    }
    if !chain.iter().any(|tag| tag == "en") {
        chain.push("en".to_owned());
    }
    for tag in &chain {
        if let Some(dict) = dicts.get(tag.as_str())
            && let Some(val) = dict.get(key)
        {
            return val.to_owned();
        }
    }
    // Phase D.2 #8: surface the miss so QA can grow the dictionaries.
    record_missing_translation(requested_tag, key);
    key.to_owned()
}

/// Phase D.2 #8: shared sink for missing `(locale_tag, key)` pairs.
fn missing_translation_sink()
-> &'static std::sync::Mutex<std::collections::HashSet<(String, String)>> {
    use std::sync::{Mutex, OnceLock};
    static SEEN: OnceLock<Mutex<std::collections::HashSet<(String, String)>>> = OnceLock::new();
    SEEN.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

/// Phase D.2 #8: missing-key sink. Each unique `(locale, key)` pair
/// is logged once via `tracing::warn!` so a long-running session
/// doesn't spam the journal for the same untranslated label. The
/// in-memory set is also queryable via
/// [`missing_translation_snapshot`] for test / diagnostic UI.
fn record_missing_translation(locale_tag: &str, key: &str) {
    let Ok(mut guard) = missing_translation_sink().lock() else {
        return;
    };
    let entry = (locale_tag.to_owned(), key.to_owned());
    if guard.insert(entry) {
        tracing::warn!(locale = %locale_tag, key = %key, "i18n missing translation");
    }
}

/// Phase D.2 #8: snapshot of every `(locale_tag, key)` pair that has
/// been reported missing by [`translate_chain`] during this process.
/// Used by the developer-tools diagnostic surface and the i18n unit
/// tests; production code should not iterate this.
pub fn missing_translation_snapshot() -> Vec<(String, String)> {
    let Ok(guard) = missing_translation_sink().lock() else {
        return Vec::new();
    };
    let mut out: Vec<_> = guard.iter().cloned().collect();
    out.sort();
    out
}

/// Get the current text direction.
pub fn text_direction(signal: &I18nSignal) -> TextDirection {
    signal.read().0.direction()
}

/// Format a UTC timestamp with locale-specific ordering.
pub fn format_datetime(locale: Locale, timestamp: DateTime<Utc>) -> String {
    match locale {
        Locale::En => timestamp.format("%b %d, %Y %H:%M UTC").to_string(),
        Locale::Zh => timestamp.format("%Y年%m月%d日 %H:%M UTC").to_string(),
        Locale::Ar => timestamp.format("%Y/%m/%d %H:%M UTC").to_string(),
        // Phase D.2 #8 locale extensions:
        //   * Spanish uses day-first DD/MM/YYYY (DM ordering matches ES/MX/AR conventions).
        //   * Japanese uses Y年M月D日 like Chinese.
        //   * French uses DD/MM/YYYY (matches FR/CA conventions).
        Locale::Es => timestamp.format("%d/%m/%Y %H:%M UTC").to_string(),
        Locale::Ja => timestamp.format("%Y年%m月%d日 %H:%M UTC").to_string(),
        Locale::Fr => timestamp.format("%d/%m/%Y %H:%M UTC").to_string(),
    }
}

/// Format a non-negative integer with locale-appropriate grouping.
pub fn format_number(locale: Locale, value: u64) -> String {
    let grouped = group_decimal(value);
    match locale {
        // English / Arabic / Japanese: comma-grouped thousands.
        Locale::En | Locale::Ar | Locale::Ja => grouped,
        // Chinese: Eastern convention uses non-breaking space as a soft
        // separator since the thousands grouping is not native to the
        // language; we keep this for parity with the pre-D.2 behaviour.
        Locale::Zh => grouped.replace(',', " "),
        // Spanish / French: dot grouping (es-ES / fr-FR style). Newer
        // ISO 31 recommends thin-space grouping but the existing
        // tooling consumes ASCII, so the dot is the pragmatic choice.
        Locale::Es | Locale::Fr => grouped.replace(',', "."),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranslationCompleteness {
    pub locale: Locale,
    pub total_keys: usize,
    pub missing_keys: Vec<String>,
}

impl TranslationCompleteness {
    pub fn is_complete(&self) -> bool {
        self.missing_keys.is_empty()
    }

    pub fn missing_count(&self) -> usize {
        self.missing_keys.len()
    }
}

/// Compare a locale dictionary against a reference dictionary.
pub fn translation_completeness(
    reference: &TranslationDict,
    candidate: &TranslationDict,
) -> TranslationCompleteness {
    let mut missing_keys: Vec<String> = reference
        .strings
        .keys()
        .filter(|key| !candidate.strings.contains_key(*key))
        .cloned()
        .collect();
    missing_keys.sort();
    TranslationCompleteness {
        locale: candidate.locale,
        total_keys: reference.strings.len(),
        missing_keys,
    }
}

fn group_decimal(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (idx, ch) in digits.chars().rev().enumerate() {
        if idx > 0 && idx % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}

/// Build the default English translation dictionary.
pub fn english_translations() -> TranslationDict {
    let mut dict = TranslationDict::new(Locale::En);

    // Navigation & Shell
    dict.set("app.title", "yougen");
    dict.set("nav.dashboard", "Home");
    dict.set("nav.timeline", "Timeline");
    dict.set("nav.chat", "Chat");
    dict.set("nav.forum", "Forum");
    dict.set("nav.directory", "Directory");
    dict.set("nav.notifications", "Notifications");
    dict.set("nav.settings", "Settings");
    dict.set("nav.login", "Login");
    dict.set("nav.audit", "Audit");
    dict.set("nav.devices", "Devices");
    dict.set("nav.collaboration", "Collaboration");
    dict.set("nav.contacts", "Contacts");
    dict.set("nav.direct_messages", "Direct");
    dict.set("nav.new_realm_short", "Realm");
    dict.set("nav.add_contact_short", "Contact");
    dict.set("direct.empty", "No direct conversations");
    dict.set("direct.sign_in", "Sign in to load direct conversations");
    dict.set("direct.open", "Open direct conversation");
    dict.set("direct.unavailable", "Direct conversation unavailable");
    dict.set("contacts.empty", "No contacts yet");
    dict.set("contacts.sign_in", "Sign in to load contacts");

    // CKP-0007 Circle error keys (P3B.3.2)
    add_circle_error_keys(&mut dict);

    // Login
    dict.set("login.server", "Server");
    dict.set("login.connection_test", "connection test");
    dict.set("login.server_url", "Server URL");
    dict.set("login.test_connection", "Test Connection");
    dict.set("login.account", "Account");
    dict.set("login.account_did", "Account DID");
    dict.set("login.device_id", "Device ID");
    dict.set("login.passkey", "Passkey Login");
    dict.set("login.oidc", "OIDC Login");
    dict.set("login.dev_login", "Dev Login");
    dict.set("login.session", "Session");
    dict.set("login.disconnected", "disconnected");
    dict.set("login.connected", "connected");
    dict.set("login.soft_logout", "soft-logout");
    dict.set("login.no_token", "No active token");
    dict.set("login.token_active", "Token active");
    dict.set("login.refresh_token", "Refresh Token");
    dict.set("login.re_login", "Re-Login");
    dict.set(
        "login.session_expired",
        "Your session has expired. Log in again to continue.",
    );

    // Timeline
    dict.set(
        "timeline.composer_placeholder",
        "Write a plaintext dev-mode message (Ctrl+Enter to send)",
    );
    dict.set(
        "timeline.encrypted_placeholder",
        "Write an encrypted message (Ctrl+Enter to send)",
    );
    dict.set("timeline.send", "Send");
    dict.set("timeline.reply", "Reply");
    dict.set("timeline.react", "React");
    dict.set("timeline.edit", "Edit");
    dict.set("timeline.redact", "Redact");
    dict.set("timeline.thread", "Thread");
    dict.set("timeline.save", "Save");
    dict.set("timeline.cancel", "Cancel");
    dict.set("timeline.pending", "(pending)");
    dict.set("timeline.edited", "(edited)");
    dict.set("timeline.redacted", "[Message redacted]");
    dict.set("timeline.search_placeholder", "Search messages...");
    dict.set(
        "timeline.no_events",
        "No timeline events yet. Compose a dev-mode message.",
    );
    dict.set("timeline.encrypt_local", "Encrypt Local");
    dict.set("timeline.attach_blob", "Attach Blob");
    dict.set("timeline.report_queue", "Report / Queue");

    // Directory
    dict.set("directory.title", "Directory");
    dict.set("directory.search_placeholder", "Search...");
    dict.set("directory.search", "Search");
    dict.set("directory.load_more", "Load More");
    dict.set("directory.tab.realms", "Realms");
    dict.set("directory.tab.organizations", "Organizations");
    dict.set("directory.tab.actors", "Actors");
    dict.set("directory.tab.objects", "Objects");
    dict.set("directory.tab.applets", "Applets");
    dict.set("directory.applet.ping", "Ping");
    dict.set("directory.applet.metadata", "Metadata");

    // Notifications
    dict.set("notifications.title", "Notifications");
    dict.set("notifications.empty", "No notifications loaded.");
    dict.set("notifications.mark_read", "Mark Read");
    dict.set("notifications.archive", "Archive");

    // Settings
    dict.set("settings.title", "Settings");
    dict.set("settings.theme", "Theme");
    dict.set("settings.language", "Language");
    dict.set("settings.light", "Light");
    dict.set("settings.dark", "Dark");
    dict.set("settings.system", "System");

    // T1.3 — proof mode (event signing) status. Exposed in the settings
    // panel and the top status bar so the user can confirm at a glance
    // whether outgoing events are placeholder-dev, real-Ed25519, or
    // backed by an external signer (and refused on production targets
    // when no signer is configured).
    dict.set("settings.proof_mode.label", "Event signing");
    dict.set(
        "settings.proof_mode.hint",
        "Determines what proof is attached when this device submits events.",
    );
    dict.set(
        "settings.proof_mode.placeholder_dev",
        "Development placeholder",
    );
    dict.set("settings.proof_mode.real_ed25519", "real Ed25519");
    dict.set("settings.proof_mode.external_signer", "external signer");
    dict.set("settings.proof_mode.production", "no signer (production)");

    // T5.2 — signer DID / key id / freshness panel under the proof
    // mode indicator. Exposed in the settings panel so the user can
    // confirm at a glance that the device is signing with the expected
    // identity and how recently a proof has been produced.
    dict.set("settings.signer.label", "Active signer");
    dict.set("settings.signer.freshness.label", "Last signed");
    dict.set("settings.signer.freshness.never", "never");

    // Common
    dict.set("common.loading", "Loading...");
    dict.set("common.error", "Error");
    dict.set("common.retry", "Retry");
    dict.set("common.close", "Close");
    dict.set("common.confirm", "Confirm");
    dict.set("common.cancel", "Cancel");
    dict.set("common.save", "Save");
    dict.set("common.delete", "Delete");
    dict.set("common.edit", "Edit");
    dict.set("common.send", "Send");
    dict.set("common.refresh", "Refresh");
    dict.set("common.back", "Back");
    dict.set("common.next", "Next");
    dict.set("common.online", "online");
    dict.set("common.offline", "offline");
    dict.set("common.reconnecting", "reconnecting");

    // R-i18n-002 extra keys for the highest-visibility surfaces.
    dict.set(
        "topbar.search_placeholder",
        "Jump to a Realm, view or action...",
    );
    dict.set("topbar.notifications", "Notifications");
    dict.set("topbar.new_space", "New Space");
    dict.set("topbar.account_menu", "Account menu");

    dict.set("login.continue", "Continue");
    dict.set("login.working", "Working...");
    dict.set("login.signed_in_as", "Signed in as");

    dict.set("dashboard.home", "Home");
    dict.set("dashboard.notifications_label", "Notifications");
    dict.set(
        "dashboard.notifications_delta_unread",
        "Unread and approvals",
    );
    dict.set("dashboard.notifications_delta_signin", "Sign in required");
    dict.set("dashboard.realms_label", "Realms");
    dict.set("dashboard.realms_delta_search", "Search or join a Realm");
    dict.set("dashboard.realms_delta_signin", "Sign in to load realms");
    dict.set("dashboard.workspace_setup", "Realm Setup");
    dict.set(
        "dashboard.workspace_setup_delta",
        "Bootstrap your first Realm and initial policy",
    );
    dict.set("dashboard.onboarding", "Onboarding");
    dict.set("dashboard.onboarding_steps", "4 steps");
    dict.set(
        "dashboard.onboarding_delta",
        "Identity, device, and recovery setup",
    );
    dict.set("dashboard.recent_realms", "Recent Realms");
    dict.set("dashboard.no_realms", "No realms loaded");
    dict.set(
        "dashboard.no_realms_help",
        "The connected server did not return realms yet.",
    );
    dict.set(
        "dashboard.no_session_help",
        "The client is not showing placeholder realms.",
    );
    // F-I18N-CLEAN-1: en strings previously hard-coded in dashboard / chat /
    // kanban / settings / realm_admin views.
    dict.set("dashboard.no_notifications", "No notifications loaded");
    dict.set(
        "dashboard.notifications_signin",
        "Sign in to load notifications",
    );
    dict.set(
        "dashboard.notifications_empty_sub",
        "Unread items, approvals, and alerts appear here",
    );
    dict.set("chat.empty_discussions", "No discussion tracks available.");
    dict.set("chat.empty_messages", "No messages yet.");
    dict.set("chat.loading_messages", "Loading discussion...");
    // F-CHAT-DEAD-UI-1: discussion settings panel.
    dict.set("chat.settings.mute_notifications", "Mute notifications");
    dict.set("chat.settings.read_receipts", "Read receipts");
    dict.set("chat.settings.shared_history", "Shared history");
    dict.set(
        "chat.settings.shared_history_hint",
        "Realm-scoped policy - managed under Realm admin.",
    );
    dict.set(
        "settings.muted_realms_empty",
        "No realms muted. Use the Notifications view to mute a noisy realm.",
    );
    dict.set("realm_admin.no_members_loaded", "No members yet.");
    dict.set(
        "realm_admin.members_empty_hint",
        "Invite your first member with the + button above.",
    );
    dict.set(
        "realm_admin.members_no_match",
        "No members match your search.",
    );
    dict.set(
        "realm_admin.invite_hint",
        "Paste the invite locator link generated by the recipient.",
    );

    dict.set("notifications.archived", "Show archived");
    dict.set("notifications.mark_all_read", "Mark all read");
    dict.set("notifications.empty_state", "No notifications loaded.");
    // F-NOTIF-VLIST-1: client-side paging UI.
    dict.set("notifications.showing", "Showing");
    dict.set("notifications.load_more", "Load more");
    dict.set("directory.loading_more", "Loading...");
    dict.set("directory.load_more_realms", "Load More Realms");
    dict.set(
        "directory.load_more_organizations",
        "Load More Organizations",
    );
    dict.set("directory.load_more_actors", "Load More Actors");

    dict.set("composer.send", "Send");
    dict.set("composer.encrypted_toggle", "Encrypt locally");
    dict.set(
        "composer.plaintext_warning",
        "Plaintext messages may be visible to the configured server.",
    );

    dict.set("command_palette.realms", "Realms");
    dict.set("command_palette.jump_to", "Jump to");
    dict.set(
        "command_palette.empty",
        "No matching realms or views. Press Esc to close.",
    );
    dict.set("command_palette.close", "Close (Esc)");

    dict.set("mobile.filter_realms", "Filter realms...");
    dict.set("mobile.no_match", "No realms match.");

    // Kanban / Board view (header + section labels)
    dict.set("kanban.board_header", "Board");
    dict.set("kanban.board_title", "Board");
    dict.set("kanban.board_hint", "Drag cards between lists.");
    dict.set("chat.send", "Send");
    dict.set("chat.send_secure", "Send Secure");
    dict.set(
        "chat.plaintext_blocked",
        "Type a message before secure send",
    );
    dict.set("realm_admin.save_profile", "Save Profile");
    dict.set("realm_admin.destroy_realm", "Destroy Realm");
    dict.set("realm_admin.archive_realm", "Archive Realm");
    dict.set("verify_device.refresh_trust", "Refresh");
    dict.set("verify_device.verify_action", "Verify");
    dict.set("verify_device.revoke_action", "Revoke");
    dict.set("verify_device.revoke_confirm_title", "Revoke this device?");
    dict.set("verify_device.revoke_confirm_button", "Confirm Revoke");
    dict.set("common.cancel_button", "Cancel");
    dict.set("common.refresh", "Refresh");
    dict.set("common.save", "Save");
    dict.set("common.submit", "Submit");
    dict.set("kanban.refresh_from_api", "Refresh from API");
    dict.set("kanban.add_card", "Add Card");
    dict.set("kanban.add_list", "Add List");
    dict.set("kanban.save_card", "Save");
    dict.set("kanban.cancel_card", "Cancel");
    dict.set(
        "kanban.security_not_ready",
        "Security state not ready; please retry shortly before writing to this Realm.",
    );
    dict.set("realm_admin.apply_policy", "Apply Policy");
    dict.set(
        "realm_admin.grant_capability_move",
        "Grant capability (Move)",
    );
    dict.set(
        "realm_admin.revoke_capability_move",
        "Revoke capability (Move)",
    );
    dict.set("realm_admin.admin_grant_title", "Realm administrators");
    dict.set(
        "realm_admin.admin_grant_hint",
        "Grant or revoke ck.realm.admin authority. Authored as a signed capability event; takes effect once the soland reducer projects it.",
    );
    dict.set("realm_admin.admin_subject_label", "Admin subject (DID)");
    dict.set("realm_admin.admin_grant_id_label", "Grant ID");
    dict.set(
        "realm_admin.admin_subject_required",
        "enter the subject DID to make an admin",
    );
    dict.set(
        "realm_admin.admin_grant_id_required",
        "enter the grant ID to revoke admin authority",
    );
    dict.set("realm_admin.admin_grant_button", "Make admin");
    dict.set("realm_admin.admin_revoke_button", "Revoke admin");
    dict.set("realm_admin.refresh_members", "Refresh");
    dict.set("realm_admin.kick_member", "Kick");
    dict.set("realm_admin.ban_member", "Ban");
    dict.set("realm_admin.kick_member_move", "Kick (Move)");
    dict.set("realm_admin.ban_member_move", "Ban (Move)");
    dict.set("realm_admin.rotate_epoch", "Rotate Epoch");
    dict.set("realm_admin.leave_realm", "Leave");
    dict.set("directory.list_contacts", "List");
    dict.set("directory.search_button", "Search");
    dict.set("directory.resolve_selected", "Resolve Selected");
    dict.set("settings.store_backup", "Store Backup");
    dict.set("settings.register_push", "Register Push");
    dict.set("settings.unregister_push", "Unregister Push");
    dict.set("kanban.archive_action", "Archive");
    dict.set("kanban.restore_action", "Restore");
    dict.set("kanban.archived_lists_header", "Archived lists");
    dict.set("kanban.archived_lists_empty", "No archived lists.");
    dict.set("kanban.archived_cards_header", "Archived cards");
    dict.set("kanban.archived_cards_empty", "No archived cards.");
    dict.set("kanban.move_queue_header", "Move Queue");
    dict.set("kanban.move_queue_empty", "No local board Moves queued.");

    // Directory view (tabs share the existing `directory.tab.*` keys).
    dict.set(
        "directory.org_empty_body",
        "No organizations found. Try a search.",
    );
    dict.set(
        "directory.actors_empty_body",
        "No actors found. Try a search.",
    );

    // Recovery view (top-level section headers)
    dict.set("recovery.title", "Recovery");
    dict.set("recovery.recovery_key_section", "Recovery Key (24 words)");
    dict.set("recovery.social_section", "Social Recovery");
    dict.set("mls_unlock.aria_label", "Authorize this device");
    dict.set("mls_unlock.title", "Authorize this device");
    dict.set("mls_unlock.subtitle", "Existing device approval");
    dict.set(
        "mls_unlock.description",
        "This browser is signed in, but it is not an authorized device for encrypted history yet. Cokret v1 requires an already-authorized device to approve a new device before MLS history keys are shared.",
    );
    dict.set(
        "mls_unlock.approve_step_existing_title",
        "On an existing device",
    );
    dict.set(
        "mls_unlock.approve_step_existing_body",
        "Open Settings -> Devices -> Pair new device, review the pending request, compare the code, and approve it.",
    );
    dict.set("mls_unlock.approve_step_new_title", "On this browser");
    dict.set(
        "mls_unlock.approve_step_new_body",
        "Open the pairing request screen and keep it available while the existing device approves.",
    );
    dict.set(
        "mls_unlock.loading_hint",
        "Restoring multiple encrypted realms can take a few seconds. Keep this tab open.",
    );
    dict.set("mls_unlock.open_pairing", "Show pairing request");
    dict.set("mls_unlock.show_recovery_key", "Use recovery key instead");
    dict.set("mls_unlock.hide_recovery_key", "Hide recovery key");
    dict.set(
        "mls_unlock.recovery_fallback_hint",
        "Use this only if no authorized device is available. The 24-word Recovery Key starts the recovery path and unlocks encrypted-history backups after policy checks.",
    );
    dict.set("mls_unlock.placeholder", "24-word recovery key");
    dict.set("mls_unlock.button_idle", "Unlock with key");
    dict.set("mls_unlock.button_busy", "Unlocking...");
    dict.set("mls_unlock.dismiss", "Do this later");
    dict.set("mls_unlock.reopen", "Authorize this device");
    dict.set(
        "mls_unlock.status.enter_passphrase",
        "Enter your 24-word recovery key to unlock encrypted history.",
    );
    dict.set(
        "mls_unlock.status.invalid_recovery_key",
        "Enter the 24 words exactly as shown on the device that created the backup.",
    );
    dict.set(
        "mls_unlock.status.fetching",
        "Looking up encrypted history backups...",
    );
    dict.set("mls_unlock.status.restoring_prefix", "Restoring");
    dict.set(
        "mls_unlock.status.restoring_suffix",
        "encrypted backup(s). This can take a few seconds.",
    );
    dict.set("mls_unlock.status.restored_prefix", "Restored");
    dict.set("mls_unlock.status.restored_suffix", "encrypted space(s).");
    dict.set("mls_unlock.status.failed_suffix", "failed");
    dict.set(
        "mls_recovery_missing.aria_label",
        "This device does not have the encryption key yet",
    );
    dict.set(
        "mls_recovery_missing.title",
        "This device doesn't have the key yet",
    );
    dict.set(
        "mls_recovery_missing.subtitle",
        "encrypted content can't be opened here right now",
    );
    dict.set(
        "mls_recovery_missing.description",
        "This Realm is end-to-end encrypted. If you just accepted an invite, the key is delivered to you automatically when you join — nothing to enter; reload or let sync finish and new messages will open. Messages sent before you joined cannot be opened on any device — that is by design, and no recovery backup will unlock them. A recovery backup only brings back content from YOUR OWN earlier devices: set it up under Settings -> Recovery by generating your Recovery Key (24 words) — your encrypted history is backed up to it automatically.",
    );
    dict.set("mls_recovery_missing.button_dismiss", "Dismiss");

    // One-time account-MLS-secret BACKUP prompt (mirror of mls_unlock).
    dict.set("mls_backup.aria_label", "Back up encrypted history");
    dict.set("mls_backup.title", "Protect your encrypted history");
    dict.set("mls_backup.subtitle", "24 recovery words");
    dict.set(
        "mls_backup.description",
        "You're using encryption, but this account does not have an encrypted-history recovery backup yet. Create a 24-word recovery key so a fresh browser or device can restore the same history.",
    );
    dict.set(
        "mls_backup.description_existing",
        "You're using encryption, but this account does not have an encrypted-history recovery backup yet. Use your existing 24-word Recovery Key to encrypt and upload the backup.",
    );
    dict.set(
        "mls_backup.warning.passphrase_loss",
        "Save the 24 recovery words when they appear. They are shown once and are not stored by Cokret; existing devices keep working if you lose them, but new devices cannot restore this history.",
    );
    dict.set(
        "mls_backup.warning.existing_key",
        "The Recovery Key words are not uploaded. They are used locally to encrypt the backup before it leaves this device.",
    );
    dict.set("mls_backup.button_idle", "Create recovery key");
    dict.set("mls_backup.button_existing", "Back up with Recovery Key");
    dict.set("mls_backup.button_retry", "Retry backup");
    dict.set("mls_backup.button_busy", "Backing up...");
    dict.set("mls_backup.button_dismiss", "Remind me later");
    dict.set("mls_backup.button_saved", "I saved the key");
    dict.set("mls_backup.button_done", "Done");
    dict.set("mls_backup.copy_key", "Copy");
    dict.set("mls_backup.copy_key_done", "Copied ✓");
    dict.set("mls_backup.download_key", "Download .txt");
    dict.set("mls_backup.existing_key_label", "Recovery Key (24 words)");
    dict.set(
        "mls_backup.existing_key_placeholder",
        "Enter the 24-word Recovery Key you already saved",
    );
    dict.set(
        "mls_backup.existing_key_hint",
        "This verifies you still have the offline key before encrypted-history backup is enabled.",
    );
    dict.set(
        "mls_backup.generated_key_label",
        "Your 24-word recovery key",
    );
    dict.set(
        "mls_backup.generated_key_warning",
        "Store these words now. They will disappear when you close this prompt.",
    );
    dict.set(
        "mls_backup.status.uploading",
        "Encrypting and uploading backup...",
    );
    dict.set(
        "mls_backup.status.created",
        "Backup created. Save the 24 recovery words now.",
    );
    dict.set(
        "mls_backup.status.generate_failed",
        "Recovery key generation failed:",
    );
    dict.set(
        "mls_backup.status.invalid_recovery_key",
        "Enter the full 24-word Recovery Key.",
    );

    // X11.1 — persistent MLS recovery-key settings section.
    dict.set("settings.mls_recovery.title", "Encrypted history recovery");
    dict.set(
        "settings.mls_recovery.status.loading",
        "Checking backup status…",
    );
    dict.set(
        "settings.mls_recovery.status.no_local_secret",
        "Not yet used encryption — there's nothing to back up until you send an encrypted message or write to an encrypted board.",
    );
    dict.set(
        "settings.mls_recovery.status.backed_up",
        "Backed up — encrypted history can be restored with your 24-word recovery key.",
    );
    dict.set(
        "settings.mls_recovery.status.not_backed_up",
        "Not backed up — create a 24-word recovery key so a fresh browser or device can restore your encrypted history.",
    );
    dict.set(
        "settings.mls_recovery.submit",
        "Create / replace recovery key words",
    );

    // Space-admin view (section labels)
    dict.set("realm_admin.title", "Realm Settings");
    dict.set("realm_admin.devices", "Devices");
    dict.set("realm_admin.members", "Members");
    dict.set("realm_admin.access", "Access");
    dict.set("realm_admin.security_mls", "Security & MLS");

    // Chat / Discussion view (panel headers + key buttons; reuse common.* for
    // generic verbs like Save/Cancel/Retry/Edit/Confirm).
    dict.set("chat.discussions_header", "Strand discussions");
    dict.set("chat.users_header", "Users");
    dict.set("chat.settings_header", "Settings");
    dict.set("chat.new_discussion", "New discussion");
    dict.set("chat.new_strand", "New Strand");
    dict.set("chat.hide_list", "Hide discussion list");
    dict.set("chat.label.title", "Title");
    dict.set("chat.label.summary", "Summary");
    dict.set("common.remove", "Remove");
    dict.set("chat.call.voice", "Start voice call");
    dict.set("chat.call.video", "Start video call");
    // T7.2 watch level fast switcher.
    dict.set("chat.watch_level.prefix", "Watching");
    dict.set(
        "chat.watch_level.tooltip",
        "Choose how often this Strand notifies you.",
    );
    dict.set("chat.watch_level.mentions_only", "Mentions only");
    dict.set("chat.watch_level.participating", "Participating");
    dict.set("chat.watch_level.all", "All");
    dict.set("chat.watch_level.muted", "Muted");
    dict.set("chat.watch_level.pending", "Updating watch level…");
    dict.set("chat.watch_level.saved", "Watch level updated.");
    dict.set(
        "chat.watch_level.failed",
        "Watch level update failed (rolled back).",
    );
    // T7.3 handle reassigned context.
    dict.set("chat.handle_reassigned.badge", "handle reassigned");
    dict.set(
        "chat.handle_reassigned.tooltip",
        "This handle was captured at compose time but currently resolves to a different DID. Compare the captured label against the current sender.",
    );
    dict.set("chat.binding_context.separator", " @ ");
    dict.set("chat.binding_context.details", "Show service binding");
    // T7.4 E2EE status indicators.
    dict.set("chat.crypto.decrypting", "Decrypting…");
    dict.set("chat.crypto.decrypt_failed", "Failed to decrypt");
    dict.set("chat.crypto.decrypt_failed_action", "Open recovery");
    dict.set("chat.crypto.key_missing", "Key not yet received");
    dict.set(
        "chat.crypto.key_missing_hint",
        "Waiting for a Welcome message from the Space admin or another device.",
    );
    dict.set(
        "chat.crypto.needs_verification",
        "Sender needs verification",
    );
    dict.set("chat.mls.epoch", "MLS epoch");
    dict.set("chat.mls.key_package", "Key package");
    dict.set("chat.mls.welcome", "Welcome");
    // T7.5 layout polish.
    dict.set("chat.tabs.settings", "Settings");
    dict.set("chat.tabs.members", "Members");
    dict.set("chat.tabs.notifications", "Notifications");
    dict.set("chat.button.create", "Create");
    dict.set("chat.button.reply", "Reply");
    dict.set("chat.button.react", "React");
    dict.set("chat.button.redact", "Redact");
    dict.set("chat.you_badge", "You");
    // Member visual indicators surfaced wherever a principal DID is
    // rendered (realm-admin member list, @mention picker, chat sender
    // attribution).
    dict.set("member.badge.agent", "Agent");
    // Compose drop-zone + attachment upload (A6.2).
    dict.set(
        "compose.drop_zone.hint",
        "Drop files here to attach, or click Attach",
    );
    dict.set("compose.upload_progress", "Uploading…");
    dict.set("compose.upload_error", "Upload failed");
    // Message pinning (A6.3).
    dict.set("message.pin", "Pin");
    dict.set("message.unpin", "Unpin");
    dict.set("pinned_bar.title", "Pinned messages");
    dict.set("pinned_bar.empty", "No pinned messages.");
    dict.set("pinned_bar.scroll_to", "Jump to message");
    // Actor-private Realm list pinning.
    dict.set("realm.pin", "Pin Realm");
    dict.set("realm.unpin", "Unpin Realm");
    dict.set("realm.pinned", "Pinned Realm");
    dict.set("realm.pin_failed", "Realm pin account-data save failed");
    dict.set("realm.add_member", "Add Member");
    dict.set("realm.settings", "Settings");
    dict.set("chat.empty.title", "No discussion track available");
    dict.set(
        "chat.empty.description",
        "This Space should expose a default Strand discussion track.",
    );
    dict.set("chat.empty.create_button", "Create Strand");

    // Notifications panel (group tabs + toolbar tooltips)
    dict.set("notifications.feed_title", "Notification feed");
    dict.set("notifications.view.latest", "Latest");
    dict.set("notifications.view.realm", "Realm");
    dict.set("notifications.view.type", "Type");
    dict.set("notifications.tooltip.settings", "Notification settings");
    dict.set("notifications.tooltip.mark_all_read", "Mark all read");
    dict.set("notifications.tooltip.show_archived", "Show archived");
    dict.set("notifications.tooltip.hide_archived", "Hide archived");
    dict.set("notifications.tooltip.refresh", "Refresh notifications");
    dict.set(
        "notifications.filtered_body",
        "All loaded notifications are currently hidden by archive, type, or per-Realm mute rules.",
    );

    // Verify Device (cross-signing / SAS)
    dict.set("verify_device.title", "Device Verification");
    dict.set("verify_device.choose_method", "choose method");
    dict.set("verify_device.qr_code", "QR Code");
    dict.set("verify_device.sas_emoji", "SAS (Emoji)");
    dict.set("verify_device.qr_section", "QR Verification");
    dict.set("verify_device.qr_section_hint", "scan or display");
    dict.set("verify_device.sas_section", "SAS Verification");
    dict.set("verify_device.sas_section_hint", "emoji comparison");
    dict.set("verify_device.target_device_id", "Target Device ID");
    dict.set(
        "verify_device.target_device_placeholder",
        "Device ID to verify",
    );
    dict.set("verify_device.generate_qr", "Generate QR Data");
    dict.set("verify_device.start_sas", "Start SAS Verification");
    dict.set(
        "verify_device.short_auth_string",
        "Short Authentication String",
    );

    // A6.4 — keyboard shortcut help overlay.
    dict.set("shortcuts.title", "Keyboard shortcuts");
    dict.set("shortcuts.dismiss", "Dismiss");
    dict.set("shortcuts.list.help", "Show this shortcut help");
    dict.set("shortcuts.list.dismiss", "Close any open dialog");
    dict.set("shortcuts.list.palette", "Open command palette");
    dict.set("shortcuts.list.palette_mac", "Open command palette (macOS)");
    dict.set("shortcuts.list.send", "Send the current message");
    // Personal blocklist (A5) — actor-private `ck.account.blocklist`
    // account-data namespace. Used by the Settings → Privacy panel, the
    // member-row context action, and the timeline/chat "blocked user"
    // placeholder row.
    dict.set("settings.privacy.title", "Privacy");
    dict.set("settings.privacy.blocked_users.title", "Blocked users");
    dict.set(
        "settings.privacy.blocked_users.empty",
        "No users blocked. Block someone from a member list or message row to manage entries here.",
    );
    dict.set(
        "settings.privacy.blocked_users.did_placeholder",
        "DID to block",
    );
    dict.set(
        "settings.privacy.blocked_users.reason_placeholder",
        "Reason (optional)",
    );
    dict.set("settings.privacy.blocked_users.add", "Block");
    dict.set("settings.privacy.blocked_users.added", "Blocked");
    dict.set("settings.privacy.blocked_users.removed", "Unblocked");
    dict.set(
        "settings.privacy.blocked_users.duplicate",
        "Already blocked",
    );
    dict.set(
        "settings.privacy.blocked_users.did_required",
        "Enter a DID first.",
    );
    // F-BLOCKLIST-VALID-1: shown live as the user types, and as a
    // submit-time guard when the input still doesn't look like a DID.
    dict.set(
        "settings.privacy.blocked_users.did_invalid",
        "DID must start with did: (e.g. did:web:alice.example).",
    );
    dict.set("settings.privacy.unblock", "Unblock");
    // A4b — avatar upload UI keys.
    dict.set("settings.avatar.title", "Profile picture");
    dict.set("settings.avatar.upload", "Upload new avatar");
    dict.set("settings.avatar.clear", "Remove avatar");
    dict.set("settings.avatar.uploading", "Uploading avatar…");
    dict.set("settings.avatar.processing", "Preparing avatar…");
    dict.set("settings.avatar.crop_ready", "Adjust crop, then upload.");
    dict.set(
        "settings.avatar.invalid_image",
        "Selected file is not an image.",
    );
    dict.set("settings.avatar.upload_cropped", "Upload cropped avatar");
    dict.set("settings.avatar.cancel_crop", "Cancel crop");
    dict.set("settings.avatar.zoom", "Zoom");
    dict.set("settings.avatar.pan_x", "Horizontal");
    dict.set("settings.avatar.pan_y", "Vertical");
    dict.set("settings.avatar.error", "Avatar upload failed");
    // A6.1 — global cross-Realm message search.
    dict.set("search.title", "Search messages");
    dict.set("search.placeholder", "Search across all your realms...");
    dict.set(
        "search.results.empty",
        "Type a query to search across your realms.",
    );
    dict.set("search.results.loading", "Searching…");
    dict.set("search.results.error", "Search failed");
    dict.set("search.no_results", "No matches found.");
    dict.set("search.result.snippet", "Snippet");
    dict.set("topbar.search_button", "Open search");
    dict.set("shortcuts.list.search", "Open global message search");
    dict.set("member.block", "Block this user");
    dict.set("member.block_confirm.title", "Block this user?");
    dict.set(
        "member.block_confirm.body",
        "Their messages will be hidden behind a placeholder. You can unblock them anytime from Settings → Privacy.",
    );
    dict.set("member.block_confirm.confirm", "Block");
    dict.set("timeline.blocked_user", "[Blocked user]");
    dict.set("timeline.show_anyway", "Show anyway");

    // A3 (round 28): rich content renderer (markdown / image / video /
    // audio / code / generic attachment).
    dict.set("content.code.copy", "Copy");
    dict.set("content.image.broken", "Image unavailable");
    dict.set(
        "content.video.unsupported",
        "Your browser does not support inline video.",
    );
    dict.set(
        "content.audio.unsupported",
        "Your browser does not support inline audio.",
    );
    dict.set("content.attachment.download", "Download");

    // T7.1 — friendly product-language terms surfaced in the main strand.
    // Raw protocol identifiers (did:web:, ck.*, schema ids, profile ids)
    // are only shown inside Developer Tools / Diagnostics surfaces.
    dict.set(
        "friendly.identifier.placeholder",
        "john:example.com or did:web:...",
    );
    dict.set(
        "friendly.identifier.placeholder_multiline",
        "alice:example.com\nbob:example.com",
    );
    dict.set("friendly.identifier.label", "Member identifier");
    dict.set(
        "friendly.identifier.hint",
        "Enter a handle like user:domain.com, or paste a full DID.",
    );
    dict.set("friendly.identifier.handle_or_email", "Handle or DID");
    dict.set("friendly.member.automated", "Automated member");
    dict.set("friendly.member.bot", "Bot");
    dict.set("friendly.member.human", "Person");
    dict.set("friendly.member.agent_badge", "Bot");
    dict.set("friendly.identifier.technical", "Protocol identifier");
    dict.set(
        "friendly.identifier.show_technical",
        "Show technical details",
    );
    dict.set(
        "friendly.identifier.hide_technical",
        "Hide technical details",
    );
    dict.set("friendly.security.encrypted", "Encrypted");
    dict.set("friendly.security.encrypted_short", "Encrypted");
    dict.set("friendly.draft.label", "Draft");
    dict.set("friendly.sync.state", "Sync state");
    dict.set("friendly.sync.synced", "Up to date");
    dict.set("friendly.sync.pending", "Syncing…");
    dict.set("friendly.sync.frontier", "Sync state");

    // Friendly labels for the security-boundary Realm and container Space split.
    dict.set("friendly.realm", "Realm");
    dict.set("friendly.realm.short", "Realm");
    dict.set("friendly.realm.description", "Security boundary — membership, policy, federation, and encryption are governed at this level.");
    dict.set("friendly.realm.security_class", "Security boundary");
    dict.set(
        "friendly.realm.security_class.standard",
        "Standard security",
    );
    dict.set(
        "friendly.realm.security_class.high_assurance",
        "High assurance",
    );
    dict.set("friendly.realm.settings", "Realm settings");
    dict.set(
        "friendly.realm.settings.subtitle",
        "Policy, membership, federation, and E2EE",
    );
    dict.set("friendly.realm.switcher", "Switch Realm");
    dict.set("friendly.realm.ref_label", "Realm");
    dict.set("friendly.space", "Space");
    dict.set("friendly.space.short", "Space");
    dict.set(
        "friendly.space.description",
        "Navigation container — boards, lists, and sections live inside a Realm.",
    );
    dict.set("friendly.space.container_class", "Navigation container");
    dict.set("friendly.space.settings", "Space settings");
    dict.set(
        "friendly.space.settings.subtitle",
        "Navigation, sort, and display",
    );
    dict.set("friendly.discussion.realm_ref", "Realm");
    dict.set(
        "friendly.discussion.realm_ref.hint",
        "Which Realm this discussion belongs to (security boundary).",
    );

    // Profile gate (friendly version of ProfileGateNotice).
    dict.set("profile_gate.title", "Feature not available on this server");
    dict.set(
        "profile_gate.body",
        "This server does not yet support the capabilities needed for this view. Try a different server or contact your administrator.",
    );
    dict.set("profile_gate.friendly.minimal_client", "Basic client");
    dict.set("profile_gate.friendly.kanban_mvp", "Boards");
    dict.set("profile_gate.friendly.chat_mvp", "Discussions");
    dict.set("profile_gate.friendly.full_client", "Full client");
    dict.set("profile_gate.friendly.e2ee_client", "Encrypted messaging");
    dict.set("profile_gate.friendly.unknown", "Client feature");

    // Developer Tools / Diagnostics entry points used to expose the
    // protocol-level details that used to leak into the main strand.
    dict.set("nav.developer", "Developer Tools");
    dict.set("developer.title", "Developer Tools");
    dict.set("developer.subtitle", "Protocol diagnostics and audit");
    dict.set("developer.section.schemas", "Schemas & event kinds");
    dict.set("developer.section.profiles", "Server profiles");
    dict.set("developer.section.events", "Raw event log");
    dict.set("developer.section.conformance", "Protocol conformance");
    dict.set("developer.section.protocol_version", "Protocol version");
    dict.set(
        "developer.hint",
        "These details are intended for developers and operators. End users do not need to read them.",
    );
    dict.set("developer.profile.required", "Required profile id");
    dict.set("developer.profile.advertised", "Server advertised");
    dict.set("developer.event.kind", "Event kind");
    dict.set("developer.schema.id", "Schema id");

    // Round R2/R3 (T11) — fail-closed blob presign error strings.
    dict.set(
        "blob.error.legal_hold_active",
        "This file can't be downloaded right now. A legal hold is in effect; the file will remain inaccessible until the hold is lifted.",
    );
    dict.set(
        "blob.error.redacted",
        "This file was redacted by an administrator and can no longer be downloaded.",
    );
    dict.set(
        "blob.error.plaintext_not_authorised",
        "This file can't be opened by the current service because plaintext access wasn't authorised.",
    );
    dict.set(
        "blob.error.not_authorised",
        "You don't have permission to download this file.",
    );

    // Round R2/R3 (T06) — moderation appeal state labels.
    dict.set("moderation.appeal.state.none", "No appeal filed");
    dict.set(
        "moderation.appeal.state.submitted",
        "Appeal submitted — awaiting review",
    );
    dict.set("moderation.appeal.state.under_review", "Under review");
    dict.set("moderation.appeal.state.decided", "Decided");
    dict.set("moderation.appeal.state.closed", "Closed");

    // Round R2/R3 (T16) — late key recovery banner.
    dict.set(
        "timeline.late_recovery.banner",
        "Older messages were just decrypted, {minutes} minutes after they arrived.",
    );

    // Round R2/R3 (T07) — Realm terminal-state banner.
    dict.set(
        "realm.destroyed.banner",
        "This realm has been permanently retired.",
    );

    // Round R2/R3 (T15) — OOB lookup-form generic error string.
    dict.set(
        "oob.code.invalid_or_expired",
        "That code is invalid or expired.",
    );

    // Round 4 (spec a77b995) — invite terminal-state labels surfaced
    // by [`crate::invite_claim::InviteTerminalState`].
    dict.set("invite.terminal.claimed", "Claimed");
    dict.set(
        "invite.terminal.send_failed",
        "Could not deliver the invite (network or auth-server error).",
    );
    dict.set(
        "invite.terminal.revoked_by_capability_loss",
        "Revoked — the inviter no longer has permission to invite.",
    );
    dict.set(
        "invite.terminal.revoked_by_inviter_left",
        "Revoked — the inviter left the space.",
    );
    dict.set(
        "invite.terminal.invalidated_by_rate_limit",
        "Invalidated — too many failed attempts; the invite is now blocked.",
    );

    // Round 4 — e2ee_late_recovery banner sourced from
    // `late_recovery_original_event_id`.
    dict.set(
        "timeline.e2ee_late_recovery.banner",
        "Older messages were just decrypted, {minutes} minutes after they arrived.",
    );

    // R3 spec sync (b47ff6ec) — new error toast strings surfaced by the
    // cokret-spec error code expansion (CKP-0010 media binding,
    // agent FSM, handle homograph wire-level enforce, recovery
    // policy). The HTTP error reply carries a stable
    // `code` / `reason` field that the toast layer maps via these
    // keys. zh translations follow in `chinese_translations()`.
    add_r3_error_keys(&mut dict);

    // Contacts UI, invite-receive policy, and the realm "invite from
    // contacts" picker. English is the authoritative default; zh follows
    // in `chinese_translations()`.
    add_contacts_keys(&mut dict);

    dict
}

/// English strings for the contacts surfaces (contact-request panel, contact
/// rows, contacts list), the invite-receive policy settings card, and the
/// realm-admin "invite from contacts" block. zh follows in
/// [`add_contacts_keys_zh`].
fn add_contacts_keys(dict: &mut TranslationDict) {
    // ── ContactsPanel ─────────────────────────────────────────────────
    dict.set("contacts.title", "Contacts");
    dict.set("contacts.add_button", "Add contact");
    dict.set("contacts.load_error", "Couldn't load contacts: {error}");
    dict.set("contacts.retry", "Retry");
    dict.set("contacts.loading", "Loading contacts…");
    dict.set("contacts.empty_title", "No contacts yet");
    dict.set(
        "contacts.empty_hint",
        "Add a contact to send a friend request — they'll show up here once it's accepted.",
    );
    dict.set("contacts.empty_add", "Add a contact");

    // ── ContactNewPanel ───────────────────────────────────────────────
    dict.set("contacts.new.title", "Add contact");
    dict.set("contacts.new.subtitle", "Needs their approval");
    dict.set(
        "contacts.new.intro",
        "Enter the other person's DID to send a friend request. By default contacts can both message you and invite you to groups (just like a regular friend). For tighter control, uncheck options below.",
    );
    dict.set("contacts.new.target_label", "Their DID");
    dict.set(
        "contacts.new.recipient_service_label",
        "Their server (only when adding across servers)",
    );
    dict.set(
        "contacts.new.recipient_service_placeholder",
        "did:web:ps.bob.example (leave blank if same server)",
    );
    dict.set(
        "contacts.new.recipient_service_hint",
        "If they're on a different server (Principal Server), enter its service DID; leave blank if you're on the same server.",
    );
    dict.set(
        "contacts.new.scope_label",
        "Friend permissions (both on by default for a regular contact)",
    );
    dict.set("contacts.new.scope_empty", "Pick at least one permission.");
    dict.set("contacts.new.message_label", "Note (optional)");
    dict.set("contacts.new.message_placeholder", "Say hello…");
    dict.set("contacts.new.sending", "Sending request…");
    dict.set(
        "contacts.new.sent",
        "Request sent — waiting for them to accept.",
    );
    dict.set("contacts.new.send_failed", "Failed to send: {error}");
    dict.set("contacts.new.submit", "Send request");
    dict.set("contacts.new.submit_busy", "Sending…");

    // ── scope_label ───────────────────────────────────────────────────
    dict.set(
        "contacts.scope.direct_message",
        "Direct messages (can DM me)",
    );
    dict.set("contacts.scope.invite", "Can invite me to groups");
    dict.set("contacts.scope.voice_call", "Voice calls");
    dict.set("contacts.scope.video_call", "Video calls");
    dict.set("contacts.shared_scopes", "Shared permissions: ");

    // ── ContactRow ────────────────────────────────────────────────────
    dict.set("contacts.state.pending_incoming", "Waiting on you");
    dict.set("contacts.state.pending_outgoing", "Waiting for them");
    dict.set("contacts.state.accepted", "Contact");
    dict.set("contacts.state.rejected", "Declined");
    dict.set("contacts.state.tombstoned", "Removed");
    dict.set("contacts.state.blocked", "Blocked");
    dict.set("contacts.action.accept", "Accept");
    dict.set("contacts.action.reject", "Decline");
    dict.set("contacts.action.withdraw", "Withdraw");
    dict.set("contacts.action.message", "Message");
    dict.set("contacts.action.call_voice", "Voice call");
    dict.set("contacts.action.call_video", "Video call");
    dict.set("contacts.action.block", "Block");
    dict.set("contacts.action.accepting", "Accepting…");
    dict.set("contacts.action.rejecting", "Declining…");
    dict.set("contacts.action.withdrawing", "Withdrawing…");
    dict.set("contacts.action.blocking", "Blocking…");
    dict.set("contacts.dm.opening", "Opening direct chat…");
    dict.set(
        "contacts.dm.not_ready",
        "Direct chat isn't ready yet, try again shortly.",
    );
    dict.set(
        "contacts.dm.open_failed",
        "Couldn't open direct chat: {error}",
    );
    dict.set("contacts.block.confirm_title", "Block this contact?");
    dict.set(
        "contacts.block.confirm_body",
        "Blocking removes this contact and stops them from sending you requests or invites again.",
    );
    dict.set("contacts.block.confirm_button", "Confirm block");
    dict.set("contacts.block.cancel", "Cancel");
    dict.set("contacts.action_failed", "Action failed: {error}");

    // ── InvitePolicySettingsCard ──────────────────────────────────────
    dict.set("invite_policy.title", "Who can invite me");
    dict.set("invite_policy.loading", "Loading…");
    dict.set(
        "invite_policy.intro",
        "Choose which sources can invite you to groups. Invites outside the allowed range are dropped or held for review per the rules below.",
    );
    dict.set(
        "invite_policy.load_failed",
        "Couldn't read your current policy from the server (using defaults): {error}",
    );
    dict.set("invite_policy.kinds_title", "Allowed invite sources");
    dict.set(
        "invite_policy.kind.consent_grant",
        "Contacts (friends you've approved)",
    );
    dict.set("invite_policy.kind.locator_ref", "Invite links");
    dict.set("invite_policy.kind.shared_realm", "Members of my groups");
    dict.set(
        "invite_policy.kind.same_principal_server",
        "Users on my server",
    );
    dict.set(
        "invite_policy.kind.explicit_address",
        "Anyone who knows my address",
    );
    dict.set(
        "invite_policy.explicit_label",
        "How to handle \"anyone who knows my address\"",
    );
    dict.set("invite_policy.explicit.drop", "Drop");
    dict.set("invite_policy.explicit.quarantine", "Hold for review");
    dict.set("invite_policy.explicit.notify", "Notify me");
    dict.set(
        "invite_policy.unknown_prefix",
        "Invites from unknown sources will be ",
    );
    dict.set("invite_policy.unknown_drop", "dropped");
    dict.set("invite_policy.unknown_quarantine", "held for review");
    dict.set("invite_policy.unknown_suffix", ".");
    dict.set("invite_policy.disclosure_title", "Receipts");
    dict.set(
        "invite_policy.disclosure_toggle",
        "Let contacts see the invite outcome",
    );
    dict.set(
        "invite_policy.disclosure_hint",
        "Strangers (low-trust sources) never get a receipt, so you don't reveal whether you're online or accepted the invite.",
    );
    dict.set("invite_policy.blocked_title", "Blocked inviters");
    dict.set("invite_policy.blocked_empty", "No blocked inviters.");
    dict.set("invite_policy.unblock", "Remove");
    dict.set(
        "invite_policy.unblocked_hint",
        "Removed from the block list — remember to save.",
    );
    dict.set("invite_policy.saving", "Saving…");
    dict.set("invite_policy.saved", "Saved.");
    dict.set("invite_policy.save_failed", "Save failed: {error}");
    dict.set("invite_policy.save", "Save");
    dict.set("invite_policy.save_busy", "Saving…");

    // ── realm-admin: invite from contacts ─────────────────────────────
    dict.set("realm_admin.invite_from_contacts", "Add from contacts");
    dict.set("realm_admin.invite_recommended", "Recommended");
    dict.set("realm_admin.invite_loading_contacts", "Loading contacts…");
    dict.set(
        "realm_admin.invite_contacts_failed",
        "Couldn't load contacts: {error}",
    );
    dict.set(
        "realm_admin.invite_no_contacts",
        "No contacts available to invite yet.",
    );
    dict.set(
        "realm_admin.invite_unauthorized",
        "Hasn't authorized invites",
    );
    dict.set(
        "realm_admin.invite_none_eligible",
        "No contacts can be invited (missing consent grant).",
    );
    dict.set("realm_admin.invite_sending", "Inviting {total} contact(s)…");
    dict.set(
        "realm_admin.invite_sent",
        "Invited {ok} contact(s) (pending acceptance).",
    );
    dict.set(
        "realm_admin.invite_partial",
        "Invited {ok}/{total} contact(s); some failed: {error}",
    );
    dict.set("realm_admin.invite_selected", "Invite selected contacts");
    dict.set(
        "realm_admin.invite_divider",
        "Or invite a stranger (paste an invite link)",
    );
    dict.set(
        "realm_admin.invite_bad_server",
        "Invalid server address: {error}",
    );
}

/// R3 spec sync (b47ff6ec) — English toast / inline-error strings for
/// the new error codes. Sub-grouped into agent FSM, media binding,
/// handle wire-level enforce, and recovery proof.
fn add_r3_error_keys(dict: &mut TranslationDict) {
    // Agent FSM + pairing.
    dict.set(
        "error.agent.pairing_request_expired",
        "Pairing request expired — start a fresh pairing strand and re-scan.",
    );
    dict.set(
        "error.agent.proof_invalid",
        "Proof signature did not verify — re-sign the request and retry.",
    );
    dict.set(
        "error.agent.paused",
        "Agent is paused. Resume the agent before retrying.",
    );
    dict.set(
        "error.agent.deactivated",
        "Agent is permanently deactivated. Provision a new agent to continue.",
    );
    dict.set(
        "error.agent.accountability_grant_missing",
        "Controller accountability grant is missing or stale; reattach a grant before retrying.",
    );
    dict.set(
        "error.agent.approval_already_consumed",
        "This approval nonce was already consumed. Request a fresh approval.",
    );

    // Media binding (CKP-0010).
    dict.set(
        "error.call.focus_unavailable_for_client",
        "The selected media focus is unavailable for this client. Retry or leave the call.",
    );
    dict.set(
        "error.call.focus_mismatch",
        "Media focus disagreement with the call state. Rejoin the call to reconcile.",
    );
    dict.set(
        "error.call.unknown_focus_type",
        "Unknown media focus type. Update the app to a compatible version.",
    );
    dict.set(
        "error.call.token_issuer_unauthorised",
        "Media token issuer is not the realm's current media service. Refusing connection.",
    );
    dict.set(
        "error.call.participant_binding_invalid",
        "Participant binding failed validation (signature, TTL, or tuple mismatch).",
    );
    dict.set(
        "error.call.participant_identity_unrecognised",
        "Backend reported a participant identity not present in the call state. Failing closed.",
    );
    dict.set(
        "error.call.session_focus_already_committed",
        "The call's session focus is already committed; rejoin to use it.",
    );
    dict.set(
        "error.call.e2ee_key_source_unauthorised",
        "Refusing media key from an unauthorised source — MLS exporter is the only allowed origin.",
    );
    dict.set(
        "error.call.recording_artifact_pipeline_bypassed",
        "Recording destination is not a Cokret authenticated blob — refusing to record.",
    );
    dict.set(
        "error.call.desktop_media_unavailable",
        "Desktop calling is not ready yet on this build — no media transport. Use a web client to place this call.",
    );

    // Handle wire-level enforce.
    dict.set(
        "error.handle.homograph_forbidden",
        "This handle uses script-mixed or confusable characters and cannot be registered.",
    );
    dict.set(
        "error.handle.script_mixed_warning",
        "Warning: the handle mixes scripts (e.g. Latin + Cyrillic). Registration will be rejected.",
    );
    dict.set(
        "error.handle.nfc_normalization_warning",
        "Handle was Unicode-normalised (NFC). The normalised form will be the canonical handle.",
    );

    // Recovery.
    dict.set(
        "error.recovery.witness_revoke_lagging",
        "Recovery witness revoke is lagging — wait for witness chain to catch up.",
    );
    dict.set(
        "error.recovery.policy_mismatch",
        "Recovery policy mismatch: the on-server policy version differs from the request.",
    );
    dict.set(
        "error.recovery.challenge_proof_invalid",
        "Recovery challenge proof did not verify. Re-collect the proof and retry.",
    );
}

/// R3 spec sync — Chinese error toast strings.
fn add_r3_error_keys_zh(dict: &mut TranslationDict) {
    dict.set(
        "error.agent.pairing_request_expired",
        "配对请求已过期 — 请重新发起配对并重新扫描。",
    );
    dict.set(
        "error.agent.proof_invalid",
        "证明签名验证失败 — 请重新签名后再试。",
    );
    dict.set(
        "error.agent.paused",
        "Agent 已暂停。请先恢复 Agent 再重试。",
    );
    dict.set(
        "error.agent.deactivated",
        "Agent 已永久停用。请重新配置一个新的 Agent。",
    );
    dict.set(
        "error.agent.accountability_grant_missing",
        "控制方问责授权缺失或已失效；请重新挂载授权后再试。",
    );
    dict.set(
        "error.agent.approval_already_consumed",
        "该 approval nonce 已被消费,请申请新的 approval。",
    );

    dict.set(
        "error.call.focus_unavailable_for_client",
        "所选媒体 focus 对此客户端不可用。请重试或离开通话。",
    );
    dict.set(
        "error.call.focus_mismatch",
        "媒体 focus 与通话状态不一致。请重新加入通话。",
    );
    dict.set(
        "error.call.unknown_focus_type",
        "未知的媒体 focus 类型,请将应用升级到兼容版本。",
    );
    dict.set(
        "error.call.token_issuer_unauthorised",
        "媒体 token 签发者不是 realm 当前的媒体服务。拒绝连接。",
    );
    dict.set(
        "error.call.participant_binding_invalid",
        "Participant binding 校验失败(签名/TTL/字段不一致)。",
    );
    dict.set(
        "error.call.participant_identity_unrecognised",
        "后端报告的 participant identity 不在通话状态列表中。Fail closed。",
    );
    dict.set(
        "error.call.session_focus_already_committed",
        "本通话的 session focus 已提交,请重新加入。",
    );
    dict.set(
        "error.call.e2ee_key_source_unauthorised",
        "拒绝接受来自非授权来源的媒体密钥 — 仅 MLS Exporter 派生密钥被接受。",
    );
    dict.set(
        "error.call.recording_artifact_pipeline_bypassed",
        "录制目标不是 Cokret 认证 blob — 拒绝录制。",
    );
    dict.set(
        "error.call.desktop_media_unavailable",
        "桌面端通话尚未就绪(此版本无媒体传输)。请改用 Web 客户端发起本次通话。",
    );

    dict.set(
        "error.handle.homograph_forbidden",
        "该 handle 含有跨脚本或易混淆字符,无法注册。",
    );
    dict.set(
        "error.handle.script_mixed_warning",
        "警告:handle 混合了多种文字系统(例如 Latin + Cyrillic),将被拒绝。",
    );
    dict.set(
        "error.handle.nfc_normalization_warning",
        "Handle 已进行 Unicode 规范化(NFC),规范化结果将作为唯一形式。",
    );

    dict.set(
        "error.recovery.witness_revoke_lagging",
        "Recovery witness 撤销链落后 — 请等待 witness 链跟上。",
    );
    dict.set(
        "error.recovery.policy_mismatch",
        "Recovery policy 不匹配:服务器上的 policy 版本与请求不一致。",
    );
    dict.set(
        "error.recovery.challenge_proof_invalid",
        "Recovery 挑战证明验证失败。请重新采集证明后再试。",
    );

    // R3.3 (CKP-0011) — shareable object links (English dict). Error copy in
    // this dict follows the existing Chinese-first convention for `error.*`;
    // the dedicated zh dict carries the Chinese UI strings.
    dict.set("object_link.share", "Share link");
    dict.set("object_link.share_realm", "Share this Realm");
    dict.set("object_link.share_strand", "Share this Strand");
    dict.set("object_link.share_message", "Share this Message");
    dict.set("object_link.copy_https", "Copy link");
    dict.set("object_link.copy_app", "Copy \"open in app\" link");
    dict.set("object_link.copied", "Link copied");
    dict.set("object_link.open", "Open shared link");
    dict.set(
        "object_link.open_placeholder",
        "Paste a web+cokret: or https share link",
    );
    dict.set("object_link.opening", "Opening link\u{2026}");
    dict.set(
        "object_link.error.unavailable",
        "This link is unavailable or has expired.",
    );
    dict.set(
        "object_link.error.invalid",
        "That link format was not recognized.",
    );
}

/// Build Chinese translation dictionary.
pub fn chinese_translations() -> TranslationDict {
    let mut dict = TranslationDict::new(Locale::Zh);

    dict.set("app.title", "yougen");
    dict.set("nav.dashboard", "主页");
    dict.set("nav.timeline", "时间线");
    dict.set("nav.chat", "聊天");
    dict.set("nav.forum", "论坛");
    dict.set("nav.directory", "目录");
    dict.set("nav.notifications", "通知");
    dict.set("nav.settings", "设置");
    dict.set("nav.login", "登录");
    dict.set("nav.audit", "审计");
    dict.set("nav.devices", "设备");
    dict.set("nav.collaboration", "协作");
    dict.set("nav.contacts", "联系人");
    dict.set("nav.direct_messages", "私聊");
    dict.set("nav.new_realm_short", "领域");
    dict.set("nav.add_contact_short", "联系人");
    dict.set("direct.empty", "暂无私聊");
    dict.set("direct.sign_in", "登录后加载私聊");
    dict.set("direct.open", "打开私聊");
    dict.set("direct.unavailable", "暂不可发送");
    dict.set("contacts.empty", "暂无联系人");
    dict.set("contacts.sign_in", "登录后加载联系人");

    dict.set("login.server", "服务器");
    dict.set("login.connection_test", "连接测试");
    dict.set("login.server_url", "服务器地址");
    dict.set("login.test_connection", "测试连接");
    dict.set("login.account", "账户");
    dict.set("login.account_did", "账户 DID");
    dict.set("login.device_id", "设备 ID");
    dict.set("login.passkey", "Passkey 登录");
    dict.set("login.oidc", "OIDC 登录");
    dict.set("login.dev_login", "开发者登录");
    dict.set("login.session", "会话");
    dict.set("login.disconnected", "未连接");
    dict.set("login.connected", "已连接");
    dict.set("login.soft_logout", "软登出");
    dict.set("login.no_token", "无活跃令牌");
    dict.set("login.token_active", "令牌活跃");
    dict.set("login.refresh_token", "刷新令牌");
    dict.set("login.re_login", "重新登录");
    dict.set(
        "login.session_expired",
        "您的会话已过期。请重新登录以继续。",
    );

    dict.set("timeline.send", "发送");
    dict.set("timeline.reply", "回复");
    dict.set("timeline.react", "反应");
    dict.set("timeline.edit", "编辑");
    dict.set("timeline.redact", "撤回");
    dict.set("timeline.thread", "线程");
    dict.set("timeline.save", "保存");
    dict.set("timeline.cancel", "取消");
    dict.set("timeline.pending", "(待定)");
    dict.set("timeline.edited", "(已编辑)");
    dict.set("timeline.redacted", "[消息已撤回]");

    dict.set("common.loading", "加载中...");
    dict.set("common.error", "错误");
    dict.set("common.retry", "重试");
    dict.set("common.close", "关闭");
    dict.set("common.confirm", "确认");
    dict.set("common.cancel", "取消");
    dict.set("common.save", "保存");
    dict.set("common.delete", "删除");
    dict.set("common.edit", "编辑");
    dict.set("common.send", "发送");
    dict.set("common.refresh", "刷新");
    dict.set("common.back", "返回");
    dict.set("common.next", "下一步");
    dict.set("common.online", "在线");
    dict.set("common.offline", "离线");
    dict.set("common.reconnecting", "重连中");

    // R-i18n-002 mirrored keys.
    dict.set("topbar.search_placeholder", "跳转到 Realm、视图或操作...");
    dict.set("topbar.notifications", "通知");
    dict.set("topbar.new_space", "新建空间");
    dict.set("topbar.account_menu", "账号菜单");

    dict.set("login.continue", "继续");
    dict.set("login.working", "处理中...");
    dict.set("login.signed_in_as", "已登录为");

    dict.set("dashboard.home", "主页");
    dict.set("dashboard.notifications_label", "通知");
    dict.set("dashboard.notifications_delta_unread", "未读与待审批");
    dict.set("dashboard.notifications_delta_signin", "需要登录");
    dict.set("dashboard.realms_label", "Realm");
    dict.set("dashboard.realms_delta_search", "搜索或加入 Realm");
    dict.set("dashboard.realms_delta_signin", "登录后加载 Realm");
    dict.set("dashboard.workspace_setup", "Realm 设置");
    dict.set(
        "dashboard.workspace_setup_delta",
        "创建第一个 Realm 与初始策略",
    );
    dict.set("dashboard.onboarding", "引导");
    dict.set("dashboard.onboarding_steps", "4 步");
    dict.set("dashboard.onboarding_delta", "身份、设备与恢复方案");
    dict.set("dashboard.recent_realms", "最近 Realm");
    dict.set("dashboard.no_realms", "暂无 Realm");
    dict.set("dashboard.no_realms_help", "服务器尚未返回 Realm 列表。");
    dict.set("dashboard.no_session_help", "客户端不会展示占位 Realm。");
    // F-I18N-CLEAN-1: 与 en dict 同步的新 keys。
    dict.set("dashboard.no_notifications", "暂无通知");
    dict.set("dashboard.notifications_signin", "登录后加载通知");
    dict.set(
        "dashboard.notifications_empty_sub",
        "未读项、审批请求与提醒会显示在此处",
    );
    dict.set("chat.empty_discussions", "暂无可用讨论 track。");
    dict.set("chat.empty_messages", "尚无消息。");
    dict.set("chat.loading_messages", "正在加载讨论...");
    // F-CHAT-DEAD-UI-1: 与 en dict 同步的讨论设置面板文案。
    dict.set("chat.settings.mute_notifications", "静音通知");
    dict.set("chat.settings.read_receipts", "已读回执");
    dict.set("chat.settings.shared_history", "共享历史");
    dict.set(
        "chat.settings.shared_history_hint",
        "Space 级别策略——在 Space 管理处设置。",
    );
    dict.set(
        "settings.muted_realms_empty",
        "未静音任何 Realm。在通知视图中静音吵闹 Realm。",
    );
    dict.set("realm_admin.no_members_loaded", "还没有成员。");
    dict.set(
        "realm_admin.members_empty_hint",
        "用上方的 + 按钮邀请第一位成员。",
    );
    dict.set("realm_admin.members_no_match", "没有匹配的成员。");
    dict.set(
        "realm_admin.invite_hint",
        "粘贴对方生成的邀请 locator 链接。",
    );

    dict.set("notifications.archived", "显示已归档");
    dict.set("notifications.mark_all_read", "全部标记已读");
    dict.set("notifications.empty_state", "暂无通知。");
    // F-NOTIF-VLIST-1: 与 en dict 同步的分页按钮文案。
    dict.set("notifications.showing", "已显示");
    dict.set("notifications.load_more", "加载更多");
    dict.set("directory.loading_more", "加载中…");
    dict.set("directory.load_more_realms", "加载更多 Realm");
    dict.set("directory.load_more_organizations", "加载更多组织");
    dict.set("directory.load_more_actors", "加载更多用户");

    dict.set("composer.send", "发送");
    dict.set("composer.encrypted_toggle", "本地加密");
    dict.set(
        "composer.plaintext_warning",
        "明文消息对所配置的服务器可见。",
    );

    dict.set("command_palette.realms", "Realm");
    dict.set("command_palette.jump_to", "跳转到");
    dict.set(
        "command_palette.empty",
        "未找到匹配的 Realm 或视图。按 Esc 关闭。",
    );
    dict.set("command_palette.close", "关闭 (Esc)");

    dict.set("mobile.filter_realms", "筛选 Realm...");
    dict.set("mobile.no_match", "未找到匹配 Realm。");

    // Kanban / Board view
    dict.set("kanban.board_header", "看板");
    dict.set("kanban.board_title", "看板");
    dict.set("kanban.board_hint", "拖动卡片到不同列即可移动。");
    dict.set("chat.send", "发送");
    dict.set("chat.send_secure", "加密发送");
    dict.set("chat.plaintext_blocked", "先输入消息内容再加密发送");
    dict.set("realm_admin.save_profile", "保存资料");
    dict.set("realm_admin.destroy_realm", "销毁 Realm");
    dict.set("realm_admin.archive_realm", "归档 Realm");
    dict.set("verify_device.refresh_trust", "刷新");
    dict.set("verify_device.verify_action", "验证");
    dict.set("verify_device.revoke_action", "撤销");
    dict.set("verify_device.revoke_confirm_title", "确认撤销此设备？");
    dict.set("verify_device.revoke_confirm_button", "确认撤销");
    dict.set("common.cancel_button", "取消");
    dict.set("common.refresh", "刷新");
    dict.set("common.save", "保存");
    dict.set("common.submit", "提交");
    dict.set("kanban.refresh_from_api", "从 API 刷新");
    dict.set("kanban.add_card", "添加卡片");
    dict.set("kanban.add_list", "添加列表");
    dict.set("kanban.save_card", "保存");
    dict.set("kanban.cancel_card", "取消");
    dict.set(
        "kanban.security_not_ready",
        "安全状态未就绪,请稍候重试后再写入该 Realm。",
    );
    dict.set("realm_admin.apply_policy", "应用策略");
    dict.set("realm_admin.grant_capability_move", "授予权限（Move）");
    dict.set("realm_admin.revoke_capability_move", "撤销权限（Move）");
    dict.set("realm_admin.admin_grant_title", "Realm 管理员");
    dict.set(
        "realm_admin.admin_grant_hint",
        "授予或撤销 ck.realm.admin 权限。以签名 capability 事件提交;待 soland reducer 投影后生效。",
    );
    dict.set("realm_admin.admin_subject_label", "管理员主体(DID)");
    dict.set("realm_admin.admin_grant_id_label", "Grant ID");
    dict.set(
        "realm_admin.admin_subject_required",
        "请填写要设为管理员的主体 DID",
    );
    dict.set(
        "realm_admin.admin_grant_id_required",
        "请填写要撤销的 Grant ID",
    );
    dict.set("realm_admin.admin_grant_button", "设为管理员");
    dict.set("realm_admin.admin_revoke_button", "撤销管理员");
    dict.set("realm_admin.refresh_members", "刷新");
    dict.set("realm_admin.kick_member", "踢出");
    dict.set("realm_admin.ban_member", "封禁");
    dict.set("realm_admin.kick_member_move", "踢出（Move）");
    dict.set("realm_admin.ban_member_move", "封禁（Move）");
    dict.set("realm_admin.rotate_epoch", "轮换 Epoch");
    dict.set("realm_admin.leave_realm", "退出");
    dict.set("directory.list_contacts", "列出");
    dict.set("directory.search_button", "搜索");
    dict.set("directory.resolve_selected", "解析选中");
    dict.set("settings.store_backup", "存储备份");
    dict.set("settings.register_push", "注册推送");
    dict.set("settings.unregister_push", "注销推送");
    // T1.3 — 事件签名 / proof mode 状态显示。
    dict.set("settings.proof_mode.label", "事件签名");
    dict.set(
        "settings.proof_mode.hint",
        "决定本设备提交事件时附加的 proof 类型。",
    );
    dict.set("settings.proof_mode.placeholder_dev", "开发占位");
    dict.set("settings.proof_mode.real_ed25519", "真实 Ed25519");
    dict.set("settings.proof_mode.external_signer", "外部 signer");
    dict.set(
        "settings.proof_mode.production",
        "未配置 signer（生产模式）",
    );

    // T5.2 — signer DID / key id / freshness panel
    dict.set("settings.signer.label", "活跃签名者");
    dict.set("settings.signer.freshness.label", "上次签名时间");
    dict.set("settings.signer.freshness.never", "尚未签名");
    dict.set("kanban.archive_action", "归档");
    dict.set("kanban.restore_action", "恢复");
    dict.set("kanban.archived_lists_header", "已归档列表");
    dict.set("kanban.archived_lists_empty", "暂无已归档列表。");
    dict.set("kanban.archived_cards_header", "已归档卡片");
    dict.set("kanban.archived_cards_empty", "暂无已归档卡片。");
    dict.set("kanban.move_queue_header", "Move 队列");
    dict.set("kanban.move_queue_empty", "本地没有排队的 Move。");

    // Directory view
    dict.set("directory.org_empty_body", "未找到组织，可尝试搜索。");
    dict.set("directory.actors_empty_body", "未找到 actor，可尝试搜索。");

    // Recovery view
    dict.set("recovery.title", "恢复");
    dict.set("recovery.recovery_key_section", "恢复密钥（24 词）");
    dict.set("recovery.social_section", "社交恢复");
    dict.set("mls_unlock.aria_label", "授权此设备");
    dict.set("mls_unlock.title", "授权此设备");
    dict.set("mls_unlock.subtitle", "优先使用已授权设备确认");
    dict.set(
        "mls_unlock.description",
        "此浏览器已经登录，但还不是可读取加密历史的已授权设备。Cokret v1 要求已有授权设备先批准新设备，然后才共享 MLS 历史密钥。",
    );
    dict.set("mls_unlock.approve_step_existing_title", "在已有设备上");
    dict.set(
        "mls_unlock.approve_step_existing_body",
        "打开 Settings -> Devices -> Pair new device，查看待审批请求，比对验证码后批准。",
    );
    dict.set("mls_unlock.approve_step_new_title", "在此浏览器上");
    dict.set(
        "mls_unlock.approve_step_new_body",
        "打开配对请求页面并保持可见，等待已有设备完成批准。",
    );
    dict.set(
        "mls_unlock.loading_hint",
        "批量恢复加密空间可能需要几秒钟，请保持此标签页打开。",
    );
    dict.set("mls_unlock.open_pairing", "显示配对请求");
    dict.set("mls_unlock.show_recovery_key", "改用恢复密钥");
    dict.set("mls_unlock.hide_recovery_key", "隐藏恢复密钥");
    dict.set(
        "mls_unlock.recovery_fallback_hint",
        "仅在无法使用任何已授权设备时使用。24 词恢复密钥会进入恢复路径，并在策略校验后解锁加密历史备份。",
    );
    dict.set("mls_unlock.placeholder", "24 词恢复密钥");
    dict.set("mls_unlock.button_idle", "用密钥解锁");
    dict.set("mls_unlock.button_busy", "正在解锁…");
    dict.set("mls_unlock.dismiss", "稍后处理");
    dict.set("mls_unlock.reopen", "授权此设备");
    dict.set(
        "mls_unlock.status.enter_passphrase",
        "输入 24 词恢复密钥以解锁加密历史。",
    );
    dict.set(
        "mls_unlock.status.invalid_recovery_key",
        "请完整输入创建备份时显示的 24 个恢复词。",
    );
    dict.set("mls_unlock.status.fetching", "正在查找加密历史备份…");
    dict.set("mls_unlock.status.restoring_prefix", "正在恢复");
    dict.set(
        "mls_unlock.status.restoring_suffix",
        "个加密备份，可能需要几秒钟。",
    );
    dict.set("mls_unlock.status.restored_prefix", "已恢复");
    dict.set("mls_unlock.status.restored_suffix", "个加密空间。");
    dict.set("mls_unlock.status.failed_suffix", "个失败");
    dict.set("mls_recovery_missing.aria_label", "此设备尚未拿到加密密钥");
    dict.set(
        "mls_recovery_missing.title",
        "此设备还没有这个 Realm 的密钥",
    );
    dict.set("mls_recovery_missing.subtitle", "当前无法在此打开加密内容");
    dict.set(
        "mls_recovery_missing.description",
        "这个 Realm 是端到端加密的。如果你刚接受邀请,密钥会在你加入时自动送达——无需输入任何凭证,刷新或等同步完成,新消息即可打开。你加入之前发的消息在任何设备上都无法打开——这是设计使然,任何恢复备份都解不开它们。恢复备份只用于找回你自己其他设备上的内容:请到 设置 → Recovery,生成 24 词恢复密钥——你的加密历史会自动备份到它名下。",
    );
    dict.set("mls_recovery_missing.button_dismiss", "关闭");

    // 一次性账号 MLS secret 备份提示（mls_unlock 的镜像）。
    dict.set("mls_backup.aria_label", "备份加密历史");
    dict.set("mls_backup.title", "保护你的加密历史");
    dict.set("mls_backup.subtitle", "24 个恢复词");
    dict.set(
        "mls_backup.description",
        "你已在使用加密，但账号还没有加密历史恢复备份。创建一个 24 词恢复密钥后，新浏览器或新设备才能恢复同一份加密历史。",
    );
    dict.set(
        "mls_backup.description_existing",
        "你已在使用加密，但账号还没有加密历史恢复备份。请使用已经保存的 24 词恢复密钥来加密并上传备份。",
    );
    dict.set(
        "mls_backup.warning.passphrase_loss",
        "24 个恢复词出现后请立即保存。Cokret 不会保存它们；遗失后，已设置好的设备仍可继续使用，但新设备无法恢复这份加密历史。",
    );
    dict.set(
        "mls_backup.warning.existing_key",
        "恢复密钥不会上传；它只在本设备本地用于加密备份，然后才上传密文。",
    );
    dict.set("mls_backup.button_idle", "创建恢复密钥");
    dict.set("mls_backup.button_existing", "用恢复密钥备份");
    dict.set("mls_backup.button_retry", "重试备份");
    dict.set("mls_backup.button_busy", "正在备份…");
    dict.set("mls_backup.button_dismiss", "稍后提醒");
    dict.set("mls_backup.button_saved", "我已保存密钥");
    dict.set("mls_backup.button_done", "完成");
    dict.set("mls_backup.copy_key", "复制");
    dict.set("mls_backup.copy_key_done", "已复制 ✓");
    dict.set("mls_backup.download_key", "下载 .txt");
    dict.set("mls_backup.existing_key_label", "恢复密钥（24 词）");
    dict.set(
        "mls_backup.existing_key_placeholder",
        "输入你已经保存的 24 词恢复密钥",
    );
    dict.set(
        "mls_backup.existing_key_hint",
        "启用加密历史备份前，需要确认你仍然持有离线恢复密钥。",
    );
    dict.set("mls_backup.generated_key_label", "你的 24 词恢复密钥");
    dict.set(
        "mls_backup.generated_key_warning",
        "请现在保存这些词。关闭此提示后它们将不再显示。",
    );
    dict.set("mls_backup.status.uploading", "正在加密并上传备份…");
    dict.set(
        "mls_backup.status.created",
        "备份已创建。请立即保存这 24 个恢复词。",
    );
    dict.set("mls_backup.status.generate_failed", "恢复密钥生成失败：");
    dict.set(
        "mls_backup.status.invalid_recovery_key",
        "请输入完整的 24 词恢复密钥。",
    );

    // X11.1 — 持久化的 MLS 恢复密钥设置区。
    dict.set("settings.mls_recovery.title", "加密历史恢复");
    dict.set("settings.mls_recovery.status.loading", "正在检查备份状态…");
    dict.set(
        "settings.mls_recovery.status.no_local_secret",
        "尚未使用加密——在你发送加密消息或写入加密看板之前，没有可备份的内容。",
    );
    dict.set(
        "settings.mls_recovery.status.backed_up",
        "已备份——可使用你的 24 词恢复密钥恢复加密历史。",
    );
    dict.set(
        "settings.mls_recovery.status.not_backed_up",
        "未备份——请创建 24 词恢复密钥，以便新浏览器或新设备能够恢复你的加密历史。",
    );
    dict.set("settings.mls_recovery.submit", "创建 / 替换恢复词");

    // Space-admin view
    dict.set("realm_admin.title", "Realm 设置");
    dict.set("realm_admin.devices", "设备");
    dict.set("realm_admin.members", "成员");
    dict.set("realm_admin.access", "访问控制");
    dict.set("realm_admin.security_mls", "安全与 MLS");

    // Chat / Discussion view
    dict.set("chat.discussions_header", "Strand 讨论");
    dict.set("chat.users_header", "用户");
    dict.set("chat.settings_header", "设置");
    dict.set("chat.new_discussion", "新建讨论");
    dict.set("chat.new_strand", "新建 Strand");
    dict.set("chat.hide_list", "隐藏讨论列表");
    dict.set("chat.label.title", "标题");
    dict.set("chat.label.summary", "概述");
    dict.set("common.remove", "移除");
    dict.set("chat.call.voice", "发起语音通话");
    dict.set("chat.call.video", "发起视频通话");
    // T7.2 watch level 快捷切换
    dict.set("chat.watch_level.prefix", "关注");
    dict.set("chat.watch_level.tooltip", "选择此 Strand 的通知频率。");
    dict.set("chat.watch_level.mentions_only", "仅 @ 我");
    dict.set("chat.watch_level.participating", "参与中");
    dict.set("chat.watch_level.all", "全部");
    dict.set("chat.watch_level.muted", "静音");
    dict.set("chat.watch_level.pending", "正在更新 watch level…");
    dict.set("chat.watch_level.saved", "watch level 已更新。");
    dict.set(
        "chat.watch_level.failed",
        "watch level 更新失败（已回滚）。",
    );
    // T7.3 handle 重新分配上下文
    dict.set("chat.handle_reassigned.badge", "handle 已被重新分配");
    dict.set(
        "chat.handle_reassigned.tooltip",
        "撰写时记录的 handle 当前指向不同的 DID。请比对捕获的标签与当前发送者。",
    );
    dict.set("chat.binding_context.separator", " @ ");
    dict.set("chat.binding_context.details", "显示服务绑定");
    // T7.4 E2EE 状态
    dict.set("chat.crypto.decrypting", "解密中…");
    dict.set("chat.crypto.decrypt_failed", "解密失败");
    dict.set("chat.crypto.decrypt_failed_action", "前往恢复");
    dict.set("chat.crypto.key_missing", "尚未收到密钥");
    dict.set(
        "chat.crypto.key_missing_hint",
        "等待 Space 管理员或其他设备发送的 Welcome 消息。",
    );
    dict.set("chat.crypto.needs_verification", "发送方需要验证");
    dict.set("chat.mls.epoch", "MLS epoch");
    dict.set("chat.mls.key_package", "Key package");
    dict.set("chat.mls.welcome", "Welcome");
    // T7.5 布局调整
    dict.set("chat.tabs.settings", "设置");
    dict.set("chat.tabs.members", "成员");
    dict.set("chat.tabs.notifications", "通知");
    dict.set("chat.button.create", "创建");
    dict.set("chat.button.reply", "回复");
    dict.set("chat.button.react", "回应");
    dict.set("chat.button.redact", "撤回");
    dict.set("chat.you_badge", "我");
    // 成员视觉标识 (member.badge.*)
    dict.set("member.badge.agent", "智能体");
    // 撰写区拖拽附件 (A6.2)
    dict.set(
        "compose.drop_zone.hint",
        "将文件拖放到此处以附加,或点击「附加」",
    );
    dict.set("compose.upload_progress", "上传中…");
    dict.set("compose.upload_error", "上传失败");
    // 消息钉选 (A6.3)
    dict.set("message.pin", "钉选");
    dict.set("message.unpin", "取消钉选");
    dict.set("pinned_bar.title", "钉选消息");
    dict.set("pinned_bar.empty", "暂无钉选消息。");
    dict.set("pinned_bar.scroll_to", "跳转到消息");
    // Actor-private Realm list pinning.
    dict.set("realm.pin", "置顶 Realm");
    dict.set("realm.unpin", "取消置顶 Realm");
    dict.set("realm.pinned", "已置顶 Realm");
    dict.set("realm.add_member", "添加成员");
    dict.set("realm.settings", "设置");
    dict.set("realm.pin_failed", "Realm 置顶 account-data 写入失败");
    dict.set("chat.empty.title", "暂无可用讨论 track");
    dict.set(
        "chat.empty.description",
        "该 Space 应该提供默认 Strand 的讨论 track。",
    );
    dict.set("chat.empty.create_button", "创建 Strand");

    // Notifications panel
    dict.set("notifications.feed_title", "通知流");
    dict.set("notifications.view.latest", "最新");
    dict.set("notifications.view.realm", "Realm");
    dict.set("notifications.view.type", "类型");
    dict.set("notifications.tooltip.settings", "通知设置");
    dict.set("notifications.tooltip.mark_all_read", "全部标为已读");
    dict.set("notifications.tooltip.show_archived", "显示已归档");
    dict.set("notifications.tooltip.hide_archived", "隐藏已归档");
    dict.set("notifications.tooltip.refresh", "刷新通知");
    dict.set(
        "notifications.filtered_body",
        "已加载的通知全部被归档、类型或空间静音规则过滤掉了。",
    );

    // Verify Device
    dict.set("verify_device.title", "设备验证");
    dict.set("verify_device.choose_method", "选择方式");
    dict.set("verify_device.qr_code", "二维码");
    dict.set("verify_device.sas_emoji", "SAS（表情）");
    dict.set("verify_device.qr_section", "二维码验证");
    dict.set("verify_device.qr_section_hint", "扫描或显示");
    dict.set("verify_device.sas_section", "SAS 验证");
    dict.set("verify_device.sas_section_hint", "表情对比");
    dict.set("verify_device.target_device_id", "目标设备 ID");
    dict.set("verify_device.target_device_placeholder", "要验证的设备 ID");
    dict.set("verify_device.generate_qr", "生成二维码");
    dict.set("verify_device.start_sas", "开始 SAS 验证");
    dict.set("verify_device.short_auth_string", "短认证串");

    // A6.4 — keyboard shortcut help overlay。
    dict.set("shortcuts.title", "键盘快捷键");
    dict.set("shortcuts.dismiss", "关闭");
    dict.set("shortcuts.list.help", "显示此快捷键面板");
    dict.set("shortcuts.list.dismiss", "关闭任何打开的对话框");
    dict.set("shortcuts.list.palette", "打开命令面板");
    dict.set("shortcuts.list.palette_mac", "打开命令面板 (macOS)");
    dict.set("shortcuts.list.send", "发送当前消息");
    // Personal blocklist (A5)
    dict.set("settings.privacy.title", "隐私");
    dict.set("settings.privacy.blocked_users.title", "已屏蔽的用户");
    dict.set(
        "settings.privacy.blocked_users.empty",
        "尚未屏蔽任何用户。在成员列表或消息行中屏蔽用户后，可在此管理。",
    );
    dict.set(
        "settings.privacy.blocked_users.did_placeholder",
        "要屏蔽的 DID",
    );
    dict.set(
        "settings.privacy.blocked_users.reason_placeholder",
        "原因（可选）",
    );
    dict.set("settings.privacy.blocked_users.add", "屏蔽");
    dict.set("settings.privacy.blocked_users.added", "已屏蔽");
    dict.set("settings.privacy.blocked_users.removed", "已取消屏蔽");
    dict.set("settings.privacy.blocked_users.duplicate", "已在屏蔽列表中");
    dict.set(
        "settings.privacy.blocked_users.did_required",
        "请先输入 DID。",
    );
    // F-BLOCKLIST-VALID-1: 与 en dict 同步的实时格式校验提示。
    dict.set(
        "settings.privacy.blocked_users.did_invalid",
        "DID 必须以 did: 开头（如 did:web:alice.example）。",
    );
    dict.set("settings.privacy.unblock", "取消屏蔽");
    // A4b — 头像上传相关。
    dict.set("settings.avatar.title", "头像");
    dict.set("settings.avatar.upload", "上传新头像");
    dict.set("settings.avatar.clear", "清除头像");
    dict.set("settings.avatar.uploading", "上传中…");
    dict.set("settings.avatar.processing", "正在准备头像…");
    dict.set("settings.avatar.crop_ready", "调整裁剪后上传。");
    dict.set("settings.avatar.invalid_image", "所选文件不是图片。");
    dict.set("settings.avatar.upload_cropped", "上传裁剪后的头像");
    dict.set("settings.avatar.cancel_crop", "取消裁剪");
    dict.set("settings.avatar.zoom", "缩放");
    dict.set("settings.avatar.pan_x", "水平");
    dict.set("settings.avatar.pan_y", "垂直");
    dict.set("settings.avatar.error", "头像上传失败");
    // A6.1 — 全局跨空间消息搜索。
    dict.set("search.title", "搜索消息");
    dict.set("search.placeholder", "在所有空间中搜索消息…");
    dict.set("search.results.empty", "输入查询以在所有空间中搜索。");
    dict.set("search.results.loading", "搜索中…");
    dict.set("search.results.error", "搜索失败");
    dict.set("search.no_results", "未找到匹配项。");
    dict.set("search.result.snippet", "摘要");
    dict.set("topbar.search_button", "打开搜索");
    dict.set("shortcuts.list.search", "打开全局消息搜索");
    dict.set("member.block", "屏蔽此用户");
    dict.set("member.block_confirm.title", "屏蔽此用户？");
    dict.set(
        "member.block_confirm.body",
        "其消息将被占位符替代。您可随时在 设置 → 隐私 中取消屏蔽。",
    );
    dict.set("member.block_confirm.confirm", "屏蔽");
    dict.set("timeline.blocked_user", "[已屏蔽用户]");
    dict.set("timeline.show_anyway", "仍要查看");

    // A3 (round 28): 富内容渲染器字符串。
    dict.set("content.code.copy", "复制");
    dict.set("content.image.broken", "图片不可用");
    dict.set("content.video.unsupported", "您的浏览器不支持内嵌视频。");
    dict.set("content.audio.unsupported", "您的浏览器不支持内嵌音频。");
    dict.set("content.attachment.download", "下载");

    // T7.1 — 友好产品语言术语（中文）。
    dict.set(
        "friendly.identifier.placeholder",
        "john:example.com 或 did:web:...",
    );
    dict.set(
        "friendly.identifier.placeholder_multiline",
        "alice:example.com\nbob:example.com",
    );
    dict.set("friendly.identifier.label", "成员标识");
    dict.set(
        "friendly.identifier.hint",
        "输入 user:domain.com 形式的句柄，或粘贴完整 DID。",
    );
    dict.set("friendly.identifier.handle_or_email", "句柄或 DID");
    dict.set("friendly.member.automated", "自动化成员");
    dict.set("friendly.member.bot", "机器人");
    dict.set("friendly.member.human", "成员");
    dict.set("friendly.member.agent_badge", "机器人");
    dict.set("friendly.identifier.technical", "协议标识符");
    dict.set("friendly.identifier.show_technical", "显示技术详情");
    dict.set("friendly.identifier.hide_technical", "隐藏技术详情");
    dict.set("friendly.security.encrypted", "已加密");
    dict.set("friendly.security.encrypted_short", "加密");
    dict.set("friendly.draft.label", "草稿");
    dict.set("friendly.sync.state", "同步状态");
    dict.set("friendly.sync.synced", "已同步");
    dict.set("friendly.sync.pending", "同步中…");
    dict.set("friendly.sync.frontier", "同步状态");

    // Realm 是安全边界（成员/策略/联邦/E2EE），Space 是容器（导航/看板/列表）。
    dict.set("friendly.realm", "Realm");
    dict.set("friendly.realm.short", "Realm");
    dict.set(
        "friendly.realm.description",
        "安全边界 — 成员、策略、联邦与加密都在这一层治理。",
    );
    dict.set("friendly.realm.security_class", "安全边界");
    dict.set("friendly.realm.security_class.standard", "标准安全");
    dict.set("friendly.realm.security_class.high_assurance", "高保障");
    dict.set("friendly.realm.settings", "Realm 设置");
    dict.set(
        "friendly.realm.settings.subtitle",
        "策略、成员、联邦与端到端加密",
    );
    dict.set("friendly.realm.switcher", "切换 Realm");
    dict.set("friendly.realm.ref_label", "Realm");
    dict.set("friendly.space", "空间");
    dict.set("friendly.space.short", "空间");
    dict.set(
        "friendly.space.description",
        "导航容器 — 看板、列表与分区都在 Realm 之内。",
    );
    dict.set("friendly.space.container_class", "导航容器");
    dict.set("friendly.space.settings", "空间设置");
    dict.set("friendly.space.settings.subtitle", "导航、排序与展示");
    dict.set("friendly.discussion.realm_ref", "Realm");
    dict.set(
        "friendly.discussion.realm_ref.hint",
        "该讨论所属的 Realm（安全边界）。",
    );

    dict.set("profile_gate.title", "此服务器暂不支持该功能");
    dict.set(
        "profile_gate.body",
        "当前服务器尚未提供该视图所需的能力。请尝试其他服务器或联系管理员。",
    );
    dict.set("profile_gate.friendly.minimal_client", "基础客户端");
    dict.set("profile_gate.friendly.kanban_mvp", "看板");
    dict.set("profile_gate.friendly.chat_mvp", "讨论");
    dict.set("profile_gate.friendly.full_client", "完整客户端");
    dict.set("profile_gate.friendly.e2ee_client", "加密通讯");
    dict.set("profile_gate.friendly.unknown", "客户端功能");

    dict.set("nav.developer", "开发者工具");
    dict.set("developer.title", "开发者工具");
    dict.set("developer.subtitle", "协议诊断与审计");
    dict.set("developer.section.schemas", "Schemas 与事件类型");
    dict.set("developer.section.profiles", "服务器 Profile");
    dict.set("developer.section.events", "原始事件日志");
    dict.set("developer.section.conformance", "协议合规");
    dict.set("developer.section.protocol_version", "协议版本");
    dict.set(
        "developer.hint",
        "以下信息面向开发者和运维人员。终端用户无需阅读。",
    );
    dict.set("developer.profile.required", "所需 Profile id");
    dict.set("developer.profile.advertised", "服务器声明");
    dict.set("developer.event.kind", "事件类型");
    dict.set("developer.schema.id", "Schema id");

    // R3 spec sync (b47ff6ec) — Chinese error toast translations.
    add_r3_error_keys_zh(&mut dict);

    // Contacts / invite-receive policy / realm invite-from-contacts.
    add_contacts_keys_zh(&mut dict);

    dict
}

/// Chinese translations for the contacts surfaces — mirrors
/// [`add_contacts_keys`].
fn add_contacts_keys_zh(dict: &mut TranslationDict) {
    // ── ContactsPanel ─────────────────────────────────────────────────
    dict.set("contacts.title", "联系人");
    dict.set("contacts.add_button", "添加联系人");
    dict.set("contacts.load_error", "加载联系人失败:{error}");
    dict.set("contacts.retry", "重试");
    dict.set("contacts.loading", "正在加载联系人…");
    dict.set("contacts.empty_title", "还没有联系人");
    dict.set(
        "contacts.empty_hint",
        "点击“添加联系人”发送一个好友请求,对方接受后就会出现在这里。",
    );
    dict.set("contacts.empty_add", "添加联系人");

    // ── ContactNewPanel ───────────────────────────────────────────────
    dict.set("contacts.new.title", "添加联系人");
    dict.set("contacts.new.subtitle", "需对方同意");
    dict.set(
        "contacts.new.intro",
        "输入对方的 DID 发送好友请求。成为好友默认既能私聊、也允许对方拉你入群(像微信好友一样)。如需更严格,可在下面取消勾选。",
    );
    dict.set("contacts.new.target_label", "对方 DID");
    dict.set(
        "contacts.new.recipient_service_label",
        "对方所在服务器(跨服务器添加时填)",
    );
    dict.set(
        "contacts.new.recipient_service_placeholder",
        "did:web:ps.bob.example(同服务器留空)",
    );
    dict.set(
        "contacts.new.recipient_service_hint",
        "对方在另一台服务器(Principal Server)时填它的 service DID;同服务器留空即可。",
    );
    dict.set("contacts.new.scope_label", "好友权限(普通好友默认两项都开)");
    dict.set("contacts.new.scope_empty", "至少需要选择一项权限。");
    dict.set("contacts.new.message_label", "附言(可选)");
    dict.set("contacts.new.message_placeholder", "打个招呼…");
    dict.set("contacts.new.sending", "正在发送请求…");
    dict.set("contacts.new.sent", "请求已发送,等待对方接受。");
    dict.set("contacts.new.send_failed", "发送失败:{error}");
    dict.set("contacts.new.submit", "发送请求");
    dict.set("contacts.new.submit_busy", "发送中…");

    // ── scope_label ───────────────────────────────────────────────────
    dict.set("contacts.scope.direct_message", "私聊(可以给我发私信)");
    dict.set("contacts.scope.invite", "可邀请我入群");
    dict.set("contacts.scope.voice_call", "语音通话");
    dict.set("contacts.scope.video_call", "视频通话");
    dict.set("contacts.shared_scopes", "共享权限:");

    // ── ContactRow ────────────────────────────────────────────────────
    dict.set("contacts.state.pending_incoming", "等待你处理");
    dict.set("contacts.state.pending_outgoing", "等待对方接受");
    dict.set("contacts.state.accepted", "已是联系人");
    dict.set("contacts.state.rejected", "已拒绝");
    dict.set("contacts.state.tombstoned", "已删除");
    dict.set("contacts.state.blocked", "已拉黑");
    dict.set("contacts.action.accept", "接受");
    dict.set("contacts.action.reject", "拒绝");
    dict.set("contacts.action.withdraw", "撤回");
    dict.set("contacts.action.message", "发消息");
    dict.set("contacts.action.call_voice", "语音通话");
    dict.set("contacts.action.call_video", "视频通话");
    dict.set("contacts.action.block", "拉黑");
    dict.set("contacts.action.accepting", "正在接受…");
    dict.set("contacts.action.rejecting", "正在拒绝…");
    dict.set("contacts.action.withdrawing", "正在撤回…");
    dict.set("contacts.action.blocking", "正在拉黑…");
    dict.set("contacts.dm.opening", "正在打开私聊…");
    dict.set("contacts.dm.not_ready", "私聊尚未就绪,请稍后再试。");
    dict.set("contacts.dm.open_failed", "打开私聊失败:{error}");
    dict.set("contacts.block.confirm_title", "确定拉黑该联系人?");
    dict.set(
        "contacts.block.confirm_body",
        "拉黑后会删除该联系人,并阻止对方再次向你发送请求或邀请。",
    );
    dict.set("contacts.block.confirm_button", "确认拉黑");
    dict.set("contacts.block.cancel", "取消");
    dict.set("contacts.action_failed", "操作失败:{error}");

    // ── InvitePolicySettingsCard ──────────────────────────────────────
    dict.set("invite_policy.title", "谁可以邀请我");
    dict.set("invite_policy.loading", "加载中…");
    dict.set(
        "invite_policy.intro",
        "选择哪些来源可以邀请你加入群组。不在允许范围内的邀请会按下面的规则丢弃或暂存待审。",
    );
    dict.set(
        "invite_policy.load_failed",
        "未能从服务器读取现有策略(将使用默认值):{error}",
    );
    dict.set("invite_policy.kinds_title", "允许的邀请来源");
    dict.set("invite_policy.kind.consent_grant", "联系人(已同意的好友)");
    dict.set("invite_policy.kind.locator_ref", "邀请链接");
    dict.set("invite_policy.kind.shared_realm", "同群成员");
    dict.set(
        "invite_policy.kind.same_principal_server",
        "同一服务器的用户",
    );
    dict.set("invite_policy.kind.explicit_address", "任何知道我地址的人");
    dict.set(
        "invite_policy.explicit_label",
        "“任何知道我地址的人”的处理方式",
    );
    dict.set("invite_policy.explicit.drop", "直接丢弃");
    dict.set("invite_policy.explicit.quarantine", "暂存待审");
    dict.set("invite_policy.explicit.notify", "通知我");
    dict.set("invite_policy.unknown_prefix", "未知来源的邀请将被");
    dict.set("invite_policy.unknown_drop", "直接丢弃");
    dict.set("invite_policy.unknown_quarantine", "暂存待审");
    dict.set("invite_policy.unknown_suffix", "。");
    dict.set("invite_policy.disclosure_title", "回执");
    dict.set("invite_policy.disclosure_toggle", "让联系人知道邀请结果");
    dict.set(
        "invite_policy.disclosure_hint",
        "对陌生人(低信任来源)始终不回执,避免暴露你是否在线或是否接受邀请。",
    );
    dict.set("invite_policy.blocked_title", "已屏蔽的邀请者");
    dict.set("invite_policy.blocked_empty", "没有被屏蔽的邀请者。");
    dict.set("invite_policy.unblock", "移除");
    dict.set(
        "invite_policy.unblocked_hint",
        "已从屏蔽列表移除,记得点击保存。",
    );
    dict.set("invite_policy.saving", "正在保存…");
    dict.set("invite_policy.saved", "已保存。");
    dict.set("invite_policy.save_failed", "保存失败:{error}");
    dict.set("invite_policy.save", "保存");
    dict.set("invite_policy.save_busy", "保存中…");

    // ── realm-admin: invite from contacts ─────────────────────────────
    dict.set("realm_admin.invite_from_contacts", "从联系人添加");
    dict.set("realm_admin.invite_recommended", "推荐");
    dict.set("realm_admin.invite_loading_contacts", "正在加载联系人…");
    dict.set(
        "realm_admin.invite_contacts_failed",
        "加载联系人失败:{error}",
    );
    dict.set("realm_admin.invite_no_contacts", "还没有可邀请的联系人。");
    dict.set("realm_admin.invite_unauthorized", "对方未授权邀请");
    dict.set(
        "realm_admin.invite_none_eligible",
        "没有可邀请的联系人(缺少同意凭证)。",
    );
    dict.set("realm_admin.invite_sending", "正在邀请 {total} 位联系人…");
    dict.set("realm_admin.invite_sent", "已邀请 {ok} 位联系人(待接受)。");
    dict.set(
        "realm_admin.invite_partial",
        "已邀请 {ok}/{total} 位联系人;部分失败:{error}",
    );
    dict.set("realm_admin.invite_selected", "邀请所选联系人");
    dict.set("realm_admin.invite_divider", "或邀请陌生人(粘贴邀请链接)");
    dict.set("realm_admin.invite_bad_server", "无效的服务器地址:{error}");
}

/// English i18n strings for the 6 CKP-0007 reason / error codes
/// surfaced by [`crate::circle::CircleErrorKind`] (P3B.3.2). Zh / Ar
/// translations follow in a later milestone; the toast falls back to
/// the English string when the locale doesn't carry the key.
fn add_circle_error_keys(dict: &mut TranslationDict) {
    dict.set(
        "error.circle.realm_mismatch",
        "This Circle belongs to a different Realm than the message you tried to send.",
    );
    dict.set(
        "error.circle.not_active",
        "The Circle is archived or tombstoned and can no longer receive messages.",
    );
    dict.set(
        "error.circle.member_not_in_realm",
        "Cannot add this user to the Circle — they are not an active member of the parent Realm.",
    );
    dict.set(
        "error.circle.scope_rebind_forbidden",
        "Changing an existing object's Circle scope requires an audited admin action.",
    );
    dict.set(
        "error.circle.metadata_floor",
        "This write would expose metadata below the Realm or Circle encryption floor.",
    );
    dict.set(
        "error.circle.encryption_below_realm_floor",
        "This Realm requires E2EE, so the Circle must stay MLS-backed.",
    );
    dict.set(
        "error.circle.encryption_profile_locked",
        "Circle encryption_profile is locked at creation. Create a new Circle to change its E2EE mode.",
    );
    dict.set(
        "error.circle.delivery_binding_handed_over",
        "The Circle's delivery binding moved to a newer set of devices — please retry the request.",
    );

    // R3.3 (CKP-0011) — shareable object links (Chinese-first).
    dict.set("object_link.share", "分享链接");
    dict.set("object_link.share_realm", "分享此领域");
    dict.set("object_link.share_strand", "分享此流程");
    dict.set("object_link.share_message", "分享此消息");
    dict.set("object_link.copy_https", "复制链接");
    dict.set("object_link.copy_app", "复制“在应用中打开”链接");
    dict.set("object_link.copied", "链接已复制");
    dict.set("object_link.open", "打开分享链接");
    dict.set(
        "object_link.open_placeholder",
        "粘贴 web+cokret: 或 https 分享链接",
    );
    dict.set("object_link.opening", "正在打开链接…");
    dict.set("object_link.error.unavailable", "链接不可用或已过期。");
    dict.set("object_link.error.invalid", "无法识别该链接格式。");
}

/// Build Arabic translation dictionary.
pub fn arabic_translations() -> TranslationDict {
    let mut dict = TranslationDict::new(Locale::Ar);

    dict.set("app.title", "yougen");
    dict.set("nav.dashboard", "Home");
    dict.set("nav.timeline", "الخط الزمني");
    dict.set("nav.chat", "الدردشة");
    dict.set("nav.forum", "المنتدى");
    dict.set("nav.directory", "الدليل");
    dict.set("nav.notifications", "الإشعارات");
    dict.set("nav.settings", "الإعدادات");
    dict.set("nav.login", "تسجيل الدخول");
    dict.set("nav.audit", "التدقيق");
    dict.set("nav.devices", "الأجهزة");

    dict.set("settings.title", "الإعدادات");
    dict.set("settings.theme", "المظهر");
    dict.set("settings.language", "اللغة");
    dict.set("settings.light", "فاتح");
    dict.set("settings.dark", "داكن");
    dict.set("settings.system", "النظام");

    dict.set("common.loading", "جار التحميل...");
    dict.set("common.error", "خطأ");
    dict.set("common.retry", "إعادة المحاولة");
    dict.set("common.online", "متصل");
    dict.set("common.offline", "غير متصل");
    dict.set("common.reconnecting", "إعادة الاتصال");

    dict
}

/// Initialize the i18n system with default translations.
pub fn init_i18n() -> I18nSignal {
    init_i18n_with_locale(Locale::En)
}

/// Initialize i18n preloaded with a specific locale.
pub fn init_i18n_with_locale(locale: Locale) -> I18nSignal {
    let mut dicts = HashMap::new();
    dicts.insert("en".to_owned(), english_translations());
    dicts.insert("zh".to_owned(), chinese_translations());
    dicts.insert("ar".to_owned(), arabic_translations());
    // Phase D.2 #8: new locale slots — coverage is intentionally a
    // subset (nav / common / login) so missing keys fall through the
    // `xx → en` chain and surface in `missing_translation_snapshot()`
    // for QA to grow as needed.
    dicts.insert("es".to_owned(), spanish_translations());
    dicts.insert("ja".to_owned(), japanese_translations());
    dicts.insert("fr".to_owned(), french_translations());
    Signal::new((locale, dicts))
}

/// Phase D.2 #8: Spanish — covers the highest-visibility nav / common
/// keys. Anything not listed falls through to English via the
/// `translate_chain` fallback.
pub fn spanish_translations() -> TranslationDict {
    let mut dict = TranslationDict::new(Locale::Es);
    dict.set("app.title", "yougen");
    dict.set("nav.dashboard", "Home");
    dict.set("nav.timeline", "Cronología");
    dict.set("nav.chat", "Chat");
    dict.set("nav.forum", "Foro");
    dict.set("nav.directory", "Directorio");
    dict.set("nav.notifications", "Notificaciones");
    dict.set("nav.settings", "Ajustes");
    dict.set("nav.login", "Iniciar sesión");
    dict.set("nav.audit", "Auditoría");
    dict.set("nav.devices", "Dispositivos");
    dict.set("common.loading", "Cargando...");
    dict.set("common.error", "Error");
    dict.set("common.retry", "Reintentar");
    dict.set("common.close", "Cerrar");
    dict.set("common.confirm", "Confirmar");
    dict.set("common.cancel", "Cancelar");
    dict.set("common.save", "Guardar");
    dict.set("common.delete", "Eliminar");
    dict.set("common.edit", "Editar");
    dict.set("common.send", "Enviar");
    dict.set("common.refresh", "Actualizar");
    dict.set("common.back", "Atrás");
    dict.set("common.next", "Siguiente");
    dict.set("common.online", "en línea");
    dict.set("common.offline", "sin conexión");
    dict.set("common.reconnecting", "reconectando");
    dict.set("settings.title", "Ajustes");
    dict.set("settings.theme", "Tema");
    dict.set("settings.language", "Idioma");
    dict.set("settings.light", "Claro");
    dict.set("settings.dark", "Oscuro");
    dict.set("settings.system", "Sistema");
    dict.set("login.server", "Servidor");
    dict.set("login.continue", "Continuar");
    dict
}

/// Phase D.2 #8: Japanese — nav / common starter set.
pub fn japanese_translations() -> TranslationDict {
    let mut dict = TranslationDict::new(Locale::Ja);
    dict.set("app.title", "yougen");
    dict.set("nav.dashboard", "Home");
    dict.set("nav.timeline", "タイムライン");
    dict.set("nav.chat", "チャット");
    dict.set("nav.forum", "フォーラム");
    dict.set("nav.directory", "ディレクトリ");
    dict.set("nav.notifications", "通知");
    dict.set("nav.settings", "設定");
    dict.set("nav.login", "ログイン");
    dict.set("nav.audit", "監査");
    dict.set("nav.devices", "デバイス");
    dict.set("common.loading", "読み込み中...");
    dict.set("common.error", "エラー");
    dict.set("common.retry", "再試行");
    dict.set("common.close", "閉じる");
    dict.set("common.confirm", "確認");
    dict.set("common.cancel", "キャンセル");
    dict.set("common.save", "保存");
    dict.set("common.delete", "削除");
    dict.set("common.edit", "編集");
    dict.set("common.send", "送信");
    dict.set("common.refresh", "更新");
    dict.set("common.back", "戻る");
    dict.set("common.next", "次へ");
    dict.set("common.online", "オンライン");
    dict.set("common.offline", "オフライン");
    dict.set("common.reconnecting", "再接続中");
    dict.set("settings.title", "設定");
    dict.set("settings.theme", "テーマ");
    dict.set("settings.language", "言語");
    dict.set("settings.light", "ライト");
    dict.set("settings.dark", "ダーク");
    dict.set("settings.system", "システム");
    dict.set("login.server", "サーバー");
    dict.set("login.continue", "続行");
    dict
}

/// Phase D.2 #8: French — nav / common starter set.
pub fn french_translations() -> TranslationDict {
    let mut dict = TranslationDict::new(Locale::Fr);
    dict.set("app.title", "yougen");
    dict.set("nav.dashboard", "Home");
    dict.set("nav.timeline", "Chronologie");
    dict.set("nav.chat", "Discussion");
    dict.set("nav.forum", "Forum");
    dict.set("nav.directory", "Annuaire");
    dict.set("nav.notifications", "Notifications");
    dict.set("nav.settings", "Paramètres");
    dict.set("nav.login", "Connexion");
    dict.set("nav.audit", "Audit");
    dict.set("nav.devices", "Appareils");
    dict.set("common.loading", "Chargement...");
    dict.set("common.error", "Erreur");
    dict.set("common.retry", "Réessayer");
    dict.set("common.close", "Fermer");
    dict.set("common.confirm", "Confirmer");
    dict.set("common.cancel", "Annuler");
    dict.set("common.save", "Enregistrer");
    dict.set("common.delete", "Supprimer");
    dict.set("common.edit", "Modifier");
    dict.set("common.send", "Envoyer");
    dict.set("common.refresh", "Actualiser");
    dict.set("common.back", "Retour");
    dict.set("common.next", "Suivant");
    dict.set("common.online", "en ligne");
    dict.set("common.offline", "hors ligne");
    dict.set("common.reconnecting", "reconnexion");
    dict.set("settings.title", "Paramètres");
    dict.set("settings.theme", "Thème");
    dict.set("settings.language", "Langue");
    dict.set("settings.light", "Clair");
    dict.set("settings.dark", "Sombre");
    dict.set("settings.system", "Système");
    dict.set("login.server", "Serveur");
    dict.set("login.continue", "Continuer");
    dict
}

/// Switch the active locale on an existing signal without rebuilding the
/// translation tables. Call this from the Settings language picker.
pub fn set_locale(signal: &mut I18nSignal, locale: Locale) {
    if signal.read().0 == locale {
        return;
    }
    let dicts = signal.read().1.clone();
    signal.set((locale, dicts));
}

/// Convenience: pull the current i18n signal from Dioxus context and
/// translate `key`. Views call this once they have been wrapped in a
/// `provide_context(init_i18n_with_locale(...))` ancestor — currently
/// `WorkspaceView`. Falls back to the key itself when no context is
/// installed (e.g. unit tests outside Dioxus runtime).
pub fn tr(key: &str) -> String {
    match try_consume_context::<I18nSignal>() {
        Some(signal) => t(&signal, key),
        None => key.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_from_code() {
        assert_eq!(Locale::from_code("en"), Locale::En);
        assert_eq!(Locale::from_code("zh"), Locale::Zh);
        assert_eq!(Locale::from_code("zh-CN"), Locale::Zh);
        assert_eq!(Locale::from_code("ar"), Locale::Ar);
        // Phase D.2 #8: `fr`, `es`, `ja` are first-class now.
        assert_eq!(Locale::from_code("fr"), Locale::Fr);
        assert_eq!(Locale::from_code("fr-CA"), Locale::Fr);
        assert_eq!(Locale::from_code("es"), Locale::Es);
        assert_eq!(Locale::from_code("es-MX"), Locale::Es);
        assert_eq!(Locale::from_code("ja"), Locale::Ja);
        assert_eq!(Locale::from_code("ja-JP"), Locale::Ja);
        // ar-SA collapses to ar (entry point of the
        // `ar-SA → ar → en` chain in `translate_chain`).
        assert_eq!(Locale::from_code("ar-SA"), Locale::Ar);
        // Unknown locale still falls back to English.
        assert_eq!(Locale::from_code("xx"), Locale::En);
    }

    #[test]
    fn translate_chain_walks_region_then_base_then_english() {
        // Phase D.2 #8: `ar-SA → ar → en` lookup chain.
        let mut dicts = HashMap::new();
        let mut ar_sa = TranslationDict::new(Locale::Ar);
        ar_sa.set("region.specific", "ar-SA value");
        let mut ar = TranslationDict::new(Locale::Ar);
        ar.set("base.value", "ar value");
        let mut en = TranslationDict::new(Locale::En);
        en.set("english.only", "en value");
        dicts.insert("ar-SA".to_owned(), ar_sa);
        dicts.insert("ar".to_owned(), ar);
        dicts.insert("en".to_owned(), en);
        // Region-specific value wins.
        assert_eq!(
            translate_chain("ar-SA", &dicts, "region.specific"),
            "ar-SA value"
        );
        // Base value picked up via `ar-SA → ar`.
        assert_eq!(translate_chain("ar-SA", &dicts, "base.value"), "ar value");
        // English fallback via `ar-SA → ar → en`.
        assert_eq!(translate_chain("ar-SA", &dicts, "english.only"), "en value");
        // Missing everywhere → returns the key itself + records the miss.
        let _ = missing_translation_snapshot(); // ensure helper compiles
        assert_eq!(
            translate_chain("ar-SA", &dicts, "nothing.here"),
            "nothing.here"
        );
    }

    #[test]
    fn locale_direction_matches_layout_expectations() {
        assert_eq!(Locale::En.direction(), TextDirection::Ltr);
        assert_eq!(Locale::Zh.direction(), TextDirection::Ltr);
        assert_eq!(Locale::Ar.direction(), TextDirection::Rtl);
        assert_eq!(Locale::Ar.direction().as_str(), "rtl");
    }

    #[test]
    fn translation_lookup_fallback() {
        let mut dicts = HashMap::new();
        let en = english_translations();
        let zh = chinese_translations();
        dicts.insert("en".to_owned(), en);
        dicts.insert("zh".to_owned(), zh);

        // Chinese translation exists
        assert_eq!(translate(Locale::Zh, &dicts, "login.server"), "服务器");

        // Fallback to English for missing Chinese key
        let partial_dicts = {
            let mut partial = HashMap::new();
            let mut zh_partial = TranslationDict::new(Locale::Zh);
            zh_partial.set("login.server", "服务器");
            partial.insert("en".to_owned(), english_translations());
            partial.insert("zh".to_owned(), zh_partial);
            partial
        };
        assert_eq!(
            translate(Locale::Zh, &partial_dicts, "login.passkey"),
            "Passkey Login"
        );

        // Fallback to key itself when not found anywhere
        assert_eq!(
            translate(Locale::En, &HashMap::new(), "nonexistent.key"),
            "nonexistent.key"
        );
    }

    #[test]
    fn locale_formatters_are_stable() {
        let timestamp = DateTime::parse_from_rfc3339("2026-04-29T07:08:09Z")
            .unwrap()
            .with_timezone(&Utc);

        assert_eq!(
            format_datetime(Locale::En, timestamp),
            "Apr 29, 2026 07:08 UTC"
        );
        assert_eq!(
            format_datetime(Locale::Zh, timestamp),
            "2026年04月29日 07:08 UTC"
        );
        assert_eq!(
            format_datetime(Locale::Ar, timestamp),
            "2026/04/29 07:08 UTC"
        );
        assert_eq!(format_number(Locale::En, 1234567), "1,234,567");
        assert_eq!(format_number(Locale::Zh, 1234567), "1 234 567");
    }

    #[test]
    fn translation_completeness_reports_missing_keys() {
        let en = english_translations();
        let zh = chinese_translations();
        let report = translation_completeness(&en, &zh);
        assert_eq!(report.locale, Locale::Zh);
        assert_eq!(report.total_keys, en.strings.len());
        assert!(report.missing_count() > 0);
        assert!(
            report
                .missing_keys
                .contains(&"directory.applet.metadata".to_owned())
        );

        let complete = translation_completeness(&en, &en);
        assert!(complete.is_complete());
    }
}
