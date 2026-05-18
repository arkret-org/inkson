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
}

impl Locale {
    pub fn code(&self) -> &'static str {
        match self {
            Locale::En => "en",
            Locale::Zh => "zh",
            Locale::Ar => "ar",
        }
    }

    pub fn from_code(code: &str) -> Self {
        match code {
            "zh" | "zh-CN" | "zh-TW" => Locale::Zh,
            "ar" | "ar-SA" | "ar-EG" => Locale::Ar,
            _ => Locale::En,
        }
    }

    pub fn direction(&self) -> TextDirection {
        match self {
            Locale::Ar => TextDirection::Rtl,
            Locale::En | Locale::Zh => TextDirection::Ltr,
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
pub fn translate(locale: Locale, dicts: &HashMap<String, TranslationDict>, key: &str) -> String {
    // Try requested locale
    if let Some(dict) = dicts.get(locale.code()) {
        if let Some(val) = dict.get(key) {
            return val.to_owned();
        }
    }
    // Fallback to English
    if locale != Locale::En {
        if let Some(dict) = dicts.get("en") {
            if let Some(val) = dict.get(key) {
                return val.to_owned();
            }
        }
    }
    // Last resort: return the key itself
    key.to_owned()
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
    }
}

/// Format a non-negative integer with locale-appropriate grouping.
pub fn format_number(locale: Locale, value: u64) -> String {
    let grouped = group_decimal(value);
    match locale {
        Locale::En | Locale::Ar => grouped,
        Locale::Zh => grouped.replace(',', " "),
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
    dict.set("nav.dashboard", "Dashboard");
    dict.set("nav.timeline", "Timeline");
    dict.set("nav.chat", "Chat");
    dict.set("nav.forum", "Forum");
    dict.set("nav.directory", "Directory");
    dict.set("nav.notifications", "Notifications");
    dict.set("nav.settings", "Settings");
    dict.set("nav.login", "Login");
    dict.set("nav.audit", "Audit");
    dict.set("nav.devices", "Devices");

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
    dict.set("directory.tab.spaces", "Spaces");
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
        "Jump to a space, view or action…",
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
    dict.set("dashboard.spaces_label", "Spaces");
    dict.set("dashboard.spaces_delta_search", "Search or join a Space");
    dict.set("dashboard.spaces_delta_signin", "Sign in to load spaces");
    dict.set("dashboard.current_space", "Current Space");
    dict.set("dashboard.workspace_setup", "Workspace Setup");
    dict.set(
        "dashboard.workspace_setup_delta",
        "Bootstrap your first Space and initial policy",
    );
    dict.set("dashboard.onboarding", "Onboarding");
    dict.set("dashboard.onboarding_steps", "4 steps");
    dict.set(
        "dashboard.onboarding_delta",
        "Identity, device, and recovery setup",
    );
    dict.set("dashboard.recent_spaces", "Recent Spaces");
    dict.set("dashboard.no_spaces", "No spaces loaded");
    dict.set(
        "dashboard.no_spaces_help",
        "The connected server did not return spaces yet.",
    );
    dict.set(
        "dashboard.no_session_help",
        "The client is not showing placeholder spaces.",
    );

    dict.set("notifications.archived", "Show archived");
    dict.set("notifications.mark_all_read", "Mark all read");
    dict.set("notifications.empty_state", "No notifications loaded.");

    dict.set("composer.send", "Send");
    dict.set("composer.encrypted_toggle", "Encrypt locally");
    dict.set(
        "composer.plaintext_warning",
        "Plaintext messages may be visible to the configured server.",
    );

    dict.set("command_palette.spaces", "Spaces");
    dict.set("command_palette.jump_to", "Jump to");
    dict.set(
        "command_palette.empty",
        "No matching spaces or views. Press Esc to close.",
    );
    dict.set("command_palette.close", "Close (Esc)");

    dict.set("mobile.filter_spaces", "Filter spaces…");
    dict.set("mobile.no_match", "No spaces match.");

    // Kanban / Board view (header + section labels)
    dict.set("kanban.board_header", "Launch Board");
    dict.set("kanban.board_title", "Board");
    dict.set(
        "kanban.board_hint",
        "Drag cards across lists to queue cx.flow.move; projection refresh promotes seed data when the server view endpoint is available.",
    );
    dict.set(
        "chat.mls_passphrase_placeholder",
        "MLS passphrase (this Space)",
    );
    dict.set("chat.mls_passphrase_save", "Save passphrase");
    dict.set("chat.mls_publish_key_package", "Publish key package");
    dict.set("chat.mls_invite_actor_placeholder", "Invite actor DID");
    dict.set("chat.mls_invite_device_placeholder", "Invite device id");
    dict.set("chat.mls_invite_member", "Invite to MLS group");
    dict.set("chat.send", "Send");
    dict.set("chat.send_secure", "Send Secure");
    dict.set(
        "chat.plaintext_blocked",
        "Type a message before secure send",
    );
    dict.set("recovery.vault_encrypt_button", "Encrypt and upload");
    dict.set("recovery.vault_rotate_button", "Rotate passphrase");
    dict.set(
        "recovery.vault_rotate_hint",
        "Reuses the existing backup_id but re-derives a fresh KEK / nonce.",
    );
    dict.set(
        "recovery.vault_rotate_prompt",
        "Enter a new passphrase above and click Encrypt and upload to rotate.",
    );
    dict.set("space_admin.save_metadata", "Save Metadata");
    dict.set("space_admin.save_metadata_move", "Save Metadata (Move)");
    dict.set("space_admin.tombstone_delete", "Tombstone / Delete");
    dict.set("space_admin.archive_space", "Archive Space");
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
    dict.set("space_admin.apply_policy", "Apply Policy");
    dict.set(
        "space_admin.grant_capability_move",
        "Grant capability (Move)",
    );
    dict.set(
        "space_admin.revoke_capability_move",
        "Revoke capability (Move)",
    );
    dict.set("space_admin.refresh_members", "Refresh");
    dict.set("space_admin.kick_member", "Kick");
    dict.set("space_admin.ban_member", "Ban");
    dict.set("space_admin.kick_member_move", "Kick (Move)");
    dict.set("space_admin.ban_member_move", "Ban (Move)");
    dict.set("space_admin.rotate_epoch", "Rotate Epoch");
    dict.set("space_admin.leave_space", "Leave");
    dict.set("recovery.primary", "Primary");
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
    dict.set("recovery.vault_section", "Encrypted Cloud Vault");
    dict.set("recovery.recovery_key_section", "Recovery Key");
    dict.set("recovery.social_section", "Social Recovery");

    // Space-admin view (section labels)
    dict.set("space_admin.title", "Space Admin");
    dict.set("space_admin.governance", "Governance");
    dict.set("space_admin.devices", "Devices");
    dict.set("space_admin.members", "Members");
    dict.set("space_admin.access", "Access");
    dict.set("space_admin.security_mls", "Security & MLS");
    dict.set(
        "space_admin.mls_remove_header",
        "MLS Remove (device revoke)",
    );
    dict.set(
        "space_admin.mls_remove_hint",
        "Decrypt the local MLS snapshot, run remove_member_by_principal against the target device, and submit cx.mls.commit. Post-commit state is re-encrypted on success.",
    );
    dict.set("space_admin.mls_remove_button", "Build & submit MLS Remove");
    dict.set(
        "space_admin.mls_remove_target_placeholder",
        "Target device DID (did:web:…)",
    );
    dict.set(
        "space_admin.mls_remove_passphrase_placeholder",
        "Snapshot passphrase",
    );

    // Chat / Discussion view (panel headers + key buttons; reuse common.* for
    // generic verbs like Save/Cancel/Retry/Edit/Confirm).
    dict.set("chat.discussions_header", "Discussions");
    dict.set("chat.users_header", "Users");
    dict.set("chat.settings_header", "Settings");
    dict.set("chat.new_discussion", "New discussion");
    dict.set("chat.hide_list", "Hide discussion list");
    dict.set("chat.label.title", "Title");
    dict.set("chat.label.summary", "Summary");
    dict.set("chat.label.watchers", "Add watchers");
    dict.set(
        "chat.watchers.hint",
        "不影响访问控制 — Watching only changes notifications, \
         not who can see the Flow.",
    );
    dict.set("chat.button.create", "Create");
    dict.set("chat.button.reply", "Reply");
    dict.set("chat.button.react", "React");
    dict.set("chat.button.redact", "Redact");
    dict.set("chat.you_badge", "You");
    // Member visual indicators surfaced wherever a principal DID is
    // rendered (space-admin member list, @mention picker, chat sender
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
    dict.set("pinned_bar.empty", "No pinned messages.");
    dict.set("pinned_bar.scroll_to", "Jump to message");
    dict.set("chat.empty.title", "No discussions yet");
    dict.set(
        "chat.empty.description",
        "Create a discussion to start chatting in this Space.",
    );
    dict.set("chat.empty.create_button", "Create your first discussion");

    // Notifications panel (group tabs + toolbar tooltips)
    dict.set("notifications.group.all", "All");
    dict.set("notifications.group.space", "Space");
    dict.set("notifications.group.type", "Type");
    dict.set("notifications.group.time", "Time");
    dict.set("notifications.tooltip.mark_all_read", "Mark all read");
    dict.set("notifications.tooltip.show_archived", "Show archived");
    dict.set("notifications.tooltip.hide_archived", "Hide archived");
    dict.set("notifications.tooltip.refresh", "Refresh notifications");
    dict.set("notifications.settings_card", "Notification settings");
    dict.set("notifications.settings_card_hint", "managed in Settings");
    dict.set(
        "notifications.settings_card_body",
        "Notification rules, muted spaces, and push delivery preferences now live in Settings.",
    );
    dict.set("notifications.settings_card_open", "Open settings");
    dict.set(
        "notifications.empty_body",
        "No server-derived notifications loaded yet.",
    );
    dict.set(
        "notifications.filtered_body",
        "All loaded notifications are currently hidden by archive, type, or per-space mute rules.",
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

    // Agent Workspace (`cx.profile.agent_workspace.v1`)
    dict.set("nav.agent_workspace", "Agents");
    dict.set("agent_workspace.dashboard.title", "My Agents");
    dict.set("agent_workspace.add_agent", "+ Add Agent");
    dict.set(
        "agent_workspace.add_agent.hint",
        "Add one of your agents to a source Flow",
    );
    dict.set("agent_workspace.add_first_agent", "Add your first agent");
    dict.set(
        "agent_workspace.protocol_session_monitor",
        "Protocol sessions",
    );
    dict.set("agent_workspace.pending", "Needs your attention");
    dict.set(
        "agent_workspace.pending.subtitle",
        "Source-side transparency or authority has changed. Reconfirm or cancel.",
    );
    dict.set("agent_workspace.in_flight", "In flight");
    dict.set("agent_workspace.recent", "Recently completed");
    dict.set("agent_workspace.my_agents", "My Agents");
    dict.set("agent_workspace.back", "Back");
    dict.set("agent_workspace.task.open", "Open");
    dict.set("agent_workspace.task.reconfirm", "Continue anyway");
    dict.set("agent_workspace.task.cancel", "Cancel task");
    dict.set("agent_workspace.task.no_source", "(no source)");
    dict.set("agent_workspace.task.loading", "Loading task…");
    dict.set("agent_workspace.task.anchor", "Source context anchor");
    dict.set("agent_workspace.task.instruction", "Your instruction");
    dict.set("agent_workspace.task.draft", "Agent draft");
    dict.set("agent_workspace.task.publish", "Publish to source Flow");
    dict.set(
        "agent_workspace.task.publish_hint",
        "Send the agent draft to the source Flow as your own message (with optional attribution).",
    );
    dict.set(
        "agent_workspace.task.publish_disabled_reason",
        "Task is not in active state; please reconfirm or cancel first.",
    );
    dict.set("agent_workspace.task.mark_complete", "Mark complete");
    dict.set("agent_workspace.task.rewrite", "Ask agent to rewrite");
    dict.set("agent_workspace.task.conversation", "Conversation");
    dict.set(
        "agent_workspace.task.compose_placeholder",
        "Reply or instruct further…",
    );
    dict.set("agent_workspace.task.send", "Send");
    dict.set("agent_workspace.task.audit_trail", "Audit trail");
    dict.set(
        "agent_workspace.banner.transparency_lost",
        "Source mention has been redacted. The agent has paused.",
    );
    dict.set(
        "agent_workspace.banner.source_authority_revoked",
        "The agent's source-side access has been revoked.",
    );
    dict.set("agent_workspace.fsm.execution", "Execution");
    dict.set("agent_workspace.fsm.transparency", "Transparency");
    dict.set("agent_workspace.fsm.source_authority", "Source authority");
    dict.set(
        "agent_workspace.fsm.aria_label",
        "Three orthogonal task state cells",
    );
    dict.set("agent_workspace.agent.consulting", "consulting");
    dict.set(
        "agent_workspace.agent.no_active_sources",
        "(mirror-only; not active in any source Space)",
    );
    dict.set(
        "agent_workspace.empty.in_flight.message",
        "No agent tasks are running right now.",
    );
    dict.set(
        "agent_workspace.empty.in_flight.hint",
        "Mention one of your agents in a chat or discussion to start a private task.",
    );
    dict.set(
        "agent_workspace.empty.agents.message",
        "You haven't added any agents yet.",
    );
    dict.set("agent_workspace.compose.private_routing_notice", "This instruction will be sent to your private Agent Workspace. Source Flow members will only see a generic summary.");
    dict.set(
        "agent_workspace.compose.summary_visible_warning",
        "This summary is visible to all source Flow members.",
    );
    dict.set(
        "agent_workspace.compose.send_private",
        "Send (Private to Agent)",
    );
    // A6.4 — keyboard shortcut help overlay.
    dict.set("shortcuts.title", "Keyboard shortcuts");
    dict.set("shortcuts.dismiss", "Dismiss");
    dict.set("shortcuts.list.help", "Show this shortcut help");
    dict.set("shortcuts.list.dismiss", "Close any open dialog");
    dict.set("shortcuts.list.palette", "Open command palette");
    dict.set(
        "shortcuts.list.palette_mac",
        "Open command palette (macOS)",
    );
    dict.set("shortcuts.list.send", "Send the current message");
    // A2 — mirror Space banner + compose banner + nav tooltip text.
    dict.set(
        "agent_workspace.private_mirror.title",
        "Private Mirror Space",
    );
    dict.set(
        "agent_workspace.private_mirror.body",
        "Drafts in this mirror Space are only visible to you. The agent may publish a redacted summary to source Space {source}.",
    );
    dict.set(
        "agent_workspace.private_mirror.body_no_source",
        "Drafts in this mirror Space are only visible to you. The agent may publish a redacted summary back to the source Space.",
    );
    dict.set(
        "agent_workspace.compose.private_to_agent_banner",
        "Composing privately to {agent}: only the agent receives this message; source Flow members see only the generic summary.",
    );
    dict.set(
        "agent_workspace.nav.info_title",
        "What is My Agents?",
    );
    dict.set(
        "agent_workspace.nav.info_body",
        "Your private Agent Workspace mirrors source Spaces where your agents act. Drafts stay private; only redacted summaries cross back to the source Space.",
    );
    dict.set(
        "agent_workspace.nav.info_button",
        "About My Agents",
    );

    // Publish modal (AW-3.7 + AW-3.20)
    dict.set("agent_workspace.publish.signer_legend", "Signing identity");
    dict.set("agent_workspace.publish.signer_self", "Post as me");
    dict.set(
        "agent_workspace.publish.signer_self_with_attribution",
        "Post as me, with \"drafted by agent\" note",
    );
    dict.set("agent_workspace.publish.cancel", "Cancel");
    dict.set("agent_workspace.publish.confirm", "Publish");

    // Add agent modal (AW-3.8)
    dict.set(
        "agent_workspace.add_agent.select_legend",
        "Pick one of your agents",
    );
    dict.set(
        "agent_workspace.add_agent.profile_legend",
        "Capability profile",
    );
    dict.set(
        "agent_workspace.add_agent.profile.observer",
        "Observer (read-only history)",
    );
    dict.set(
        "agent_workspace.add_agent.profile.read_only",
        "Read + react",
    );
    dict.set(
        "agent_workspace.add_agent.profile.mention_respond_only",
        "Respond only when @-mentioned (recommended)",
    );
    dict.set(
        "agent_workspace.add_agent.profile.full_collaborator",
        "Full collaborator",
    );
    dict.set(
        "agent_workspace.add_agent.no_owned_agents",
        "You haven't created any controllable agents yet. Visit Settings → Agents to add one.",
    );
    dict.set("agent_workspace.add_agent.disclosure", "Agent membership is publicly visible to all source-Space members; the agent's work in your mirror Workspace remains private.");
    dict.set("agent_workspace.add_agent.cancel", "Cancel");
    dict.set("agent_workspace.add_agent.send_invite", "Send invite");

    // Settings page (AW-3.4)
    dict.set("agent_workspace.settings.title", "Agent Workspace settings");
    dict.set("agent_workspace.settings.agents", "My agents");
    dict.set(
        "agent_workspace.settings.default_profile",
        "Default capability profile for new agent invites",
    );
    dict.set("agent_workspace.settings.default_profile_hint", "Applied as the pre-selected option in the Add Agent modal. You can still override per-invite.");
    dict.set("agent_workspace.settings.danger_zone", "Danger zone");
    dict.set("agent_workspace.settings.teardown_hint", "Tear down the entire Agent Workspace (`cx.space.tombstone(workspace_root)`). Mirror Spaces cascade-tombstone via housekeeping. Existing mention_redirect events in source Spaces are preserved for audit.");
    dict.set("agent_workspace.settings.teardown", "Tear down workspace");

    // Notification renderer (AW-3.12)
    dict.set("agent_workspace.notification.added", "was added to");
    dict.set("agent_workspace.notification.removed", "was removed from");
    dict.set(
        "agent_workspace.notification.profile_changed",
        "had its capability changed in",
    );
    dict.set(
        "agent_workspace.notification.unknown_target",
        "(unknown source)",
    );

    // Personal blocklist (A5) — actor-private `client.blocklist`
    // account-data namespace. Used by the Settings → Privacy panel, the
    // member-row context action, and the timeline/chat "blocked user"
    // placeholder row.
    dict.set("settings.privacy.title", "Privacy");
    dict.set("settings.privacy.blocked_users.title", "Blocked users");
    dict.set(
        "settings.privacy.blocked_users.empty",
        "No users blocked. Block someone from a member list or message row to manage entries here.",
    );
    dict.set("settings.privacy.unblock", "Unblock");
    // A4b — avatar upload UI keys.
    dict.set("settings.avatar.title", "Profile picture");
    dict.set("settings.avatar.upload", "Upload new avatar");
    dict.set("settings.avatar.clear", "Remove avatar");
    dict.set("settings.avatar.uploading", "Uploading avatar…");
    dict.set("settings.avatar.error", "Avatar upload failed");
    // A6.1 — global cross-space message search.
    dict.set("search.title", "Search messages");
    dict.set("search.placeholder", "Search across all your spaces…");
    dict.set("search.results.empty", "Type a query to search across your spaces.");
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
    dict.set("content.video.unsupported", "Your browser does not support inline video.");
    dict.set("content.audio.unsupported", "Your browser does not support inline audio.");
    dict.set("content.attachment.download", "Download");

    dict
}

/// Build Chinese translation dictionary.
pub fn chinese_translations() -> TranslationDict {
    let mut dict = TranslationDict::new(Locale::Zh);

    dict.set("app.title", "yougen");
    dict.set("nav.dashboard", "仪表盘");
    dict.set("nav.timeline", "时间线");
    dict.set("nav.chat", "聊天");
    dict.set("nav.forum", "论坛");
    dict.set("nav.directory", "目录");
    dict.set("nav.notifications", "通知");
    dict.set("nav.settings", "设置");
    dict.set("nav.login", "登录");
    dict.set("nav.audit", "审计");
    dict.set("nav.devices", "设备");

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
    dict.set("topbar.search_placeholder", "跳转到空间、视图或操作…");
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
    dict.set("dashboard.spaces_label", "空间");
    dict.set("dashboard.spaces_delta_search", "搜索或加入空间");
    dict.set("dashboard.spaces_delta_signin", "登录后加载空间");
    dict.set("dashboard.current_space", "当前空间");
    dict.set("dashboard.workspace_setup", "工作区设置");
    dict.set(
        "dashboard.workspace_setup_delta",
        "创建第一个空间与初始策略",
    );
    dict.set("dashboard.onboarding", "引导");
    dict.set("dashboard.onboarding_steps", "4 步");
    dict.set("dashboard.onboarding_delta", "身份、设备与恢复方案");
    dict.set("dashboard.recent_spaces", "最近空间");
    dict.set("dashboard.no_spaces", "暂无空间");
    dict.set("dashboard.no_spaces_help", "服务器尚未返回空间列表。");
    dict.set("dashboard.no_session_help", "客户端不会展示占位空间。");

    dict.set("notifications.archived", "显示已归档");
    dict.set("notifications.mark_all_read", "全部标记已读");
    dict.set("notifications.empty_state", "暂无通知。");

    dict.set("composer.send", "发送");
    dict.set("composer.encrypted_toggle", "本地加密");
    dict.set(
        "composer.plaintext_warning",
        "明文消息对所配置的服务器可见。",
    );

    dict.set("command_palette.spaces", "空间");
    dict.set("command_palette.jump_to", "跳转到");
    dict.set(
        "command_palette.empty",
        "未找到匹配的空间或视图。按 Esc 关闭。",
    );
    dict.set("command_palette.close", "关闭 (Esc)");

    dict.set("mobile.filter_spaces", "筛选空间…");
    dict.set("mobile.no_match", "未找到匹配空间。");

    // Kanban / Board view
    dict.set("kanban.board_header", "启动看板");
    dict.set("kanban.board_title", "看板");
    dict.set(
        "kanban.board_hint",
        "拖动卡片到不同列以排队 cx.flow.move 写入；服务端 view 接口可用时刷新会替换种子数据。",
    );
    dict.set("chat.mls_passphrase_placeholder", "MLS 口令（本 Space）");
    dict.set("chat.mls_passphrase_save", "保存口令");
    dict.set("chat.mls_publish_key_package", "发布 Key Package");
    dict.set("chat.mls_invite_actor_placeholder", "邀请目标 actor DID");
    dict.set("chat.mls_invite_device_placeholder", "邀请目标设备 id");
    dict.set("chat.mls_invite_member", "邀请加入 MLS 群");
    dict.set("chat.send", "发送");
    dict.set("chat.send_secure", "加密发送");
    dict.set("chat.plaintext_blocked", "先输入消息内容再加密发送");
    dict.set("recovery.vault_encrypt_button", "加密并上传");
    dict.set("recovery.vault_rotate_button", "轮换口令");
    dict.set(
        "recovery.vault_rotate_hint",
        "复用现有 backup_id，但重新派生 KEK / nonce。",
    );
    dict.set(
        "recovery.vault_rotate_prompt",
        "请在上方输入新口令并点击「加密并上传」完成轮换。",
    );
    dict.set("space_admin.save_metadata", "保存元数据");
    dict.set("space_admin.save_metadata_move", "通过 Move 保存元数据");
    dict.set("space_admin.tombstone_delete", "终结 / 删除");
    dict.set("space_admin.archive_space", "归档 Space");
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
    dict.set("space_admin.apply_policy", "应用策略");
    dict.set("space_admin.grant_capability_move", "授予权限（Move）");
    dict.set("space_admin.revoke_capability_move", "撤销权限（Move）");
    dict.set("space_admin.refresh_members", "刷新");
    dict.set("space_admin.kick_member", "踢出");
    dict.set("space_admin.ban_member", "封禁");
    dict.set("space_admin.kick_member_move", "踢出（Move）");
    dict.set("space_admin.ban_member_move", "封禁（Move）");
    dict.set("space_admin.rotate_epoch", "轮换 Epoch");
    dict.set("space_admin.leave_space", "退出");
    dict.set("recovery.primary", "主");
    dict.set("directory.list_contacts", "列出");
    dict.set("directory.search_button", "搜索");
    dict.set("directory.resolve_selected", "解析选中");
    dict.set("settings.store_backup", "存储备份");
    dict.set("settings.register_push", "注册推送");
    dict.set("settings.unregister_push", "注销推送");
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
    dict.set("recovery.vault_section", "加密云保险箱");
    dict.set("recovery.recovery_key_section", "恢复密钥");
    dict.set("recovery.social_section", "社交恢复");

    // Space-admin view
    dict.set("space_admin.title", "Space 管理");
    dict.set("space_admin.governance", "治理");
    dict.set("space_admin.devices", "设备");
    dict.set("space_admin.members", "成员");
    dict.set("space_admin.access", "访问控制");
    dict.set("space_admin.security_mls", "安全与 MLS");
    dict.set("space_admin.mls_remove_header", "MLS 移除（设备吊销）");
    dict.set(
        "space_admin.mls_remove_hint",
        "用本地 MLS 快照口令解密群状态，运行 remove_member_by_principal，提交 cx.mls.commit；成功后重新加密持久化新一轮 epoch。",
    );
    dict.set("space_admin.mls_remove_button", "构建并提交 MLS 移除");
    dict.set(
        "space_admin.mls_remove_target_placeholder",
        "目标设备 DID（did:web:…）",
    );
    dict.set("space_admin.mls_remove_passphrase_placeholder", "快照口令");

    // Chat / Discussion view
    dict.set("chat.discussions_header", "讨论");
    dict.set("chat.users_header", "用户");
    dict.set("chat.settings_header", "设置");
    dict.set("chat.new_discussion", "新建讨论");
    dict.set("chat.hide_list", "隐藏讨论列表");
    dict.set("chat.label.title", "标题");
    dict.set("chat.label.summary", "概述");
    dict.set("chat.label.watchers", "添加关注者");
    dict.set(
        "chat.watchers.hint",
        "不影响访问控制 —— 关注只改变通知，不改变谁能看到该 Flow。",
    );
    dict.set("chat.button.create", "创建");
    dict.set("chat.button.reply", "回复");
    dict.set("chat.button.react", "回应");
    dict.set("chat.button.redact", "撤回");
    dict.set("chat.you_badge", "我");
    // 成员视觉标识 (member.badge.*)
    dict.set("member.badge.agent", "智能体");
    // 撰写区拖拽附件 (A6.2)
    dict.set("compose.drop_zone.hint", "将文件拖放到此处以附加,或点击「附加」");
    dict.set("compose.upload_progress", "上传中…");
    dict.set("compose.upload_error", "上传失败");
    // 消息钉选 (A6.3)
    dict.set("message.pin", "钉选");
    dict.set("message.unpin", "取消钉选");
    dict.set("pinned_bar.empty", "暂无钉选消息。");
    dict.set("pinned_bar.scroll_to", "跳转到消息");
    dict.set("chat.empty.title", "还没有讨论");
    dict.set(
        "chat.empty.description",
        "创建一个讨论,以在该空间中开始聊天。",
    );
    dict.set("chat.empty.create_button", "创建第一个讨论");

    // Notifications panel
    dict.set("notifications.group.all", "全部");
    dict.set("notifications.group.space", "按空间");
    dict.set("notifications.group.type", "按类型");
    dict.set("notifications.group.time", "按时间");
    dict.set("notifications.tooltip.mark_all_read", "全部标为已读");
    dict.set("notifications.tooltip.show_archived", "显示已归档");
    dict.set("notifications.tooltip.hide_archived", "隐藏已归档");
    dict.set("notifications.tooltip.refresh", "刷新通知");
    dict.set("notifications.settings_card", "通知设置");
    dict.set("notifications.settings_card_hint", "在「设置」中管理");
    dict.set(
        "notifications.settings_card_body",
        "通知规则、静音空间、推送偏好现在统一在「设置」中管理。",
    );
    dict.set("notifications.settings_card_open", "打开设置");
    dict.set("notifications.empty_body", "尚未加载到任何服务端通知。");
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

    // Agent Workspace (`cx.profile.agent_workspace.v1`)
    dict.set("nav.agent_workspace", "我的 Agents");
    dict.set("agent_workspace.dashboard.title", "我的 Agents");
    dict.set("agent_workspace.add_agent", "+ 添加 Agent");
    dict.set(
        "agent_workspace.add_agent.hint",
        "把你的一个 agent 加到某个源 Flow",
    );
    dict.set("agent_workspace.add_first_agent", "添加你的第一个 agent");
    dict.set("agent_workspace.protocol_session_monitor", "Agent 协议会话");
    dict.set("agent_workspace.pending", "待处理");
    dict.set(
        "agent_workspace.pending.subtitle",
        "源端透明度或权限有变化。请选择「继续」或「取消」。",
    );
    dict.set("agent_workspace.in_flight", "进行中");
    dict.set("agent_workspace.recent", "最近完成");
    dict.set("agent_workspace.my_agents", "我的 Agents");
    dict.set("agent_workspace.back", "返回");
    dict.set("agent_workspace.task.open", "打开");
    dict.set("agent_workspace.task.reconfirm", "继续执行");
    dict.set("agent_workspace.task.cancel", "取消任务");
    dict.set("agent_workspace.task.no_source", "(无源)");
    dict.set("agent_workspace.task.loading", "正在加载任务…");
    dict.set("agent_workspace.task.anchor", "源上下文锚点");
    dict.set("agent_workspace.task.instruction", "你的指令");
    dict.set("agent_workspace.task.draft", "Agent 草稿");
    dict.set("agent_workspace.task.publish", "发布到源 Flow");
    dict.set(
        "agent_workspace.task.publish_hint",
        "把 agent 草稿以你自己身份发到源 Flow（可选注明）。",
    );
    dict.set(
        "agent_workspace.task.publish_disabled_reason",
        "任务不在 active 状态；请先 reconfirm 或 cancel。",
    );
    dict.set("agent_workspace.task.mark_complete", "标记完成");
    dict.set("agent_workspace.task.rewrite", "让 agent 重写");
    dict.set("agent_workspace.task.conversation", "对话");
    dict.set(
        "agent_workspace.task.compose_placeholder",
        "回复或追加指令…",
    );
    dict.set("agent_workspace.task.send", "发送");
    dict.set("agent_workspace.task.audit_trail", "审计 trail");
    dict.set(
        "agent_workspace.banner.transparency_lost",
        "源 mention 已被撤回。Agent 已暂停。",
    );
    dict.set(
        "agent_workspace.banner.source_authority_revoked",
        "Agent 在源 Space 的权限已被撤销。",
    );
    dict.set("agent_workspace.fsm.execution", "执行");
    dict.set("agent_workspace.fsm.transparency", "透明度");
    dict.set("agent_workspace.fsm.source_authority", "源权限");
    dict.set("agent_workspace.fsm.aria_label", "三个正交任务状态 cell");
    dict.set("agent_workspace.agent.consulting", "consulting");
    dict.set(
        "agent_workspace.agent.no_active_sources",
        "(仅 mirror；不在任何源 Space 中)",
    );
    dict.set(
        "agent_workspace.empty.in_flight.message",
        "当前没有任何 agent 任务在跑。",
    );
    dict.set(
        "agent_workspace.empty.in_flight.hint",
        "在聊天或讨论里 @ 你的 agent 即可开启私人任务。",
    );
    dict.set(
        "agent_workspace.empty.agents.message",
        "你还没有添加任何 agent。",
    );
    dict.set(
        "agent_workspace.compose.private_routing_notice",
        "此指令将发送到你的私人 Agent Workspace。源 Flow 其他成员只会看到通用摘要。",
    );
    dict.set(
        "agent_workspace.compose.summary_visible_warning",
        "此摘要对源 Flow 所有成员可见。",
    );
    dict.set(
        "agent_workspace.compose.send_private",
        "发送 (Private to Agent)",
    );
    // A6.4 — keyboard shortcut help overlay。
    dict.set("shortcuts.title", "键盘快捷键");
    dict.set("shortcuts.dismiss", "关闭");
    dict.set("shortcuts.list.help", "显示此快捷键面板");
    dict.set("shortcuts.list.dismiss", "关闭任何打开的对话框");
    dict.set("shortcuts.list.palette", "打开命令面板");
    dict.set("shortcuts.list.palette_mac", "打开命令面板 (macOS)");
    dict.set("shortcuts.list.send", "发送当前消息");
    // A2 — mirror Space banner + compose banner + nav tooltip 文案。
    dict.set("agent_workspace.private_mirror.title", "私人 Mirror Space");
    dict.set(
        "agent_workspace.private_mirror.body",
        "此 mirror Space 中的草稿仅对你可见。Agent 可以将经过 redaction 的摘要发布到源 Space {source}。",
    );
    dict.set(
        "agent_workspace.private_mirror.body_no_source",
        "此 mirror Space 中的草稿仅对你可见。Agent 可以将经过 redaction 的摘要发布回源 Space。",
    );
    dict.set(
        "agent_workspace.compose.private_to_agent_banner",
        "正在私聊 {agent}：仅 agent 收到该消息；源 Flow 其他成员只会看到通用摘要。",
    );
    dict.set("agent_workspace.nav.info_title", "什么是「我的 Agents」？");
    dict.set(
        "agent_workspace.nav.info_body",
        "私人 Agent Workspace 镜像了 agent 在源 Space 中工作的状态。草稿保持私有；只有经过 redaction 的摘要会回到源 Space。",
    );
    dict.set("agent_workspace.nav.info_button", "关于「我的 Agents」");

    // Publish modal (AW-3.7 + AW-3.20)
    dict.set("agent_workspace.publish.signer_legend", "签名身份");
    dict.set("agent_workspace.publish.signer_self", "作为我自己发布");
    dict.set(
        "agent_workspace.publish.signer_self_with_attribution",
        "作为我自己发布，附注「由 agent 起草」",
    );
    dict.set("agent_workspace.publish.cancel", "取消");
    dict.set("agent_workspace.publish.confirm", "发布");

    // Add agent modal (AW-3.8)
    dict.set(
        "agent_workspace.add_agent.select_legend",
        "选择你的一个 agent",
    );
    dict.set(
        "agent_workspace.add_agent.profile_legend",
        "权限 (capability profile)",
    );
    dict.set(
        "agent_workspace.add_agent.profile.observer",
        "Observer (只读历史)",
    );
    dict.set(
        "agent_workspace.add_agent.profile.read_only",
        "只读 + reaction",
    );
    dict.set(
        "agent_workspace.add_agent.profile.mention_respond_only",
        "仅在被 @ 时回复 (推荐)",
    );
    dict.set(
        "agent_workspace.add_agent.profile.full_collaborator",
        "完整成员",
    );
    dict.set(
        "agent_workspace.add_agent.no_owned_agents",
        "你还没有创建任何受控 agent。前往 Settings → Agents 添加。",
    );
    dict.set(
        "agent_workspace.add_agent.disclosure",
        "Agent 成员身份对源 Space 所有成员可见；agent 在你的私人 Workspace 内的工作过程仍然私密。",
    );
    dict.set("agent_workspace.add_agent.cancel", "取消");
    dict.set("agent_workspace.add_agent.send_invite", "发送邀请");

    // Settings page (AW-3.4)
    dict.set("agent_workspace.settings.title", "Agent Workspace 设置");
    dict.set("agent_workspace.settings.agents", "我的 Agents");
    dict.set(
        "agent_workspace.settings.default_profile",
        "新邀请的默认 capability profile",
    );
    dict.set(
        "agent_workspace.settings.default_profile_hint",
        "Add Agent 弹窗的预选项。每次邀请仍可单独覆盖。",
    );
    dict.set("agent_workspace.settings.danger_zone", "危险区域");
    dict.set("agent_workspace.settings.teardown_hint", "解散整个 Agent Workspace（`cx.space.tombstone(workspace_root)`）。所有 mirror Space 会通过 housekeeping 级联 tombstone；源 Space 中已发出的 mention_redirect 会保留用于 audit。");
    dict.set("agent_workspace.settings.teardown", "解散 workspace");

    // Notification renderer (AW-3.12)
    dict.set("agent_workspace.notification.added", "被加入到");
    dict.set("agent_workspace.notification.removed", "被移出");
    dict.set(
        "agent_workspace.notification.profile_changed",
        "的权限发生变化于",
    );
    dict.set(
        "agent_workspace.notification.unknown_target",
        "（未知来源）",
    );

    // Personal blocklist (A5)
    dict.set("settings.privacy.title", "隐私");
    dict.set("settings.privacy.blocked_users.title", "已屏蔽的用户");
    dict.set(
        "settings.privacy.blocked_users.empty",
        "尚未屏蔽任何用户。在成员列表或消息行中屏蔽用户后，可在此管理。",
    );
    dict.set("settings.privacy.unblock", "取消屏蔽");
    // A4b — 头像上传相关。
    dict.set("settings.avatar.title", "头像");
    dict.set("settings.avatar.upload", "上传新头像");
    dict.set("settings.avatar.clear", "清除头像");
    dict.set("settings.avatar.uploading", "上传中…");
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

    dict
}

/// Build Arabic translation dictionary.
pub fn arabic_translations() -> TranslationDict {
    let mut dict = TranslationDict::new(Locale::Ar);

    dict.set("app.title", "yougen");
    dict.set("nav.dashboard", "لوحة التحكم");
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
    let en = english_translations();
    let zh = chinese_translations();
    let ar = arabic_translations();
    dicts.insert("en".to_owned(), en);
    dicts.insert("zh".to_owned(), zh);
    dicts.insert("ar".to_owned(), ar);
    Signal::new((locale, dicts))
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
        assert_eq!(Locale::from_code("fr"), Locale::En); // fallback
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
