//! English (`en`) translation dictionary plus its private helper
//! string sets. `english_translations` is the authoritative reference
//! locale; helpers live alongside it so all `dict.set` calls stay in one
//! module.

use super::{TranslationDict, UiLocale};

/// Build the default English translation dictionary.
pub fn english_translations() -> TranslationDict {
    let mut dict = TranslationDict::new(UiLocale::En);

    // Navigation & Shell
    dict.set("nav.dashboard", "Home");
    dict.set("nav.directory", "Directory");
    dict.set("nav.notifications", "Notifications");
    dict.set("nav.settings", "Settings");
    dict.set("nav.files", "Files");
    dict.set("nav.collaboration", "Collaboration");
    dict.set("nav.contacts", "Contacts");
    dict.set("direct.unavailable", "Direct conversation unavailable");
    dict.set("contacts.empty", "No contacts yet");
    dict.set("contacts.sign_in", "Sign in to load contacts");
    dict.set("sidebar.search_realms", "Search Realms");
    dict.set("sidebar.search_contacts", "Search contacts");
    dict.set("sidebar.search", "Search");
    dict.set("sidebar.realms_empty", "No Realms loaded yet");
    dict.set("sidebar.realms_sign_in", "Sign in to load Realms");
    dict.set("sidebar.realms_no_results", "No matching Realms");

    // Circle error keys (P3B.3.2)
    add_circle_error_keys(&mut dict);

    // Directory
    dict.set("directory.tab.organizations", "Organizations");
    dict.set("directory.tab.actors", "People");

    // Settings navigation — section labels (design/settings-ia-reorg.md §3.1).
    // Terminology humanised: Capabilities → App authorizations, Blocked actors → Block list,
    // Consent → Invites & consent, Diagnostics → Release status.
    dict.set("settings.section.account", "Account information");
    dict.set("settings.section.agents", "My Agents");
    dict.set("settings.section.server", "Server information");
    dict.set("settings.section.devices", "Devices");
    dict.set("settings.section.storage", "Data & sync");
    dict.set("settings.section.encryption", "Security");
    dict.set("settings.section.recovery", "Recovery");
    dict.set("settings.section.mimi", "Integrations");
    dict.set("settings.section.notifications", "Notifications");
    dict.set("settings.section.privacy", "Privacy & sharing");
    dict.set("settings.section.invite_policy", "Who can invite me");
    dict.set("settings.section.consent", "Invites & consent");
    dict.set("settings.section.blocklist", "Block list");
    dict.set("settings.section.capabilities", "App authorizations");
    dict.set("settings.section.theme", "Appearance & locale");
    dict.set("settings.section.release", "Release status");
    dict.set("settings.section.audit", "Audit log");
    dict.set("settings.section.developer", "Developer tools");
    // Settings navigation — group labels + hints.
    dict.set("settings.group.account", "Account");
    dict.set(
        "settings.group.account.hint",
        "Identity, agents, and server.",
    );
    dict.set("settings.group.security", "Devices & security");
    dict.set(
        "settings.group.security.hint",
        "Signed-in devices, recovery, and app authorizations.",
    );
    dict.set("settings.group.privacy", "Privacy");
    dict.set(
        "settings.group.privacy.hint",
        "Actor-private disclosure controls.",
    );
    dict.set("settings.group.notifications", "Notifications");
    dict.set(
        "settings.group.notifications.hint",
        "Notification delivery behavior.",
    );
    dict.set("settings.group.appearance", "Appearance & language");
    dict.set("settings.group.appearance.hint", "Theme and locale.");
    dict.set("settings.group.advanced", "Advanced");
    dict.set(
        "settings.group.advanced.hint",
        "Data, connections, and protocol diagnostics.",
    );
    // Settings-nav filter (design §3.4).
    dict.set("settings.search.placeholder", "Search settings…");

    // T1.3 — proof mode (event signing) status. Exposed in the settings
    // panel and the top status bar so the user can confirm at a glance
    // whether outgoing events are placeholder-dev, real-Ed25519, or
    // backed by an external signer (and refused on production targets
    // when no signer is configured).
    dict.set("settings.proof_mode.label", "Event signing");
    dict.set("settings.proof_mode.real_ed25519", "real Ed25519");
    dict.set("settings.proof_mode.external_signer", "external signer");
    dict.set("settings.proof_mode.production", "no signer (production)");

    // T5.2 — signer DID / key id / freshness panel under the proof
    // mode indicator. Exposed in the settings panel so the user can
    // confirm at a glance that the device is signing with the expected
    // identity and how recently a proof has been produced.
    dict.set("settings.signer.label", "Active signer");

    // Settings surfaces wired in the `views/settings/mod.rs` sweep:
    // server information, local stores, storage diagnostics, encryption,
    // MIMI interop, notifications, push, privacy/presence, read receipts,
    // remarks, handle, appearance and session diagnostics.
    dict.set("settings.server.context", "Server context");
    dict.set("settings.server.station", "Station");
    dict.set("settings.server.session", "Session");
    dict.set("settings.server.session_authenticated", "Authenticated");
    dict.set("settings.server.push", "Push");
    dict.set("settings.avatar.account_alt", "Account avatar");
    dict.set("settings.avatar.edit_dialog", "Edit avatar");
    dict.set("settings.avatar.selected_alt", "Selected avatar");
    dict.set(
        "settings.avatar.cleared_synced",
        "Avatar cleared from synced preferences",
    );
    dict.set(
        "settings.avatar.restored_synced",
        "Avatar restored from synced preferences",
    );
    dict.set(
        "settings.avatar.removing",
        "Removing avatar from the public profile.",
    );
    dict.set(
        "settings.avatar.removed",
        "Avatar removed; syncing clear to other devices.",
    );
    dict.set("settings.local_stores.title", "Local Stores");
    dict.set("settings.local_stores.badge", "status");
    dict.set("settings.local_stores.config_store", "Config Store");
    dict.set("settings.local_stores.state_store", "State Store");
    dict.set("settings.local_stores.active", "Active");
    dict.set("settings.local_stores.config_size", "Config Size");
    dict.set("settings.local_stores.approx_bytes", "~{bytes} bytes");
    dict.set("settings.local_stores.platform", "Platform");
    dict.set("settings.local_stores.platform_web", "Web (localStorage)");
    dict.set(
        "settings.local_stores.platform_native",
        "Native (filesystem)",
    );
    dict.set("settings.storage_risks.title", "Storage diagnostics");
    dict.set(
        "settings.storage_risks.bounded_projection",
        "Bounded localStorage projection ",
    );
    dict.set(
        "settings.storage_risks.bounded_projection_hint",
        "localStorage carries the small root/config projection. Account state, E2EE plaintext, session credentials, and key material use the protected IndexedDB tier.",
    );
    dict.set("settings.storage_risks.badge_bounded", "Bounded");
    dict.set(
        "settings.storage_risks.protected_e2ee",
        "Protected E2EE storage ",
    );
    dict.set(
        "settings.storage_risks.protected_e2ee_hint",
        "E2EE plaintext caches and secret account state are encrypted in IndexedDB with a non-extractable SubtleCrypto wrapping key and are never mirrored to localStorage.",
    );
    dict.set(
        "settings.storage_risks.single_tab",
        "Single Active Browser Tab ",
    );
    dict.set(
        "settings.storage_risks.single_tab_hint",
        "Inkson allows one active tab per browser profile so IndexedDB, device keys, MLS state, cursors, and outbound writes have a single owner.",
    );
    dict.set("settings.storage_risks.badge_info", "Info");
    dict.set("settings.storage_risks.filesystem", "Filesystem Storage ");
    dict.set(
        "settings.storage_risks.filesystem_hint",
        "Native filesystem storage is used. Data persists across sessions. Ensure proper file permissions for security.",
    );
    dict.set("settings.storage_risks.badge_ok", "OK");
    dict.set("settings.encryption.badge", "MLS / E2EE");
    dict.set(
        "settings.encryption.always_on",
        "End-to-end encryption is always on for encrypted Realms. Manage your recovery key below.",
    );
    dict.set(
        "settings.key_backup.title",
        "Advanced key backup diagnostics",
    );
    dict.set("settings.key_backup.badge", "developer tools");
    dict.set(
        "settings.key_backup.body",
        "Encrypted history recovery above creates key backup envelopes automatically. The recovery backup id is generated when a backup is created; it is not something to type by hand.",
    );
    dict.set(
        "settings.key_backup.open_recovery_hint",
        "Open Recovery when debugging a specific backup envelope.",
    );
    dict.set("settings.key_backup.open_recovery", "Recovery & backups");
    dict.set(
        "settings.key_backup.contract",
        "Contract: ak.schema.key_backup.v1 over /_arkret/self/keys/backups/*. This is not required for encrypted-history recovery setup.",
    );
    dict.set("settings.mimi.title", "MIMI interop checks");
    dict.set("settings.mimi.refresh_directory", "Refresh Directory");
    dict.set("settings.mimi.identifier_query", "Identifier Query");
    dict.set("settings.mimi.submit_message", "Submit Test Message");
    dict.set("settings.mimi.proxy_download", "Proxy Download");
    dict.set("settings.mimi.directory_badge", "features");
    dict.set("settings.mimi.receipt_title", "Receipt");
    dict.set("settings.mimi.receipt_badge", "last action");
    dict.set("settings.mimi.not_loaded", "Not loaded");
    dict.set("settings.mimi.no_receipt", "No MIMI action receipt");
    dict.set(
        "settings.notifications.defaults_title",
        "Global notification defaults",
    );
    dict.set("settings.notifications.defaults_badge", "synced");
    dict.set(
        "settings.notifications.defaults_body",
        "Apply to every Realm unless you add a per-Realm override below.",
    );
    dict.set("settings.notifications.sound_on", " Sound alerts");
    dict.set("settings.notifications.sound_off", " Sound alerts off");
    dict.set(
        "settings.notifications.sound_enabled",
        "Sound alerts enabled.",
    );
    dict.set(
        "settings.notifications.sound_disabled",
        "Sound alerts disabled.",
    );
    dict.set("settings.notifications.sound_test", "Test sound");
    dict.set(
        "settings.notifications.sound_test_played",
        "Sound alert test played.",
    );
    dict.set(
        "settings.notifications.sound_test_blocked",
        "Enable sound alerts before testing.",
    );
    dict.set("settings.notifications.dnd", " Do not disturb");
    dict.set("settings.notifications.dnd_off", "Off");
    dict.set("settings.notifications.dnd_now", "Now");
    dict.set(
        "settings.notifications.overrides_title",
        "Per-realm overrides",
    );
    dict.set(
        "settings.notifications.overrides_body",
        "Pick a Realm and how much it should notify you. This overrides the global defaults above for that Realm only.",
    );
    dict.set(
        "settings.notifications.no_realms",
        "No Realms available yet",
    );
    dict.set("settings.notifications.select_realm", "Select a Realm…");
    dict.set("settings.notifications.notify_label", "Notify me about");
    dict.set("settings.notifications.level_all", "All messages");
    dict.set("settings.notifications.add_override", "Add override");
    dict.set(
        "settings.notifications.overrides_empty",
        "No per-Realm overrides yet. Unconfigured Realms follow the global defaults.",
    );
    dict.set(
        "settings.notifications.clear_overrides",
        "Clear all overrides",
    );
    dict.set("settings.push.title", "Push delivery");
    dict.set("settings.push.badge", "configure");
    dict.set(
        "settings.push.body",
        "Push notification preferences and gateway registration.",
    );
    dict.set("settings.push.current", "Current: {state}");
    dict.set("settings.push.not_registered", "Not registered");
    dict.set("settings.privacy.badge", "visibility controls");
    dict.set(
        "settings.privacy.presence_visibility",
        "Presence visibility",
    );
    dict.set(
        "settings.privacy.presence_visibility.public",
        "Everyone in shared Realms",
    );
    dict.set(
        "settings.privacy.presence_visibility.contacts_only",
        "Contacts only",
    );
    dict.set(
        "settings.privacy.presence_visibility.nobody",
        "Nobody (appear offline)",
    );
    dict.set("settings.privacy.status_title", "My status");
    dict.set("settings.privacy.status_badge", "manual presence");
    dict.set("settings.privacy.presence_state.auto", "Automatic");
    dict.set("settings.privacy.presence_state.online", "Online");
    dict.set("settings.privacy.presence_state.idle", "Idle");
    dict.set(
        "settings.privacy.presence_state.dnd",
        "Do not disturb (busy)",
    );
    dict.set(
        "settings.privacy.status_message_placeholder",
        "Status message (e.g. In a meeting)",
    );
    dict.set("settings.privacy.status_expiry.never", "Don't clear");
    dict.set("settings.privacy.status_expiry.30m", "Clear in 30 minutes");
    dict.set("settings.privacy.status_expiry.1h", "Clear in 1 hour");
    dict.set("settings.privacy.status_expiry.today", "Clear today");
    dict.set("settings.privacy.status_save", "Save status");
    dict.set("settings.privacy.status_clear", "Clear");
    dict.set(
        "settings.privacy.status_invalid",
        "Status message is invalid: {error}",
    );
    dict.set(
        "settings.privacy.status_state_unknown",
        "Status state is not in the protocol closed set.",
    );
    dict.set("settings.privacy.status_cleared", "Status cleared.");
    dict.set("settings.privacy.status_saved", "Status saved.");
    dict.set("settings.read_receipts.default_badge", "Default");
    dict.set(
        "settings.read_receipts.send_default",
        " Send read receipts by default",
    );
    dict.set(
        "settings.read_receipts.display_default",
        " Show others' read receipts by default",
    );
    dict.set(
        "settings.read_receipts.realm_exceptions",
        "Realm exceptions",
    );
    dict.set("settings.read_receipts.badge_sending", "sending");
    dict.set("settings.read_receipts.badge_skipping", "skipping");
    dict.set("settings.read_receipts.locked", "locked by Realm policy");
    dict.set("settings.read_receipts.switch_to_skip", "Switch to skip");
    dict.set("settings.read_receipts.switch_to_send", "Switch to send");
    dict.set("settings.read_receipts.inherit_default", "Inherit default");
    dict.set("settings.read_receipts.add_skip", "Add (skip)");
    dict.set("settings.read_receipts.add_send", "Add (send)");
    dict.set("settings.remarks.badge_private", "Private");
    dict.set("settings.realm_remarks.title", "Realm remarks");
    dict.set(
        "settings.realm_remarks.empty",
        "No remarks yet. Add one below to distinguish duplicate-titled Realms.",
    );
    dict.set(
        "settings.realm_remarks.local_name_private",
        "Local name (private)",
    );
    dict.set("settings.realm_remarks.local_name", "Local name");
    dict.set("settings.realm_remarks.add", "Add remark");
    dict.set("settings.contact_petnames.title", "Contact petnames");
    dict.set(
        "settings.contact_petnames.body",
        "Petnames are global across all Realms. Add or edit them from an accepted human Contact row; arbitrary DIDs and Realm members cannot receive a petname.",
    );
    dict.set(
        "settings.contact_petnames.empty",
        "No saved contact petnames.",
    );
    dict.set("settings.handle.title", "Handle");
    dict.set(
        "settings.handle.managed_badge",
        "Managed by your organization",
    );
    dict.set(
        "settings.handle.managed_body",
        "Your handle is managed by your organization. This client cannot set or change it directly — request changes through your organization's issuer.",
    );
    dict.set(
        "settings.handle.issuer_link",
        "Manage handle at your organization's issuer",
    );
    dict.set(
        "settings.handle.issuer_link_unavailable",
        "Issuer link unavailable",
    );
    dict.set("settings.theme.badge", "appearance");
    dict.set("settings.theme.light", "Light theme");
    dict.set("settings.theme.night", "Night theme");
    dict.set("settings.theme.system", "System theme");
    dict.set("settings.theme.current", "Current: {theme}");
    dict.set("settings.language.title", "Language");
    dict.set("settings.session_diagnostics.title", "Session diagnostics");

    // Common
    dict.set("common.retry", "Retry");
    dict.set("common.close", "Close");
    dict.set("common.cancel", "Cancel");
    dict.set("common.save", "Save");
    dict.set("common.edit", "Edit");
    dict.set("common.refresh", "Refresh");
    dict.set("common.online", "online");
    dict.set("common.offline", "offline");
    dict.set("qr_share.scan", "Scan QR code");
    dict.set("qr_share.unavailable", "QR unavailable");
    dict.set("qr_share.use_link", "Or use this link");
    dict.set("qr_share.copy_link", "Copy link");
    dict.set("qr_share.copied", "Copied");
    dict.set(
        "qr_share.private_hint",
        "Keep this link private. It expires automatically; pairing links also stop working once accepted.",
    );
    dict.set("message.actions", "Message actions");

    // R-i18n-002 extra keys for the highest-visibility surfaces.
    dict.set(
        "topbar.search_placeholder",
        "Jump to a Realm, view or action...",
    );
    dict.set("topbar.account_menu", "Account menu");

    dict.set("login.continue", "Continue");
    dict.set("login.working", "Working...");
    dict.set("login.title", "Sign in");
    dict.set("login.completing", "Completing sign in");
    dict.set("login.station", "Sign-in server");
    dict.set("login.station_url", "Sign-in server URL");
    dict.set("login.show_preset_servers", "Show preset servers");
    dict.set("login.preset_servers", "Preset servers");
    dict.set("login.status.signed_out", "signed-out");
    dict.set("login.status.session_expired", "session-expired");
    dict.set("login.status.signed_in", "signed-in");
    dict.set("register.opening", "Opening the account service…");
    dict.set("register.error.technical_details", "Technical details");
    dict.set(
        "register.error.invalid_server.title",
        "Invalid server address",
    );
    dict.set(
        "register.error.invalid_server.guidance",
        "Check the address and try again.",
    );
    dict.set(
        "register.error.unavailable.title",
        "Account service unavailable",
    );
    dict.set(
        "register.error.unavailable.guidance",
        "Try again in a moment.",
    );
    dict.set("register.error.unexpected.title", "Could not continue");
    dict.set(
        "register.error.unexpected.guidance",
        "Try again. If the problem continues, open the technical details below.",
    );
    dict.set("login.refresh_now", "Refresh now");

    dict.set("dashboard.notifications_label", "Notifications");
    dict.set(
        "dashboard.notifications_delta_unread",
        "Unread and approvals",
    );
    dict.set("dashboard.notifications_delta_signin", "Sign in required");
    dict.set(
        "dashboard.no_session_help",
        "The client is not showing placeholder Realms.",
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
        "Realm-scoped policy - managed under Realm settings.",
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
        "For the most secure invite, use the invite link the person shares with you. If they allow being found, enter their handle or identity address plus their server.",
    );

    // F-NOTIF-VLIST-1: client-side paging UI.
    dict.set("notifications.showing", "Showing");
    dict.set("notifications.load_more", "Load more");
    dict.set("directory.loading_more", "Loading...");
    dict.set("directory.load_more_realms", "Load More Realms");
    dict.set(
        "directory.load_more_organizations",
        "Load More Organizations",
    );
    dict.set("directory.load_more_actors", "Load More People");

    dict.set("command_palette.realms", "Realms");
    dict.set("command_palette.jump_to", "Jump to");
    dict.set(
        "command_palette.empty",
        "No matching Realms or views. Press Esc to close.",
    );
    dict.set("command_palette.close", "Close (Esc)");

    dict.set("mobile.filter_realms", "Filter Realms...");
    dict.set("mobile.no_match", "No Realms match.");

    // Kanban / Board view (header + section labels)
    dict.set("kanban.board_header", "Board");
    dict.set("chat.send", "Send");
    dict.set("chat.send_secure", "Send Secure");
    dict.set("chat.scheduled_send.send_at", "Send at");
    dict.set("chat.scheduled_send.create", "Schedule message");
    dict.set(
        "chat.scheduled_send.needs_body",
        "Type a message and pick a time before scheduling",
    );
    dict.set(
        "chat.scheduled_send.empty",
        "No scheduled messages for this discussion.",
    );
    dict.set("chat.scheduled_send.created", "Message scheduled.");
    dict.set("chat.scheduled_send.updated", "Scheduled message updated.");
    dict.set(
        "chat.scheduled_send.cancelled",
        "Scheduled message cancelled.",
    );
    dict.set("chat.scheduled_send.edit", "Edit");
    dict.set("chat.scheduled_send.save", "Save");
    dict.set("chat.scheduled_send.dismiss_edit", "Cancel");
    dict.set("chat.scheduled_send.cancel_plan", "Delete");
    dict.set("realm_admin.save_profile", "Save Profile");
    dict.set("realm_admin.destroy_realm", "Destroy Realm");
    dict.set("realm_admin.archive_realm", "Archive Realm");
    dict.set("kanban.add_card", "Add Card");
    dict.set("kanban.add_list", "Add List");
    dict.set("kanban.save_card", "Save");
    dict.set("kanban.cancel_card", "Cancel");
    dict.set("kanban.rename_list_hint", "Double-click to rename");
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
        "Grant or revoke admin rights for this Realm. The change is signed and takes effect once the server processes it.",
    );
    dict.set("realm_admin.admin_subject_label", "Admin subject id");
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
    dict.set("realm_admin.leave_realm", "Leave");
    dict.set("realm_admin.leave_confirm_title", "Leave this Realm?");
    dict.set(
        "realm_admin.leave_confirm_body",
        "After leaving you will need a new invitation to rejoin this Realm, and its local cache on this device will be cleared.",
    );
    dict.set("realm_admin.leave_confirm_target", "Realm to leave");
    dict.set("realm_admin.leave_confirm_button", "Leave Realm");
    dict.set("realm_admin.leave_confirm_cancel", "Cancel");
    dict.set("directory.list_contacts", "List");
    dict.set("directory.search_button", "Search");
    dict.set("directory.resolve_selected", "Resolve Selected");
    dict.set("settings.register_push", "Register Push");
    dict.set("settings.unregister_push", "Unregister Push");
    dict.set("kanban.archive_action", "Archive");
    dict.set("kanban.card.draft", "draft");
    dict.set(
        "kanban.card.draft_hint",
        "Queued locally; waiting for the server to confirm this card.",
    );
    dict.set(
        "kanban.archive_draft_blocked",
        "This card is still a local draft; wait for it to sync before archiving.",
    );
    dict.set("kanban.archive_board_action", "Archive board");
    dict.set(
        "kanban.archive_board_pending",
        "Archiving board and all its cards...",
    );
    dict.set(
        "kanban.archive_board_done",
        "Board archived; cards cascaded to archived.",
    );
    dict.set("kanban.archive_board_confirm_title", "Archive this board?");
    dict.set(
        "kanban.archive_board_confirm_scope",
        "This archives the board plus {lists} active list(s) and {cards} active card(s) on it.",
    );
    dict.set(
        "kanban.archive_board_confirm_recover",
        "Archived lists and cards can be restored later from the Archived panels.",
    );
    dict.set("kanban.archive_board_confirm_confirm", "Archive board");
    dict.set("kanban.archive_board_confirm_cancel", "Cancel");
    dict.set("kanban.archive_list_confirm_title", "Archive this list?");
    dict.set(
        "kanban.archive_list_confirm_body",
        "Archiving \"{title}\" hides the list and its {cards} active card(s) from the board. You can restore it from the Archived lists panel.",
    );
    dict.set("kanban.archive_list_confirm_confirm", "Archive list");
    dict.set("kanban.archive_list_confirm_cancel", "Cancel");
    dict.set("kanban.restore_action", "Restore");
    dict.set("kanban.archived_lists_header", "Archived lists");
    dict.set("kanban.archived_lists_empty", "No archived lists.");
    dict.set("kanban.archived_cards_header", "Archived cards");
    dict.set("kanban.archived_cards_empty", "No archived cards.");
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
    dict.set("recovery.recovery_key_section", "Recovery Key (24 words)");

    // Custody-confirmed Recovery Key upload status (`views/recovery/upload.rs`).
    dict.set(
        "recovery.upload.publishing",
        "Recovery key confirmed — publishing the recovery policy and encrypted backup…",
    );
    dict.set(
        "recovery.upload.backed_up",
        "Recovery key created; the recovery policy and encrypted account backup are stored. Write the 24 words down — they are the only way to restore on a new device.",
    );
    dict.set(
        "recovery.upload.device_unauthorized",
        "This device isn't authorized to set up the account recovery key. Authorize it from a device you already use, or restore with your existing 24-word recovery key.",
    );
    dict.set(
        "recovery.upload.unreachable",
        "Couldn't reach the server to set up recovery (nothing was changed): {error}. Try again.",
    );

    // Recovery panel (`views/recovery/panel.rs`) — headers, buttons,
    // status lines, and backup-history copy.
    dict.set("recovery.panel.aria_label", "Recovery and key backup");
    dict.set("recovery.panel.options", "Recovery options");
    dict.set(
        "recovery.panel.overview_help",
        "The Recovery Key (24 words) is the only recovery credential. Arkret never stores it on the server; backups are encrypted on this device before upload. A new device is authorized only after your recovery policy accepts its proof.",
    );
    dict.set(
        "recovery.panel.status.publishing",
        "publishing the confirmed recovery key…",
    );
    dict.set(
        "recovery.panel.status.write_down",
        "write the words down now",
    );
    dict.set("recovery.panel.status.accepted", "recovery key accepted ✓");
    dict.set(
        "recovery.panel.status.unconfirmed",
        "backup on server — unconfirmed here",
    );
    dict.set("recovery.panel.status.not_set", "not set ⚠");
    dict.set(
        "recovery.panel.detail.publishing",
        "Your offline copy is confirmed; the recovery policy and first encrypted backup are being saved.",
    );
    dict.set(
        "recovery.panel.detail.custody",
        "Write the words down, then re-enter them before anything is published.",
    );
    dict.set(
        "recovery.panel.detail.confirmed",
        "Recovery Key confirmed on this device",
    );
    dict.set("recovery.panel.detail.accepted_at", "Accepted {when}");
    dict.set(
        "recovery.panel.detail.material_elsewhere",
        "A confirmed recovery key exists, but this device does not keep the words.",
    );
    dict.set(
        "recovery.panel.detail.generate_cta",
        "Generate one to enable cross-device recovery",
    );
    dict.set("recovery.panel.protects_title", "What it protects");
    dict.set("recovery.panel.protects_value", "Encrypted history");
    dict.set(
        "recovery.panel.protects_hint",
        "your encryption keys and your own content, backed up automatically",
    );
    dict.set("recovery.panel.keep_offline", "keep offline");
    dict.set("recovery.panel.badge_not_backed_up", "Not backed up yet");
    dict.set("recovery.panel.badge_backed_up", "Backed up");
    dict.set(
        "recovery.panel.key_help",
        "This is your account's only recovery credential. Generating it protects your encryption keys behind these 24 words and uploads an encrypted backup; your own content is then backed up automatically. The words themselves never leave this device (only a fingerprint is kept locally); Arkret cannot recover them for you, so write them down. Losing them means your encrypted history cannot be restored.",
    );
    dict.set(
        "recovery.panel.publishing_title",
        "Publishing the recovery policy and encrypted backup…",
    );
    dict.set(
        "recovery.panel.publishing_hint",
        "The confirmed words stay only in memory until this write succeeds or you retry.",
    );
    dict.set("recovery.panel.not_generated", "Not generated yet");
    dict.set(
        "recovery.panel.not_generated_hint",
        "Generate one so a new device can unlock your encrypted backups.",
    );
    dict.set(
        "recovery.panel.write_down_title",
        "Write these 24 words down now.",
    );
    dict.set(
        "recovery.panel.write_down_body",
        "Re-enter the saved words below before clearing them from this screen.",
    );
    dict.set(
        "recovery.panel.confirm_label",
        "Re-enter the saved Recovery Key",
    );
    dict.set(
        "recovery.panel.confirm_placeholder",
        "Type or paste the 24 words you saved",
    );
    dict.set(
        "recovery.panel.confirm_hint",
        "The words must match before the plaintext is cleared. If a word is wrong, the check tells you which position to fix — no need to regenerate.",
    );
    dict.set(
        "recovery.panel.plaintext_cleared",
        "The words are no longer in memory. Replacing the recovery key requires the staged handoff workflow.",
    );
    dict.set(
        "recovery.panel.rotation_guard_title",
        "Direct replacement is disabled.",
    );
    dict.set(
        "recovery.panel.rotation_guard_body",
        "A new Recovery Key must be activated through the two-step handoff, and all protected backups must be re-encrypted before the old key is revoked.",
    );
    dict.set("recovery.panel.last_accepted", "Last accepted");
    dict.set(
        "recovery.panel.rotate_hint",
        "Rotate only through the staged handoff workflow",
    );
    dict.set("recovery.panel.fingerprint", "Fingerprint");
    dict.set(
        "recovery.panel.fingerprint_hint",
        "stored locally, never uploaded",
    );
    dict.set(
        "recovery.panel.goto_devices_title",
        "Authorize this device from one you already use, then come back and generate the key.",
    );
    dict.set("recovery.panel.goto_devices", "Open device settings");
    dict.set(
        "recovery.panel.regenerate_title_fresh",
        "Discard the displayed words and prepare a fresh recovery secret.",
    );
    dict.set(
        "recovery.panel.regenerate_title_guard",
        "Direct replacement is unsafe; use the staged handoff.",
    );
    dict.set(
        "recovery.panel.regenerate_title_default",
        "Generate the words locally; nothing is published until you re-enter them.",
    );
    dict.set("recovery.panel.generate_failed", "Generate failed: {error}");
    dict.set(
        "recovery.panel.generated_status",
        "Write the words down offline and re-enter them. No recovery key has been published yet.",
    );
    dict.set("recovery.panel.publishing_button", "Publishing…");
    dict.set("recovery.panel.start_over", "Start over with a new key");
    dict.set("recovery.panel.generate", "Generate");
    dict.set("recovery.panel.handoff_required", "Staged handoff required");
    dict.set(
        "recovery.panel.copy_title",
        "Copy the 24-word Recovery Key to the clipboard.",
    );
    dict.set("recovery.panel.copied", "✓ Copied!");
    dict.set("recovery.panel.copy", "Copy");
    dict.set(
        "recovery.panel.retry_title",
        "Clear the entry and type the saved words again.",
    );
    dict.set("recovery.panel.retry", "Clear and retry");
    dict.set(
        "recovery.panel.clear_live_title",
        "Confirm the offline copy before publishing the recovery key.",
    );
    dict.set(
        "recovery.panel.custody_confirmed",
        "Offline copy confirmed. Publishing the recovery policy and first encrypted backup…",
    );
    dict.set(
        "recovery.panel.metadata_save_failed",
        "The recovery key was accepted, but saving local metadata failed.",
    );
    dict.set(
        "recovery.panel.accepted_done",
        "Recovery key accepted; the words were cleared from memory. Keep your offline copy safe.",
    );
    dict.set(
        "recovery.panel.retry_extra",
        " If your saved copy keeps failing, start over with a new key.",
    );
    dict.set(
        "recovery.panel.word_count",
        "You entered {entered} of 24 words. Complete the phrase, then confirm again.{extra}",
    );
    dict.set(
        "recovery.panel.word_mismatch",
        "Word {index} does not match the displayed key. Fix it and confirm again.{extra}",
    );
    dict.set(
        "recovery.panel.confirm_publish",
        "Confirm custody and publish",
    );
    dict.set("recovery.panel.history_title", "Advanced · Backup history");
    dict.set(
        "recovery.panel.history_subtitle",
        "encrypted server copies only",
    );
    dict.set(
        "recovery.panel.history_help",
        "Shows when encrypted backups were created on the server. Backup contents stay encrypted and are not shown here.",
    );
    dict.set("recovery.panel.fetching", "Fetching backup times…");
    dict.set("recovery.panel.fetch_failed", "Backup times: {error}");
    dict.set("recovery.panel.loading", "Loading…");
    dict.set("recovery.panel.refresh", "Refresh backup times");
    dict.set(
        "recovery.panel.clear_title",
        "Only clears this local panel. It does not delete server backups.",
    );
    dict.set(
        "recovery.panel.cleared",
        "Cleared local backup history state. Server backups were not deleted.",
    );
    dict.set("recovery.panel.clear", "Clear panel");
    dict.set(
        "recovery.panel.no_backups",
        "No encrypted server backups found. Recovery policy status is checked separately.",
    );
    dict.set("recovery.panel.not_loaded", "No backup times loaded yet.");
    dict.set(
        "recovery.panel.inventory_empty",
        "Loaded 0 backup timestamps from the server. Recovery policy status is checked separately from encrypted backup inventory.",
    );
    dict.set(
        "recovery.panel.inventory_loaded",
        "Loaded {count} backup timestamp(s). Last backup: {latest}",
    );
    dict.set("recovery.panel.last_backup", "Last backup");
    dict.set("recovery.panel.backups_found", "Backups found");
    dict.set("recovery.panel.snapshots", "encrypted snapshots");
    dict.set("recovery.panel.backup_times", "Backup times");
    dict.set("recovery.panel.total", "{total} total");
    dict.set("recovery.panel.latest", "latest");
    dict.set(
        "recovery.panel.older_hidden",
        "{count} older backup time(s) hidden",
    );
    dict.set(
        "recovery.panel.writeback_title",
        "Advanced · What happens when recovery succeeds",
    );
    dict.set(
        "recovery.panel.writeback_subtitle",
        "method-specific evidence",
    );
    dict.set(
        "recovery.panel.writeback_body",
        "A complete recovery makes the new device create its own keys, prove them against your active recovery policy, record a recovery receipt, authorize itself, and then unlock your encrypted history backups. Backup history stays visible above; the proof and device authorization are separate follow-up steps.",
    );
    dict.set("device_authorization.title", "Authorize this device");
    dict.set(
        "device_authorization.subtitle",
        "Approve from another device",
    );
    dict.set(
        "device_authorization.description",
        "This browser is signed in, but it is not trusted for encrypted data yet. Start an approval request here — a device you already trust will usually show a confirmation prompt.",
    );
    dict.set(
        "device_authorization.approve_step_existing_title",
        "On an existing device",
    );
    dict.set(
        "device_authorization.approve_step_existing_body",
        "Compare the 8-character code in the confirmation prompt, then approve. If no prompt appears, open Settings → Devices → Add a device and refresh requests.",
    );
    dict.set(
        "device_authorization.approve_step_new_title",
        "On this browser",
    );
    dict.set(
        "device_authorization.approve_step_new_body",
        "Keep the approval request open. After approving on the other device, return here and check the status.",
    );
    dict.set(
        "device_authorization.limitation",
        "Until approved, encrypted history and security-sensitive actions remain unavailable. You can continue with limited access and return to this step at any time.",
    );
    dict.set("device_authorization.open_pairing", "Start device approval");
    dict.set(
        "device_authorization.dismiss",
        "Continue with limited access",
    );
    dict.set("device_authorization.reopen", "Authorize this device");
    dict.set("mls_unlock.title", "Restore encrypted history");
    dict.set(
        "mls_unlock.subtitle",
        "Use another device or your Recovery Key",
    );
    dict.set(
        "mls_unlock.description",
        "This device is authorized, but it does not have the keys to open encrypted history yet. Restore them from another device you own, or use your recovery key.",
    );
    dict.set(
        "mls_unlock.approve_step_existing_title",
        "From another authorized device",
    );
    dict.set(
        "mls_unlock.approve_step_existing_body",
        "If this device still shows an approval request, approve it on the other device and compare the code. Key sharing continues after approval.",
    );
    dict.set("mls_unlock.approve_step_new_title", "On this browser");
    dict.set(
        "mls_unlock.approve_step_new_body",
        "Keep this tab open while keys are restored, or choose Use recovery key instead below.",
    );
    dict.set(
        "mls_unlock.loading_hint",
        "Restoring multiple encrypted Realms can take a few seconds. Keep this tab open.",
    );
    dict.set(
        "mls_unlock.limitation",
        "You can continue without restoring now, but older encrypted content stays unavailable until this step is complete.",
    );
    dict.set("mls_unlock.open_pairing", "Open device approval");
    dict.set("mls_unlock.show_recovery_key", "Use recovery key instead");
    dict.set("mls_unlock.hide_recovery_key", "Hide recovery key");
    dict.set(
        "mls_unlock.recovery_fallback_hint",
        "Only use this if none of your other devices are available. Your 24-word recovery key unlocks your encrypted-history backups once the server's checks pass.",
    );
    dict.set("mls_unlock.placeholder", "24-word recovery key");
    dict.set("mls_unlock.button_idle", "Unlock with key");
    dict.set("mls_unlock.button_busy", "Unlocking...");
    dict.set("mls_unlock.dismiss", "Continue without history");
    dict.set("mls_unlock.reopen", "Restore encrypted history");
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
        "This Realm is end-to-end encrypted, and this device does not have the key yet. If you just joined, the key arrives automatically — reload or wait for sync to finish; messages from before you joined cannot be opened on any device. To restore content from your own earlier devices, set up your recovery key in Settings → Recovery.",
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
        "Save the 24 recovery words when they appear. They are shown once and are not stored by Arkret; existing devices keep working if you lose them, but new devices cannot restore this history.",
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
    dict.set("mls_backup.button_confirm_saved", "Confirm saved key");
    dict.set("mls_backup.button_regenerate", "Generate a new key");
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
        "mls_backup.confirm_key_label",
        "Re-enter the saved Recovery Key",
    );
    dict.set(
        "mls_backup.confirm_key_placeholder",
        "Type or paste the 24 words you saved",
    );
    dict.set(
        "mls_backup.confirm_key_hint",
        "You can finish only after the saved copy matches exactly. If the copy is wrong, generate a new key and save that one instead.",
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
    dict.set(
        "mls_backup.status.confirm_mismatch",
        "The entered words do not match this Recovery Key. Check your saved copy, or generate a new key and save that one instead.",
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
    dict.set(
        "settings.mls_keypackages.refill_description",
        "If invitations cannot reach this device, publish one bounded batch of fresh MLS KeyPackages.",
    );
    dict.set(
        "settings.mls_keypackages.refill_button",
        "Check and replenish KeyPackages",
    );
    dict.set(
        "settings.mls_keypackages.refill_busy",
        "Checking the local MLS KeyPackage inventory…",
    );
    dict.set(
        "settings.mls_keypackages.refill_done",
        "KeyPackage maintenance complete; published:",
    );
    dict.set(
        "settings.mls_keypackages.refill_failed",
        "MLS KeyPackage refill failed:",
    );

    // Space-admin view (section labels)
    dict.set("realm_admin.members", "Members");
    dict.set("realm_admin.access", "Access");

    // Chat / Discussion view (panel headers + key buttons; reuse common.* for
    // generic verbs like Save/Cancel/Retry/Edit/Confirm).
    dict.set("chat.discussions_header", "Strand discussions");
    dict.set("chat.users_header", "Users");
    dict.set("chat.settings_header", "Settings");
    dict.set("chat.new_strand", "New Strand");
    dict.set("chat.hide_list", "Hide discussion list");
    dict.set("chat.label.title", "Title");
    dict.set("chat.label.summary", "Summary");
    dict.set("chat.call.voice", "Start voice call");
    dict.set("chat.call.video", "Start video call");
    // T7.2 watch level fast switcher.
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
    dict.set("chat.binding_context.details", "Show service binding");
    // T7.4 E2EE status indicators.
    dict.set("chat.crypto.decrypting", "Decrypting…");
    dict.set("chat.crypto.key_missing", "Key not yet received");
    dict.set(
        "chat.crypto.key_missing_hint",
        "Awaiting a Welcome message or an authorized history source response.",
    );
    dict.set(
        "chat.crypto.needs_verification",
        "Verifying sender identity…",
    );
    // T6: human-readable copy for late-recovery rejections; the raw
    // protocol reason code is only surfaced via the element tooltip.
    dict.set(
        "chat.crypto.late_recovery_rejected",
        "This message can't be recovered — its encryption key was rotated before you joined.",
    );
    dict.set(
        "chat.crypto.undecryptable_generic",
        "This message can't be decrypted on this device.",
    );
    // T7.5 layout polish.
    dict.set("chat.tabs.settings", "Settings");
    dict.set("chat.tabs.members", "Members");
    dict.set("chat.button.create", "Create");
    dict.set("chat.button.reply", "Reply");
    dict.set("moderation.report.action", "Report");
    dict.set("moderation.report.title", "Report message");
    dict.set(
        "moderation.report.help",
        "Choose the reason that best describes the problem. The signed report is submitted to this Realm's moderation process.",
    );
    dict.set("moderation.report.reason", "Reason");
    dict.set("moderation.report.reason.spam", "Spam");
    dict.set("moderation.report.reason.harassment", "Harassment");
    dict.set("moderation.report.reason.hate_speech", "Hate speech");
    dict.set("moderation.report.reason.nsfw", "Sexual content");
    dict.set("moderation.report.reason.illegal", "Illegal content");
    dict.set("moderation.report.reason.misinformation", "Misinformation");
    dict.set("moderation.report.reason.other", "Other");
    dict.set(
        "moderation.report.description",
        "Details (required for Other)",
    );
    dict.set(
        "moderation.report.other_required",
        "Add details for an Other report",
    );
    dict.set("moderation.report.submit", "Submit report");
    dict.set("moderation.report.submitting", "Submitting…");
    dict.set("moderation.report.submitted", "Report submitted");
    dict.set("moderation.report.failed", "Report failed");
    dict.set("chat.button.react", "React");
    dict.set("chat.button.redact", "Redact");
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
    // Message write-status revision counter (edit history).
    dict.set("chat.message.revised", "revised");
    dict.set("chat.message.write_status", "This message has been edited");
    dict.set("chat.message.private_sidecar.label", "Private sidecar");
    dict.set(
        "chat.message.private_sidecar.tooltip",
        "Only you and the eligible Agents in this sidecar can see this message.",
    );
    // Offline send outbox.
    dict.set(
        "chat.outbox.queued_offline",
        "Offline - queued, will send when you reconnect.",
    );
    dict.set(
        "chat.outbox.offline_banner",
        "You're offline. Messages are queued and will send on reconnect.",
    );
    dict.set(
        "chat.outbox.flushing",
        "Back online - sending queued messages...",
    );
    // Message shared pin and holder-private saved item actions.
    dict.set("message.shared_pin", "Pin for everyone");
    dict.set("message.shared_unpin", "Unpin for everyone");
    dict.set("message.shared_pin_pending", "Sharing pin...");
    dict.set("message.shared_unpin_pending", "Removing shared pin...");
    dict.set("message.shared_pinned", "Shared pin updated.");
    dict.set("message.shared_unpinned", "Shared pin removed.");
    dict.set("message.private_save", "Save for me");
    dict.set("message.private_saved", "Saved for me");
    dict.set("pinned_bar.title", "Shared pinned messages");
    dict.set("pinned_bar.scroll_to", "Jump to message");
    // Actor-private Realm list pinning.
    dict.set("realm.pin", "Pin Realm");
    dict.set("realm.unpin", "Unpin Realm");
    dict.set("realm.pinned", "Pinned Realm");
    dict.set("realm.unpinned", "Unpinned Realm");
    dict.set("realm.pin_failed", "Realm pin account-data save failed");
    // Actor-private contact list pinning.
    dict.set("contact.pin", "Pin Contact");
    dict.set("contact.unpin", "Unpin Contact");
    dict.set("contact.pinned", "Pinned Contact");
    dict.set("contact.unpinned", "Unpinned Contact");
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
    // Default titles / actions per notification kind (the model stores these
    // keys; render translates via tr()).
    dict.set("notifications.default_title.invite", "Realm invite");
    dict.set("notifications.default_title.reaction", "New reaction");
    dict.set("notifications.default_title.mention", "You were mentioned");
    dict.set(
        "notifications.default_title.assignment",
        "You were assigned",
    );
    dict.set("notifications.default_title.schedule", "Schedule updated");
    dict.set("notifications.default_title.message", "New message");
    dict.set("notifications.default_action.accept", "Accept");
    dict.set("notifications.default_action.view", "View");
    // Watch-level suppression hints (T4.4).
    dict.set(
        "notifications.watch_hint.not_mentioned",
        "You're not getting notifications for this discussion — change watch level",
    );
    dict.set(
        "notifications.watch_hint.not_participating",
        "You're only being notified about threads you've joined — change watch level",
    );
    dict.set(
        "notifications.watch_hint.limited",
        "Notifications for this discussion are limited by your watch level",
    );
    // Dashboard projection collection labels (helpers return these keys;
    // render translates via tr()).
    dict.set("dashboard.node_kind.realm", "Realm");
    dict.set("dashboard.node_kind.space", "Space");
    dict.set("dashboard.collection.realms_and_spaces", "Realms & Spaces");
    dict.set("dashboard.collection.spaces", "Spaces");
    dict.set("dashboard.collection.realms", "Realms");
    dict.set(
        "dashboard.collection.recent_realms_and_spaces",
        "Recent Realms & Spaces",
    );
    dict.set("dashboard.collection.recent_spaces", "Recent Spaces");
    dict.set("dashboard.collection.recent_realms", "Recent Realms");
    dict.set(
        "dashboard.collection.browse_realm_or_space",
        "Search or join a Realm or Space",
    );
    dict.set(
        "dashboard.collection.browse_space",
        "Search or join a Space",
    );
    dict.set(
        "dashboard.collection.browse_realm",
        "Search or join a Realm",
    );
    dict.set(
        "dashboard.collection.signin_realms_and_spaces",
        "Sign in to load Realms and Spaces",
    );
    dict.set(
        "dashboard.collection.signin_spaces",
        "Sign in to load Spaces",
    );
    dict.set(
        "dashboard.collection.signin_realms",
        "Sign in to load Realms",
    );
    dict.set(
        "dashboard.collection.empty_realms_and_spaces",
        "No Realms or Spaces loaded",
    );
    dict.set("dashboard.collection.empty_spaces", "No Spaces loaded");
    dict.set("dashboard.collection.empty_realms", "No Realms loaded");
    dict.set(
        "dashboard.collection.empty_help_realms_and_spaces",
        "The connected server did not return Realms or Spaces yet.",
    );
    dict.set(
        "dashboard.collection.empty_help_spaces",
        "The connected server did not return Spaces yet.",
    );
    dict.set(
        "dashboard.collection.empty_help_realms",
        "The connected server did not return Realms yet.",
    );

    // Verify Device (device-lifecycle.md §10 Verification Strands: SAS / QR)
    dict.set("verify_device.title", "Device Verification");
    dict.set("verify_device.choose_method", "choose method");
    dict.set("verify_device.qr_code", "QR Code");
    dict.set("verify_device.sas_emoji", "Emoji comparison");
    dict.set("verify_device.qr_section", "QR Verification");
    dict.set("verify_device.qr_section_hint", "scan or display");
    dict.set("verify_device.sas_section", "Emoji verification");
    dict.set("verify_device.sas_section_hint", "emoji comparison");
    dict.set("verify_device.target_device_id", "Target Device ID");
    dict.set(
        "verify_device.target_device_placeholder",
        "Device ID to verify",
    );
    dict.set("verify_device.generate_qr", "Generate QR Data");
    dict.set("verify_device.start_sas", "Start emoji verification");
    dict.set("verify_device.short_auth_string", "Comparison code");
    // SAS strand — plain-language rewrite: no SAS / X25519 jargon in
    // user-facing copy. This panel has no "technical details" affordance,
    // so the jargon is dropped rather than tucked behind one.
    dict.set("verify_device.key_exchange_title", "Key exchange");
    dict.set("verify_device.keypair_ready", "key ready");
    dict.set("verify_device.keypair_missing", "not generated");
    dict.set(
        "verify_device.key_exchange_hint",
        "Generate a fresh one-time key, send the public part to your other device, and paste the other device's public key below. The emoji and digits update as soon as both sides are connected.",
    );
    dict.set("verify_device.generate_keypair", "Generate my key");
    dict.set(
        "verify_device.keypair_generated",
        "Key generated — click Send to share the public part with the other device.",
    );
    dict.set(
        "verify_device.keypair_generate_failed",
        "Could not generate a key: {error}",
    );
    dict.set("verify_device.send_public_key", "Send my public key");
    dict.set("verify_device.generate_first", "Generate a key first.");
    dict.set(
        "verify_device.target_required",
        "Enter the device ID to verify first.",
    );
    dict.set(
        "verify_device.send_failed_signing",
        "Send failed — this device's signing key is unavailable: {error}",
    );
    dict.set(
        "verify_device.send_failed_sign",
        "Send failed — could not sign the key message: {error}",
    );
    dict.set("verify_device.send_failed", "Send failed: {error}");
    dict.set(
        "verify_device.public_key_sent",
        "Public key sent. Waiting for the other device's key.",
    );
    dict.set("verify_device.my_public_key", "My public key: {key}");
    dict.set(
        "verify_device.peer_key_placeholder",
        "Paste the other device's public key",
    );
    dict.set(
        "verify_device.peer_key_autofilled",
        "The other device's public key arrived automatically.",
    );
    dict.set(
        "verify_device.session_started",
        "Verification session started. Generate and exchange keys on both devices to see the real emoji and digits.",
    );
    dict.set(
        "verify_device.compare_hint",
        "Compare these emoji and digits on both devices — they must look identical.",
    );
    dict.set(
        "verify_device.source_secure",
        "Derived from the secure key exchange between both devices.",
    );
    dict.set(
        "verify_device.source_demo_invalid",
        "Placeholder — the other device's key is invalid.",
    );
    dict.set(
        "verify_device.source_demo_waiting",
        "Placeholder — waiting for the other device's key.",
    );
    dict.set(
        "verify_device.match_requires_keys",
        "Both devices' keys are needed first — generate and send your key, then wait for the other device's key.",
    );
    dict.set(
        "verify_device.match_failed_signing",
        "Confirmation failed — this device's signing key is unavailable: {error}",
    );
    dict.set(
        "verify_device.match_failed_sign",
        "Confirmation failed — could not sign the proof: {error}",
    );
    dict.set(
        "verify_device.matched",
        "Codes match for {target}. The confirmation is signed on this device; authorization continues through the pairing flow.",
    );
    dict.set(
        "verify_device.mismatch_aborted",
        "Mismatch — aborted. The new device will not be authorized and will not receive encrypted history.",
    );
    dict.set("verify_device.they_match", "They match");
    dict.set("verify_device.they_dont_match", "They don't match");
    dict.set(
        "verify_device.after_confirm_title",
        "What happens after you confirm",
    );
    dict.set(
        "verify_device.after_confirm_body",
        "The comparison only confirms that you trust the new device's key. The four steps below record that trust in your account, so the device becomes a long-term member and can read encrypted history.",
    );
    dict.set("verify_device.step_authorize", "Authorize device");
    dict.set(
        "verify_device.step_authorize_hint",
        "Add the new device's public key to your authorized set",
    );
    dict.set("verify_device.step_record", "Record acceptance");
    dict.set(
        "verify_device.step_record_hint",
        "Your account's device directory records the authorization",
    );
    dict.set("verify_device.step_rejoin", "Rejoin encrypted groups");
    dict.set(
        "verify_device.step_rejoin_hint",
        "Each space updates its encryption to include the new device",
    );
    dict.set("verify_device.step_sync", "Sync secret storage");
    dict.set(
        "verify_device.step_sync_hint",
        "Fetch the encrypted key backup so past history is readable",
    );
    dict.set(
        "verify_device.after_confirm_note",
        "Sign-in, device authorization, and device verification are three separate steps. Skipping verification leaves you with a short-lived session that cannot decrypt past messages.",
    );

    // A6.4 — keyboard shortcut help overlay.
    dict.set("shortcuts.title", "Keyboard shortcuts");
    dict.set("shortcuts.list.help", "Show this shortcut help");
    dict.set("shortcuts.list.dismiss", "Close any open dialog");
    dict.set("shortcuts.list.palette", "Open command palette");
    dict.set("shortcuts.list.palette_mac", "Open command palette (macOS)");
    dict.set("shortcuts.list.send", "Send the current message");
    dict.set(
        "shortcuts.list.send_alias",
        "Send the current message (alternate binding)",
    );
    // Personal blocklist — every visible string in the settings card is
    // localized; wire values remain untranslated Select values.
    dict.set("settings.privacy.blocklist.title", "Personal blocklist");
    dict.set(
        "settings.privacy.blocklist.description",
        "Blocked targets are hidden from messages and notifications on your devices. Blocks stay private and do not change what other members see.",
    );
    dict.set("settings.privacy.blocklist.empty_title", "Blocklist empty");
    dict.set(
        "settings.privacy.blocklist.empty_body",
        "You haven't blocked anything yet.",
    );
    dict.set("settings.privacy.blocklist.kind.domain", "Domain");
    dict.set("settings.privacy.blocklist.kind.actor", "Person or agent");
    dict.set(
        "settings.privacy.blocklist.applies_summary",
        "Applies to: {surfaces}",
    );
    dict.set(
        "settings.privacy.blocklist.expires_summary",
        "Expires: {expires}",
    );
    dict.set(
        "settings.privacy.blocklist.reason_summary",
        "Reason: {reason}",
    );
    dict.set("settings.privacy.blocklist.unblock", "Unblock");
    dict.set(
        "settings.privacy.blocklist.status.unblocked",
        "Unblocked {target}",
    );
    dict.set("settings.privacy.blocklist.target_type", "Target type");
    dict.set(
        "settings.privacy.blocklist.target.actor",
        "Target account or agent",
    );
    dict.set("settings.privacy.blocklist.target.domain", "Target domain");
    dict.set(
        "settings.privacy.blocklist.invalid.actor",
        "Enter the complete account or agent identity, including its Station.",
    );
    dict.set(
        "settings.privacy.blocklist.invalid.domain",
        "Enter a valid domain, such as example.com.",
    );
    dict.set("settings.privacy.blocklist.applies_to", "Applies to");
    dict.set(
        "settings.privacy.blocklist.applies_required",
        "Select at least one surface to block.",
    );
    dict.set("settings.privacy.blocklist.surface.messages", "Messages");
    dict.set("settings.privacy.blocklist.surface.mentions", "Mentions");
    dict.set("settings.privacy.blocklist.surface.dm", "Direct messages");
    dict.set("settings.privacy.blocklist.surface.calls", "Calls");
    dict.set("settings.privacy.blocklist.surface.contacts", "Contacts");
    dict.set("settings.privacy.blocklist.surface.applets", "Apps");
    dict.set("settings.privacy.blocklist.surface.presence", "Presence");
    dict.set(
        "settings.privacy.blocklist.surface.notifications",
        "Notifications",
    );
    dict.set("settings.privacy.blocklist.surface.directory", "Directory");
    dict.set(
        "settings.privacy.blocklist.reason_optional",
        "Reason (optional)",
    );
    dict.set("settings.privacy.blocklist.no_reason", "No reason");
    dict.set("settings.privacy.blocklist.expires", "Expires");
    dict.set(
        "settings.privacy.blocklist.expiry.never",
        "Never (permanent)",
    );
    dict.set("settings.privacy.blocklist.expiry.1d", "24 hours");
    dict.set("settings.privacy.blocklist.expiry.7d", "7 days");
    dict.set("settings.privacy.blocklist.expiry.30d", "30 days");
    dict.set("settings.privacy.blocklist.block", "Block target");
    dict.set(
        "settings.privacy.blocklist.status.added",
        "Blocked {target}",
    );
    dict.set(
        "settings.privacy.blocklist.status.duplicate",
        "{target} is already blocked",
    );
    // A4b — avatar upload UI keys.
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
    dict.set("settings.account.identity", "Account identity");
    dict.set(
        "settings.account.no_device_session",
        "No authenticated device session",
    );
    dict.set("settings.account.handles", "Handles");
    dict.set("settings.account.current_device", "Current device");
    dict.set("settings.account.copy_did", "Copy DID");
    dict.set("settings.account.copy_handles", "Copy handles");
    dict.set("settings.account.copy_device_id", "Copy device ID");
    dict.set("settings.invite_locator.title", "Invite locator");
    dict.set("settings.invite_locator.expiry", "Expires in 15 min");
    dict.set("settings.invite_locator.issuing", "Issuing secure locator…");
    dict.set(
        "settings.invite_locator.rotating",
        "Rotating secure locator…",
    );
    dict.set(
        "settings.invite_locator.unavailable",
        "Invite locator unavailable",
    );
    dict.set(
        "settings.invite_locator.refresh_failed",
        "Invite locator refresh failed",
    );
    dict.set("settings.invite_locator.qr_aria", "Invite locator QR code");
    dict.set("settings.invite_locator.url_aria", "Invite locator URL");
    dict.set(
        "settings.invite_locator.sign_in",
        "Sign in to show invite locator",
    );
    // A6.1 — global cross-Realm message search.
    dict.set("search.title", "Search messages");
    dict.set("search.placeholder", "Search across all your Realms...");
    dict.set(
        "search.results.empty",
        "Type a query to search across your Realms.",
    );
    dict.set("search.results.loading", "Searching…");
    dict.set("search.results.error", "Search failed");
    dict.set("search.no_results", "No matches found.");
    dict.set("shortcuts.list.search", "Open global message search");
    dict.set("member.block", "Block this user");
    dict.set("member.block_confirm.title", "Block this user?");
    dict.set(
        "member.block_confirm.body",
        "Their messages will be hidden behind a placeholder. You can unblock them anytime from Settings → Privacy.",
    );
    dict.set("member.block_confirm.confirm", "Block");
    dict.set("message.blocked_user", "[Blocked user]");
    dict.set("message.show_anyway", "Show anyway");

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
    // Raw protocol identifiers (did:webvh:, ak.*, schema ids, profile ids)
    // are only shown inside Developer Tools / Diagnostics surfaces.
    dict.set(
        "friendly.identifier.show_technical",
        "Show technical details",
    );
    dict.set(
        "friendly.identifier.hide_technical",
        "Hide technical details",
    );

    // Friendly labels for the security-boundary Realm and container Space split.
    dict.set("friendly.realm", "Realm");
    dict.set(
        "friendly.realm.description",
        "A Realm owns membership, rules, sharing between servers, and encryption for everything inside it.",
    );
    dict.set("friendly.space", "Space");
    dict.set(
        "friendly.space.description",
        "A space groups boards, lists, and sections inside a Realm.",
    );

    // Profile gate (friendly version of ProfileGateNotice).
    dict.set("profile_gate.title", "Feature not available on this server");
    dict.set(
        "profile_gate.body",
        "This server does not yet support the capabilities needed for this view. Try a different server or contact your administrator.",
    );
    dict.set(
        "profile_gate.technical_detail",
        "Write controls for this surface are hidden until /server/describe advertises the matching profile requirements.",
    );
    dict.set("profile_gate.friendly.minimal_client", "Basic client");
    dict.set("profile_gate.friendly.kanban_mvp", "Boards");
    dict.set("profile_gate.friendly.chat_mvp", "Discussions");
    dict.set("profile_gate.friendly.full_client", "Full client");
    dict.set("profile_gate.friendly.e2ee_client", "Encrypted messaging");
    dict.set("profile_gate.friendly.unknown", "Client feature");

    // Developer Tools / Diagnostics entry points used to expose the
    // protocol-level details that used to leak into the main strand.
    dict.set("developer.title", "Developer Tools");
    dict.set("developer.subtitle", "Protocol diagnostics and audit");
    dict.set("developer.section.events", "Raw event log");
    dict.set("developer.section.protocol_version", "Protocol version");
    dict.set(
        "developer.hint",
        "These details are intended for developers and operators. End users do not need to read them.",
    );
    dict.set("developer.profile.required", "Required profile id");

    // R3 spec sync (b47ff6ec) — new error toast strings surfaced by the
    // arkret-spec error code expansion (media binding,
    // agent FSM, handle homograph wire-level enforce, recovery
    // policy). The HTTP error reply carries a stable
    // `code` / `reason` field that the toast layer maps via these
    // keys. zh translations follow in `chinese_translations()`.
    add_r3_error_keys(&mut dict);
    add_generic_error_keys(&mut dict);

    // Contacts UI, invite-receive policy, and the realm "invite from
    // contacts" picker. English is the authoritative default; zh follows
    // in `chinese_translations()`.
    add_contacts_keys(&mut dict);

    // Unified feedback system (toast host + app banner), Wave 0.
    add_feedback_keys(&mut dict);

    // Setup surface (Realm wizard / Space form / overview) and the
    // breadcrumb route labels. zh follows in `chinese_translations()`.
    setup_strings(&mut dict);
    route_label_strings(&mut dict);
    prompt_copy_strings(&mut dict);

    dict
}

/// English strings for the unified feedback surface
/// (`components::feedback` — toast host + app banner). zh follows in
/// `add_feedback_keys_zh`; other locales fall back through the
/// `xx → en → key` chain.
fn add_feedback_keys(dict: &mut TranslationDict) {
    dict.set(
        "feedback.policy_denied",
        "This action isn't allowed by the server's policy.",
    );
    dict.set(
        "feedback.banner_offline",
        "You are offline. Changes will sync once the connection is restored.",
    );
    dict.set("feedback.toast_overflow", "+{count} more");
    dict.set("feedback.copy_detail", "Copy details");
    dict.set("feedback.dismiss", "Dismiss");

    // Wave 1 — operation-feedback toasts (former global status writes).
    dict.set(
        "feedback.account_not_connected",
        "Account is not connected; sign in first",
    );
    dict.set("feedback.contacts_load_failed", "Failed to load contacts");
    dict.set("feedback.realm_leaving", "Leaving Realm: {realm}");
    dict.set("feedback.realm_left", "Left Realm: {realm}");
    dict.set(
        "feedback.realm_leave_failed",
        "Failed to leave Realm {realm}",
    );
    dict.set("feedback.contact_deleting", "Deleting contact: {name}");
    dict.set("feedback.contact_deleted", "Deleted contact: {name}");
    dict.set(
        "feedback.contact_delete_failed",
        "Failed to delete contact {name}",
    );
    dict.set(
        "feedback.direct_open_failed",
        "Could not open the direct conversation",
    );
    dict.set(
        "feedback.directory_search_failed",
        "Directory search failed",
    );
    dict.set(
        "feedback.directory_resolve_failed",
        "Directory resolve failed",
    );
    dict.set(
        "feedback.directory_load_more_failed",
        "Loading more results failed",
    );
    dict.set(
        "feedback.realm_resolved",
        "Realm resolved (join rule: {join_rule})",
    );
    dict.set("feedback.realm_create_failed", "Realm creation failed");
    dict.set("feedback.copied_did", "DID copied");
    dict.set("feedback.copied_handles", "Handles copied");
    dict.set("feedback.copied_device_id", "Device ID copied");
    dict.set("feedback.avatar_updated", "Avatar updated");
    dict.set("feedback.mimi_failed", "MIMI request failed");
    dict.set("feedback.notification_kind_enabled", "{label} enabled");
    dict.set("feedback.notification_kind_muted", "{label} muted");
    dict.set(
        "feedback.override_pick_realm",
        "Pick a Realm before adding an override",
    );
    dict.set("feedback.watch_level_set", "Set {realm} to {level}");
    dict.set("feedback.override_removed", "Removed override for {realm}");
    dict.set(
        "feedback.overrides_cleared",
        "Cleared all per-Realm overrides",
    );
    dict.set("feedback.push_registered", "Push registered: {label}");
    dict.set("feedback.push_register_failed", "Push registration failed");
    dict.set("feedback.push_unregistered", "Push unregistered");
    dict.set("feedback.push_unregister_failed", "Push unregister failed");
    dict.set(
        "feedback.presence_visibility_set",
        "Presence visibility: {visibility}",
    );
    dict.set(
        "feedback.read_receipt_default_send_on",
        "Read receipts: send by default",
    );
    dict.set(
        "feedback.read_receipt_default_send_off",
        "Read receipts: skip by default",
    );
    dict.set(
        "feedback.read_receipt_default_display_on",
        "Read receipts: shown in conversations",
    );
    dict.set(
        "feedback.read_receipt_default_display_off",
        "Read receipts: hidden in conversations",
    );
    dict.set(
        "feedback.read_receipt_override_send",
        "Read receipts for {realm}: send",
    );
    dict.set(
        "feedback.read_receipt_override_skip",
        "Read receipts for {realm}: skip",
    );
    dict.set(
        "feedback.read_receipt_override_inherit",
        "Read receipts for {realm}: inherit default",
    );
    dict.set("feedback.enter_realm_id", "Enter a Realm ID first");
    dict.set(
        "feedback.realm_remark_saved",
        "Realm remark saved: {realm} \u{2192} {name}",
    );
    dict.set(
        "feedback.realm_remark_cleared",
        "Realm remark cleared for {realm}",
    );
    dict.set(
        "feedback.enter_realm_and_name",
        "Enter both a Realm ID and a local name",
    );
    dict.set(
        "feedback.invalid_realm_id",
        "Realm ID must start with ak:realm:",
    );
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
        "Enter the other person's DID or handle to send a friend request. By default contacts can both message you and invite you to groups (just like a regular friend). For tighter control, uncheck options below.",
    );
    dict.set("contacts.new.target_label", "Their DID or handle");
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
    dict.set("contacts.scope.presence", "Presence");
    dict.set("contacts.shared_scopes", "Shared permissions: ");
    dict.set(
        "contacts.scope_update.label",
        "Permissions you grant this contact",
    );
    dict.set("contacts.scope_update.save", "Save permissions");
    dict.set("contacts.scope_update.saving", "Saving permissions…");
    dict.set(
        "contacts.scope_update.empty_hint",
        "Saving an empty set suspends this contact without removing it.",
    );

    // ── ContactRow ────────────────────────────────────────────────────
    dict.set("contacts.state.pending_incoming", "Waiting on you");
    dict.set("contacts.state.pending_outgoing", "Waiting for them");
    dict.set("contacts.state.accepted", "Contact");
    dict.set("contacts.state.rejected", "Declined");
    dict.set("contacts.state.tombstoned", "Removed");
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
    dict.set("contacts.petname.placeholder", "Petname (private)");
    dict.set("contacts.petname.save", "Save petname");
    dict.set("contacts.petname.saved", "Petname saved");
    dict.set("contacts.petname.cleared", "Petname cleared");
    dict.set("contacts.petname.badge", "Petname");
    dict.set("contacts.petname.invalid", "Invalid petname");
    dict.set(
        "contacts.petname.invalid_principal",
        "Invalid Contact principal",
    );
    dict.set(
        "contacts.petname.confusable_warning",
        "Possible Contact impersonation",
    );
    dict.set("contacts.dm.opening", "Opening direct chat…");
    dict.set(
        "contacts.dm.awaiting_founder",
        "Waiting for the other person to set up this chat. It will open automatically.",
    );
    dict.set("contacts.dm.creating", "Setting up the encrypted chat…");
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
        "invite_policy.kind.handle_claim",
        "People who know my handle",
    );
    dict.set("invite_policy.kind.same_station", "Users on my server");
    dict.set(
        "invite_policy.kind.explicit_address",
        "Anyone who knows my address",
    );
    dict.set(
        "invite_policy.explicit_label",
        "How to handle \"anyone who knows my address\"",
    );
    dict.set(
        "invite_policy.handle_label",
        "How to handle invites by handle",
    );
    dict.set(
        "invite_policy.handle_allowed_domains",
        "Allowed handle domains",
    );
    dict.set(
        "invite_policy.handle_blocked_domains",
        "Blocked handle domains",
    );
    dict.set(
        "invite_policy.handle_hint",
        "Publishing your handle makes you discoverable. Empty domain lists mean no extra user-level domain filter; the server may still enforce stricter caps.",
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
        "invite_policy.disclosure_hint",
        "Strangers (low-trust sources) never get a receipt, so you don't reveal whether you're online or accepted the invite.",
    );
    dict.set("invite_policy.server_caps_title", "Server minimums");
    dict.set("invite_policy.server_caps_empty", "No advertised caps.");
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
    dict.set("realm_admin.invite_divider", "Or add by handle");
    dict.set("realm_admin.invite_by_handle", "Add by handle");
    dict.set("realm_admin.invite_handle_opt_in", "Recipient opt-in");
    dict.set(
        "realm_admin.invite_target_label",
        "Handle or invite address",
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
        "The agent's owner approval is missing or out of date. Reconnect the agent's approval, then try again.",
    );
    dict.set(
        "error.agent.approval_already_consumed",
        "This approval nonce was already consumed. Request a fresh approval.",
    );

    // Media binding.
    dict.set(
        "error.call.focus_unavailable_for_client",
        "This call's media connection isn't available in this app. Try again, or leave the call and rejoin.",
    );
    dict.set(
        "error.call.focus_mismatch",
        "The call's connection info is out of sync. Leave and rejoin the call to fix it.",
    );
    dict.set(
        "error.call.unknown_focus_type",
        "This call uses a connection type this app doesn't understand. Update the app to the latest version.",
    );
    dict.set(
        "error.call.token_issuer_unauthorised",
        "The call's access token did not come from this Realm's media service, so the connection was refused.",
    );
    dict.set(
        "error.call.participant_binding_invalid",
        "A participant's call credentials did not pass validation, so they can't join.",
    );
    dict.set(
        "error.call.participant_id_unrecognised",
        "The server reported a participant who isn't in this call. The connection was refused to stay safe.",
    );
    dict.set(
        "error.call.e2ee_key_source_unauthorised",
        "The call's encryption key came from an untrusted source, so it was refused. Keys may only come from the group's own encryption.",
    );
    dict.set(
        "error.call.recording_artifact_pipeline_bypassed",
        "The recording destination isn't a verified Arkret storage location, so recording was refused.",
    );
    dict.set(
        "error.call.transcription_artifact_pipeline_bypassed",
        "The transcript destination isn't a verified Arkret storage location, so transcription was refused.",
    );
    dict.set(
        "error.call.media_service_binding_uncovered",
        "This Realm hasn't approved the call's media service, so joining was refused. Ask an admin to review the call settings.",
    );
    dict.set(
        "error.call.media_plaintext_service_not_authorised",
        "This media service isn't allowed to handle unencrypted media, so the connection was refused.",
    );
    dict.set(
        "error.call.mls_governance_binding_stale",
        "The call's approval record is out of date for the current media policy, so the connection was refused. Rejoin the call to refresh it.",
    );
    dict.set(
        "error.call.desktop_media_unavailable",
        "Desktop calling isn't ready in this build yet. Use the web app to place this call.",
    );
    dict.set(
        "error.invite.live_target_occupied",
        "This person already has a live invite to this Realm, so a second one wasn't created.",
    );

    // Recovery.
    dict.set(
        "error.recovery.witness_revoke_lagging",
        "The recovery helper's removal has not finished syncing yet. Wait a moment, then try again.",
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

/// Generic API-error copy for the user-facing error funnel
/// ([`crate::api_error::display_user_facing`]). These keys cover the common
/// server-failure classes that have no dedicated `error.*` key; every
/// string follows the error formula (what happened + what it means + one
/// next action) and carries no protocol identifiers.
fn add_generic_error_keys(dict: &mut TranslationDict) {
    dict.set(
        "error.generic",
        "Something went wrong while talking to the server. Try again.",
    );
    dict.set(
        "error.network_unavailable",
        "Can't reach the server. Check your connection, then try again.",
    );
    dict.set(
        "error.server_unavailable",
        "The server is unavailable right now. Check the server address, or wait a moment and try again.",
    );
    dict.set(
        "error.session_expired",
        "Your session has expired. Sign in again to continue.",
    );
    dict.set(
        "error.device_not_authorized",
        "This device isn't authorized for that action. Authorize it from a device that's already signed in, then try again.",
    );
    dict.set(
        "error.rate_limited",
        "Too many requests. Wait a moment, then try again.",
    );
    dict.set(
        "error.not_found",
        "The server couldn't find what you were looking for. It may have been moved or deleted. Refresh and try again.",
    );
    dict.set(
        "error.permission_denied",
        "You don't have permission to perform this action. Ask a Realm owner or administrator to review your access.",
    );
    dict.set(
        "error.unsupported_profile",
        "This Realm uses a profile this app or server does not support. Update the unsupported component, then try again.",
    );
    dict.set(
        "error.unsupported_protocol_data",
        "This operation uses a protocol data type this app or server does not support. Update the unsupported component, then try again.",
    );
    dict.set(
        "error.invalid_protocol_data",
        "The server rejected data that does not match the current protocol. Refresh and try again; if it continues, report the problem.",
    );
    dict.set(
        "error.realm_state_conflict",
        "This Realm has an unresolved state conflict affecting this operation. Resolve or repair the conflicting Realm state before trying again.",
    );
}

/// English i18n strings for the 6 Circle reason / error codes
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
        "error.circle.not_archived",
        "Only archived Circles can be restored.",
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
    // CircleScopePicker — default scope option + help text (render site
    // localizes; `CircleScope::label()` stays a static str).
    dict.set("circle.scope.realm_everyone", "Realm (everyone)");
    dict.set(
        "circle.scope.help",
        "Choose a Circle to restrict visibility to a strict subset of Realm members.",
    );

    // Shareable object links.
    dict.set("object_link.open", "Open shared link");
    dict.set("object_link.open_placeholder", "Paste a shared link");
    dict.set("object_link.opening", "Opening link…");
    dict.set(
        "object_link.error.unavailable",
        "This link is unavailable or has expired.",
    );
    dict.set(
        "object_link.error.invalid",
        "This link's format is not recognized.",
    );
}

/// Setup surface: the `ak.realm.create` wizard, the `ak.space.create` form,
/// and the surface-map overview. Split out of [`english_translations`] only
/// to keep that function readable — the keys share the flat `setup.*`
/// namespace like every other dictionary section.
fn setup_strings(dict: &mut TranslationDict) {
    // Realm wizard shell.
    dict.set("setup.new_realm", "New Realm");
    dict.set("setup.create_steps", "Create steps");
    dict.set("setup.step_progress", "{current} / {total}");
    dict.set("setup.state.draft", "Draft not created yet");
    dict.set("setup.state.bootstrap", "Bootstrap state");

    // Wizard steps.
    dict.set("setup.step.basics.label", "Basics");
    dict.set("setup.step.basics.subtitle", "name and intent");
    dict.set("setup.step.boundary.label", "Boundary");
    dict.set("setup.step.boundary.subtitle", "three policy axes");
    dict.set("setup.step.create.label", "Create");
    dict.set("setup.step.create.subtitle", "review and create");
    dict.set("setup.step.done.label", "Done");
    dict.set("setup.step.done.subtitle", "open created Realm");

    // Basics step.
    dict.set("setup.field.realm_title", "Realm title");
    dict.set(
        "setup.field.realm_title_placeholder",
        "Engineering, Research, Design system...",
    );
    dict.set("setup.field.summary", "Summary");
    dict.set(
        "setup.field.realm_summary_placeholder",
        "What this Realm is for.",
    );
    dict.set("setup.field.realm_alias", "Realm alias");
    dict.set("setup.field.realm_alias_placeholder", "engineering");

    // Boundary step.
    dict.set("setup.axis.discoverability", "Discoverability");
    dict.set(
        "setup.axis.discoverability.question",
        "Who can discover that this Realm exists?",
    );
    dict.set(
        "setup.axis.discoverability.unset",
        "Discovery posture is not set.",
    );
    dict.set("setup.axis.join_rule", "Join rule");
    dict.set(
        "setup.axis.join_rule.question",
        "How does a principal become a member?",
    );
    dict.set("setup.axis.join_rule.unset", "Join path is not set.");
    dict.set("setup.axis.history_access", "History access");
    dict.set(
        "setup.axis.history_access.question",
        "What history can new members read?",
    );
    dict.set(
        "setup.axis.history_access.unset",
        "History access is not set.",
    );
    dict.set("setup.axis.encryption", "Encryption");
    dict.set("setup.axis.encryption.question", "Protection");
    dict.set(
        "setup.axis.encryption.unset",
        "Encryption profile is not set.",
    );
    dict.set("setup.axis.encryption.locked", "Locked after creation.");
    dict.set("setup.axis.content_scheme", "Content scheme");
    dict.set(
        "setup.axis.content_scheme.question",
        "Which MLS content scheme should this Realm use?",
    );
    dict.set(
        "setup.axis.content_scheme.unset",
        "Content scheme is not set.",
    );
    dict.set(
        "setup.axis.content_scheme.prejoin_forced",
        "Pre-join history uses content_scheme=mls_exporter_aead_v1.",
    );
    dict.set(
        "setup.axis.content_scheme.capability_only",
        "Capability only — actual delivery still follows History visibility.",
    );
    dict.set("setup.axis.security_class", "Security class");
    dict.set(
        "setup.axis.security_class.question",
        "Posture for federation and audit defaults.",
    );
    dict.set(
        "setup.axis.security_class.unset",
        "Security class is not set.",
    );
    dict.set("setup.axis.federation_policy", "Federation policy");
    dict.set(
        "setup.axis.federation_policy.question",
        "How does this Realm interoperate with other deployments?",
    );
    dict.set(
        "setup.axis.federation_policy.unset",
        "Federation policy is not set.",
    );
    dict.set(
        "setup.axis.federation_policy.high_assurance",
        "High assurance allows only restricted, closed, or quarantine federation.",
    );
    dict.set("setup.axis.hash_profile", "Hash profile");
    dict.set(
        "setup.axis.hash_profile.question",
        "Digest algorithm for canonical hashing.",
    );
    dict.set("setup.axis.hash_profile.unset", "Hash profile is not set.");
    dict.set(
        "setup.boundary.advanced_summary",
        "Advanced (federation policy / hash profile)",
    );

    // Create blockers / progress.
    dict.set(
        "setup.blocker.already_created",
        "Realm created. Continue from the Done step.",
    );
    dict.set("setup.blocker.sign_in", "Sign in before creating a Realm.");
    dict.set(
        "setup.blocker.secure_store",
        "Device signing storage is still starting. Try again in a moment.",
    );
    dict.set(
        "setup.blocker.account_context_unavailable",
        "Active account context is unavailable.",
    );
    dict.set("setup.blocker.creating", "Creating Realm...");
    dict.set(
        "setup.error.session_expired",
        "Session expired. Refresh or sign in again before creating a Realm.",
    );

    // Bootstrap progress breadcrumbs, joined with " · " into the
    // "Bootstrap state" line after a successful create.
    dict.set(
        "setup.progress.accepted",
        "Realm {id} accepted; finishing encrypted setup",
    );
    dict.set("setup.progress.created", "Created {id}");
    dict.set(
        "setup.progress.canonical_policy",
        "canonical policy {discoverability} / {join_rule} / {history_access}",
    );
    dict.set(
        "setup.progress.plaintext_services",
        "Unencrypted services: {count}",
    );
    dict.set(
        "setup.progress.mls_ready_local",
        "Encryption ready on this device",
    );
    dict.set(
        "setup.progress.floor_required",
        "Metadata and content are end-to-end encrypted",
    );
    dict.set(
        "setup.error.signer_not_ready",
        "Your signing key is not ready yet, so the Realm could not be created. Try again in a moment. Details: {error}",
    );
    dict.set("setup.error.create_failed", "create failed: {error}");
    dict.set("setup.error.created_then_failed", "created {id}; {error}");
    dict.set(
        "setup.error.invalid_server_url",
        "invalid server URL: {error}",
    );
    dict.set(
        "setup.error.invalid_default_strand_id",
        "The server accepted an invalid default Strand identifier: {error}",
    );

    // Done step.
    dict.set("setup.done.created_realm", "Created Realm");
    dict.set(
        "setup.done.empty",
        "Create a Realm before opening the next context.",
    );

    // Encrypted-Realm recovery gate.
    dict.set(
        "setup.recovery_gate.aria",
        "Set up recovery before creating an encrypted Realm",
    );
    dict.set("setup.recovery_gate.title", "Set up recovery first");
    dict.set("setup.recovery_gate.badge", "encrypted Realm");
    dict.set(
        "setup.recovery_gate.body",
        "This Realm is end-to-end encrypted. If you lose this device and have no Recovery Key or backup configured, its contents are permanently unrecoverable. Set up your 24-word Recovery Key and back up your keys before creating it.",
    );
    dict.set(
        "setup.recovery_gate.checking",
        "Checking your recovery setup. Please try again in a moment.",
    );

    // Actions.
    dict.set("setup.action.back", "Back");
    dict.set("setup.action.next_boundary", "Next: Boundary");
    dict.set("setup.action.next_create", "Next: Create");
    dict.set("setup.action.create_realm", "Create Realm");
    dict.set("setup.action.finishing", "Finishing setup...");
    dict.set("setup.action.open_realm", "Open Realm");
    dict.set("setup.action.setup_recovery_key", "Set up Recovery Key");

    setup_option_strings(dict);
    setup_policy_hint_strings(dict);
    setup_space_strings(dict);
    setup_overview_strings(dict);
}

/// Labels + hints for the create-form option tables in
/// `views::setup::data`. Key shape is `setup.opt.<axis>.<value>[.hint]`.
fn setup_option_strings(dict: &mut TranslationDict) {
    dict.set("setup.opt.discoverability.public", "Public");
    dict.set(
        "setup.opt.discoverability.public.hint",
        "Findable in Search. Existence and join surface can be broadly disclosed.",
    );
    dict.set("setup.opt.discoverability.listed", "Listed");
    dict.set(
        "setup.opt.discoverability.listed.hint",
        "Visible in Search, but still separate from how people join or what history they see.",
    );
    dict.set("setup.opt.discoverability.restricted", "Restricted");
    dict.set(
        "setup.opt.discoverability.restricted.hint",
        "Directory presence is limited to principals that already satisfy server-side policy.",
    );
    dict.set("setup.opt.discoverability.unlisted", "Unlisted");
    dict.set(
        "setup.opt.discoverability.unlisted.hint",
        "Not browseable in Search. Entry depends on a direct link or explicit reference.",
    );
    dict.set("setup.opt.discoverability.invite_only", "Invite only");
    dict.set(
        "setup.opt.discoverability.invite_only.hint",
        "Existence is disclosed only to specifically invited principals.",
    );
    dict.set("setup.opt.discoverability.secret", "Secret");
    dict.set(
        "setup.opt.discoverability.secret.hint",
        "The Realm should not disclose that it exists to unauthorized viewers.",
    );

    dict.set("setup.opt.join_rule.public", "Public");
    dict.set(
        "setup.opt.join_rule.public.hint",
        "Anyone who can see the Realm can join without a separate approval step.",
    );
    dict.set("setup.opt.join_rule.invite", "Invite");
    dict.set(
        "setup.opt.join_rule.invite.hint",
        "Joining requires a member or admin to grant admission explicitly.",
    );
    dict.set("setup.opt.join_rule.knock", "Knock");
    dict.set(
        "setup.opt.join_rule.knock.hint",
        "Applicants can request entry and wait for review.",
    );
    dict.set("setup.opt.join_rule.restricted", "Restricted");
    dict.set(
        "setup.opt.join_rule.restricted.hint",
        "Joining depends on policy or claims, even if the Realm is discoverable.",
    );

    dict.set("setup.opt.history_access.since_join", "Since joining");
    dict.set(
        "setup.opt.history_access.since_join.hint",
        "A member can recover only history from the start of its current membership incarnation. This terminal value cannot be widened.",
    );
    dict.set(
        "setup.opt.history_access.all_history_for_current_members",
        "All history for current members",
    );
    dict.set(
        "setup.opt.history_access.all_history_for_current_members.hint",
        "Every current member can recover all retained Realm history. The policy may later tighten only to since_join.",
    );

    dict.set("setup.opt.encryption_profile.mls_rfc9420", "Encrypted");
    dict.set(
        "setup.opt.encryption_profile.mls_rfc9420.hint",
        "Recommended. Metadata and content use MLS E2EE.",
    );
    dict.set("setup.opt.encryption_profile.none", "No encryption");
    dict.set(
        "setup.opt.encryption_profile.none.hint",
        "Plaintext is visible to the server. Use only for public Realms.",
    );

    dict.set(
        "setup.opt.content_scheme.mls_exporter_aead_v1",
        "MLS exporter AEAD",
    );
    dict.set(
        "setup.opt.content_scheme.mls_exporter_aead_v1.hint",
        "content_scheme=mls_exporter_aead_v1. New members can be granted history from before they joined. Forward secrecy is per-epoch.",
    );
    dict.set("setup.opt.content_scheme.mls_rfc9420", "MLS PrivateMessage");
    dict.set(
        "setup.opt.content_scheme.mls_rfc9420.hint",
        "content_scheme=mls_rfc9420. Pre-join history can never be shared with late joiners. Per-message forward secrecy.",
    );

    dict.set("setup.opt.security_class.standard", "Standard");
    dict.set(
        "setup.opt.security_class.standard.hint",
        "Default posture. Federation policy can be open or restricted per Realm settings.",
    );
    dict.set("setup.opt.security_class.high_assurance", "High assurance");
    dict.set(
        "setup.opt.security_class.high_assurance.hint",
        "Tightened defaults: federation is forced to restricted/closed/quarantine, audit signals are recorded.",
    );

    dict.set("setup.opt.federation_policy.open", "Open");
    dict.set(
        "setup.opt.federation_policy.open.hint",
        "Any peer can interact. Not allowed when security_class=high_assurance.",
    );
    dict.set("setup.opt.federation_policy.restricted", "Restricted");
    dict.set(
        "setup.opt.federation_policy.restricted.hint",
        "Allow-list of peers (governance / org-vetted). Default for high_assurance.",
    );
    dict.set("setup.opt.federation_policy.closed", "Closed");
    dict.set(
        "setup.opt.federation_policy.closed.hint",
        "No federation at all. Use for fully internal Realms.",
    );
    dict.set("setup.opt.federation_policy.quarantine", "Quarantine");
    dict.set(
        "setup.opt.federation_policy.quarantine.hint",
        "Inbound is accepted but held for review. Outbound is blocked.",
    );

    dict.set("setup.opt.hash_profile.sha256", "SHA-256");
    dict.set(
        "setup.opt.hash_profile.sha256.hint",
        "Default. Interoperable everywhere.",
    );
    dict.set("setup.opt.hash_profile.sha512", "SHA-512");
    dict.set(
        "setup.opt.hash_profile.sha512.hint",
        "Wider digest. Choose only if your deployment policy requires it.",
    );
    dict.set("setup.opt.hash_profile.sha3_256", "SHA3-256");
    dict.set(
        "setup.opt.hash_profile.sha3_256.hint",
        "Keccak family. Use for FIPS-compatible deployments that mandate SHA-3.",
    );
    dict.set("setup.opt.hash_profile.blake3", "BLAKE3");
    dict.set(
        "setup.opt.hash_profile.blake3.hint",
        "Faster on modern CPUs. Use only when all peers support BLAKE3.",
    );

    dict.set("setup.opt.space_kind.space", "Space (generic)");
    dict.set("setup.opt.space_kind.space.hint", "");
    dict.set("setup.opt.space_kind.project", "Project");
    dict.set(
        "setup.opt.space_kind.project.hint",
        "Top-level scope for a piece of work; usually contains boards / lists.",
    );
    dict.set("setup.opt.space_kind.folder", "Folder");
    dict.set(
        "setup.opt.space_kind.folder.hint",
        "Pure navigation container. Holds child Spaces / Strands but isn't a workflow.",
    );
    dict.set("setup.opt.space_kind.board", "Board");
    dict.set(
        "setup.opt.space_kind.board.hint",
        "Kanban / pipeline view. Cells track strand placement (rank cas-register).",
    );
    dict.set("setup.opt.space_kind.list", "List");
    dict.set(
        "setup.opt.space_kind.list.hint",
        "Ordered list view. Useful for backlog / triage / queue surfaces.",
    );
}

/// Cross-axis policy warnings emitted by `views::setup::helpers`.
fn setup_policy_hint_strings(dict: &mut TranslationDict) {
    dict.set("setup.policy_hint.secret_conflict", "Combination invalid");
    dict.set(
        "setup.policy_hint.secret_conflict.body",
        "A secret Space cannot also advertise public admission or world-readable history.",
    );
    dict.set(
        "setup.policy_hint.invite_public",
        "Combination is contradictory",
    );
    dict.set(
        "setup.policy_hint.invite_public.body",
        "Invite-only discovery paired with public join usually means the discovery model is underspecified.",
    );
    dict.set(
        "setup.content_scheme.prejoin_requires_exporter",
        "Pre-join history requires content_scheme=mls_exporter_aead_v1.",
    );
}

/// `ak.space.create` form + Space lifecycle actions.
fn setup_space_strings(dict: &mut TranslationDict) {
    dict.set("setup.space.new_space", "New Space");
    dict.set("setup.space.parent.root", "(root — no parent)");
    dict.set("setup.space.default_realm.label", "default_realm_id");
    dict.set(
        "setup.space.default_realm.inherit",
        "(inherit — use home Realm)",
    );
    dict.set("setup.space.not_created", "not created yet");
    dict.set(
        "setup.space.wire_shape.body",
        "ak.space.create event + optional parent_space_id / default_realm_id. Lifecycle actions below dispatch ak.space.archive / restore / tombstone.",
    );
    dict.set(
        "setup.space.lifecycle.hint",
        "archive / restore / tombstone",
    );
    dict.set(
        "setup.space.error.create_failed",
        "create_space failed: {error}",
    );
    dict.set(
        "setup.space.error.archive_failed",
        "archive failed: {error}",
    );
    dict.set(
        "setup.space.error.restore_failed",
        "restore failed: {error}",
    );
    dict.set(
        "setup.space.error.tombstone_failed",
        "tombstone failed: {error}",
    );
    dict.set(
        "setup.space.error.invalid_base_url",
        "invalid base URL: {error}",
    );
    dict.set("setup.space.field.title", "Space title");
    dict.set(
        "setup.space.field.title_placeholder",
        "Backlog, Roadmap, Onboarding...",
    );
    dict.set("setup.space.field.kind", "Kind");
    dict.set(
        "setup.space.field.summary_placeholder",
        "Optional description.",
    );
    dict.set("setup.space.field.parent", "Parent Space (optional)");
    dict.set(
        "setup.space.parent.no_realm",
        "Choose New Space from a Realm or Space row in the sidebar to set the home Realm.",
    );
    dict.set(
        "setup.space.parent.no_siblings",
        "No sibling Spaces in this Realm yet — leave at root.",
    );
    dict.set(
        "setup.space.advanced_summary",
        "Advanced (cross-Realm default for new resources)",
    );
    dict.set(
        "setup.space.default_realm.empty",
        "Need at least one Realm to point at.",
    );
    dict.set(
        "setup.space.default_realm.hint",
        "New Strands / Morphs / Views created from this Space land in this Realm by default. Doesn't grant access — the user still needs membership.",
    );
    dict.set("setup.space.action.create", "Create Space");
    dict.set("setup.space.outcome", "Outcome");
    dict.set("setup.space.outcome.hint", "Space create");
    dict.set("setup.space.created", "Created Space");
    dict.set("setup.space.status", "Status");
    dict.set("setup.space.wire_shape", "Wire shape");
    dict.set("setup.space.lifecycle", "Lifecycle actions");
    dict.set(
        "setup.space.lifecycle.empty",
        "Create a Space above to enable lifecycle actions on it.",
    );
    dict.set("setup.space.action.archive", "Archive");
    dict.set(
        "setup.space.action.archive.title",
        "Set state to archived; server doesn't cascade.",
    );
    dict.set("setup.space.action.restore", "Restore");
    dict.set(
        "setup.space.action.restore.title",
        "Move archived → active; only valid from archived.",
    );
    dict.set("setup.space.action.tombstone", "Tombstone");
    dict.set(
        "setup.space.action.tombstone.title",
        "Irreversible. Server rejects if live child Spaces / placement Strands exist.",
    );
    dict.set(
        "setup.space.tombstone_warning",
        "Tombstone is irreversible — server rejects with space_has_live_dependents if any child Space or placement Strand is still live (spec §3.4).",
    );
    dict.set(
        "setup.space.state.submitting_create",
        "Submitting ak.space.create...",
    );
    dict.set(
        "setup.space.state.submitting_archive",
        "Submitting ak.space.archive...",
    );
    dict.set(
        "setup.space.state.submitting_restore",
        "Submitting ak.space.restore...",
    );
    dict.set(
        "setup.space.state.submitting_tombstone",
        "Submitting ak.space.tombstone...",
    );
    dict.set(
        "setup.space.state.created",
        "Created Space {id} (kind={kind}) inside {realm}{parent}",
    );
    dict.set("setup.space.state.archived", "Archived {id}");
    dict.set("setup.space.state.restored", "Restored {id}");
    dict.set(
        "setup.space.state.tombstoned",
        "Tombstoned {id} (irreversible)",
    );
}

/// Setup surface map (the overview section).
fn setup_overview_strings(dict: &mut TranslationDict) {
    dict.set("setup.overview.surfaces", "Setup Surfaces");
    dict.set("setup.overview.surfaces.hint", "single-purpose entrypoints");
    dict.set("setup.overview.realm.hint", "security-boundary bootstrap");
    dict.set("setup.overview.realm.open", "Open New Realm");
    dict.set(
        "setup.overview.space.hint",
        "navigation container inside a Realm",
    );
    dict.set(
        "setup.overview.space.body",
        "Hover a Realm or Space in the left sidebar and click the inline + — that's the canonical entry, because it pre-fills the parent context for you. The link below opens the form blank (you'll have to pick a Realm manually).",
    );
    dict.set("setup.overview.space.open", "Open blank form");
    dict.set("setup.overview.onboarding", "Onboarding");
    dict.set("setup.overview.onboarding.hint", "identity bootstrap");
    dict.set("setup.overview.onboarding.open", "Open Onboarding");
    dict.set("setup.overview.search", "Search");
    dict.set("setup.overview.search.hint", "actors / handles / Realms");
    dict.set("setup.overview.search.open", "Open Search");
    dict.set("setup.overview.board", "Board");
    dict.set("setup.overview.board.hint", "after bootstrap");
    dict.set("setup.overview.board.open_current", "Open Current Realm");
    dict.set("setup.overview.board.open", "Open Board");
    dict.set("setup.overview.moved", "What Moved");
    dict.set("setup.overview.moved.hint", "IA cleanup");
    dict.set(
        "setup.overview.badge.onboarding",
        "Onboarding = identity bootstrap",
    );
    dict.set(
        "setup.overview.badge.search",
        "Search = discovery and people",
    );
    dict.set(
        "setup.overview.badge.realm",
        "New Realm = security-boundary bootstrap",
    );
    dict.set(
        "setup.overview.badge.settings",
        "Settings = recovery and operations",
    );
}

/// Breadcrumb / context-bar labels resolved by `app::feature_gate`.
fn route_label_strings(dict: &mut TranslationDict) {
    dict.set("route.dashboard", "Home");
    dict.set("route.login", "Login");
    dict.set("route.register", "Create identity");
    dict.set("route.realms_manage", "Manage Realms");
    dict.set("route.principal_control", "Principal Control");
    dict.set("route.realm", "Realm");
    dict.set("route.chat", "Discussion");
    dict.set("route.direct", "Direct");
    dict.set("route.contacts_manage", "Manage Contacts");
    dict.set("route.contacts", "Contacts");
    dict.set("route.files", "Files");
    dict.set("route.directory", "Search");
    dict.set("route.setup", "Setup");
    dict.set("route.setup_realms", "New Realm");
    dict.set("route.setup_new_space", "New Space");
    dict.set("route.settings", "Settings");
    dict.set("route.notifications", "Notifications");
    dict.set("route.verify_device", "Verify Device");
    dict.set("route.realm_members", "Members");
    dict.set("route.circles", "Circles");
    dict.set("route.realm_admin", "Realm Settings");
    dict.set("route.realm_admin.profile", "Profile");
    dict.set("route.realm_admin.access", "Access Policy");
    dict.set("route.realm_admin.security", "Security & MLS");
    dict.set("route.realm_admin.federation", "Federation Trust");
    dict.set("route.realm_admin.repair", "Repair & Danger");
    dict.set("route.audit", "Audit log");
    dict.set("route.developer", "Developer tools");
    dict.set("route.board", "Board View");
    dict.set("route.call", "Call");
    dict.set("route.recovery", "Recovery");
    dict.set("route.devices", "Devices");
    dict.set("route.devices_pair", "Add a device");
    dict.set("route.onboarding", "Onboarding");
    dict.set("route.quarantine", "Pending Review");
    dict.set("route.applets", "Applets");

    dict.set("route.settings.server", "Account & server");
    dict.set("route.settings.storage", "Data & sync");
    dict.set("route.settings.encryption", "Security");
    dict.set("route.settings.mimi", "Integrations");
    dict.set("route.settings.privacy", "Privacy & sharing");
    dict.set("route.settings.invite_policy", "Who can invite me");
    dict.set("route.settings.blocklist", "Blocked actors");
    dict.set("route.settings.capabilities", "Capabilities");
    dict.set("route.settings.theme", "Appearance & locale");
    dict.set("route.settings.release", "Diagnostics");
}

/// Plain-language copy for the inline prompts, banners, and manage
/// pages migrated off hardcoded literals. Keep both locales in this
/// same list shape: every key gets an en value here and a zh value in
/// `zh.rs`'s `prompt_copy_strings`, and the parity test enforces it.
fn prompt_copy_strings(dict: &mut TranslationDict) {
    dict.set("did_health.label.degraded", "Limited");
    dict.set("did_health.label.stale_cache", "Outdated cache");
    dict.set("did_health.label.metadata", "Metadata");
    dict.set("did_health.label.outage", "Offline");
    dict.set("did_health.label.server_metadata", "Server metadata");
    dict.set("did_health.title.degraded", "Identity checks are limited");
    dict.set(
        "did_health.title.metadata_mismatch",
        "Identity info format mismatch",
    );
    dict.set(
        "did_health.title.unavailable",
        "Identity checks are offline",
    );
    dict.set(
        "did_health.title.service_unavailable",
        "Identity service unavailable",
    );
    dict.set("did_health.detail.fresh_cache", "Identity checks are offline right now; showing recently confirmed information for display only.");
    dict.set("did_health.detail.stale_cache", "Identity checks are offline right now, and the saved information is out of date. Actions that need trust are paused.");
    dict.set("did_health.detail.metadata_mismatch", "The identity service did not provide the expected information format. Actions that need trust remain paused.");
    dict.set(
        "did_health.detail.partial",
        "Some identity checks are unavailable right now. Actions that need trust remain paused.",
    );
    dict.set("did_health.detail.no_cache", "Identity checks are offline and no saved information is available. Actions that need trust are paused.");
    dict.set("did_health.detail.server_metadata", "This server did not provide the expected identity metadata, so identity checks are blocked.");
    dict.set(
        "did_health.detail.blocked",
        "Identity checks are blocked until the service recovers.",
    );
    dict.set(
        "recovery_setup.err_requires_account",
        "Sign in before setting up a recovery key.",
    );
    dict.set(
        "recovery_setup.err_generation_failed",
        "The recovery key couldn't be generated ({error}). Try again.",
    );
    dict.set(
        "recovery_setup.status_after_generate",
        "Write the 24 words down offline, then re-enter them. Nothing has been published yet.",
    );
    dict.set("recovery_setup.generating", "Generating recovery key…");
    dict.set(
        "recovery_setup.generating_replacement",
        "Generating a new recovery key…",
    );
    dict.set(
        "recovery_setup.save_first_guard",
        "Save these 24 words first, then confirm them below.",
    );
    dict.set("recovery_setup.aria_label", "Set up your recovery key");
    dict.set(
        "recovery_setup.title",
        "Set up your recovery key (24 words)",
    );
    dict.set("recovery_setup.subtitle", "Required before encryption");
    dict.set("recovery_setup.device_unauthorized", "This device isn't authorized to save recovery data yet. The words stay on this screen only. Authorize this device and try again with the same words, or restore with your existing recovery key.");
    dict.set("recovery_setup.intro", "Generate 24 words here and write them down somewhere safe offline, then continue to encrypted Realms. Arkret cannot recover these words for you.");
    dict.set(
        "recovery_setup.generated_key_label",
        "Recovery key (24 words)",
    );
    dict.set("recovery_setup.copied", "Copied");
    dict.set("recovery_setup.copy_words", "Copy words");
    dict.set("recovery_setup.download", "Download .txt");
    dict.set("recovery_setup.save_warning", "Save these words now. They are never uploaded, and won't be shown again once you close this window.");
    dict.set(
        "recovery_setup.confirm_label",
        "Re-enter the saved recovery key",
    );
    dict.set(
        "recovery_setup.confirm_placeholder",
        "Type or paste the 24 words you saved",
    );
    dict.set("recovery_setup.confirm_hint", "You can continue only when the words match exactly. If they're wrong, generate a new key and save that one instead.");
    dict.set(
        "recovery_setup.restore_button",
        "Restore with existing recovery key",
    );
    dict.set("recovery_setup.close", "Close");
    dict.set("recovery_setup.try_again", "Try again");
    dict.set("recovery_setup.generating_button", "Generating…");
    dict.set("recovery_setup.not_now", "Not now");
    dict.set("recovery_setup.regenerate", "Generate a new key");
    dict.set(
        "recovery_setup.close_unpublished",
        "Close without publishing",
    );
    dict.set(
        "recovery_setup.err_word_count",
        "You entered {entered} of 24 words. Complete the phrase, then confirm again.",
    );
    dict.set(
        "recovery_setup.err_word_mismatch",
        "Word {index} does not match this recovery key. Fix it and confirm again.",
    );
    dict.set(
        "recovery_setup.publishing",
        "Saved copy confirmed. Publishing your recovery settings and first encrypted backup…",
    );
    dict.set(
        "recovery_setup.metadata_save_failed",
        "Recovery was set up, but local details couldn't be saved on this device.",
    );
    dict.set("recovery_setup.confirm_button", "Confirm saved key");
    // identity-handles.md §3.8.2 step 5 — every fallback rung MUST be
    // visually marked so a degraded label never looks like a resolved one.
    dict.set("identity.tier.cached", "Cached name");
    dict.set(
        "identity.tier.cached_detail",
        "Shown from a saved copy. We could not re-check this name just now.",
    );
    dict.set("identity.tier.name_only", "Unverified name");
    dict.set(
        "identity.tier.name_only_detail",
        "This is the name captured earlier, not a checked one.",
    );
    dict.set("identity.tier.unresolved", "Name unavailable");
    dict.set(
        "identity.tier.unresolved_detail",
        "We could not look up a name for this account, so the account id is shown.",
    );
    dict.set("settings.devices.title", "Device access");
    dict.set(
        "settings.devices.subtitle",
        "Review trusted devices or approve another one.",
    );
    dict.set("settings.devices.help", "Manage the devices bound to your account. Revoking a device removes it from the active set and triggers MLS leaf removal in any E2EE Realm the device participates in.");
    dict.set("settings.devices.tabs_aria_label", "Device settings");
    dict.set("settings.devices.tab_list", "Devices");
    dict.set("settings.devices.tab_add", "Add a device");
    dict.set("settings.devices.refresh", "Refresh");
    dict.set("settings.devices.active_title", "Active devices");
    dict.set("settings.devices.empty_title", "No devices loaded yet");
    dict.set(
        "settings.devices.empty_message",
        "Loading your devices… or click Refresh to retry.",
    );
    dict.set("settings.devices.column_device", "Device");
    dict.set("settings.devices.column_verification", "Verification");
    dict.set("settings.devices.column_authorized", "Authorized");
    dict.set("settings.devices.column_actions", "Actions");
    dict.set("settings.devices.this_device", "this device");
    dict.set("settings.devices.state_verified", "Verified");
    dict.set("settings.devices.state_unverified", "Unverified");
    dict.set("settings.devices.state_revoked", "Revoked");
    dict.set(
        "settings.devices.state_title",
        "Device verification state: {state}",
    );
    dict.set("settings.devices.revoke_title", "Revoke device");
    dict.set(
        "settings.devices.revoke_recovery_label",
        "Recovery Key (24 words)",
    );
    dict.set(
        "settings.devices.revoke_recovery_placeholder",
        "Your 24-word Recovery Key — required to rotate encrypted history backups",
    );
    dict.set("settings.devices.revoke_confirm", "Confirm revoke");
    dict.set("settings.devices.pair_this_browser", "This browser");
    dict.set("settings.devices.pair_title", "Approve this device");
    dict.set("settings.devices.pair_required_badge", "Approval required");
    dict.set("settings.devices.pair_body", "Generate a pairing QR code or link, then scan or open it on an already-authorized device. No automatic account notification is sent.");
    dict.set("settings.devices.pair_hide_link", "Hide link");
    dict.set(
        "settings.devices.pair_qr_aria_label",
        "Device approval QR code",
    );
    dict.set(
        "settings.devices.pair_link_aria_label",
        "Device approval link",
    );
    dict.set("settings.devices.accept_title", "Approve using a link");
    dict.set(
        "settings.devices.accept_body",
        "Use this fallback on an authorized device when no confirmation prompt appears.",
    );
    dict.set(
        "settings.devices.accept_placeholder",
        "Paste the pairing link (…/device-pairing/resolve#token=…) or the token",
    );
    dict.set("settings.devices.session_active", "Signed in");
    dict.set("settings.devices.session_inactive", "Not signed in");
    dict.set("settings.devices.revoke_self_blocked", "Cannot self-revoke");
    dict.set("settings.devices.revoke", "Revoke");
    dict.set("settings.devices.revoke_body_before", "This will write ");
    dict.set("settings.devices.revoke_body_after", " to your principal control Realm, remove the device from any E2EE Realm it participates in, and rotate the account MLS history secret. The action cannot be undone.");
    dict.set("settings.devices.pair_requesting", "Requesting…");
    dict.set("settings.devices.pair_request", "Request approval");
    dict.set("settings.devices.pair_checking", "Checking…");
    dict.set("settings.devices.pair_check", "Check approval");
    dict.set("settings.devices.accept_resolving", "Resolving…");
    dict.set("settings.devices.accept_resolve", "Resolve link");
    dict.set(
        "settings.devices.accept_rejected",
        "Pairing request dismissed. Nothing was approved.",
    );
    dict.set("settings.devices.accept_device_name", "Device name");
    dict.set("settings.devices.accept_device_id", "Device id");
    dict.set("settings.devices.accept_key_fingerprint", "Key fingerprint");
    dict.set(
        "settings.devices.accept_gate_audience",
        "Approving account server",
    );
    dict.set("settings.devices.accept_unnamed_device", "Not provided");
    dict.set("settings.devices.revoke_threat_note", "Revoking is not a remote wipe. It cannot erase secrets or cached history already copied onto that device. Treat a lost or stolen device as able to read anything it kept before you revoked it.");
    dict.set("audit.title", "Audit log");
    dict.set("audit.help", "Some Realms record every read, others record every write. This view is read-only and shows only what this device has already seen.");
    dict.set("audit.access_events", "Reads recorded");
    dict.set(
        "audit.access_events_hint",
        "Recorded when a Realm logs every read",
    );
    dict.set("audit.write_receipts", "Writes recorded");
    dict.set(
        "audit.write_receipts_hint",
        "Recorded when a Realm logs every write",
    );
    dict.set("audit.total_observed", "Total seen here");
    dict.set(
        "audit.total_observed_hint",
        "Only what this device has synced so far",
    );
    dict.set("audit.empty_title", "No audit records yet");
    dict.set("audit.empty_message", "Nothing has been recorded yet. Records appear only for Realms whose settings ask for them.");
    dict.set("quarantine.title", "Pending review");
    dict.set("quarantine.status", "Items waiting for your decision are stored privately for you. Review controls appear once the consent flow is available.");
    dict.set("quarantine.invite_delivery_title", "Invitations");
    dict.set(
        "quarantine.invite_delivery_hint",
        "Someone invited you to a Realm. Accepting builds a consent grant; you may still decide about the invitation itself separately.",
    );
    dict.set(
        "quarantine.consent_request_title",
        "Contact permission requests",
    );
    dict.set(
        "quarantine.consent_request_hint",
        "Someone asked for your permission to reach you. Accepting builds a consent grant and nothing else; they retry on their own afterwards.",
    );
    dict.set("quarantine.empty", "Nothing is waiting for your decision.");
    dict.set("quarantine.scope_label", "Requested for");
    dict.set(
        "consent.grant.grantee_station_label",
        "Grantee Station DID (blank = this Station)",
    );
    dict.set("quarantine.expires_label", "Discarded after");
    dict.set("theme.switcher_aria_label", "Theme");
    dict.set("common.delete", "Delete");
    dict.set("app.boot.opening_secure_storage", "Opening secure storage");
    dict.set(
        "app.boot.loading_keys",
        "Loading encrypted account and device keys…",
    );
    dict.set(
        "app.recovery.incomplete_title",
        "Recovery setup is incomplete",
    );
    dict.set("app.recovery.incomplete_body", "Generate your Recovery Key (24 words) before relying on this account. Backups are stored server-side as ciphertext only; Arkret cannot recover the 24 words for you.");
    dict.set("app.recovery.configure", "Configure recovery");
    dict.set("app.recovery.history_status", "Encrypted history status");
    dict.set("app.recovery.history_status_body", "Encrypted-history recovery needs an account MLS secret; if this is a brand-new account, the app will prompt again after your first encrypted write creates material that can be backed up.");
    dict.set("app.nav.close_menu", "Close menu");
    dict.set("app.nav.open_menu", "Open menu");
    dict.set("app.nav.main_navigation", "Main navigation");
    dict.set("app.nav.resize_menu", "Drag to resize menu");
    dict.set("app.nav.scope_toggle", "Collaboration and contacts");
    dict.set("app.nav.show_navigation", "Show navigation");
    dict.set("app.nav.hide_navigation", "Hide navigation");
    dict.set("app.brand.home", "Inkson | Arkret Home");
    dict.set("app.main_content", "Main content");
    dict.set("app.sidebar.hide_own_agents", "Hide your AI agents");
    dict.set("app.sidebar.show_own_agents", "Show your AI agents");
    dict.set("app.sidebar.opening", "Opening...");
    dict.set("app.sidebar.agent_badge", "AI agent");
    dict.set("app.sidebar.remark", "Remark");
    dict.set(
        "app.sidebar.remark_title",
        "Local remark (private to this account)",
    );
    dict.set("app.sidebar.direct_badge", "DM");
    dict.set("app.sidebar.agent_count", "Agents {count}");
    dict.set("app.sidebar.contact_actions", "Contact actions");
    dict.set("app.sidebar.close_row_actions", "Close row actions");
    dict.set("app.sidebar.delete_contact", "Delete Contact");
    dict.set("app.topbar.current_view", "Current view: {surface}");
    dict.set("app.topbar.open_global_search", "Open global search");
    dict.set("app.account.open_settings", "Open settings");
    dict.set("app.account.did", "DID");
    dict.set("app.account.server", "Server");
    dict.set("app.account.refresh_session", "Refresh session");
    dict.set("app.account.log_out", "Log out");
    dict.set("theme.switch_to_light", "Switch to light theme");
    dict.set("theme.switch_to_night", "Switch to night theme");
    dict.set("account.not_signed_in", "Not signed in");
    dict.set(
        "account.refresh_then_sign_in",
        "Refresh server metadata, then sign in",
    );
    dict.set("visibility.pill_title", "Who can find and see this");
    dict.set("moderation.workbench_aria_label", "Moderation decisions");
    dict.set("moderation.decide_title", "Record a decision");
    dict.set("moderation.decide_badge", "Decision");
    dict.set(
        "moderation.target_placeholder",
        "What this decision applies to",
    );
    dict.set("moderation.decide_submit", "Record decision");
    dict.set("moderation.standing_title", "Decisions in force");
    dict.set(
        "moderation.standing_empty",
        "No decisions are in force on this device yet.",
    );
    dict.set(
        "moderation.decision_row_summary",
        "Applies to {target} — {reason}",
    );
    dict.set("moderation.lift", "Lift decision");
    dict.set(
        "device_pair.aria_label",
        "A new device is requesting access to your account",
    );
    dict.set("device_pair.title", "New device wants to join your account");
    dict.set("device_pair.subtitle", "Device pairing");
    dict.set("device_pair.body", "A device is asking to be added to your account. Approve it only if you started this — compare the code below on both devices first.");
    dict.set("device_pair.platform", "Platform: {platform}");
    dict.set("device_pair.expires", "Request expires {time}");
    dict.set(
        "device_pair.compare_code",
        "Compare this code on both devices",
    );
    dict.set("device_pair.approving", "Approving…");
    dict.set(
        "device_pair.err_approval_failed",
        "Couldn't approve the device: {error}",
    );
    dict.set("device_pair.reject", "Reject");
    dict.set("device_pair.approve", "Approve");
    dict.set(
        "agent_runtime.aria_label",
        "An agent runtime is requesting access to your account",
    );
    dict.set("agent_runtime.title", "Agent runtime approval requested");
    dict.set("agent_runtime.subtitle", "Agent pairing");
    dict.set("agent_runtime.body", "An agent runtime is asking to finish pairing. Approve only if you started this request and the code matches the runtime screen.");
    dict.set(
        "agent_runtime.replacement_warning",
        "This replaces the runtime key of an active or paused agent.",
    );
    dict.set("agent_runtime.slug", "Slug: {slug}");
    dict.set("agent_runtime.requested", "Requested {time}");
    dict.set(
        "agent_runtime.compare_code",
        "Compare this code before approving",
    );
    dict.set("agent_runtime.runtime_key", "Runtime key");
    dict.set("agent_runtime.proof_expires", "Proof expires {time}");
    dict.set(
        "agent_runtime.rejecting",
        "Rejecting request and rotating the pairing code…",
    );
    dict.set(
        "agent_runtime.rejected",
        "Request rejected and pairing code rotated.",
    );
    dict.set(
        "agent_runtime.err_rotate_failed",
        "Couldn't rotate the pairing code. {error}",
    );
    dict.set("agent_runtime.reject_rotate", "Reject and rotate code");
    dict.set("agent_runtime.dismiss", "Dismiss");
    dict.set("agent_runtime.err_no_account", "Sign in before approving.");
    dict.set(
        "agent_runtime.err_invalid_request",
        "The runtime key request is invalid. {error}",
    );
    dict.set("agent_runtime.approving", "Approving agent runtime…");
    dict.set(
        "agent_runtime.approved_refresh_failed",
        "Runtime key approved ({id}). Couldn't refresh the agent's recovery backup: {error}",
    );
    dict.set(
        "agent_runtime.approved_current",
        "Runtime key approved ({id}). The agent's recovery backup is up to date.",
    );
    dict.set(
        "agent_runtime.err_approval_failed",
        "Couldn't approve the runtime key. {error}",
    );
    dict.set("agent_runtime.approving_button", "Approving…");
    dict.set("agent_runtime.approve", "Approve");
    dict.set("manage.realms_title", "Manage Realms");
    dict.set("manage.principal_control_button", "PCR");
    dict.set(
        "manage.principal_control_subtitle",
        "System identity and device authority. It is separate from collaboration Realms.",
    );
    dict.set("manage.principal_control_purpose_label", "Purpose");
    dict.set(
        "manage.principal_control_purpose_value",
        "Identity, device authorization, and recovery control",
    );
    dict.set("manage.principal_control_realm_id", "Realm ID");
    dict.set(
        "manage.principal_control_no_business_surfaces",
        "This control-plane Realm does not provide Boards, Spaces, discussions, members, or other business surfaces.",
    );
    dict.set(
        "manage.principal_control_unavailable",
        "The accepted Principal Control Realm has not arrived in the local projection yet.",
    );
    dict.set("manage.back_to_realms", "Back to Realm management");
    dict.set(
        "manage.realms_empty_hint",
        "Realms will appear here once sync finishes.",
    );
    dict.set(
        "manage.no_results_hint",
        "Try a different search to see more.",
    );
    dict.set("manage.row_encrypted", "Encrypted");
    dict.set("manage.row_unencrypted", "Unencrypted");
    dict.set("manage.row_spaces", "{count} spaces");
    dict.set("manage.contacts_title", "Manage contacts");
    dict.set("manage.search_contacts", "Search contacts");
    dict.set(
        "manage.contacts_empty_hint",
        "Your contacts appear here once loading finishes.",
    );
    dict.set("manage.contacts_no_results", "No matching contacts");
    dict.set("manage.contact_no_scopes", "No shared scopes");
    dict.set("manage.contact_dm", "DM {state}");
    dict.set("manage.contact_no_dm", "No DM");
}
