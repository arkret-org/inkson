//! English (`en`) translation dictionary plus its private helper
//! string sets. `english_translations` is the authoritative reference
//! locale; helpers live alongside it so all `dict.set` calls stay in one
//! module.

use super::{Locale, TranslationDict};

/// Build the default English translation dictionary.
pub fn english_translations() -> TranslationDict {
    let mut dict = TranslationDict::new(Locale::En);

    // Navigation & Shell
    dict.set("app.title", "inkson");
    dict.set("nav.dashboard", "Home");
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

    // AKP-0007 Circle error keys (P3B.3.2)
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
    dict.set("login.session_credential", "Session Credential");
    dict.set("login.re_login", "Re-Login");
    dict.set(
        "login.session_expired",
        "Your session has expired. Log in again to continue.",
    );

    dict.set("message.redacted", "[Message redacted]");

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

    // Settings navigation — section labels (design/settings-ia-reorg.md §3.1).
    // Terminology humanised: TSP connections → External connections,
    // Capabilities → App authorizations, Blocked actors → Block list,
    // Consent → Invites & consent, Diagnostics → Release status.
    dict.set("settings.section.account", "Account information");
    dict.set("settings.section.agents", "My Agents");
    dict.set("settings.section.server", "Server information");
    dict.set("settings.section.devices", "Devices");
    dict.set("settings.section.storage", "Data & sync");
    dict.set("settings.section.encryption", "Security");
    dict.set("settings.section.recovery", "Recovery");
    dict.set("settings.section.mimi", "Integrations");
    dict.set("settings.section.connections", "External connections");
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
    dict.set("settings.search.no_results", "No matching settings");

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
        "Use an invite locator link for highest trust, or enter a handle / DID + server DID when the recipient allows discovery.",
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
    dict.set("kanban.rename_list_hint", "Double-click to rename");
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
        "Grant or revoke ak.realm.admin authority. Authored as a signed capability event; takes effect once the soland reducer projects it.",
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
    dict.set("realm_admin.leave_confirm_title", "Leave this Realm?");
    dict.set(
        "realm_admin.leave_confirm_body",
        "After leaving you will need a new invitation to rejoin this Realm, and its local cache on this device will be cleared.",
    );
    dict.set("realm_admin.leave_confirm_target", "Realm to leave");
    dict.set("realm_admin.leave_confirm_button", "Leave Realm");
    dict.set("realm_admin.leave_confirm_cancel", "Cancel");
    dict.set(
        "realm_admin.durability_title",
        "Realm recovery key (durability)",
    );
    dict.set(
        "realm_admin.durability_scheme_not_eligible",
        "scheme not eligible",
    );
    dict.set(
        "realm_admin.durability_intro",
        "Declares who can unseal this Realm's history after every member device is lost or all members have left. Changing the policy is a control-plane Move: it only applies to new epochs once a following ak.mls.commit covers the membership frontier, which also triggers re-disclosure to members.",
    );
    dict.set(
        "realm_admin.durability_scheme_warning",
        "This Realm does not use mls-exporter-aead-v1, so there is no deliverable history_secret; declaring mode != none will be rejected (durability_scheme_incompatible).",
    );
    dict.set("realm_admin.durability_mode_label", "Mode");
    dict.set(
        "realm_admin.durability_mode_none",
        "none — no organizational recovery (losing all devices loses history forever)",
    );
    dict.set(
        "realm_admin.durability_mode_org",
        "org_recovery_key — a single organizational RRK",
    );
    dict.set(
        "realm_admin.durability_mode_threshold",
        "threshold — k-of-n threshold",
    );
    dict.set(
        "realm_admin.durability_recipients_label",
        "Recovery recipients",
    );
    dict.set(
        "realm_admin.durability_recipients_hint",
        "One per line: recipient_id | principal_did | verification_method [ | controller_org_did]",
    );
    dict.set(
        "realm_admin.durability_threshold_label",
        "Threshold k (of n = recipient count)",
    );
    dict.set(
        "realm_admin.durability_revision_label",
        "Policy revision (monotonic)",
    );
    dict.set(
        "realm_admin.durability_apply_button",
        "Apply durability policy",
    );
    dict.set("realm_admin.durability_submitting", "Submitting…");
    dict.set(
        "realm_admin.durability_submitted",
        "Submitted ak.realm.policy_components; advance one ak.mls.commit to activate the sealing obligation and trigger re-disclosure.",
    );
    dict.set(
        "realm_admin.durability_submit_failed",
        "Submit failed: {error}",
    );
    dict.set(
        "realm_admin.durability_parse_failed",
        "Failed to parse recovery recipients: {error}",
    );
    dict.set(
        "realm_admin.durability_policy_invalid",
        "Invalid policy: {error}",
    );
    dict.set(
        "realm_admin.durability_err_recipient_fields",
        "line {line}: expected `recipient_id | principal_did | verification_method`",
    );
    dict.set(
        "realm_admin.durability_err_principal_did",
        "line {line}: invalid principal DID: {error}",
    );
    dict.set(
        "realm_admin.durability_err_org_did",
        "line {line}: invalid controller_organization DID: {error}",
    );
    dict.set(
        "realm_admin.durability_err_unknown_mode",
        "unknown durability mode {mode}",
    );
    dict.set(
        "realm_admin.durability_err_recipients_required",
        "mode != none requires at least one recovery recipient",
    );
    dict.set(
        "realm_admin.durability_err_duplicate_recipient",
        "duplicate recipient_id {recipient_id}",
    );
    dict.set(
        "realm_admin.durability_err_threshold_k",
        "threshold k must satisfy 1 <= k <= n ({n}), got {k}",
    );
    dict.set("directory.list_contacts", "List");
    dict.set("directory.search_button", "Search");
    dict.set("directory.resolve_selected", "Resolve Selected");
    dict.set("settings.store_backup", "Store Backup");
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
        "This browser is signed in, but it is not an authorized device for encrypted history yet. Arkret v1 requires an already-authorized device to approve a new device before MLS history keys are shared.",
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
    dict.set("mls_backup.button_saved", "I saved the key");
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
    dict.set("chat.you_badge", "ME");
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
    dict.set("chat.outbox.flushed", "Queued message sent.");
    // Message shared pin and holder-private saved item actions.
    dict.set("message.pin", "Pin");
    dict.set("message.unpin", "Unpin");
    dict.set("message.shared_pin", "Pin for everyone");
    dict.set("message.shared_unpin", "Unpin for everyone");
    dict.set("message.shared_pin_pending", "Sharing pin...");
    dict.set("message.shared_unpin_pending", "Removing shared pin...");
    dict.set("message.shared_pinned", "Shared pin updated.");
    dict.set("message.shared_unpinned", "Shared pin removed.");
    dict.set("message.private_save", "Save for me");
    dict.set("message.private_saved", "Saved for me");
    dict.set("pinned_bar.title", "Shared pinned messages");
    dict.set("pinned_bar.empty", "No pinned messages.");
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
        "Sign in to load realms and Spaces",
    );
    dict.set(
        "dashboard.collection.signin_spaces",
        "Sign in to load Spaces",
    );
    dict.set(
        "dashboard.collection.signin_realms",
        "Sign in to load realms",
    );
    dict.set(
        "dashboard.collection.empty_realms_and_spaces",
        "No realms or Spaces loaded",
    );
    dict.set("dashboard.collection.empty_spaces", "No Spaces loaded");
    dict.set("dashboard.collection.empty_realms", "No realms loaded");
    dict.set(
        "dashboard.collection.empty_help_realms_and_spaces",
        "The connected server did not return realms or Spaces yet.",
    );
    dict.set(
        "dashboard.collection.empty_help_spaces",
        "The connected server did not return Spaces yet.",
    );
    dict.set(
        "dashboard.collection.empty_help_realms",
        "The connected server did not return realms yet.",
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
    dict.set(
        "verify_device.sas_demo_warning",
        "Key exchange is not complete yet. The sequence below is a placeholder and must not be used for verification.",
    );
    dict.set(
        "verify_device.sas_match_disabled_hint",
        "Complete the X25519 key exchange first — the placeholder sequence cannot be confirmed as a match.",
    );

    // A6.4 — keyboard shortcut help overlay.
    dict.set("shortcuts.title", "Keyboard shortcuts");
    dict.set("shortcuts.dismiss", "Dismiss");
    dict.set("shortcuts.list.help", "Show this shortcut help");
    dict.set("shortcuts.list.dismiss", "Close any open dialog");
    dict.set("shortcuts.list.palette", "Open command palette");
    dict.set("shortcuts.list.palette_mac", "Open command palette (macOS)");
    dict.set("shortcuts.list.send", "Send the current message");
    // Personal blocklist (A5) — actor-private `ak.account.blocklist`
    // account-data namespace. Used by the Settings → Privacy panel, the
    // member-row context action, and the message "blocked user"
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
        "DID must start with did: (e.g. did:webvh:alice.example).",
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
        "friendly.identifier.placeholder",
        "john:example.com or did:webvh:...",
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

    // R3 spec sync (b47ff6ec) — new error toast strings surfaced by the
    // arkret-spec error code expansion (AKP-0010 media binding,
    // agent FSM, handle homograph wire-level enforce, recovery
    // policy). The HTTP error reply carries a stable
    // `code` / `reason` field that the toast layer maps via these
    // keys. zh translations follow in `chinese_translations()`.
    add_r3_error_keys(&mut dict);

    // Contacts UI, invite-receive policy, and the realm "invite from
    // contacts" picker. English is the authoritative default; zh follows
    // in `chinese_translations()`.
    add_contacts_keys(&mut dict);

    // Unified feedback system (toast host + app banner), Wave 0.
    add_feedback_keys(&mut dict);

    dict
}

/// English strings for the unified feedback surface
/// (`components::feedback` — toast host + app banner). zh follows in
/// `add_feedback_keys_zh`; other locales fall back through the
/// `xx → en → key` chain.
fn add_feedback_keys(dict: &mut TranslationDict) {
    dict.set(
        "feedback.policy_denied",
        "Action blocked by server policy: {code} — {message}",
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
    dict.set("feedback.bulk_realms_leaving", "Leaving {total} Realm(s)…");
    dict.set(
        "feedback.bulk_realms_left",
        "Left {done} of {total} Realm(s)",
    );
    dict.set(
        "feedback.bulk_realms_leave_failed",
        "Left {done} of {total} Realm(s); some failed",
    );
    dict.set(
        "feedback.bulk_contacts_deleting",
        "Deleting {total} contact(s)…",
    );
    dict.set(
        "feedback.bulk_contacts_deleted",
        "Deleted {done} of {total} contact(s)",
    );
    dict.set(
        "feedback.bulk_contacts_delete_failed",
        "Deleted {done} of {total} contact(s); some failed",
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
    dict.set("feedback.copied_invite_url", "Invite locator URL copied");
    dict.set(
        "feedback.invite_locator_refreshed",
        "Invite locator refreshed",
    );
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
        "Cleared all per-realm overrides",
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
    dict.set(
        "feedback.contact_remark_saved",
        "Contact remark saved: {name} \u{2192} {local_name}",
    );
    dict.set(
        "feedback.contact_remark_cleared",
        "Contact remark cleared for {name}",
    );
    dict.set(
        "feedback.invalid_actor_identifier",
        "Enter an actor DID or handle like alice:example.com",
    );
    dict.set(
        "feedback.enter_actor_and_name",
        "Enter both an actor identifier and a local name",
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
        "contacts.new.recipient_service_label",
        "Their server (only when adding across servers)",
    );
    dict.set(
        "contacts.new.recipient_service_placeholder",
        "did:webvh:ps.bob.example (leave blank if same server)",
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
        "invite_policy.kind.handle_claim",
        "People who know my handle",
    );
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
        "invite_policy.disclosure_toggle",
        "Let contacts see the invite outcome",
    );
    dict.set(
        "invite_policy.discovery_disclosure_toggle",
        "Let handle-based inviters see the outcome",
    );
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
        "Controller accountability grant is missing or stale; reattach a grant before retrying.",
    );
    dict.set(
        "error.agent.approval_already_consumed",
        "This approval nonce was already consumed. Request a fresh approval.",
    );

    // Media binding (AKP-0010).
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
        "Recording destination is not a Arkret authenticated blob — refusing to record.",
    );
    dict.set(
        "error.call.transcription_artifact_pipeline_bypassed",
        "Transcript destination is not a Arkret authenticated blob — refusing transcription.",
    );
    dict.set(
        "error.call.media_service_binding_uncovered",
        "Media service declaration is not covered by the current MLS governance binding. Refusing media join.",
    );
    dict.set(
        "error.call.media_plaintext_service_not_authorised",
        "This media service is not authorised to decrypt plaintext media. Refusing media negotiation.",
    );
    dict.set(
        "error.call.mls_governance_binding_stale",
        "MLS governance binding is stale for the current media policy. Refusing media negotiation.",
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

/// English i18n strings for the 6 AKP-0007 reason / error codes
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
    dict.set(
        "error.circle.encryption_profile_locked",
        "Circle encryption_profile is locked at creation. Create a new Circle to change its E2EE mode.",
    );
    dict.set(
        "error.circle.delivery_binding_handed_over",
        "The Circle's delivery binding moved to a newer set of devices — please retry the request.",
    );
    dict.set("circle.action.leave", "Leave Circle");
    dict.set("circle.action.archive", "Archive Circle");
    dict.set("circle.action.restore", "Restore Circle");
    dict.set("circle.action.tombstone", "Tombstone Circle");
    dict.set("circle.action.scope_rotate", "Rotate scope");
    dict.set("circle.status.active", "Active");
    dict.set("circle.status.archived", "Archived");
    dict.set("circle.status.tombstoned", "Tombstoned");

    // R3.3 (AKP-0011) — shareable object links (Chinese-first).
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
        "粘贴 web+arkret: 或 https 分享链接",
    );
    dict.set("object_link.opening", "正在打开链接…");
    dict.set("object_link.error.unavailable", "链接不可用或已过期。");
    dict.set("object_link.error.invalid", "无法识别该链接格式。");
}
