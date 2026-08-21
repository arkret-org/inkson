// =============================================================================
// View modules — protocol / design-doc cross reference
// =============================================================================
//
// Each view plays a fixed role between the `claude-design/` UI mockups and
// the protocol spec. Before adding a new view, cross-check the table below:
//
// | View module        | claude-design page                | spec sections                                           | primary event kinds                                                |
// |--------------------|-----------------------------------|---------------------------------------------------------|--------------------------------------------------------------------|
// | login              | desktop/login.html, mobile/login  | crypto-media/device-lifecycle §1-3                     | ak.session.grant, ak.device.authorize                            |
// | dashboard          | desktop/home.html, mobile/home    | overview/architecture §3, sync/client-sync             | (read-only projection of frontier + spaces + notifications)        |
// | kanban             | desktop/board.html, mobile/board  | overview/current-model §4, models/views §6             | ak.strand.move, ak.strand.reorder, ak.space.update (board/list container)|
// | chat               | desktop/discussion.html           | models/object-model-standard §5, current-model §3      | ak.strand.tracks.update (unified), ak.message.*                      |
// | directory          | desktop/directory.html            | discovery/discovery-directory                          | (read-only); writes via ak.realm.discovery state event              |
// | notifications      | desktop/inbox.html, mobile/inbox  | discovery/push-notifications, discovery/read-receipts §6 | (projection only — derived from ak.read_cursor.advance / ak.receipt.read / @-mention) |
// | verify_device      | desktop/verify-device.html        | crypto-media/device-lifecycle (verification)           | ak.key.verification.*, ak.mls.welcome                              |
// | realm_admin        | desktop/realm-admin.html          | authz/{capabilities,policy-server}, governance/content-moderation, sync/federation | ak.policy.{rule,action,set}, ak.capability.{grant,revoke}, ak.realm.owner.transfer, ak.realm.authority.{reset,basis_update} |
// | settings           | desktop/settings.html             | identity/identity-handles §16, identity/account-lifecycle, authz/capabilities §10.4 | ak.profile.update, ak.account.status, ak.identity.disclosure_*, ak.capability.relinquish (subject-only, settings/capabilities) |
// | setup              | (workspace bootstrap helper page) | overview/architecture                                  | (workspace bootstrap)                                              |
//
// Pending views:
// - onboarding   → desktop/onboarding.html        (independent stepper; T12)
// - recovery     → desktop/recovery.html          (Recovery Key (24 words) / SSS; T10)
//
// Shared rules:
// 1. Any write UI must explicitly label the canonical event kind it emits.
// 2. discoverability / join_rule / history_access are independent and must be displayed
//    independently — none implies the other.
// 3. Cross-Space references default to lazy_link — never expand title / members / counts on the
//    consumer side.
// 4. Push paths default to masked payloads (`background_sync_needed`); the body is decrypted
//    locally.
// 5. The Auth Service can only issue short-lived `ak.session.grant`; any change to the long-lived
//    device set must go through `ak.device.authorize`.

pub mod agents;
pub mod applets;
pub mod audit;
pub mod call;
pub mod call_signals;
pub mod chat;
pub mod circles;
pub mod contacts;
pub mod dashboard;
/// T7.1 — Developer Tools / Diagnostics aggregator. Hosts the
/// protocol-level details (raw event log, audit rows, profile / schema
/// ids, conformance status) that used to leak into the main strand. End
/// users do not need to read this surface.
pub mod developer;
pub mod directory;
pub mod file_transfer;
/// A6.1 — global cross-Realm message search panel. The Arkret HTTP
/// catalog currently has no spec-defined global search endpoint; cross-Realm
/// coverage will improve once the durable projection lands.
pub mod global_search;
pub mod helpers;
pub mod kanban;
pub mod login;
pub(crate) mod member_display;
pub mod message_streams;
/// P3 — moderation reviewer workbench (decision/lift + appeal review/decide/
/// close). Admin-scope reviewer surface, mounted as the RealmAdmin
/// `Moderation` section; drives the daily-governance `moderation_*` /
/// `appeal_*` API. Companion to the appellant-facing [`moderation_appeal`].
pub mod moderation;
/// Round R2/R3 (T06) — moderation appeal user strand. Entrypoint button +
/// `ak.moderation.appeal.submit` builder. Renders near user-facing
/// moderation decisions; reviewer surface is admin-scope.
pub mod moderation_appeal;
pub mod notifications;
pub mod onboarding;
/// Actor-private invite-quarantine status surface.
pub mod quarantine;
/// Receiver-side projection of other members' `ak.receipt.read` Signals
/// (`read-receipts.md` §2). Shared read hints only; this actor's own private
/// multi-device cursor is `ak.read_cursor.advance` and lives elsewhere.
pub mod read_receipts;
pub mod realm_admin;
pub mod recovery;
pub mod register;
/// Shared E2EE "Send Secure" pipeline (MLS encrypt → forced commit →
/// encrypted `ak.message.create`) used by chat message writes.
pub mod secure_send;
/// `views::settings` is a module directory. The aggregate entry lives in
/// `settings/mod.rs`; per-card panels live in sibling files. See the
/// settings/mod.rs head comment for the territory split (G3.Y1 vs G3.Y3).
pub mod settings;
pub mod setup;
pub mod verify_device;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AppView {
    Login,
    Dashboard,
    Chat,
    Contacts,
    Directory,
    Setup,
    Settings,
    VerifyDevice,
    RealmAdmin,
    Circles,
    Kanban,
    /// Realm management list (`/realms/manage`). Distinct from `Kanban` so the
    /// management surface round-trips 1:1 with its route
    /// (design/route-view-ia.md §3.1).
    RealmsManage,
    /// Live call surface (`/call?…`). Its own view variant so the route maps
    /// 1:1 instead of masquerading as `Dashboard`.
    Call,
    /// Applets host (`/applets`). Own view variant for the same 1:1 reason;
    /// gated behind the `experimental-applets` feature at render time.
    Applets,
    /// Notifications. Per `models/overview.md` (object table: `ak:notification:`
    /// is an inbox projection), `notification` is a *derived* projection — NOT a
    /// canonical wire object.
    /// The only canonical events feeding this view are `ak.read_cursor.advance`,
    /// `ak.receipt.read`, `@-mention` extractions, plus capability/grant
    /// approval requests. Writes here MUST land on those canonical kinds, not
    /// on a synthetic `ak.notification.*` event.
    Notifications,
    FileTransfer,
    /// Recovery — Recovery Key (24 words) + restore-from-backup, with Social
    /// Recovery behind an Advanced fold (claude-design `desktop/recovery.html`,
    /// crypto-media/device-lifecycle.md §10-§13 — secret storage / key backup / recovery)
    Recovery,
    /// Onboarding stepper — 4-step strand (DID method / Handle / Device / Recovery).
    /// Account creation now starts from coauth's OIDC pages; this panel is a signed-in identity
    /// setup surface. (claude-design `desktop/onboarding.html`, identity-did §3 +
    /// identity-handles + device-lifecycle §1-§13)
    Onboarding,
    /// Actor-private invite-quarantine status surface.
    Quarantine,
    /// A6.1 — global cross-Space message search panel. Triggered by
    /// the `topbar-search-button`, `Cmd+F` (Ctrl+F off-mac), or by
    /// direct navigation to `Route::Search`.
    Search,
    /// G3.Y1 — device management surface (list + revoke + QR pair).
    /// Rendered for both `/settings/devices` and `/settings/devices/pair`
    /// because the pair strand is a single panel mounted on a sub-route.
    SettingsDevices,
    /// `/settings/recovery` renders through `AppView::Settings` so the Settings
    /// sidebar remains visible.
    SettingsRecovery,
}

// The connection-status label enum is a sync-layer concept; it now lives in
// `sync_engine` (YGN-ARCH-01, so the sync core no longer reaches back into
// `views`). Re-exported here so the app-shell call sites that reference it as
// `crate::views::ConnectionState` keep resolving unchanged.
pub use crate::sync_engine::ConnectionState;
