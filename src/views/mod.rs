// =============================================================================
// View modules — protocol / design-doc cross reference
// =============================================================================
//
// Each view plays a fixed role between the `claude-design/` UI mockups and
// the protocol spec. Before adding a new view, cross-check the table below:
//
// | View module        | claude-design page                | spec sections                                           | primary event kinds                                                |
// |--------------------|-----------------------------------|---------------------------------------------------------|--------------------------------------------------------------------|
// | login              | desktop/login.html, mobile/login  | crypto-media/device-lifecycle §1-3                     | cx.session.grant, cx.device.authorized                            |
// | dashboard          | desktop/home.html, mobile/home    | overview/architecture §3, sync/client-sync             | (read-only projection of frontier + spaces + notifications)        |
// | timeline           | desktop/space.html (timeline view)| sync/client-sync, models/views §7                      | cx.flow.update, cx.message.create, derived projection              |
// | kanban             | desktop/board.html, mobile/board  | overview/current-model §4, models/views §6             | cx.flow.move, cx.flow.reorder, cx.space.update (board/list container)|
// | chat               | desktop/discussion.html           | models/object-model-standard §5, current-model §3      | cx.flow.tracks.update (unified), cx.message.*                      |
// | document           | (no dedicated page yet; View.kind=document) | models/views §4                              | cx.flow.update on synthesis track                                  |
// | directory          | desktop/directory.html            | discovery/discovery-directory                          | (read-only); writes via cx.realm.discovery state event              |
// | notifications      | desktop/inbox.html, mobile/inbox  | discovery/push-notifications, discovery/read-receipts §6 | (projection only — derived from cx.read.marker / cx.receipt.read / @-mention) |
// | verify_device      | desktop/verify-device.html        | crypto-media/device-lifecycle (verification)           | cx.key.verification.*, cx.mls.welcome                              |
// | space_admin        | desktop/space-admin.html          | authz/{capabilities,policy-server}, governance/content-moderation, sync/federation | cx.policy.{rule,action,set}, cx.capability.{grant,revoke,delegate}  |
// | settings           | desktop/settings.html             | identity/identity-handles §16, identity/account-lifecycle | cx.profile.update, cx.account.status, cx.identity.disclosure_*      |
// | setup              | (workspace bootstrap helper page) | overview/architecture                                  | (workspace bootstrap)                                              |
//
// Pending views (see `_todos.md`):
// - onboarding   → desktop/onboarding.html        (independent stepper; T12)
// - recovery     → desktop/recovery.html          (Argon2id / SSS / Recovery Key; T10)
//
// Shared rules (`_todos.md` §6):
// 1. Any write UI must explicitly label the canonical event kind it emits.
// 2. discoverability / join_rule / history_visibility are independent and
//    must be displayed independently — none implies the other.
// 3. Cross-Space references default to lazy_link — never expand title /
//    members / counts on the consumer side.
// 4. Push paths default to masked payloads (`background_sync_needed`); the
//    body is decrypted locally.
// 5. The Auth Service can only issue short-lived `cx.session.grant`; any
//    change to the long-lived device set must go through `cx.device.authorized`.

pub mod agent_workspace;
pub mod agents;
pub mod applets;
pub mod audit;
pub mod call;
pub mod chat;
/// First end-to-end UI Move-flow PoC.
/// "Grant consent" button under settings → Privacy that builds + signs +
/// POSTs a `cx.consent.grant` Move via the move_builder + api::submit_move
/// pipeline.
pub mod consent_demo;
pub mod dashboard;
/// T7.1 — Developer Tools / Diagnostics aggregator. Hosts the
/// protocol-level details (raw event log, audit rows, profile / schema
/// ids, conformance status) that used to leak into the main flow. End
/// users do not need to read this surface.
pub mod developer;
pub mod directory;
pub mod document;
/// A6.1 — global cross-Space message search panel. Backed by soland's
/// `POST /api/v1/index/search` (substring scan over the in-memory
/// projection); cross-space coverage will improve once the durable
/// projection lands.
pub mod global_search;
pub mod helpers;
pub mod kanban;
pub mod login;
/// Round R2/R3 (T06) — moderation appeal user flow. Entrypoint button +
/// `cx.moderation.appeal.submit` builder. Renders near user-facing
/// moderation decisions; reviewer surface is admin-scope.
pub mod moderation_appeal;
pub mod notifications;
pub mod onboarding;
/// Invite-quarantine list + admin approve/reject buttons.
/// (claude-design no dedicated page yet; lives at `/quarantine` and is
/// linked from the Settings sidebar for admins.)
pub mod quarantine;
pub mod recovery;
pub mod settings;
/// G3.Y3 — personal blocklist settings card (`/settings/blocklist`).
/// Lives next to the monolithic `settings` module to avoid touching
/// the 2.7k-line file while G3.Y1 / G3.Y2 are also editing it.
pub mod settings_blocklist;
/// G3.Y3 — capability delegation viewer (`/settings/capabilities`).
pub mod settings_capabilities;
/// G3.Y3 — consent grants settings card (`/settings/consent`).
pub mod settings_consent;
/// G3.Y1 — device management (list + revoke + QR pairing) split out
/// from `settings.rs` so the device / key-backup territory stays
/// distinct from the policy / consent territory (G3.Y3) at file
/// granularity. Hosts `/settings/devices` and `/settings/devices/pair`.
pub mod settings_devices;
/// G3.Y1 — fresh-device restore ceremony hosted at `/recover`. Takes
/// the recovery passphrase, derives the vault KEK locally, fetches
/// the latest backup envelope, and decrypts it without exposing the
/// passphrase to the server.
pub mod settings_recover_restore;
/// G3.Y1 — single-purpose passphrase setup ceremony surfaced from
/// the settings sidebar at `/settings/recovery`. Distinct from
/// `views/recovery.rs` which hosts the broader recovery-options
/// aggregator at `/recovery`.
pub mod settings_recovery;
/// G3.Y1 — manual key-backup status / trigger / restore controls at
/// `/settings/security`. Wires (where possible) to the existing
/// `cx.schema.key_backup.v1` API surface; soland MLS-key backup
/// endpoints that don't yet exist are tagged `TODO(G3.Y1-followup)`.
pub mod settings_security;
pub mod setup;
pub mod space_admin;
pub mod timeline;
pub mod verify_device;
/// G3.Y4 — real WebRTC call surface (1:1 + group + mute + screen
/// share + recording controls). Renders next to `call::CallPanel`
/// (the signaling-only landing page) at `/call` so the durable
/// signal count + the live call FSM live on the same route.
pub mod webrtc;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum View {
    Login,
    Dashboard,
    Timeline,
    Directory,
    Setup,
    Settings,
    VerifyDevice,
    SpaceAdmin,
    Kanban,
    Chat,
    /// Notifications. Per `models/object-model-core.md` §1,
    /// `notification` is a *derived* projection — NOT a canonical wire object.
    /// The only canonical events feeding this view are `cx.read.marker`,
    /// `cx.receipt.read`, `@-mention` extractions, plus capability/grant
    /// approval requests. Writes here MUST land on those canonical kinds, not
    /// on a synthetic `cx.notification.*` event.
    Notifications,
    Document,
    /// Recovery / Encrypted Cloud Vault / Social Recovery / Recovery Key
    /// (claude-design `desktop/recovery.html`, crypto-media/device-lifecycle.md §10-§13 — secret storage / key backup / recovery)
    Recovery,
    /// Onboarding stepper — 4-step flow (DID method / Handle / Device / Recovery).
    /// Account creation now starts from coauth's OIDC pages; this panel is a signed-in identity setup surface.
    /// (claude-design `desktop/onboarding.html`, identity-did §3 + identity-handles + device-lifecycle §1-§13)
    Onboarding,
    /// Invite-quarantine list. Admins see all entries from coauth's
    /// `GET /admin/v1/invite-quarantine`; non-admins see their own
    /// quarantined invites. Approve / reject buttons POST
    /// `/admin/v1/invite-quarantine/{id}/resolve`.
    Quarantine,
    /// Agent endpoint + protocol_session monitor.
    /// Spec `extensions/agent-integration.md`. Writes `cx.agent.endpoint` /
    /// `cx.agent.protocol_session.{start,status,result}` via
    /// `crate::operation::cx_ops::agent_*` builders.
    Agents,
    /// Agent Workspace dashboard — controller's private mirror Space entry.
    /// Spec `extensions/agent-workspace-profile.md` (`cx.profile.agent_workspace.v1`).
    /// Shows pending / in-flight / completed agent_task objects, with
    /// transparency / source_authority FSM cell state visible.
    AgentWorkspace,
    /// A6.1 — global cross-Space message search panel. Triggered by
    /// the `topbar-search-button`, `Cmd+F` (Ctrl+F off-mac), or by
    /// direct navigation to `Route::Search`.
    Search,
    /// G3.Y1 — device management surface (list + revoke + QR pair).
    /// Rendered for both `/settings/devices` and `/settings/devices/pair`
    /// because the pair flow is a single panel mounted on a sub-route.
    SettingsDevices,
    /// G3.Y1 — passphrase ceremony surface at `/settings/recovery`.
    SettingsRecovery,
    /// G3.Y1 — local key-backup status + manual trigger at `/settings/security`.
    SettingsSecurity,
    /// G3.Y1 — fresh-device restore-from-backup surface at `/recover`.
    Recover,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    Offline,
    Loading,
    Online,
    Reconnecting,
    Empty,
    Error,
}

impl ConnectionState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Offline => "Offline",
            Self::Loading => "Loading",
            Self::Online => "Online",
            Self::Reconnecting => "Reconnecting",
            Self::Empty => "Empty",
            Self::Error => "Error",
        }
    }
}
