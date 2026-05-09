// =============================================================================
// View modules — protocol / design-doc cross reference
// =============================================================================
//
// 每个 view 都在 `claude-design/`（基于 `contrix-spec/spec/v1/zh/` 的 UI 设计稿）和协议
// 规范之间承担一个固定的角色。引入新视图前请先核对：
//
// | View module        | claude-design page                | spec sections                                           | primary event kinds                                                |
// |--------------------|-----------------------------------|---------------------------------------------------------|--------------------------------------------------------------------|
// | login              | desktop/login.html, mobile/login  | crypto-media/device-lifecycle §1-3                     | cx.session.grant, cx.device.authorized                            |
// | register           | desktop/onboarding.html (拆分中)  | identity/identity-did, identity-handles                | cx.actor.profile.update, cx.identity.recovery (initial)            |
// | dashboard          | desktop/home.html, mobile/home    | overview/architecture §3, sync/client-sync             | (read-only projection of frontier + spaces + inbox)                |
// | timeline           | desktop/space.html (timeline 视图)| sync/client-sync, models/views §7                      | cx.flow.update, cx.message.create, derived projection              |
// | kanban             | desktop/board.html, mobile/board  | overview/current-model §4, models/views §6             | cx.flow.move, cx.flow.reorder, cx.space.update (board/list)        |
// | chat / forum       | desktop/discussion.html           | models/object-model-standard §5, current-model §3      | cx.flow.track.{enable,disable,set_primary}, cx.message.*           |
// | document           | (尚无对应；属于 View.kind=document)| models/views §4                                         | cx.flow.update on synthesis track                                  |
// | directory          | desktop/directory.html            | discovery/discovery-directory                          | (read-only); writes via cx.space.discovery state event              |
// | notifications      | desktop/inbox.html, mobile/inbox  | discovery/push-notifications, discovery/read-receipts §6 | (projection only — derived from cx.read.marker / cx.receipt.read / @-mention) |
// | devices            | desktop/devices.html, mobile      | crypto-media/device-lifecycle                          | cx.device.{authorized,revoked}, cx.device.list_update              |
// | verify_device      | desktop/verify-device.html        | crypto-media/device-lifecycle (verification)           | cx.key.verification.*, cx.mls.welcome                              |
// | space_admin        | desktop/space-admin.html          | authz/{capabilities,policy-server}, governance/content-moderation, sync/federation | cx.space.policy.set, cx.capability.{grant,revoke,delegate}  |
// | audit              | desktop/audit.html                | sync/operations-sync, conformance/snapshot-schema      | (审计派生流；无独立写入)                                             |
// | settings           | desktop/settings.html             | identity/identity-handles §16, identity/account-lifecycle | cx.profile.update, cx.account.status, cx.identity.disclosure_*      |
// | call               | desktop/call.html                 | crypto-media/webrtc-signaling                          | ephemeral signaling + cx.morph.create morph_type=call               |
// | readiness          | (settings 内嵌)                   | overview/release-readiness, conformance/conformance-suite | (read-only)                                                      |
// | agent_runs         | desktop/applets.html (Agent tab)  | extensions/agent-protocol-interop                      | applet/agent transactions + signed result events                   |
// | memory_review      | (与 audit 联动)                   | conformance/state-resolution-conformance-vectors       | (本地 reducer 自检/调试)                                            |
// | product            | (上手流程辅助页)                  | overview/architecture                                  | (workspace bootstrap)                                              |
//
// 待新增 view（见 `_todos.md`）：
// - onboarding   → desktop/onboarding.html        (拆出独立步进；T12)
// - recovery     → desktop/recovery.html          (Argon2id / SSS / Recovery Key；T10)
// - applets      → desktop/applets.html           (Applet / Bot / Bridge / Agent 集中管理；T11)
//
// 共享准则（_todos.md §6）：
// 1. 任何写入 UI 必须显式标注其 canonical event kind。
// 2. discoverability / join_rule / history_visibility 三维度必须独立显示，不可互推。
// 3. 跨 Space 引用默认 lazy_link，不展开标题 / 成员 / 计数。
// 4. push 路径默认脱敏（background_sync_needed），正文在本地解密。
// 5. Auth Service 只能签发短期 cx.session.grant；改变长期设备集合必须 cx.device.authorized。

pub mod agent_runs;
pub mod applets;
pub mod audit;
pub mod call;
pub mod chat;
/// First end-to-end UI Move-flow PoC (C10.D 续 2026-05-09 十八轮).
/// "Grant consent" button under settings → Privacy that builds + signs +
/// POSTs a `cx.consent.grant` Move via the move_builder + api::submit_move
/// pipeline landed in 十六轮.
pub mod consent_demo;
pub mod dashboard;
pub mod devices;
pub mod directory;
pub mod document;
pub mod forum;
pub mod helpers;
pub mod kanban;
pub mod login;
pub mod memory_review;
pub mod notifications;
pub mod onboarding;
pub mod product;
/// Round 23 (M6): invite-quarantine list + admin approve/reject buttons.
/// (claude-design no dedicated page yet; lives at `/quarantine` and is
/// linked from the Settings sidebar for admins.)
pub mod quarantine;
pub mod readiness;
pub mod recovery;
pub mod register;
pub mod settings;
pub mod space_admin;
pub mod timeline;
pub mod verify_device;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum View {
    Login,
    Register,
    Dashboard,
    Timeline,
    Directory,
    Product,
    Settings,
    Devices,
    Readiness,
    VerifyDevice,
    SpaceAdmin,
    Audit,
    Kanban,
    Chat,
    Forum,
    MemoryReview,
    AgentRuns,
    /// Inbox / Notifications. Per `models/object-model-core.md` §1 (after Round 7),
    /// `notification` is a *derived* projection — NOT a canonical wire object.
    /// The only canonical events feeding this view are `cx.read.marker`,
    /// `cx.receipt.read`, `@-mention` extractions, plus capability/grant
    /// approval requests. Writes here MUST land on those canonical kinds, not
    /// on a synthetic `cx.notification.*` event.
    Notifications,
    Document,
    Call,
    /// Recovery / Encrypted Cloud Vault / Social Recovery / Recovery Key
    /// (claude-design `desktop/recovery.html`, crypto-media/device-lifecycle.md §10-§13 — secret storage / key backup / recovery)
    Recovery,
    /// Applets / Bots / Bridges / Agents / Portal Spaces
    /// (claude-design `desktop/applets.html`, extensions/applet-integration.md)
    Applets,
    /// Onboarding 步进器 — 4 步引导（DID method / Handle / Device / Recovery）。
    /// 与 Register 互补：register 是详细向导，onboarding 是轻量步进入口。
    /// (claude-design `desktop/onboarding.html`, identity-did §3 + identity-handles + device-lifecycle §1-§13)
    Onboarding,
    /// Round 23 (M6): invite-quarantine list. Admins see all entries
    /// from coauth's `GET /admin/v1/invite-quarantine`; non-admins
    /// see their own quarantined invites. Approve / reject buttons
    /// POST `/admin/v1/invite-quarantine/{id}/resolve`.
    Quarantine,
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
