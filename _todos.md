# Yougen — 与最新协议对齐的任务表

依据：`E:/Works/contrix-dev/contrix-spec`（截至 commit `fc7da5b`，2026-05-05 多轮简化后的状态）。本表只保留 **当前对照协议 / 实现 后仍未完成** 的任务；历史任务表已合并到 git 历史 (commit `ca02ebd`)。

> 标记说明：🅿 = 单文件可独立完成；🔒 = 多文件接线；⚠ = 需要 reducer / SDK 协同。

---

## 1. 协议路径迁移（Round 1 / Round 7 文件合并后）

最近 spec 把多个文件合进同一篇，yougen 内的引用需要同步。

- [ ] 🅿 **T1. `crypto-media/devices-and-auth.md` + `crypto-media/device-crypto-verification.md` → `crypto-media/device-lifecycle.md`**：更新所有引用（`src/views/{mod,devices,verify_device,notifications,recovery}.rs`、`src/conformance.rs`、`claude-design/README.md`）。
- [ ] 🅿 **T2. `models/conversation-model.md` → `models/object-model-standard.md` §5.1-§5.3**：更新 `src/views/mod.rs`、`src/conformance.rs` 中的引用。
- [ ] 🅿 **T3. `authz/moderation.md` → `governance/content-moderation.md`**：更新 `src/components/write_state.rs` doc。
- [ ] 🅿 **T4. `authz/account-lifecycle.md` → `identity/account-lifecycle.md`**：更新 `src/views/mod.rs` 头表。
- [ ] 🅿 **T5. `identity/progressive-disclosure.md` → `identity/identity-handles.md` §16**：更新 `src/views/mod.rs`、`claude-design/README.md`。
- [ ] 🅿 **T6. `crypto-media/encrypted-envelope-schema.md` → `crypto-media/encryption-and-audit.md` §2.3**：检查 `src/crypto.rs`、`src/local_state.rs` 中的注释引用（如有）。
- [ ] 🅿 **T7. 五个 `*-conformance-vectors.md` → 单一 `conformance/conformance-vectors.md`**：更新 `src/conformance.rs` 注释。
- [ ] 🅿 **T8. `sync/federation-wire.md` → `sync/federation.md` §4.5**：检查 `src/api.rs` / `src/views/space_admin.rs` 引用。

## 2. 注册表 / Event Kind 漂移

`zh/artifacts/registry/event-kind-registry.json` 当前有 **109 个 active** event kinds。yougen 的 `conformance::known_event_kinds()` 列了一批 spec 没有的 / 已经改名的 event kind。

- [ ] 🔒 **T10. 重写 `src/conformance.rs::known_event_kinds()` 与协议 registry 对齐**：
  - 删除：`cx.flow.convert`（Round 7 真删，原已 deprecated）、`cx.mls.epoch`（Round 1 batch 1 删除 wire event）、`cx.notification.dismiss`、`cx.read_marker.update`、`cx.federation.txn`、`cx.snapshot.publish`、`cx.account.suspend/resume/erase`、`cx.actor.profile.update`、`cx.space.archive`、`cx.space.discovery`、`cx.space.policy.update`、`cx.identity.recovery`、`cx.identity.recovery_attestation`、`cx.applet.transaction`、`cx.agent.session`、`cx.moderation.quarantine`、`cx.moderation.appeal`、`cx.device.cross_sign`、`cx.capability.grant.request`、`cx.view.delete`、`cx.reaction.create`、`cx.morph.update`（保留：在 registry 中已确认存在的）。
  - 改名：`cx.actor.profile.update` → `cx.profile.update`、`cx.read_marker.update` → `cx.read.marker`、`cx.space.policy.update` → `cx.space.policy.set`、`cx.account.*` → `cx.account.status` + `cx.account.blocklist`、`cx.reaction.create` → `cx.reaction.add`/`cx.reaction.remove`。
  - 新增：`cx.flow.archive`、`cx.flow.restore`、`cx.flow.branch.history_visibility`、`cx.flow.branch.policy_components`、`cx.flow.branch.update`、`cx.morph.archive`、`cx.morph.restore`、`cx.relation.update`、`cx.view.reconcile`、`cx.space.upgrade`、`cx.space.organization`、`cx.space.lifecycle.set`、`cx.space.policy.set`、`cx.policy.rule`、`cx.policy.action`、`cx.policy.set`、`cx.member.state`、`cx.invite.{create,accept,claim,cancel,revoke,third_party}`、`cx.capability.delegate`、`cx.capability.derived`、`cx.profile.update`、`cx.profile.space_override`、`cx.account.status`、`cx.account.blocklist`、`cx.account_data.set`、`cx.identity.disclosure_policy`、`cx.identity.disclosure_receipt`、`cx.identity.presentation_request`、`cx.identity.presentation_response`、`cx.did.proof`、`cx.organization.discovery`、`cx.organization.moderation_policy`、`cx.sovereign.did_policy`、`cx.read.marker`、`cx.receipt.read`、`cx.presence`、`cx.typing`、`cx.redaction`、`cx.audit.accessed`、`cx.audit.ryw_receipt`、`cx.agent.endpoint`、`cx.agent.protocol_session.{start,status,result}`、`cx.applet.bridge_error`、`cx.applet.protocol_session.{start,status}`、`cx.call.{signal,state,recording.start}`、`cx.container.{move_item,rebalance}`、`cx.key.verification.{request,ready,start,key,mac,accept,cancel,done}`、`cx.mls.{genesis,keypackage,commit_failed}`、`cx.moderation.frank`、`cx.schema.define`、`cx.schema.update`、`cx.space_key.{share,share_audit,withheld}`。
  - 同步刷新两个单元测试。

## 3. 默认 DID method 改变（Round 4）

v1 core 默认 principal DID method 从 `did:plc` 改为 `did:web`。`did:plc` 现为 v1.1+ extension。

- [ ] 🔒 **T20. claude-design 默认值更新**：`desktop/onboarding.html` 默认推荐由 `did:plc` 改为 `did:web`，标注 `did:plc` 为 v1.1+ AT Protocol interop extension。
- [ ] 🅿 **T21. claude-design 14 处 `did:plc:*` 示例 DID**：保持示例不变（这些只是举例的 DID，不是默认推荐），但在 onboarding 与 README 中明确标注 v1 core 默认是 `did:web`，并说明 `did:plc` 仅作为 AT Protocol interop。
- [ ] 🅿 **T22. `claude-design/README.md` 更新**：identity 表中 DID method 行说明 v1 core 用 `did:web`，high-trust 升级到 `did:webvh`，`did:plc` / `did:key` / `did:pkh` / KERI / TSP 都是 v1.1+ interop extension。

## 4. Profile tier 分离（Round 3）

`artifacts/profiles/conformance-profiles.json` 现有 `profile_tiers` 顶级字段，分 `v1_core_implementation` (14) / `v1_1_extension_implementation` (3 — applet_service / agent_runtime / mimi_interop)。

- [ ] 🔒 **T30. `src/conformance.rs` 引入 tier 概念**：在 `ClientProfileDeclaration` 加 `tier: &'static str`（"v1_core" / "v1_1_extension"）。`known_profiles()` 输出中体现。`views/applets.rs` / `views/readiness.rs` 标注哪些 profile 属于 extension。

## 5. Audited E2EE 双 profile（Round 6）

新增 `crypto-media/audited-e2ee.md`，定义 `cx.profile.attested_audit.e2ee.v1` 与 `cx.profile.disclosed_audit.e2ee.v1`，附 join warning canonical 文案、强制留痕 (`cx.audit.accessed`) / RYW receipt schema (`cx.audit.ryw_receipt`)。

- [ ] 🔒 **T40. `views/space_admin.rs` 在 Encryption 段加 audited E2EE assurance 选项**：列出 attested / disclosed / none 三档，附 `audit_disclosure` policy 与禁用的 marketing 措辞提示。

## 6. Notification / Read Marker 派生化（Round 7）

`object-model-core.md` 把 `notification` / `read_marker` 从 canonical 列表降级为"派生对象"。yougen 的 `views/notifications.rs` 已有 banner 说"Notification 是 projection"，但 `views/mod.rs` 头表与 `claude-design/README.md` 仍把它们列为可写入 canonical 对象。

- [ ] 🅿 **T50. `src/views/mod.rs` 头表**：把 notifications view 的 "primary event kinds" 列改为 `(projection only — derived from cx.read.marker / cx.receipt.read / @-mention 派生)`。
- [ ] 🅿 **T51. `claude-design/README.md`**：在 1.6 节 Read receipts 行明确 read_marker / notification 是派生 projection；写入路径只有 `cx.read.marker` 与 `cx.receipt.read`。

## 7. Constraint 14→8 family（Round 9）

`authz/constraint-schema.md` 把 14 个 constraint type 收敛为 8 family + subtype。yougen 暂未渲染 constraint type，但后续做 grant explanation UI 时需对齐。

- [ ] 🔒 **T60. `views/space_admin.rs` 的 grant-explanation 区段**：在文档注释中提示 constraint type 已经是 8-family + subtype 模型（`temporal` / `field_access` / `type_restriction` / `scope_limitation` / `delegation_control` / `quota` / `claim_based` / `confidentiality`），保留为后续 UI 的占位。

## 8. Transport 锁定（Round 5）

v1 core 互操作 transport 锁定为 HTTP/JSON。yougen 已经走 reqwest HTTP，但 `views/settings.rs` / `views/audit.rs` 没有把这一约束显式呈现给用户。

- [ ] 🅿 **T70. `views/settings.rs` / Server 区段**：加一行 "Transport: HTTP/JSON (v1 core normative; gRPC / WebSocket / SSE / MQ / libp2p 是 v1.1+ extension binding)"。

---

## 当前状态

- 上次会话：完成 21 / 32 任务并 push 到 `origin/main`（commit `ca02ebd`）。
- 本次：基于最新 spec 重新整理任务表，新增 14 项对齐任务（删除已不再适用的旧 32 项任务表，因协议层有重大简化）。
