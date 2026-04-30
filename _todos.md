# yougen Active TODO

> 更新日期: 2026-04-30
> 范围: Contrix 跨平台客户端。`yougen` 负责产品 UX、平台集成、客户端本地状态、安全边界和 E2E；协议基础模型、validators、builders 优先复用 `contrix-rust-sdk`，push registration 优先复用 `chime`。

## 0. 当前边界

- 当前已有 Dioxus app、URL routes、主要页面、Playwright 主业务流、结构化事件写入骨架、目录/通知/Agent/Space Admin 等产品面。
- 仍未达到生产发布级: 生产认证、真实 DID/handle/key-log、Web E2EE、持久安全存储、multi-device sync、授权审批 UX、真实 federation/applet/agent interop、桌面/移动发布工程。
- 本清单只跟踪 yougen 侧应做的产品和平台工作；SDK/服务端工作只作为依赖引用，不在 yougen 内重复实现。

## P0: Spec Drift - Facet-Aware Client Surface

目标: 客户端 UI 和本地写入语义跟随 `contrix-spec` 最新 facets/view renderer 模型。

- [x] Local entity model:
  - [x] 实体缓存支持 `facets`，把 `entity_type` 作为语义标签显示，不再用它推断全部交互能力。
  - [x] 通用实体卡片根据 `renderable` facet 与 server `renderer` 选择 card/row/table/message/node 渲染。
  - [x] unknown facet 保留并在调试面板展示，不丢弃服务端扩展。
- [ ] Dynamic views:
  - [x] index query 支持 `facets` 和 `renderer` 参数。
  - [ ] kanban/table/timeline/thread/graph 页面读取 `item_facets/message_facets/node_facets`。
  - [x] cursor/filter mismatch 错误展示 renderer/facet 条件，避免用户继续使用旧游标。
- [ ] Outbound operations:
  - [x] yougen 本地 operation helpers 已提供 `cx.field_position.move/reorder` 和 `cx.container.move_item/rebalance` canonical kind。
  - [ ] SDK builders 产出的 canonical kind 使用 `cx.field_position.move/reorder` 和 `cx.container.move_item/rebalance`。
  - [ ] 旧 `cx.task.move/reorder`、`cx.relation.move/rebalance` 只用于 legacy profile 迁移。
  - [ ] UI audit 链路展示 canonical kind 和服务端回显的 operation/commit id。
- [x] Capability UX:
  - [x] capability model/evaluator 支持 `allowed_entity_facets`。
  - [x] capability explanation 显示 `allowed_entity_facets`。
  - [x] 被拒绝操作区分 entity type 标签不匹配与 facet capability 不满足。

并行性: 本地模型、动态视图、操作 builder、能力解释 UI 可并行；出站写入应等待 `contrix-rust-sdk` 公共 API。

## P0: Production Auth and Identity UX

目标: 从 dev-login / demo DID 过渡到可审计的 Contrix 登录和身份绑定流程。

- [ ] coauth OIDC login:
  - [ ] authorization code + PKCE。
  - [ ] callback state/nonce validation。
  - [ ] refresh token secure storage。
  - [ ] logout/revoke。
  - [ ] token expiry and re-auth UI。
- [ ] Passkey/WebAuthn:
  - [ ] passkey registration。
  - [ ] passkey login。
  - [ ] step-up for high-risk actions。
  - [ ] recovery fallback。
- [ ] DID onboarding:
  - [ ] create `did:uuid` through starid or configured registry。
  - [ ] attach existing DID with DID control proof。
  - [ ] display registry receipt。
  - [ ] handle key-log rotate/recover/deactivate states。
- [ ] Handle verification:
  - [ ] bidirectional handle verification。
  - [ ] DNS/well-known proof display。
  - [ ] warning for unverified handle。
  - [ ] pairwise/private DID privacy UX。
- [ ] Progressive disclosure:
  - [ ] presentation request prompt。
  - [ ] claim selection UI。
  - [ ] verified email/org role/device trust badges。
  - [ ] revocation/expiry warning。

并行性: OIDC/passkey、DID onboarding、handle verification、progressive disclosure 可并行；session/token storage contract 必须先冻结。

## P0: Secure Local Storage and E2EE

目标: 任何生产构建不得依赖 Web placeholder crypto 或明文长期秘密。

- [ ] Native secure storage:
  - [ ] OS keychain integration for refresh token/session secret。
  - [ ] device identity key storage。
  - [ ] encrypted local repo/cache。
  - [ ] backup/restore UX。
- [ ] Web secure storage:
  - [ ] WebCrypto key generation/import。
  - [ ] IndexedDB crypto store。
  - [ ] IndexedDB repo/sync cursor store。
  - [ ] no hardcoded WASM crypto placeholders。
  - [ ] browser unsupported-state warning。
- [ ] MLS lifecycle:
  - [ ] KeyPackage publish/fetch。
  - [ ] group create/join。
  - [ ] Welcome processing。
  - [ ] Commit/Proposal application。
  - [ ] epoch mismatch recovery。
  - [ ] removed member fail-closed。
- [ ] Device verification:
  - [ ] SAS flow。
  - [ ] QR flow。
  - [ ] cancellation/timeout/mismatch。
  - [ ] cross-device trust propagation。
- [ ] Encrypted envelope:
  - [ ] AAD covers space/event/causal refs。
  - [ ] payload/aad digest verification。
  - [ ] undecryptable event preserved with reason。
  - [ ] retry after key arrival。
- [ ] Key backup/recovery:
  - [ ] encrypted backup export。
  - [ ] restore usable MLS state。
  - [ ] authenticity validation。
  - [ ] version rotation and rollback protection。

## P0: Write Plane, Sync and Offline Correctness

目标: UI 行为以 repo/operation/event fact chain 为依据，而不是本地 optimistic state 自说自话。

- [ ] Use SDK builders/validators for outbound operations:
  - [ ] entity/relation/view。
  - [ ] message/comment/topic/channel。
  - [ ] invite/read marker/notification preference。
  - [ ] capability proposal/approval where supported。
  - [ ] run/memory。
  - [ ] MLS proposal/commit/welcome。
- [ ] Signed fact chain:
  - [ ] local operation/commit creation when client-held repo is enabled。
  - [ ] server-verified operation/commit echo display。
  - [ ] proof failure UI。
  - [ ] audit link from UI action to operation/commit id。
- [ ] Sync bootstrap:
  - [ ] resolve services。
  - [ ] fetch invite/grants。
  - [ ] fetch snapshot manifest。
  - [ ] verify chunks。
  - [ ] pull increments。
  - [ ] run reducer。
  - [ ] enter subscription。
- [ ] Incremental sync:
  - [ ] persist cursor per account/device/server。
  - [ ] handle expired cursor。
  - [ ] handle filter mismatch。
  - [ ] `timeline.limited` gap display。
  - [ ] backfill gap on demand。
  - [ ] `state_after` consistency。
  - [ ] `X-Contrix-Wait-For` for read-your-writes。
- [ ] Offline queue:
  - [ ] durable pending operations。
  - [ ] dependency ordering。
  - [ ] retry/backoff/cancel。
  - [ ] conflict resolution after reconnect。
  - [ ] failed operation repair UI。
- [ ] Multi-device:
  - [ ] read marker merge。
  - [ ] notification state merge。
  - [ ] to-device ack。
  - [ ] device revocation handling。

## P0: Authorization, Policy and Admin-Sensitive UX

- [x] Capability explanation UI:
  - [x] show effective grants。
  - [x] show resource selectors。
  - [x] show constraints。
  - [x] show delegation chain。
  - [x] show stale frontier/conflict reason。
- [ ] High-risk actions:
  - [ ] proposal mode。
  - [ ] approval request/approve/reject。
  - [ ] guardian/controller approval display。
  - [ ] policy quarantine/review state。
  - [ ] audit reason capture。
- [ ] Denied action UX:
  - [ ] distinguish unauthenticated / denied / stale frontier / requires review。
  - [ ] never expose invisible resource existence。
  - [ ] provide retry only when safe。
- [ ] Claim-based access:
  - [ ] missing claim prompt。
  - [ ] expired/revoked claim warning。
  - [ ] minimum disclosure UI。

## P1: Core Product Surfaces

- [ ] Space hierarchy:
  - [ ] parent/child links。
  - [ ] explicit inheritance display。
  - [ ] cycle conflict warning。
  - [ ] no implicit membership/auth/history/encryption cascade。
- [ ] Dynamic views:
  - [ ] server-defined View objects。
  - [ ] kanban/table/timeline/graph projections。
  - [x] generic unknown entity card。
  - [ ] schema-driven custom fields。
- [ ] Media/blob:
  - [ ] content hash before/after download。
  - [ ] authenticated download with header auth。
  - [ ] no token in media URL。
  - [ ] image/video/audio preview policies。
  - [ ] thumbnail support。
  - [ ] unsafe type opens as attachment。
- [ ] Notifications/push:
  - [ ] register/unregister via `chime`。
  - [ ] token rotation。
  - [ ] per-space mute sync。
  - [ ] blind wakeup only for E2EE。
  - [ ] local notification permission UX。
- [ ] WebRTC:
  - [ ] to-device offer/answer/ICE。
  - [ ] call invite notification。
  - [ ] TURN credential handling。
  - [ ] screen sharing。
  - [ ] SFU/recording authorization warning。

## P1: Federation, Applet and Agent Interop

- [ ] Federation UX:
  - [ ] remote service DID display。
  - [ ] cross-domain invite/join。
  - [ ] remote operation trust/audit state。
  - [ ] fork/quarantine warning。
  - [ ] backfill authorization failure UI。
- [ ] Applet:
  - [ ] signed applet registration display。
  - [ ] namespace conflict UI。
  - [ ] ghost actor accountability。
  - [ ] portal Space mapping。
  - [ ] third-party user/location lookup。
- [ ] Agent:
  - [ ] run lifecycle from protocol facts。
  - [ ] tool audit timeline。
  - [ ] memory candidate/review/confirm/invalidate/supersede。
  - [ ] episodic vs semantic memory separation。
  - [ ] kill-switch / max capability display。
  - [ ] A2A/ACP/MCP handoff metadata。

## P1: MIMI Interop Client Surface

目标: 跟随 `cx.profile.mimi_interop.v1`，把 MIMI 作为 Provider Facade / interop projection 暴露给客户端，不替代 Contrix signed event/reducer、`space_id`、DID、HLC、capability、auth refs 或 MLS state。

- [x] Draft pinning:
  - [x] 客户端展示 `draft-ietf-mimi-protocol-06`、`draft-ietf-mimi-content-08`、`draft-ietf-mimi-room-policy-03`、`draft-kohbrok-mimi-identifiers-01`。
  - [x] provider directory UI 显示 `cx.profile.mimi_interop.v1` 和 feature set。
- [x] Typed facade API:
  - [x] `provider_directory`。
  - [x] `key_material`。
  - [x] `room_update`。
  - [x] `notify`。
  - [x] `submit_message`。
  - [x] `group_info`。
  - [x] `request_consent` / `update_consent`。
  - [x] `identifier_query`。
  - [x] `report_abuse`。
  - [x] `proxy_download`。
- [x] Settings UI:
  - [x] MIMI interop section。
  - [x] refresh directory、groupInfo、identifier query、submit test message、proxy download 操作。
  - [x] last receipt/status 展示。
- [x] Playwright:
  - [x] mock MIMI provider facade endpoints。
  - [x] e2e 覆盖 discovery、draft/feature display、group-info、identifier-query、proxy-download、submit-message 主流程。
- [ ] Follow-up:
  - [ ] 真实 HTTP Message Signature/service DID proof UX。
  - [ ] `cx.mimi.room_binding` discovery and Space/Channel binding picker。
  - [ ] consent request/update management UI。
  - [ ] abuse report evidence package UI。
  - [ ] MIMI write receipt link to native Contrix event/operation/commit audit view。

## P1: Platform Release Engineering

- [ ] Desktop:
  - [ ] Windows signing。
  - [ ] macOS notarization。
  - [ ] Linux package signing。
  - [ ] auto-update。
  - [ ] crash reporting opt-in。
- [ ] Web/PWA:
  - [ ] production WASM hosting。
  - [ ] service worker/cache policy。
  - [ ] CSP。
  - [ ] PWA manifest。
  - [ ] HTTPS-only production config。
- [ ] Mobile:
  - [ ] iOS project and signing。
  - [ ] Android project and signing。
  - [ ] push token acquisition。
  - [ ] keychain/keystore storage。
  - [ ] app store privacy disclosures。
- [ ] CI:
  - [ ] native builds。
  - [ ] web build。
  - [ ] Playwright smoke。
  - [ ] mobile build smoke where available。
  - [ ] SBOM and vulnerability gate。

## P1: Security, Privacy and Accessibility

- [x] Plaintext boundary:
  - [x] show which services may see plaintext。
  - [x] warn before sending private plaintext to undelegated service。
  - [x] embeddings/search/preview disclosure。
- [ ] URL/log leakage audit:
  - [ ] tokens。
  - [ ] push keys。
  - [ ] DID private proofs。
  - [ ] blob signed redirects。
  - [ ] recovery codes。
- [ ] Sovereign deployment:
  - [ ] resolver pinning。
  - [ ] service DID allowlist。
  - [ ] closed federation mode。
  - [ ] export approval。
  - [ ] data classification labels。
- [ ] Accessibility:
  - [ ] keyboard navigation across all dialogs。
  - [ ] focus restore。
  - [x] screen reader labels for dynamic timelines。
  - [x] high contrast mode。
  - [x] reduced motion。
- [ ] i18n:
  - [ ] English/Chinese parity。
  - [ ] RTL coverage beyond smoke。
  - [x] date/time/number formatting。
  - [x] translation completeness check。

## P0/P1 Test Plan

- [ ] Unit:
  - [ ] auth/session storage。
  - [ ] DID/handle UI state。
  - [ ] operation builders integration。
  - [x] encrypted envelope validation。
  - [x] offline queue。
  - [x] capability explanation。
- [ ] Integration:
  - [ ] yougen + soland sync。
  - [ ] yougen + coauth OIDC。
  - [ ] yougen + starid DID registration。
  - [ ] yougen + floria/chime push registration。
  - [ ] multi-device same account。
- [ ] E2E:
  - [ ] production auth flow。
  - [ ] full Space lifecycle。
  - [x] MIMI provider facade discovery/actions。
  - [ ] offline -> online replay。
  - [ ] E2EE group lifecycle。
  - [ ] push token rotate。
  - [ ] admin-sensitive approval/proposal。
  - [x] mobile viewport。
  - [x] accessibility smoke。

## Cross-Project Dependencies

- `contrix-rust-sdk`: protocol builders, validators, store traits, E2EE helpers。
- `coauth`: OIDC, passkey, account lifecycle, DID binding, claims。
- `starid`: DID creation/resolve/key-log/receipt。
- `soland`: Principal Server sync/repo/index/blob/authz/federation。
- `chime`: push registration SDK。
- `floria`: push notify gateway。
- `cotest`: release-gate integration tests。

## Definition of Done

- [ ] Feature works against real local stack, not only mock/demo state。
- [ ] Secrets are stored in platform-appropriate secure storage or explicitly marked dev-only。
- [ ] Protocol writes expose operation/commit/audit ids where relevant。
- [ ] E2E covers success, denial and recovery/error path。
- [ ] UX never leaks invisible resource existence or private plaintext boundary details。

## 本轮验证记录

- [x] 2026-04-30 spec drift: `cargo fmt --all`。
- [x] 2026-04-30 spec drift: `cargo check --message-format short`。
- [x] 2026-04-30 spec drift: `cargo test --lib entity_round_trip_serde --message-format short`。
- [x] 2026-04-30 spec drift: `cargo test --lib test_constraint_type_restriction_checks_facets --message-format short`。
- [x] 2026-04-30 facet UI: `cargo fmt --all`。
- [x] 2026-04-30 facet UI: `cargo check --message-format short`。
- [x] 2026-04-30 facet UI: `cargo check --tests --message-format short`。
- [x] 2026-04-30 facet UI: `git diff --check`。
- [x] 2026-04-30 facet UI: `npx playwright test --list`。
