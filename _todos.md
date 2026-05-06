# Yougen — 与最新协议对齐的任务表

依据：`E:/Works/contrix-dev/contrix-spec`（commit `fc7da5b`，2026-05-05 多轮简化后的状态）。

> 上一轮：T80–T92 把 57 个未触及的 canonical event kind 拆到对应视图（commit `33f8b92`）；
> T100/T101/T103 收尾：拆 onboarding 路由、event-kind 100% 覆盖（commit `7731817`）；
> T20/T21/T31 wire-up：kanban projection、chat `Flow::discussion`、device revoke 真接 API
> （commits `2c13719` / `dc2813e` / `01d04ce` / `b09282c` / `e173ff5` / `88fbe19`）；
> 仓库健壮性 / 部署文档 / Release CI / 标准元数据 R01–R06 全部落地。
> 本轮：C01–C04 + B section 收尾（actions SHA-pin、docker 多架构 + 签名、AEAD 私有数据、LICENSE）。
>
> 标记说明：🅿 = 单文件可独立完成；🔒 = 多文件接线；⚠ = 需要 reducer / SDK 协同。

---

## 当前没有 outstanding 任务

A / B / C 各组任务均已落地或确认无需 yougen 端改动。下面是参考用的「已完成」分类汇总。

## A. 仓库健壮性与运维（已完成）

- [x] 🅿 **R01. 配置环境变量直通**：`src/config.rs` 新增 `apply_env_overlay()`，`LocalConfigStore::load()` 在无持久化配置时把 `CLIENTX_SERVER_URL` / `CLIENTX_ACCOUNT_DID` / `CLIENTX_DEVICE_ID` / `CLIENTX_SESSION_TOKEN` 叠加到默认值上；持久化设置面板写入后 env 不再覆盖。两个新单元测试覆盖正常 / 空白 路径。
- [x] 🅿 **R02. 标准仓库元数据**：补齐 `SECURITY.md`（漏洞披露 + 威胁模型 + 自托管 hardening 清单）、`CONTRIBUTING.md`（构建 / 分支 / 协议对齐流程）、`.github/PULL_REQUEST_TEMPLATE.md`、`.github/ISSUE_TEMPLATE/{bug_report,feature_request,config}.yml`。
- [x] 🅿 **R03. Tag 触发的 GitHub Release 发布**：`packages.yml` 在 `v*` tag 上为每个目标平台打包成 `.zip` / `.tar.gz`，新增 `release` job（`needs: native`，`permissions: contents: write`）下载所有 archive、生成 `SHA256SUMS`、调用 `softprops/action-gh-release@v2` 发布。
- [x] 🅿 **R04. README 环境变量参考节**：`README.md` 新增「Configuration」段，把 8 个支持的环境变量列成表格（含默认值 / 用途 / 适用平台），并明确「持久化 > env > 编译期默认」的优先级。
- [x] 🅿 **R05. Web localStorage 安全限制写入 README**：在 README 的「Configuration」段补一行 callout，链回 `SECURITY.md` 的威胁模型。`views/settings.rs` 的 in-app 警告也被显式提及。
- [x] 🅿 **R06. typos 字典审计**：`crate-ci/typos` 在 `src/views/devices.rs` 上对「OTKs」中的 `OT` 误报；`.typos.toml` 加入 `OT = "OT"` 通配并通过 `typos` exit=0 验证。

## B. 协议对齐缺口（已确认无 yougen 端改动）

经本轮 grep 复核，所有「reducer 内部计算」事件在 yougen 视图层均已正确归位（client 不签名、不写入，只展示）：

- [x] **`cx.flow.branch.update`** — `src/views/chat.rs:184` 的 *Discussion = flow(kind=room)* 词汇 banner 中 7 个 `cx.flow.branch.*` 全部展示。
- [x] **`cx.morph.update`** — `src/views/kanban.rs:371` 的 View 生命周期说明 + `src/views/applets.rs:54` 的 morph_type=applet 桥接。
- [x] **`cx.relation.update`** — `src/views/kanban.rs:811` *contains list→flow*（rank stable tie-break）说明。
- [x] **`cx.capability.derived`** — `src/views/audit.rs:174` 注明「reducer 内部派生 capability set；不需要单独签名」。

实际写入这些 event 的责任在 contrix-rust-sdk reducer + soland，与 yougen 无关；此处保留记录以便后续审计。

## C. 仓库 hardening（已完成）

- [x] 🅿 **C01. GitHub Actions SHA-pin**：`ci.yml` / `packages.yml` / `typos.yml` / `docker.yml` 中所有第三方 action 从 `@v6` 形式替换为 `@<commit-sha> # v6` 形式：`actions/checkout`, `actions/setup-node`, `actions/upload-artifact`, `actions/download-artifact`, `Swatinem/rust-cache`, `softprops/action-gh-release`, `crate-ci/typos`, `docker/{setup-buildx,setup-qemu,login,metadata,build-push}-action`, `sigstore/cosign-installer`, `actions/attest-build-provenance`。Dependabot 的 `package-ecosystem: github-actions` 自动跟随 SHA pin 升级。`dtolnay/rust-toolchain@stable` 故意保留 stable 别名（该 action 设计如此）。
- [x] 🅿 **C02. Docker 镜像多架构 + 签名 + SBOM**：`docker.yml` 新增 `docker/setup-qemu-action` 启用 multi-arch；`build-push-action` 加 `platforms: linux/amd64,linux/arm64` + `provenance: mode=max` + `sbom: true`；新增 cosign keyless 签名步骤（`id-token: write` 权限）；新增 `actions/attest-build-provenance@v3` 步骤把签名过的 SBOM 推到 GHCR。README CI 段补充 `cosign verify` 验证示例。
- [x] 🅿 **C03. localStorage 私有数据加密**：`src/local_state.rs` 把 XOR 替换为 ChaCha20-Poly1305（`chacha20poly1305 = "0.10"`）。`account_key` 经 SHA-256(salt || key) 派生为 32B key；每次写入用 `getrandom` 12B 随机 nonce；存储格式 `v2:<base64(nonce||sealed)>`。旧 XOR 数据通过 `legacy_xor_decrypt` 兜底，下次写入自动升级。新增 4 个测试覆盖 roundtrip / nonce 唯一性 / wrong-key 拒绝 / legacy 兼容。`views/settings.rs` 的 storage-risk 警告从 *Critical 「No Encryption at Rest」* 降级为 *Partial 「Private Data: ChaCha20-Poly1305」* 并明确还有 plaintext 残留（session token、sync cursor、operation cache）。`SECURITY.md` 的威胁模型 + `README.md` 的 Security callout 同步更新。
- [x] 🅿 **C04. LICENSE 文件**：从 SDK 复制 Apache-2.0 `LICENSE`（与 `contrix-rust-sdk` / `contrix-spec` 选型一致）；`Cargo.toml` 添加 `license = "Apache-2.0"` + `description` + `repository`；README 顶部加 LICENSE / SECURITY / CONTRIBUTING 链接。

## 已完成（最近会话）

- 2026-05-04 / 2026-05-05 round 1–5（commit `ca02ebd`）：21 项 — UI 信息架构对齐 claude-design + 4 项 pre-existing 阻塞修复。
- 2026-05-05 round 6（commit `ea266be`）：14 项 — 与 spec fc7da5b 对齐（路径迁移 / event registry resync / DID 默认值 / profile tier / audited E2EE / constraint family / notification 派生化 / transport 锁定）。
- 2026-05-05 round 7（commit `33f8b92`）：13 项 T80-T92 — 把 57 个未触及的 canonical event kind 拆到对应视图（覆盖率 52 → 70 / 109）。
- 2026-05-05 round 8（commit `7731817`）：T100 / T101 / T103 — 拆出 Onboarding 路由 + 步进器；最后 13 个 event kind 全部 surface。**event kind 覆盖率 100% (109/109)**。
- 2026-05-06 wire-up（commits `2c13719` / `dc2813e` / `01d04ce` / `b09282c` / `e173ff5` / `88fbe19`）：T20 kanban projection 接 `/api/v1/views/{view_id}/projection`；T21 chat 使用 `Flow::discussion(...)` 类型化构造；T31 device revoke 走真实 SDK `remove_member` + epoch 推进。
- 2026-05-06 ops（前一会话）：R01–R06 — env overlay、SECURITY.md / CONTRIBUTING.md / PR + issue 模板、tag 触发 GitHub Release 发布、README 环境变量表 + 安全 callout、typos 字典 OT 通配。
- 2026-05-06 hardening（本轮）：C01–C04 + B 收尾 — 14 个 third-party action SHA-pin、docker multi-arch + cosign keyless 签名 + SBOM 推送、ChaCha20-Poly1305 替换 XOR（4 新测试 + 兼容旧数据）、Apache-2.0 LICENSE。`cargo test --lib` 通过，`typos` exit=0，所有 YAML 解析通过。
