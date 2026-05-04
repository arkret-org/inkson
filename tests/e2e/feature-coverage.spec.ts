/**
 * Feature coverage placeholders — anchors for the protocol surface that
 * `claude-design/` 与 `_todos.md` 列出但 yougen 端尚未提供端到端验证。
 *
 * 这些 test 当前都是 `test.skip`：作为后续实现的指针。每条 skip 的备注里
 * 同时给出 claude-design 页面与 contrix-spec 章节，方便接手者按图索骥。
 *
 * 当某个功能的 UI / 协议交互完成时，去掉 `.skip` 并补具体断言即可。
 */

import { expect, test } from "@playwright/test";
import { mockContrixApi } from "./mockContrixApi";

test.describe("feature coverage placeholders", () => {
  test.beforeEach(async ({ page }) => {
    await mockContrixApi(page);
    await page.goto("/", { waitUntil: "domcontentloaded", timeout: 120_000 });
    await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
    await page.getByTestId("connect-button").click();
  });

  // ---- Board / Flow / cx.flow.move 拖拽冲突 ----
  // claude-design: desktop/board.html
  // spec: overview/current-model.md §4, models/views.md §6
  test.skip("board: drag flow across lists writes cx.flow.move", async ({ page }) => {
    // 1. 打开 /kanban
    // 2. 长按或拖拽某 KanbanCard 到不同 list
    // 3. 断言 write_records 中出现 cx.flow.move 事件
    // 4. 模拟另一 actor 并发 cx.flow.move，验证 reducer 取较晚 HLC
    expect(true).toBe(true);
  });

  test.skip("board: multi-renderer header switches View.kind=collection renderer", async ({ page }) => {
    // claude-design: desktop/board.html 顶部 board/list/table/calendar/timeline tabs
    // 切换 renderer → cx.view.update（不动 Board/Flow/Relation）
    expect(true).toBe(true);
  });

  // ---- Flow detail · synthesis vs discussion ----
  // claude-design: desktop/flow-detail.html, desktop/discussion.html
  // spec: overview/current-model.md §3
  test.skip("card detail drawer shows branch tabs and respects branch access", async ({ page }) => {
    // 进入 KanbanPanel 选 card → 显示 synthesis / discussion 两 tab
    // 当 discussion branch-scoped 且当前 actor 不在 branch member 时，show locked lazy_link
    expect(true).toBe(true);
  });

  // ---- Identity / Device 三件事分开 ----
  // claude-design: desktop/devices.html, desktop/verify-device.html
  // spec: crypto-media/devices-and-auth.md §1.2
  test.skip("device verification: SAS match writes cx.device.authorized + cx.device.cross_sign", async ({ page }) => {
    // /devices/verify → 选 SAS → They Match
    // 断言 verify-status 显示已签发 cx.device.authorized + cx.device.cross_sign
    // SAS mismatch 时 *不应* 出现 device authorization 事件
    expect(true).toBe(true);
  });

  test.skip("session grant alone never reads E2EE history", async ({ page }) => {
    // 仅有 cx.session.grant 的浏览器 session：进入 discussion 显示 ciphertext locked，
    // 不允许解密；同设备完成 device authorization 后才能读历史。
    expect(true).toBe(true);
  });

  // ---- Recovery 三层 ----
  // claude-design: desktop/recovery.html
  // spec: crypto-media/devices-and-auth.md §4
  test.skip("recovery: encrypted vault rekey rewrites cipher blob client-side", async ({ page }) => {
    // /recovery → vault-rekey → 模拟服务端只看到 ciphertext blob，不见明文
    expect(true).toBe(true);
  });

  test.skip("recovery: social recovery 3 of 5 reconstruct triggers cx.identity.recovery", async ({ page }) => {
    // /recovery → social-recover-now → 三个 guardian 提交 share → cx.identity.recovery 写入
    expect(true).toBe(true);
  });

  // ---- Discoverability ≠ Join Rule ≠ History ----
  // claude-design: desktop/directory.html
  // spec: discovery/discovery-directory.md §2
  test.skip("directory: invite_only space hides existence from search", async ({ page }) => {
    // /directory → 搜索关键词不命中 invite_only Space
    // 输入精确 cx:space ID 可解析（带 invite proof）
    expect(true).toBe(true);
  });

  test.skip("directory: locked cross-space ref shows LazyLinkBadge only", async ({ page }) => {
    // /directory → 找到 access=locked 结果 → 标签上有 lazy-link-badge
    // 不暴露 title / 成员 / 计数
    expect(true).toBe(true);
  });

  // ---- Capability approval workflow ----
  // claude-design: desktop/space-admin.html
  // spec: authz/capabilities.md
  test.skip("space-admin: capability approval pending until 2 of 3 admins sign", async ({ page }) => {
    // /space/:id/admin → grant-explanation → approve agent
    // 一名 admin 批准后 pending 1/2，第二名后才 accept
    expect(true).toBe(true);
  });

  // ---- Audit · projection origin / conflict trail ----
  // claude-design: desktop/audit.html
  // spec: sync/operations-sync.md
  test.skip("audit: conflict trail shows winner + superseded events", async ({ page }) => {
    // /audit → conflict-trail 渲染 Mei (winner) 与 Alice (superseded)
    // 点击 conflict-restore-button 创建新 cx.flow.move 重写
    expect(true).toBe(true);
  });

  // ---- Applet / Agent / Portal Space ----
  // claude-design: desktop/applets.html
  // spec: extensions/applet-integration.md
  test.skip("applets: register new applet writes signed cx.applet.registration", async ({ page }) => {
    // /applets → 填写 service DID / namespace / capability → 提交
    // 断言 mock applet registration 成功；Bot Actor 加入 Space 后只能写授权过的 event kinds
    expect(true).toBe(true);
  });

  test.skip("applets: agent capability approval writes signed event chain", async ({ page }) => {
    // Researcher Agent 的 read_flow 申请 → 双 admin 批准 → 后续 agent 写入仍需签名
    expect(true).toBe(true);
  });

  // ---- WebRTC call ----
  // claude-design: desktop/call.html
  // spec: crypto-media/webrtc-signaling.md
  test.skip("call: SFU mode never enters plaintext path; recording requires explicit grant", async ({ page }) => {
    // /call → 默认 SFU + E2EE 媒体；SFU 不持有明文
    // 录制按钮在没有 capability 时为 disabled
    expect(true).toBe(true);
  });

  // ---- Push gateway 脱敏 ----
  // claude-design: desktop/inbox.html, mobile/inbox.html
  // spec: discovery/push-notifications.md, crypto-media/devices-and-auth.md §5
  test.skip("push gateway only ships background_sync_needed payload", async ({ page }) => {
    // 模拟 push gateway 收到的 payload：仅 target_did + event_type + urgency
    // 不应包含 sender handle / Space title / message body / collapse key
    expect(true).toBe(true);
  });
});
