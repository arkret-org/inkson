/**
 * Feature coverage placeholders — anchors for protocol surface that
 * `claude-design/` and `_todos.md` list but yougen does not yet exercise
 * end-to-end.
 *
 * Every test is `test.skip`: a pointer for the follow-up implementation.
 * Each skip block lists both the claude-design page and the contrix-spec
 * section so the next contributor can find the source quickly.
 *
 * When a feature's UI / protocol path lands, remove `.skip` and fill in
 * the concrete assertions.
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

  // ---- Board / Flow / cx.flow.move drag conflict ----
  // claude-design: desktop/board.html
  // spec: overview/current-model.md §4, models/views.md §6
  test.skip("board: drag flow across lists writes cx.flow.move", async ({ page }) => {
    // 1. Open /kanban.
    // 2. Long-press or drag a KanbanCard into a different list.
    // 3. Assert that a cx.flow.move event appears in write_records.
    // 4. Simulate a concurrent cx.flow.move from another actor and verify
    //    the reducer keeps the entry with the later HLC.
    expect(true).toBe(true);
  });

  test.skip("board: multi-renderer header switches View.kind=collection renderer", async ({ page }) => {
    // claude-design: desktop/board.html top board/list/table/calendar/timeline tabs.
    // Switching the renderer writes cx.view.update (Board/Flow/Relation stay put).
    expect(true).toBe(true);
  });

  // ---- Flow detail · synthesis vs discussion ----
  // claude-design: desktop/flow-detail.html, desktop/discussion.html
  // spec: overview/current-model.md §3
  test.skip("card detail drawer shows branch tabs and respects branch access", async ({ page }) => {
    // Enter KanbanPanel, pick a card, expect synthesis / discussion tabs.
    // When the discussion is branch-scoped and the current actor is not a
    // branch member, the UI shows a locked lazy_link instead.
    expect(true).toBe(true);
  });

  // ---- Identity / Device — three independent concerns ----
  // claude-design: desktop/devices.html, desktop/verify-device.html
  // spec: crypto-media/devices-and-auth.md §1.2
  test.skip("device verification: SAS match writes cx.device.authorized + cx.device.cross_sign", async ({ page }) => {
    // /devices/verify → pick SAS → They Match.
    // Assert verify-status renders the issued cx.device.authorized +
    // cx.device.cross_sign. A SAS mismatch must NOT produce a device
    // authorization event.
    expect(true).toBe(true);
  });

  test.skip("session grant alone never reads E2EE history", async ({ page }) => {
    // A browser session that only holds cx.session.grant: entering the
    // discussion shows ciphertext locked and decryption is disallowed;
    // only after device authorization on the same device can history be
    // read.
    expect(true).toBe(true);
  });

  // ---- Recovery — three layers ----
  // claude-design: desktop/recovery.html
  // spec: crypto-media/devices-and-auth.md §4
  test.skip("recovery: encrypted vault rekey rewrites cipher blob client-side", async ({ page }) => {
    // /recovery → vault-rekey → simulate that the server only ever sees a
    // ciphertext blob, never plaintext.
    expect(true).toBe(true);
  });

  test.skip("recovery: social recovery 3 of 5 reconstruct triggers cx.identity.recovery", async ({ page }) => {
    // /recovery → social-recover-now → three guardians submit shares →
    // cx.identity.recovery is written.
    expect(true).toBe(true);
  });

  // ---- Discoverability ≠ Join Rule ≠ History ----
  // claude-design: desktop/directory.html
  // spec: discovery/discovery-directory.md §2
  test.skip("directory: invite_only space hides existence from search", async ({ page }) => {
    // /directory → keyword search must not hit an invite_only Space.
    // Entering the exact cx:space ID can resolve it (with invite proof).
    expect(true).toBe(true);
  });

  test.skip("directory: locked cross-space ref shows LazyLinkBadge only", async ({ page }) => {
    // /directory → result with access=locked → row carries a
    // lazy-link-badge.
    // Title, members, and counts must not be exposed.
    expect(true).toBe(true);
  });

  // ---- Capability approval workflow ----
  // claude-design: desktop/space-admin.html
  // spec: authz/capabilities.md
  test.skip("space-admin: capability approval pending until 2 of 3 admins sign", async ({ page }) => {
    // /space/:id/admin → grant-explanation → approve agent.
    // After one admin approval, status is pending 1/2; only the second
    // approval moves it to accept.
    expect(true).toBe(true);
  });

  // ---- Audit — projection origin / conflict trail ----
  // claude-design: desktop/audit.html
  // spec: sync/operations-sync.md
  test.skip("audit: conflict trail shows winner + superseded events", async ({ page }) => {
    // /audit → conflict-trail renders Mei (winner) and Alice (superseded).
    // Clicking conflict-restore-button creates a new cx.flow.move to
    // rewrite the entry.
    expect(true).toBe(true);
  });

  // ---- Applet / Agent / Portal Space ----
  // claude-design: desktop/applets.html
  // spec: extensions/applet-integration.md
  test.skip("applets: register new applet writes signed cx.applet.registration", async ({ page }) => {
    // /applets → fill in service DID / namespace / capability → submit.
    // Assert the mock applet registration succeeds; after the Bot Actor
    // joins the Space it can only write authorized event kinds.
    expect(true).toBe(true);
  });

  test.skip("applets: agent capability approval writes signed event chain", async ({ page }) => {
    // The Researcher Agent's read_flow request → two-admin approval →
    // subsequent agent writes still require signatures.
    expect(true).toBe(true);
  });

  // ---- WebRTC call ----
  // claude-design: desktop/call.html
  // spec: crypto-media/webrtc-signaling.md
  test.skip("call: SFU mode never enters plaintext path; recording requires explicit grant", async ({ page }) => {
    // /call → default SFU + E2EE media; the SFU never holds plaintext.
    // The record button is disabled when the capability is missing.
    expect(true).toBe(true);
  });

  // ---- Push gateway masking ----
  // claude-design: desktop/inbox.html, mobile/inbox.html
  // spec: discovery/push-notifications.md, crypto-media/devices-and-auth.md §5
  test.skip("push gateway only ships background_sync_needed payload", async ({ page }) => {
    // Simulate the payload the push gateway sees: only target_did +
    // event_type + urgency.
    // Must not contain sender handle / Space title / message body /
    // collapse key.
    expect(true).toBe(true);
  });
});
