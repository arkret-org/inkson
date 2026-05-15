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

  test("cross-signing: Run setup submits cx.cross_signing.publish.v1 into the principal control space", async ({
    page,
  }) => {
    // D2 — formerly unwritten. The verify-device panel now runs the
    // CrossSigningExecutor locally (PSK/SSK/USK gen + SDK-validated
    // binding signatures + persist to a SecureKeyStore), then submits
    // the publish content as `cx.cross_signing.publish.v1` into the
    // principal control space (`cx:space:control:<did>`). This test
    // catches regressions in: (a) the executor's wire-shape contract,
    // (b) the control-space pinning, (c) the SDK binding alg field, and
    // (d) the local-state writeback that keeps the panel's status line
    // hydrated across reloads.
    await page.addInitScript(() => {
      if (localStorage.getItem("yougen.config.v1")) {
        return;
      }
      localStorage.setItem(
        "yougen.config.v1",
        JSON.stringify({
          server_url: "https://local.host",
          account_did: "did:web:alice.example",
          device_id: "cx:device:01964137-0000-7000-8000-0000000000a1",
          session_token: "sx:e2e-token",
        }),
      );
    });
    await page.goto("/verify-device", { waitUntil: "domcontentloaded", timeout: 120_000 });
    await expect(page.getByTestId("verify-device-panel")).toBeVisible({ timeout: 60_000 });

    // Step 1: build the plan. The panel populates the steps list and
    // unlocks the Run setup button below.
    await page.getByTestId("setup-cross-signing").click();
    await expect(page.getByTestId("cross-signing-plan")).toBeVisible();

    // Step 2: capture the cx.cross_signing.publish.v1 submission before
    // it fires so we don't race the spawn task.
    const publishPromise = page.waitForRequest((request) => {
      if (request.method() !== "POST" || !request.url().endsWith("/api/v1/events")) {
        return false;
      }
      const body = request.postDataJSON?.() as Record<string, unknown> | undefined;
      return body?.kind === "cx.cross_signing.publish.v1";
    });

    await page.getByTestId("run-cross-signing-setup").click();

    const publishRequest = await publishPromise;
    const body = publishRequest.postDataJSON() as Record<string, unknown>;
    expect(body.kind).toBe("cx.cross_signing.publish.v1");

    // The envelope MUST target the principal control space (spec
    // key-management.md §4.1). Yougen derives it via
    // `cx:space:control:<actor_did>`.
    expect(body.space_id).toBe("cx:space:control:did:web:alice.example");

    // Drill into the publish content payload: the executor MUST emit a
    // structurally complete publish (3 keys + binding + generation).
    const payload = body.payload as Record<string, unknown>;
    expect(payload.principal_id).toBe("did:web:alice.example");
    expect(payload.generation).toBe(1);
    const psk = payload.principal_signing_key as Record<string, unknown>;
    expect(psk.alg).toBe("EdDSA");
    expect(typeof psk.public_key).toBe("string");
    expect((psk.public_key as string).startsWith("z")).toBe(true); // multibase btc58
    const ssk = payload.self_signing_key as Record<string, unknown>;
    const sskBinding = ssk.binding as Record<string, unknown>;
    expect(sskBinding.alg).toBe("EdDSA");
    expect(typeof sskBinding.signature).toBe("string");
    expect((sskBinding.signature as string).length).toBeGreaterThan(0);
    const usk = payload.user_signing_key as Record<string, unknown>;
    const uskBinding = usk.binding as Record<string, unknown>;
    expect(uskBinding.alg).toBe("EdDSA");

    // SSK and USK MUST be distinct keys; reusing one for both breaks
    // the trust chain.
    const sskKey = ssk as Record<string, unknown>;
    const uskKey = usk as Record<string, unknown>;
    expect(sskKey.public_key).not.toBe(uskKey.public_key);

    // After submit, the UI shows the publish event id.
    await expect(page.getByTestId("cross-signing-publish-id")).toBeVisible({ timeout: 60_000 });
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
  test("recovery: encrypted vault rekey rewrites cipher blob client-side", async ({ page }) => {
    // D1 — formerly skipped. The recovery view stretches the passphrase
    // with Argon2id on the device and uploads ONLY the ciphertext blob
    // (+ random salt + nonce) to PUT /api/v1/keys/backups/{id}. The
    // server never witnesses the plaintext passphrase. We assert this
    // by intercepting the upload and checking the wire body.
    const PASSPHRASE = "correct-horse-battery-staple-7";

    await page.goto("/recovery", { waitUntil: "domcontentloaded", timeout: 120_000 });
    await expect(page.getByTestId("vault-section")).toBeVisible({ timeout: 60_000 });

    // Watch for the PUT before we trigger it so we don't race the
    // browser. The mock above returns `{status: "stored"}` so the UI
    // reaches the success branch.
    const uploadPromise = page.waitForRequest((request) => {
      return (
        request.method() === "PUT" && /\/api\/v1\/keys\/backups\//.test(request.url())
      );
    });

    await page.getByTestId("vault-passphrase").fill(PASSPHRASE);
    await page.getByTestId("vault-passphrase-confirm").fill(PASSPHRASE);
    await page.getByTestId("vault-rekey").click();

    const request = await uploadPromise;
    const raw = request.postData() ?? "";
    expect(raw, "upload body must not be empty").not.toBe("");
    const body = JSON.parse(raw);

    // Wire-shape sanity: the body MUST declare Argon2id + XChaCha20-
    // Poly1305 and carry a ciphertext + digest. Without these the
    // recovery layer is not in spec.
    expect(body.encryption?.kdf?.name).toBe("argon2id");
    expect(body.encryption?.aead?.name).toBe("xchacha20_poly1305");
    expect(typeof body.ciphertext).toBe("string");
    expect(body.ciphertext.length).toBeGreaterThan(0);
    expect(typeof body.ciphertext_digest).toBe("string");

    // The core privacy claim: the passphrase MUST NOT appear anywhere in
    // the upload. Argon2id is one-way + the AEAD blob is random-keyed,
    // so any substring match would indicate a leak.
    expect(raw).not.toContain(PASSPHRASE);
    // Equally, the placeholder demo salt/nonce from the deprecated
    // builder must not leak through if a regression swaps back to it.
    expect(raw).not.toContain("yougen_demo_salt");
    expect(raw).not.toContain("yougen_demo_nonce");
    expect(raw).not.toContain("BASE64URL_OPAQUE_BLOB_PLACEHOLDER");

    await expect(page.getByTestId("vault-status")).toContainText(/Uploaded backup|stored/i, {
      timeout: 60_000,
    });
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
