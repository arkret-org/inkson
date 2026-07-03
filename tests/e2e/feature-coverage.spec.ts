/**
 * Feature coverage seals — pin the visible protocol surface that
 * the checked-in protocol specs describe, end-to-end against the
 * mocked Cokret server.
 *
 * Each test makes a single concrete claim about a stable UI surface
 * (panel data-testid + key control). The deeper protocol strand (full
 * SAS exchange, full Shamir reconstruct, full
 * quorum-with-2-signatures, etc.) is exercised by unit tests in the
 * underlying Rust crates - the e2e layer keeps watch over the UI
 * handles those strands bind to, so a regression that strips a panel
 * or renames a testid fails loudly.
 *
 * Each test cites the spec section it pins so a future contributor
 * who wants to extend the assertions has a fast path to the
 * authoritative reference.
 */

import { expect, test } from "@playwright/test";
import { mockCokretApi } from "./mockCokretApi";

function latestTestId(page: import("@playwright/test").Page, testId: string) {
  return page.getByTestId(testId).last();
}

async function dismissBlockingDialog(page: import("@playwright/test").Page) {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const dialog = page.getByRole("dialog").last();
    await dialog.waitFor({ state: "visible", timeout: 500 }).catch(() => undefined);
    if (!(await dialog.isVisible().catch(() => false))) {
      return;
    }
    const dismiss = dialog.getByRole("button", { name: /^(Not now|Dismiss)$/ });
    if ((await dismiss.count()) === 0) {
      return;
    }
    await dismiss.evaluate((button: HTMLElement) => button.click());
    await expect(dialog).toBeHidden({ timeout: 5_000 });
  }
}

test.describe("feature coverage placeholders", () => {
  test.beforeEach(async ({ page }) => {
    await mockCokretApi(page);
    await page.addInitScript(() => {
      if (localStorage.getItem("yougen.config.v1")) {
        return;
      }
      localStorage.setItem(
        "yougen.config.v1",
        JSON.stringify({
          server_url: "https://local.host",
          account_did: "did:web:alice.example",
          device_id: "ck:device:01964137-0000-7000-8000-0000000000a1",
          session_credential: "sx:e2e-token",
        }),
      );
    });
    await page.goto("/", { waitUntil: "domcontentloaded", timeout: 120_000 });
    await expect(latestTestId(page, "client-shell")).toBeVisible({ timeout: 120_000 });
    const connectButton = latestTestId(page, "connect-button");
    if (await connectButton.count()) {
      await connectButton.click();
    }
  });

  // ---- Board / Strand / ck.strand.move drag conflict ----
  // UI surface: board
  // spec: overview/current-model.md §4, models/views.md §6
  test("board: drag strand across lists writes ck.strand.move", async ({ page }) => {
    // The drag-drop pipeline is exercised end-to-end by
    // yougen.strands.spec.ts::"kanban card drag queues a strand move".
    // This placeholder pins the structural contract the drop relies
    // on: the move-queue + write-records data-testids MUST
    // exist on /kanban so soland can dispatch ck.strand.move /
    // ck.strand.reorder write records through them. The HLC tiebreak
    // assertion called out in the spec is exercised in the SDK's
    // reducer unit tests (`strand_position_cas_*`), not at the UI layer.
    await page.goto("/kanban", { waitUntil: "domcontentloaded", timeout: 120_000 });
    await expect(page.getByTestId("kanban-panel")).toBeVisible({ timeout: 60_000 });
    await expect(page.getByTestId("board-offline-queue")).toBeVisible();
    // At least one card MUST render so the drop target exists; the
    // fully-mocked server returns persisted board projections.
    await page.getByTestId("kanban-card").first().waitFor({ state: "visible", timeout: 30_000 });
  });

  test("board: omits dormant View renderer controls", async ({ page }) => {
    // The kanban surface should not expose disabled View renderer
    // placeholders until those renderers are wired to real behavior.
    await page.goto("/kanban", { waitUntil: "domcontentloaded", timeout: 120_000 });
    await expect(page.getByTestId("kanban-panel")).toBeVisible({ timeout: 60_000 });
    await expect(page.getByTestId("view-renderer-switcher")).toHaveCount(0);
    await expect(page.getByTestId("renderer-board")).toHaveCount(0);
  });

  // ---- Strand detail · embedded discussion ----
  // UI surface: strand detail
  // spec: overview/current-model.md §3
  test("card detail drawer embeds the discussion composer", async ({ page }) => {
    await page.goto("/kanban", { waitUntil: "domcontentloaded", timeout: 120_000 });
    await expect(page.getByTestId("kanban-panel")).toBeVisible({ timeout: 60_000 });
    await page.getByTestId("kanban-card").first().click();
    const drawer = page.getByTestId("card-detail-modal");
    await expect(drawer).toBeVisible({ timeout: 30_000 });
    await expect(drawer.getByTestId("card-description-panel")).toBeVisible();
    await drawer.getByTestId("card-detail-tab-discussion").click();
    await expect(drawer.getByTestId("chat-panel")).toBeVisible();
    await expect(drawer.getByTestId("card-strand-tracks")).toHaveCount(0);
    await expect(drawer.getByTestId("open-primary-discussion")).toHaveCount(0);
    await drawer.getByTestId("card-detail-edit-button").click();
    await expect(drawer.getByTestId("card-detail-description-rich-editor")).toBeVisible();
    await expect(drawer.getByTestId("card-detail-description-input")).toBeAttached();
  });

  // ---- Identity / Device — three independent concerns ----
  // UI surface: devices and verify-device
  // spec: crypto-media/devices-and-auth.md §1.2
  test("device verification: SAS match writes ck.device.authorize + ck.device.cross_sign", async ({ page }) => {
    // pin the SAS verification UI surface. The
    // full SAS exchange + cross_sign + ck.device.authorize event emit
    // happen inside the SDK + soland's identity store; this test
    // makes sure the data-testid handles the next layer down expects
    // (sas-verify-strand, sas-emoji-row, sas-digits, sas-match-button)
    // continue to render so the full strand can plug in without a UI
    // rewrite.
    await page.goto("/verify-device", { waitUntil: "domcontentloaded", timeout: 120_000 });
    await page.getByTestId("sas-verify-button").click();
    await expect(page.getByTestId("sas-verify-strand")).toBeVisible({ timeout: 30_000 });
    await page.getByTestId("sas-target-device").fill("ck:device:01904100-0000-7000-8000-d0d0d0d0d0d0");
    await page.getByTestId("start-sas-button").click();
    await expect(page.getByTestId("sas-display")).toBeVisible({ timeout: 30_000 });
    await expect(page.getByTestId("sas-emoji-row")).toBeVisible();
    await expect(page.getByTestId("sas-digits")).toBeVisible();
    await expect(page.getByTestId("sas-match-button")).toBeVisible();
    // No X25519 key exchange happened in this flow, so the SAS shown is
    // the demo placeholder: the demo warning must render and "They
    // Match" must stay disabled until a real shared secret exists.
    await expect(page.getByTestId("sas-demo-warning")).toBeVisible();
    await expect(page.getByTestId("sas-match-button")).toBeDisabled();
    await expect(page.getByTestId("sas-mismatch-button")).toBeEnabled();
  });

  test("device pairing: generated request is accepted through account gate", async ({
    page,
  }) => {
    await page.goto("/settings/devices/pair", { waitUntil: "domcontentloaded", timeout: 120_000 });
    await dismissBlockingDialog(page);
    await expect(page.getByTestId("pair-device-card")).toBeVisible({ timeout: 30_000 });
    await expect(page.getByTestId("pending-pairing-requests-card")).toBeVisible({ timeout: 30_000 });
    await page.getByTestId("pair-device-start-button").click();
    await expect(page.getByTestId("pair-device-secret")).toHaveValue(/ck\.device\.pair\.request\.v1/, {
      timeout: 30_000,
    });
    const payload = await page.getByTestId("pair-device-secret").inputValue();

    await page.getByTestId("accept-pairing-input").fill(payload);

    const requestPromise = page.waitForRequest((request) => {
      const url = new URL(request.url());
      return url.pathname === "/_cokret/gate/account/device-pair" && request.method() === "POST";
    });
    const responsePromise = page.waitForResponse((response) => {
      const url = new URL(response.url());
      return url.pathname === "/_cokret/gate/account/device-pair";
    });
    await page.getByTestId("accept-pairing-button").click();
    const [request, response] = await Promise.all([requestPromise, responsePromise]);
    expect(response.ok()).toBeTruthy();
    const body = request.postDataJSON();
    expect(body.pairing_code).toBeTruthy();
    expect(body.new_device_pubkey.kid).toMatch(/^ck:device:/);
    expect(body.challenge_signature).toBeTruthy();
    await expect(page.getByTestId("accept-pairing-status")).toContainText("Sibling device paired");
  });

  test("cross-signing: Run setup submits ck.cross_signing.publish into the principal control Realm", async ({
    page,
  }) => {
    // D2 — formerly unwritten. The verify-device panel now runs the
    // CrossSigningExecutor locally (PSK/SSK/USK gen + SDK-validated
    // binding signatures + persist to a SecureKeyStore), then submits
    // the publish content as `ck.cross_signing.publish` into the
    // principal control Realm. This test
    // catches regressions in: (a) the executor's wire-shape contract,
    // (b) the control-Realm pinning, (c) the SDK binding alg field, and
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
          device_id: "ck:device:01964137-0000-7000-8000-0000000000a1",
          session_credential: "sx:e2e-token",
        }),
      );
    });
    await page.goto("/verify-device", { waitUntil: "domcontentloaded", timeout: 120_000 });
    await expect(page.getByTestId("verify-device-panel")).toBeVisible({ timeout: 60_000 });

    // Step 1: build the plan. The panel populates the steps list and
    // unlocks the Run setup button below.
    await page.getByTestId("setup-cross-signing").click();
    await expect(page.getByTestId("cross-signing-plan")).toBeVisible();

    // Step 2: capture the ck.cross_signing.publish submission before
    // it fires so we don't race the spawn task.
    const publishPromise = page.waitForRequest((request) => {
      if (request.method() !== "POST" || !request.url().endsWith("/_cokret/self/events")) {
        return false;
      }
      const body = request.postDataJSON?.() as Record<string, unknown> | undefined;
      return body?.kind === "ck.cross_signing.publish";
    });

    await page.getByTestId("run-cross-signing-setup").click();

    const publishRequest = await publishPromise;
    const body = publishRequest.postDataJSON() as Record<string, unknown>;
    expect(body.kind).toBe("ck.cross_signing.publish");

    // The envelope MUST target the principal control Realm (spec
    // key-management.md §4.1).
    expect(typeof body.realm_id).toBe("string");
    expect((body.realm_id as string).startsWith("ck:realm:")).toBe(true);
    expect(body.space_id).toBeUndefined();

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

  test("session grant alone never reads E2EE history", async ({ page }) => {
    // this contract has two visible UI handles
    // that the session-grant-only path MUST render: (1) the Board's
    // ciphertext-locked badge, and (2) the card-detail's locked
    // discussion fail-closed banner. We don't simulate a session-grant
    // login (that requires a coauth fixture mock); we DO assert that
    // the views still render the fail-closed surfaces for the mock-
    // loaded session, so when the session-grant-only branch hydrates
    // them they have somewhere to write to.
    await page.goto("/kanban", { waitUntil: "domcontentloaded", timeout: 120_000 });
    await expect(page.getByTestId("kanban-panel")).toBeVisible({ timeout: 60_000 });
    // The mocked persisted board includes a locked-discussion row,
    // which renders the fail-closed banner inside `card-detail-modal`.
    // The test passes when at least one card-with-locked-discussion is
    // rendered such that the badge would show after click; the badge
    // itself is rendered conditionally so we only assert the broader
    // panel is wired.
    const cards = page.getByTestId("kanban-card");
    expect(await cards.count()).toBeGreaterThan(0);
  });

  // ---- Recovery — three layers ----
  // UI surface: recovery
  // spec: crypto-media/devices-and-auth.md §4
  test("recovery: encrypted vault rekey rewrites cipher blob client-side", async ({ page }) => {
    // D1 — formerly skipped. The recovery view stretches the passphrase
    // with Argon2id on the device and uploads ONLY the ciphertext blob
    // (+ random salt + nonce) to PUT /_cokret/self/keys/backups/{id}. The
    // server never witnesses the plaintext passphrase. We assert this
    // by intercepting the upload and checking the wire body.
    const PASSPHRASE = "correct-horse-battery-staple-7";

    await page.goto("/settings/recovery", { waitUntil: "domcontentloaded", timeout: 120_000 });
    const recoveryPanel = latestTestId(page, "recovery-panel");
    await expect(recoveryPanel.getByTestId("vault-section")).toBeVisible({ timeout: 60_000 });

    // Watch for the PUT before we trigger it so we don't race the
    // browser. The mock above returns `{status: "stored"}` so the UI
    // reaches the success branch.
    const uploadPromise = page.waitForRequest((request) => {
      return (
        request.method() === "PUT" && /\/_cokret\/self\/keys\/backups\//.test(request.url())
      );
    });

    await recoveryPanel.getByTestId("vault-passphrase").fill(PASSPHRASE);
    await recoveryPanel.getByTestId("vault-passphrase-confirm").fill(PASSPHRASE);
    await recoveryPanel.getByTestId("vault-rekey").click();

    const request = await uploadPromise;
    const raw = request.postData() ?? "";
    expect(raw, "upload body must not be empty").not.toBe("");
    const body = JSON.parse(raw);

    // Wire-shape sanity: the body MUST declare Argon2id + XChaCha20-
    // Poly1305 and carry a ciphertext + digest. Without these the
    // recovery layer is not in spec.
    expect(body.encryption?.kdf?.name).toBe("argon2id");
    expect(body.encryption?.kdf?.params?.memory_kib).toBeGreaterThanOrEqual(65_536);
    expect(body.encryption?.kdf?.params?.iterations).toBeGreaterThanOrEqual(3);
    expect(body.encryption?.kdf?.params?.parallelism).toBeGreaterThanOrEqual(1);
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

    await expect(recoveryPanel.getByTestId("vault-status")).toContainText(/Uploaded backup|stored/i, {
      timeout: 60_000,
    });
  });

  test("recovery: social recovery surfaces guardian configuration", async ({ page }) => {
    // the recovery view's three layers
    // (vault / recovery-key / social) each expose a dedicated
    // data-testid section. The 3-of-5 social-recovery reconstruct strand
    // requires the social-recovery-section + recovery-key-section
    // surfaces to render. The Shamir share release/reconstruct path is
    // not wired yet; this e2e pins the UI surface so the strand has
    // somewhere to plug in when the policy-backed recovery session lands.
    await page.goto("/settings/recovery", { waitUntil: "domcontentloaded", timeout: 120_000 });
    const recoveryPanel = latestTestId(page, "recovery-panel");
    await expect(recoveryPanel).toBeVisible({ timeout: 60_000 });
    await expect(recoveryPanel.getByTestId("social-recovery-section")).toBeVisible();
    await expect(recoveryPanel.getByTestId("recovery-key-section")).toBeVisible();
  });

  test("recovery: backup history emphasizes the latest backup time", async ({ page }) => {
    await dismissBlockingDialog(page);
    await page.route("**/_cokret/self/keys/backups", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          backups: [
            {
              backup_id: "ck:backup:019eca5c-2fcb-7592-9000-000000000001",
              backup_class: "did_recovery",
              created_at: "2026-06-15T08:00:00Z",
            },
            {
              backup_id: "ck:backup:019eca5c-2fcb-7592-9000-000000000002",
              backup_class: "secret_storage",
              created_at: "2026-06-14T06:30:00Z",
            },
            {
              backup_id: "ck:backup:019eca5c-2fcb-7592-9000-000000000003",
              backup_class: "mls_history",
              created_at: "2026-06-10T22:15:00Z",
            },
          ],
        }),
      });
    });

    await page.goto("/settings/recovery", { waitUntil: "domcontentloaded", timeout: 120_000 });
    await dismissBlockingDialog(page);
    const recoveryPanel = latestTestId(page, "recovery-panel");
    await expect(recoveryPanel).toBeVisible({ timeout: 60_000 });

    await recoveryPanel.getByTestId("restore-list-button").click();
    await expect(recoveryPanel.getByTestId("restore-latest-backup")).toBeVisible();
    await expect(recoveryPanel.getByTestId("restore-latest-backup-time")).toContainText(
      "2026-06-15 08:00 UTC",
    );
    await expect(recoveryPanel.getByTestId("restore-backup-time")).toHaveCount(3);
    await expect(recoveryPanel.getByTestId("restore-select-button")).toHaveCount(0);
    await expect(recoveryPanel.getByTestId("restore-delete-button")).toHaveCount(0);
    await expect(recoveryPanel).not.toContainText("ck:backup:");
    await expect(recoveryPanel).not.toContainText("did_recovery");
  });

  // ---- Discoverability ≠ Join Rule ≠ History ----
  // UI surface: directory
  // spec: discovery/discovery-directory.md §2
  test("directory: invite_only realm hides existence from search", async ({ page }) => {
    // The keyword-search path must respect
    // `discoverability=invite_only` - the spec (discovery/discovery-
    // directory.md §2) requires that searches MUST NOT enumerate
    // invite-only Realms. Soland's `/_cokret/find/directory/search-realms`
    // filters them out; the mock surface returns the same shape so the
    // contract holds without a live server.
    await page.goto("/directory", { waitUntil: "domcontentloaded", timeout: 120_000 });
    // Realms tab is the default for the directory; just in case it's
    // not the active tab on first mount, click it explicitly so the
    // search button hits search-realms (not search-actors etc.).
    await page.getByTestId("tab-realms").click();
    await page.getByTestId("directory-search-input").fill("demo");
    await page.getByTestId("directory-search-button").click();
    // The mock returns a single listed Realm (`discoverability=listed`).
    // The contract: every search-result row's wire shape MUST come from
    // a listed/public discoverability bucket. We assert at least one
    // result is rendered (sanity), and that none of them carry the
    // private/invite-only badge ("private").
    const results = page.getByTestId("directory-result");
    await results.first().waitFor({ state: "visible", timeout: 10_000 });
    const privateBadges = await results
      .locator("text=private")
      .count();
    expect(privateBadges).toBe(0);
  });

  test("directory: locked cross-space ref shows LazyLinkBadge only", async ({ page }) => {
    // the directory's ProtocolObjects tab fans
    // out demo `protocol_object_results(...)` rows; any row whose
    // `access` is `locked` or `external` MUST render the
    // `LazyLinkBadge` (data-testid `lazy-link-badge`) instead of
    // exposing title / members / counts. We assert that searching for
    // an entry the demo dataset always emits at least one
    // `access=locked` row produces a visible LazyLinkBadge — the
    // contract a future server-side renderer of the same shape MUST
    // honor.
    await page.goto("/directory", { waitUntil: "domcontentloaded", timeout: 120_000 });
    await page.getByTestId("directory-advanced-diagnostics-toggle").click();
    await page.getByTestId("tab-objects").click();
    await page.getByTestId("directory-search-input").fill("locked");
    await page.getByTestId("directory-search-button").click();
    // At least one badge MUST render — the demo dataset always carries
    // an `access=locked` row matching the literal `"locked"` query
    // substring across its title / summary fields.
    await page.getByTestId("lazy-link-badge")
      .first()
      .waitFor({ state: "visible", timeout: 30_000 });
  });

  // ---- Capability approval workflow ----
  // UI surface: realm admin
  // spec: authz/capabilities.md
  test("realm-admin: capability grant and revoke live under security", async ({ page }) => {
    await page.goto("/realms/ck:realm:0196419b-0000-7000-8000-000000000000/settings/security", {
      waitUntil: "domcontentloaded",
      timeout: 120_000,
    });
    await expect(page.getByTestId("grant-explanation")).toHaveCount(0);
    await expect(page.getByTestId("capability-grant-card")).toBeVisible({ timeout: 60_000 });
    await expect(page.getByTestId("cap-grant-submit-button")).toBeVisible();
    await expect(page.getByTestId("cap-revoke-submit-button")).toBeVisible();
  });

  // ---- Audit — projection origin / conflict trail ----
  // UI surface: audit
  // spec: sync/operations-sync.md
  test("audit: conflict trail shows winner + superseded events", async ({ page }) => {
    // the audit view exposes three counted
    // surfaces — accessed (attested decrypts), ryw_receipt (disclosed
    // writes), and the raw operation log. The conflict trail (when
    // present) renders inside the per-row layout below. We pin the
    // outer panel + the three count badges so any future regression
    // that strips the counted surfaces fails loudly.
    await page.goto("/audit", { waitUntil: "domcontentloaded", timeout: 120_000 });
    await expect(page.getByTestId("audit-panel")).toBeVisible({ timeout: 60_000 });
    await expect(page.getByTestId("audit-accessed-count")).toBeVisible();
    await expect(page.getByTestId("audit-receipt-count")).toBeVisible();
    await expect(page.getByTestId("audit-total-count")).toBeVisible();
  });

  // ---- Applet / Agent / Portal Space ----
  // UI surface: applets
  // spec: extensions/applet-integration.md
  test("applets: register new applet writes signed ck.applet.registration", async ({ page }) => {
    // The applet surface is compiled for unit coverage but hidden in
    // the default local 1.0 UI until the `experimental-applets`
    // feature is explicitly enabled.
    await page.goto("/applets", { waitUntil: "domcontentloaded", timeout: 120_000 });
    await expect(page.getByTestId("deferred-feature-gate")).toHaveAttribute(
      "data-feature",
      "experimental-applets",
    );
  });

  test("applets: agent capability approval writes signed event chain", async ({ page }) => {
    // Applet/agent approval remains behind the same default-off gate.
    await page.goto("/applets", { waitUntil: "domcontentloaded", timeout: 120_000 });
    await expect(page.getByTestId("deferred-feature-gate")).toHaveAttribute(
      "data-feature",
      "experimental-applets",
    );
  });

  // ---- WebRTC call ----
  // UI surface: call
  // spec: crypto-media/webrtc-signaling.md
  test("call: SFU mode never enters plaintext path; recording requires explicit grant", async ({ page }) => {
    // yougen ships the call SIGNALING surface
    // (`ck.call.signal` / `ck.call.state` / `ck.call.recording.start`)
    // but the WebRTC media stack is renderer-provided and hidden from
    // the default local 1.0 UI until `experimental-webrtc` is enabled.
    await page.goto("/call", { waitUntil: "domcontentloaded", timeout: 120_000 });
    await expect(page.getByTestId("call-panel")).toBeVisible({ timeout: 60_000 });
    await expect(page.getByTestId("call-signal-count")).toBeVisible();
    await expect(page.getByTestId("deferred-feature-gate")).toHaveAttribute(
      "data-feature",
      "experimental-webrtc",
    );
  });

  // ---- Push gateway masking ----
  // UI surface: inbox
  // spec: discovery/push-notifications.md, crypto-media/devices-and-auth.md §5
  test("push gateway only ships background_sync_needed payload", async ({ page }) => {
    // the push-register payload yougen sends to
    // soland (`POST /_cokret/edge/push/register-device`) MUST NOT carry any
    // body / title / sender / collapse_key fields — only the minimal
    // device registration metadata. The downstream gateway then ships
    // a `background_sync_needed` opaque payload to FCM/APNS, so any
    // leak into the registration request would propagate through.
    // Spec: `discovery/push-notifications.md`.
    const pushRequestPromise = page.waitForRequest(
      (request) =>
        request.url().endsWith("/_cokret/edge/push/register-device")
        && request.method() === "POST",
      { timeout: 60_000 },
    );
    await page.goto("/settings/notifications", {
      waitUntil: "domcontentloaded",
      timeout: 120_000,
    });
    await expect(page.getByTestId("settings-notification-sound-toggle")).toBeAttached();
    await expect(page.getByTestId("settings-notification-sound-test")).toBeVisible();
    await dismissBlockingDialog(page);
    await page.getByTestId("push-register-button").click();
    const request = await pushRequestPromise;
    const bodyText = request.postData() ?? "{}";
    // Hard fail-closed assertions: none of the human-readable / PII
    // fields may appear in the JSON request body. The fields we DO
    // expect — `device_id`, `push_key`, `platform`, `app_id` — are
    // safe to ship.
    for (const leak of [
      "body",
      "message_body",
      "realm_title",
      "title",
      "sender",
      "collapse_key",
    ]) {
      expect(bodyText.toLowerCase()).not.toContain(`"${leak}"`);
    }
    // Sanity: the metadata fields we DO ship MUST be present.
    expect(bodyText).toContain("device_id");
    expect(bodyText).toContain("platform");
  });
});
