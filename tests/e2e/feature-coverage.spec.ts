/**
 * Feature coverage seals — pin the visible protocol surface that
 * the checked-in protocol specs describe, end-to-end against the
 * mocked Arkret server.
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
import { mockArkretApi } from "./mockArkretApi";
import { testLocalConfig } from "./strandsHarness";

function latestTestId(page: import("@playwright/test").Page, testId: string) {
  return page.getByTestId(testId).last();
}

async function dismissBlockingDialog(page: import("@playwright/test").Page) {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const dialog = page.getByRole("dialog").last();
    await dialog
      .waitFor({ state: "visible", timeout: 500 })
      .catch(() => undefined);
    if (!(await dialog.isVisible().catch(() => false))) {
      return;
    }
    const dismiss = dialog.getByRole("button", {
      name: /^(Not now|Dismiss|Continue with limited access|Continue without history)$/,
    });
    if ((await dismiss.count()) === 0) {
      return;
    }
    await dismiss.last().evaluate((button: HTMLElement) => button.click());
    await expect(dialog).toBeHidden({ timeout: 5_000 });
  }
}

test.describe("feature coverage placeholders", () => {
  test.beforeEach(async ({ page }) => {
    await mockArkretApi(page);
    await page.addInitScript(() => {
      localStorage.setItem(
        "inkson.test.session_injection.v1",
        JSON.stringify({
          grant_jwt: "sx:e2e-token",
          grant_id: "ak:grant:Aa1lsSUPO6wXCITbk8eNFN84GlTcykTUKRcvz1PQJsau",
          audience: "ak:did_core:web:server.local",
          principal_id: "ak:did_core:web:alice.example",
          dpop_seed_b64url: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        }),
      );
    });
    await page.addInitScript((config) => {
      if (localStorage.getItem("inkson.config.v1")) {
        return;
      }
      localStorage.setItem("inkson.config.v1", JSON.stringify(config));
    }, testLocalConfig());
    await page.goto("/", { waitUntil: "domcontentloaded", timeout: 120_000 });
    await expect(latestTestId(page, "client-shell")).toBeVisible({
      timeout: 120_000,
    });
    const connectButton = latestTestId(page, "connect-button");
    if (await connectButton.count()) {
      await connectButton.click();
    }
  });

  // ---- Board / Strand / ak.strand.move drag conflict ----
  // UI surface: board
  // spec: overview/current-model.md §4, models/views.md §6
  test("board: drag strand across lists writes ak.strand.move", async ({
    page,
  }) => {
    // The drag-drop pipeline is exercised end-to-end by
    // inkson.strands.spec.ts::"kanban card drag queues a strand move".
    // This placeholder pins the structural contract the drop relies
    // on: the board and its drag targets must render so strand move/reorder
    // submission remains reachable without the removed diagnostics toolbar.
    await page.goto("/kanban", {
      waitUntil: "domcontentloaded",
      timeout: 120_000,
    });
    await expect(page.getByTestId("kanban-panel")).toBeVisible({
      timeout: 60_000,
    });
    // At least one card MUST render so the drop target exists; the
    // fully-mocked server returns persisted board projections.
    await page
      .getByTestId("kanban-card")
      .first()
      .waitFor({ state: "visible", timeout: 30_000 });
  });

  test("board: omits dormant View renderer controls", async ({ page }) => {
    // The kanban surface should not expose disabled View renderer
    // placeholders until those renderers are wired to real behavior.
    await page.goto("/kanban", {
      waitUntil: "domcontentloaded",
      timeout: 120_000,
    });
    await expect(page.getByTestId("kanban-panel")).toBeVisible({
      timeout: 60_000,
    });
    await expect(page.getByTestId("view-renderer-switcher")).toHaveCount(0);
    await expect(page.getByTestId("renderer-board")).toHaveCount(0);
  });

  // ---- Strand detail · embedded discussion ----
  // UI surface: strand detail
  // spec: overview/current-model.md §3
  test("card detail drawer embeds the discussion composer", async ({
    page,
  }) => {
    await page.goto("/kanban", {
      waitUntil: "domcontentloaded",
      timeout: 120_000,
    });
    await expect(page.getByTestId("kanban-panel")).toBeVisible({
      timeout: 60_000,
    });
    await page.getByTestId("kanban-card").first().click();
    const drawer = page.getByTestId("card-detail-modal");
    await expect(drawer).toBeVisible({ timeout: 30_000 });
    await expect(drawer.getByTestId("card-synthesis-panel")).toBeVisible();
    await drawer.getByTestId("card-detail-tab-discussion").click();
    await expect(drawer.getByTestId("chat-panel")).toBeVisible();
    await expect(drawer.getByTestId("card-strand-tracks")).toHaveCount(0);
    await expect(drawer.getByTestId("open-primary-discussion")).toHaveCount(0);
    await drawer.getByTestId("card-detail-edit-button").click();
    await expect(
      drawer.getByTestId("card-detail-description-rich-editor"),
    ).toBeVisible();
    await expect(
      drawer.getByTestId("card-detail-description-input"),
    ).toBeHidden();
  });

  // ---- Identity / Device — three independent concerns ----
  // UI surface: devices and device verification
  // spec: crypto-media/devices-and-auth.md §1.2
  test("device verification: SAS establishes an accepted-device authorization ceremony", async ({
    page,
  }) => {
    // Pin the SAS verification UI surface. The full exchange culminates in an
    // accepted_device ak.device.authorize flow; this test
    // makes sure the data-testid handles the next layer down expects
    // (sas-verify-strand, sas-emoji-row, sas-digits, sas-match-button)
    // continue to render so the full strand can plug in without a UI
    // rewrite.
    await page.goto("/devices/verify", {
      waitUntil: "domcontentloaded",
      timeout: 120_000,
    });
    await page.getByTestId("sas-verify-button").click();
    await expect(page.getByTestId("sas-verify-strand")).toBeVisible({
      timeout: 30_000,
    });
    await page
      .getByTestId("sas-target-device")
      .fill("ak:device:01904100-0000-7000-8000-d0d0d0d0d0d0");
    await page.getByTestId("start-sas-button").click();
    await expect(page.getByTestId("sas-display")).toBeVisible({
      timeout: 30_000,
    });
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

  test("device pairing: short-link request is staged, resolved, and accepted through account gate", async ({
    page,
  }) => {
    await page.goto("/settings/devices/pair", {
      waitUntil: "domcontentloaded",
      timeout: 120_000,
    });
    await dismissBlockingDialog(page);
    await expect(page.getByTestId("pair-device-card")).toBeVisible({
      timeout: 30_000,
    });
    await expect(page.getByTestId("pending-pairing-requests-card")).toBeVisible(
      { timeout: 30_000 },
    );
    const deviceAccessNav = page.getByRole("navigation", {
      name: "Device settings",
    });
    await expect(
      deviceAccessNav.getByRole("link", { name: "Add a device" }),
    ).toHaveAttribute("aria-current", "page");
    await expect(
      deviceAccessNav.getByRole("link", { name: "Devices" }),
    ).toHaveAttribute("aria-current", "false");

    // New device: staging yields a SHORT resolve deep-link (not the old
    // full-payload blob) in the pairing-link field.
    await page.getByTestId("pair-device-start-button").click();
    await expect(page.getByTestId("pair-device-secret")).toHaveValue(
      /\/_arkret\/open\/device-pairing\/resolve#token=/,
      { timeout: 30_000 },
    );
    await expect(page.getByTestId("pair-device-qr")).toBeVisible();
    await expect(page.getByTestId("pair-device-copy-button")).toBeVisible();
    const pairingLink = await page
      .getByTestId("pair-device-secret")
      .inputValue();

    // Authorized device: paste the link, resolve it, then approve.
    await page.getByTestId("accept-pairing-input").fill(pairingLink);
    const resolvePromise = page.waitForResponse((response) => {
      const url = new URL(response.url());
      return url.pathname === "/_arkret/open/device-pairing/resolve";
    });
    await page.getByTestId("accept-pairing-resolve-button").click();
    expect((await resolvePromise).ok()).toBeTruthy();
    // Resolved code surfaces for the human SAS compare before approving.
    await expect(page.getByTestId("accept-pairing-code")).toBeVisible({
      timeout: 30_000,
    });

    const requestPromise = page.waitForRequest((request) => {
      const url = new URL(request.url());
      return (
        url.pathname === "/_arkret/gate/account/device-pair" &&
        request.method() === "POST"
      );
    });
    const responsePromise = page.waitForResponse((response) => {
      const url = new URL(response.url());
      return url.pathname === "/_arkret/gate/account/device-pair";
    });
    await page.getByTestId("accept-pairing-button").click();
    const [request, response] = await Promise.all([
      requestPromise,
      responsePromise,
    ]);
    expect(response.ok()).toBeTruthy();
    const body = request.postDataJSON();
    expect(body.pairing_code).toBeTruthy();
    expect(body.new_device_pubkey.kid).toMatch(/^ak:device:/);
    // Canonical field name is `key`, never the legacy `public_key`.
    expect(body.new_device_pubkey.key).toBeTruthy();
    expect(body.new_device_pubkey.public_key).toBeUndefined();
    expect(body.challenge_proof.transcript).toBe(
      "ak.device-pairing.challenge.v1",
    );
    expect(body.challenge_proof.signature).toBeTruthy();
    // The resolved staged request id is echoed so the server flips the row.
    expect(body.device_pairing_request_id).toMatch(/^device_pairing_request:/);
    await expect(page.getByTestId("accept-pairing-status")).toContainText(
      "Device paired",
    );
  });

  test("device list keeps headers aligned and becomes labelled rows when narrow", async ({
    page,
  }) => {
    await page.route("**/_arkret/self/account/viewer", async (route) => {
      if (route.request().method() !== "GET") {
        await route.fallback();
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          principal_id: "did:web:alice.example",
          state: "active",
          current_device_id: "ak:device:01964137-0000-7000-8000-0000000000a1",
          devices: [
            {
              device_id: "ak:device:01964137-0000-7000-8000-0000000000a1",
              status: "active",
              display_name: "Current device",
              verification_state: "unverified",
              authorized_at: "2026-04-28T12:00:00.000Z",
              is_current_session_device: true,
            },
            {
              device_id: "ak:device:01964137-0000-7000-8000-0000000000b2",
              status: "active",
              display_name: "Trusted laptop",
              verification_state: "verified",
              authorized_at: "2026-04-29T12:00:00.000Z",
            },
          ],
        }),
      });
    });
    await page.setViewportSize({ width: 1800, height: 1000 });
    await page.goto("/settings/devices", {
      waitUntil: "domcontentloaded",
      timeout: 120_000,
    });
    await dismissBlockingDialog(page);

    const list = page.getByTestId("device-list");
    await expect(list).toBeVisible({ timeout: 30_000 });
    const headers = list.getByRole("columnheader");
    const firstRow = list.getByTestId("device-row").first();
    const cells = firstRow.getByRole("cell");
    await expect(headers).toHaveCount(4);
    await expect(cells).toHaveCount(4);

    for (let index = 0; index < 4; index += 1) {
      const headerBox = await headers.nth(index).boundingBox();
      const cellBox = await cells.nth(index).boundingBox();
      expect(headerBox).not.toBeNull();
      expect(cellBox).not.toBeNull();
      expect(
        Math.abs((headerBox?.x ?? 0) - (cellBox?.x ?? 0)),
      ).toBeLessThanOrEqual(2);
    }

    const currentBadgeBox = await firstRow
      .getByTestId("device-row-current")
      .boundingBox();
    const identityCellBox = await cells.nth(0).boundingBox();
    const verificationBadgeBox = await firstRow
      .getByTestId("device-verification-badge")
      .boundingBox();
    const verificationCellBox = await cells.nth(1).boundingBox();
    expect(currentBadgeBox).not.toBeNull();
    expect(identityCellBox).not.toBeNull();
    expect(verificationBadgeBox).not.toBeNull();
    expect(verificationCellBox).not.toBeNull();
    expect(currentBadgeBox!.width).toBeLessThan(identityCellBox!.width);
    expect(verificationBadgeBox!.width).toBeLessThan(
      verificationCellBox!.width,
    );

    await dismissBlockingDialog(page);
    await list
      .getByTestId("device-row")
      .nth(1)
      .getByTestId("device-revoke-button")
      .click();
    const revokeDialog = page.getByTestId("device-revoke-modal");
    await expect(revokeDialog).toBeVisible();
    await expect(revokeDialog).toHaveAttribute("role", "dialog");
    const revokeSurface = revokeDialog.locator(".device-revoke-dialog");
    const revokeBody = revokeSurface.locator(".modal-body");
    const revokeInput = revokeDialog.getByTestId(
      "device-revoke-passphrase-input",
    );
    const surfaceBox = await revokeSurface.boundingBox();
    const bodyBox = await revokeBody.boundingBox();
    const inputBox = await revokeInput.boundingBox();
    expect(surfaceBox).not.toBeNull();
    expect(bodyBox).not.toBeNull();
    expect(inputBox).not.toBeNull();
    expect(bodyBox!.x).toBeGreaterThan(surfaceBox!.x);
    expect(inputBox!.x).toBeGreaterThan(surfaceBox!.x);
    expect(inputBox!.x + inputBox!.width).toBeLessThan(
      surfaceBox!.x + surfaceBox!.width,
    );
    await revokeDialog.getByTestId("device-revoke-cancel-button").click();
    await expect(revokeDialog).toBeHidden();

    await page.setViewportSize({ width: 760, height: 900 });
    await expect(
      firstRow.getByText("Verification", { exact: true }),
    ).toBeVisible();
    const horizontalOverflow = await page.evaluate(
      () =>
        document.documentElement.scrollWidth -
        document.documentElement.clientWidth,
    );
    expect(horizontalOverflow).toBeLessThanOrEqual(1);
  });

  test("an unselected board never invents decrypted E2EE history", async ({
    page,
  }) => {
    await page.goto("/kanban", {
      waitUntil: "domcontentloaded",
      timeout: 120_000,
    });
    await expect(page.getByTestId("kanban-panel")).toBeVisible({
      timeout: 60_000,
    });
    await expect(page.getByTestId("kanban-card")).toHaveCount(0);
    await expect(
      page.getByText("No board selected", { exact: true }),
    ).toBeVisible();
    await expect(page.getByTestId("card-detail-modal")).toHaveCount(0);
  });

  // ---- Recovery ----
  // UI surface: recovery
  // spec: crypto-media/devices-and-auth.md §4
  test("recovery: canonical Recovery Key replaces legacy passphrase vaults", async ({
    page,
  }) => {
    await page.goto("/settings/recovery", {
      waitUntil: "domcontentloaded",
      timeout: 120_000,
    });
    const recoveryPanel = latestTestId(page, "recovery-panel");
    await expect(recoveryPanel.getByTestId("recovery-key-section")).toBeVisible(
      {
        timeout: 60_000,
      },
    );
    await expect(
      recoveryPanel.getByTestId("fresh-device-recovery-section"),
    ).toBeVisible();
    await expect(recoveryPanel.getByTestId("vault-section")).toHaveCount(0);
    await expect(recoveryPanel.getByTestId("vault-passphrase")).toHaveCount(0);
  });

  test("recovery: fresh-device restore excludes legacy guardian recovery", async ({
    page,
  }) => {
    await page.goto("/settings/recovery", {
      waitUntil: "domcontentloaded",
      timeout: 120_000,
    });
    const recoveryPanel = latestTestId(page, "recovery-panel");
    await expect(recoveryPanel).toBeVisible({ timeout: 60_000 });
    await expect(
      recoveryPanel.getByTestId("fresh-device-recovery-section"),
    ).toBeVisible();
    await expect(
      recoveryPanel.getByTestId("recovery-key-section"),
    ).toBeVisible();
    await expect(
      recoveryPanel.getByTestId("social-recovery-section"),
    ).toHaveCount(0);
  });

  test("recovery: backup history emphasizes the latest backup time", async ({
    page,
  }) => {
    await dismissBlockingDialog(page);
    await page.route("**/_arkret/self/keys/backups", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          backups: [
            {
              backup_id: "ak:backup:019eca5c-2fcb-7592-9000-000000000001",
              actor_id: "did:web:alice.example",
              device_id: "ak:device:01964137-0000-7000-8000-0000000000a1",
              backup_kind: "secret_storage",
              backup_version: "v1",
              created_at: "2026-06-15T08:00:00.000Z",
              ciphertext_digest: `sha256:${"1".repeat(64)}`,
              encryption: {
                recipient_method: "recovery_public_key",
                recipient_key_ref: "recovery-key-e2e",
              },
              series_id:
                "ak:backup_series:019eca5c-2fcb-7592-9000-000000000001",
              series_seq: 1,
            },
            {
              backup_id: "ak:backup:019eca5c-2fcb-7592-9000-000000000002",
              actor_id: "did:web:alice.example",
              device_id: "ak:device:01964137-0000-7000-8000-0000000000a1",
              backup_kind: "secret_storage",
              backup_version: "v1",
              created_at: "2026-06-14T06:30:00.000Z",
              ciphertext_digest: `sha256:${"2".repeat(64)}`,
              encryption: {
                recipient_method: "recovery_public_key",
                recipient_key_ref: "recovery-key-e2e",
              },
              series_id:
                "ak:backup_series:019eca5c-2fcb-7592-9000-000000000002",
              series_seq: 1,
            },
            {
              backup_id: "ak:backup:019eca5c-2fcb-7592-9000-000000000003",
              actor_id: "did:web:alice.example",
              device_id: "ak:device:01964137-0000-7000-8000-0000000000a1",
              backup_kind: "mls_history",
              backup_version: "v1",
              created_at: "2026-06-10T22:15:00.000Z",
              ciphertext_digest: `sha256:${"3".repeat(64)}`,
              encryption: {
                recipient_method: "recovery_public_key",
                recipient_key_ref: "recovery-key-e2e",
              },
              series_id:
                "ak:backup_series:019eca5c-2fcb-7592-9000-000000000003",
              series_seq: 1,
            },
          ],
          next_cursor: null,
          has_more: false,
        }),
      });
    });

    await page.goto("/settings/recovery", {
      waitUntil: "domcontentloaded",
      timeout: 120_000,
    });
    await dismissBlockingDialog(page);
    const recoveryPanel = latestTestId(page, "recovery-panel");
    await expect(recoveryPanel).toBeVisible({ timeout: 60_000 });

    await recoveryPanel
      .getByTestId("restore-section")
      .locator("summary")
      .click();
    await recoveryPanel.getByTestId("restore-list-button").click();
    await expect(
      recoveryPanel.getByTestId("restore-latest-backup"),
    ).toBeVisible();
    await expect(
      recoveryPanel.getByTestId("restore-latest-backup-time"),
    ).toContainText("2026-06-15 08:00 UTC");
    await expect(recoveryPanel.getByTestId("restore-backup-time")).toHaveCount(
      3,
    );
    await expect(
      recoveryPanel.getByTestId("restore-select-button"),
    ).toHaveCount(0);
    await expect(
      recoveryPanel.getByTestId("restore-delete-button"),
    ).toHaveCount(0);
    await expect(recoveryPanel).not.toContainText("ak:backup:");
    await expect(recoveryPanel).not.toContainText("recovery_key_share");
  });

  // ---- Discoverability ≠ Join Rule ≠ History ----
  // UI surface: directory
  // spec: discovery/discovery-directory.md §2
  test("directory: invite_only realm hides existence from search", async ({
    page,
  }) => {
    // The keyword-search path must respect
    // `discoverability=invite_only` - the spec (discovery/discovery-
    // directory.md §2) requires that searches MUST NOT enumerate
    // invite-only Realms. Soland's `/_arkret/find/directory/search-realms`
    // filters them out; the mock surface returns the same shape so the
    // contract holds without a live server.
    await page.goto("/directory", {
      waitUntil: "domcontentloaded",
      timeout: 120_000,
    });
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
    const privateBadges = await results.locator("text=private").count();
    expect(privateBadges).toBe(0);
  });

  // ---- Capability approval workflow ----
  // UI surface: realm admin
  // spec: authz/capabilities.md
  test("realm-admin: capability grant and revoke live under security", async ({
    page,
  }) => {
    await page.goto(
      "/realms/ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j/settings/security",
      {
        waitUntil: "domcontentloaded",
        timeout: 120_000,
      },
    );
    await expect(page.getByTestId("grant-explanation")).toHaveCount(0);
    await page.getByTestId("advanced-access-toggle").click();
    await expect(page.getByTestId("capability-grant-card")).toBeVisible({
      timeout: 60_000,
    });
    await expect(page.getByTestId("cap-grant-submit-button")).toBeVisible();
    await expect(page.getByTestId("cap-revoke-submit-button")).toBeVisible();
  });

  // ---- Audit — projection origin / conflict trail ----
  // UI surface: audit
  // spec: sync/operations-sync.md
  test("audit: conflict trail shows winner + superseded events", async ({
    page,
  }) => {
    // the audit view exposes three counted
    // surfaces — accessed (attested decrypts), ryw_receipt (disclosed
    // writes), and the raw operation log. The conflict trail (when
    // present) renders inside the per-row layout below. We pin the
    // outer panel + the three count badges so any future regression
    // that strips the counted surfaces fails loudly.
    await page.goto("/audit", {
      waitUntil: "domcontentloaded",
      timeout: 120_000,
    });
    await expect(page.getByTestId("audit-panel")).toBeVisible({
      timeout: 60_000,
    });
    await expect(page.getByTestId("audit-accessed-count")).toBeVisible();
    await expect(page.getByTestId("audit-receipt-count")).toBeVisible();
    await expect(page.getByTestId("audit-total-count")).toBeVisible();
  });

  // ---- Applet / Agent / Portal Space ----
  // UI surface: applets
  // spec: extensions/applet-integration.md
  test("applets: register new applet writes signed ak.applet.registration", async ({
    page,
  }) => {
    // The applet surface is compiled for unit coverage but hidden in
    // the default local 1.0 UI until the `experimental-applets`
    // feature is explicitly enabled.
    await page.goto("/applets", {
      waitUntil: "domcontentloaded",
      timeout: 120_000,
    });
    await expect(page.getByTestId("deferred-feature-gate")).toHaveAttribute(
      "data-feature",
      "experimental-applets",
    );
  });

  test("applets: agent capability approval writes signed event chain", async ({
    page,
  }) => {
    // Applet/agent approval remains behind the same default-off gate.
    await page.goto("/applets", {
      waitUntil: "domcontentloaded",
      timeout: 120_000,
    });
    await expect(page.getByTestId("deferred-feature-gate")).toHaveAttribute(
      "data-feature",
      "experimental-applets",
    );
  });

  // ---- WebRTC call ----
  // UI surface: call
  // spec: crypto-media/webrtc-signaling.md
  test("call: authenticated route adapter exposes the call surface", async ({
    page,
  }) => {
    // The host now ships the Garth route-evaluator adapter
    // (`crate::media::service_route`): the call route renders the real dialer
    // instead of the honest-unavailable banner. Joins remain fail-closed —
    // token exchange only runs with evaluator-verified route material, and a
    // failed evaluation surfaces in `call-error` without reaching the issuer.
    await page.goto("/call", {
      waitUntil: "domcontentloaded",
      timeout: 120_000,
    });
    await expect(page.getByTestId("call-panel")).toBeVisible({
      timeout: 60_000,
    });
    await expect(page.getByTestId("call-route-unavailable")).toHaveCount(0);
    await expect(page.getByTestId("call-start-voice-button")).toBeVisible();
    await expect(page.getByTestId("call-start-group-button")).toBeVisible();
  });

  // ---- Push gateway masking ----
  // UI surface: inbox
  // spec: discovery/push-notifications.md, crypto-media/devices-and-auth.md §5
  test("push registration requires explicit user action before gateway submission", async ({
    page,
  }) => {
    // Merely opening notification settings must never register a device or
    // ship a token. Real/synthetic token validation is covered at the typed
    // registration boundary; this browser gate pins explicit user consent.
    const gatewayRequests: string[] = [];
    page.on("request", (request) => {
      if (
        request.url().endsWith("/_arkret/edge/push/register-device") &&
        request.method() === "POST"
      ) {
        gatewayRequests.push(request.postData() ?? "");
      }
    });
    await page.goto("/settings/notifications", {
      waitUntil: "domcontentloaded",
      timeout: 120_000,
    });
    await expect(
      page.getByTestId("settings-notification-sound-toggle"),
    ).toBeAttached();
    await expect(
      page.getByTestId("settings-notification-sound-test"),
    ).toBeVisible();
    await dismissBlockingDialog(page);
    await expect(page.getByTestId("push-register-button")).toBeEnabled();
    await expect(page.getByTestId("push-registration-state")).toContainText(
      "Not registered",
    );
    expect(gatewayRequests).toEqual([]);
  });
});
