import { expect, test } from "@playwright/test";
import { mockCokretApi } from "./mockCokretApi";

export const DEMO_REALM = "ck:realm:0196419b-0000-7000-8000-000000000000";
export const CHILD_REALM = "ck:realm:01launchchild0000000000000";

export function latestTestId(page: import("@playwright/test").Page, testId: string) {
  return page.getByTestId(testId).last();
}

export async function dismissBlockingRecoveryModal(page: import("@playwright/test").Page) {
  // Dismiss a CHAIN of blocking account-health modals. Dismissing the
  // recovery-missing modal can auto-open the one-time recovery-key setup nudge
  // (account_health::should_auto_prompt_recovery_setup); both expose a
  // "Dismiss"/"Not now" button. Re-query each iteration and don't assert a
  // specific modal hidden — a freshly spawned modal must not fail the helper.
  for (let i = 0; i < 8; i += 1) {
    const modal = page.getByRole("dialog").last();
    const visible = await modal
      .waitFor({ state: "visible", timeout: 800 })
      .then(() => true)
      .catch(() => false);
    if (!visible) {
      return;
    }
    const dismiss = modal.getByRole("button", { name: /^(Not now|Dismiss)$/ });
    if ((await dismiss.count()) === 0) {
      return;
    }
    await dismiss.first().evaluate((button: HTMLElement) => button.click());
    await page.waitForTimeout(150);
  }
}

export async function openServerSwitcher(page: import("@playwright/test").Page) {
  await dismissBlockingRecoveryModal(page);
  const menu = latestTestId(page, "server-switch-menu");
  if (await menu.isVisible()) {
    return;
  }
  await latestTestId(page, "server-switch-button").click();
  await expect(menu).toBeVisible();
}

export async function refreshServer(page: import("@playwright/test").Page) {
  await openServerSwitcher(page);
  await page.getByTestId("server-option").filter({ hasText: "https://local.host" }).click();
}

export async function gotoAndDismissRecovery(page: import("@playwright/test").Page, url: string) {
  await page.goto(url, { waitUntil: "domcontentloaded" });
  await dismissBlockingRecoveryModal(page);
}

// The default mock account has encrypted history but no local key/backup, so
// the highest-priority account-health prompt (RecoverySetupMissing) shows as a
// blocking modal. Wait for it to settle, then dismiss it so the setup form
// underneath becomes interactable. No-op when the modal never appears.
export async function dismissRecoveryMissingModal(page: import("@playwright/test").Page) {
  const modal = page.getByTestId("mls-recovery-missing-modal").last();
  const appeared = await modal
    .waitFor({ state: "visible", timeout: 8_000 })
    .then(() => true)
    .catch(() => false);
  if (appeared) {
    // Dismiss the recovery-missing modal AND the recovery-key setup nudge it
    // auto-opens, so the surface underneath becomes interactable.
    await dismissBlockingRecoveryModal(page);
  }
}

export async function openSettings(page: import("@playwright/test").Page) {
  await latestTestId(page, "account-menu-button").click();
  await latestTestId(page, "account-menu-settings").click();
}

export async function openTimeline(page: import("@playwright/test").Page) {
  await page.goto(`/timeline/${DEMO_REALM}`, { waitUntil: "domcontentloaded" });
  await dismissBlockingRecoveryModal(page);
  await expect(latestTestId(page, "timeline")).toBeVisible();
}

export async function openDiscussion(page: import("@playwright/test").Page) {
  await openKanban(page);
  await page.getByTestId("kanban-card").first().click();
  await expect(page.getByTestId("card-detail-modal")).toBeVisible();
  await expect(page.getByTestId("card-description-panel")).toBeVisible();
  await page.getByTestId("card-detail-tab-discussion").click();
  await expect(page.getByTestId("chat-panel")).toBeVisible();
}

export async function openKanban(page: import("@playwright/test").Page) {
  await refreshServer(page);
  await page.goto(`/kanban/${DEMO_REALM}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
}

export async function createDiscussion(
  page: import("@playwright/test").Page,
  name = "Test Discussion",
) {
  void name;
  await expect(page.getByTestId("chat-panel")).toBeVisible();
}

export async function writeLocalConfig(
  page: import("@playwright/test").Page,
  overrides: Partial<{
    server_url: string;
    account_did: string;
    device_id: string;
    session_token: string;
  }>,
) {
  await page.evaluate((nextConfig) => {
    const current = localStorage.getItem("yougen.config.v1");
    const parsed = current ? JSON.parse(current) : {};
    localStorage.setItem(
      "yougen.config.v1",
      JSON.stringify({
        server_url: "https://local.host",
        account_did: "did:web:alice.example",
        device_id: "ck:device:01964137-0000-7000-8000-0000000000a1",
        session_token: "sx:e2e-token",
        ...parsed,
        ...nextConfig,
      }),
    );
  }, overrides);
}

export async function writeLocalConfigAndReload(
  page: import("@playwright/test").Page,
  overrides: Partial<{
    server_url: string;
    account_did: string;
    device_id: string;
    session_token: string;
  }>,
) {
  await page.evaluate((nextConfig) => {
    const current = localStorage.getItem("yougen.config.v1");
    const parsed = current ? JSON.parse(current) : {};
    localStorage.setItem(
      "yougen.config.v1",
      JSON.stringify({
        server_url: "https://local.host",
        account_did: "did:web:alice.example",
        device_id: "ck:device:01964137-0000-7000-8000-0000000000a1",
        session_token: "sx:e2e-token",
        ...parsed,
        ...nextConfig,
      }),
    );
    window.location.reload();
  }, overrides);
  await page.waitForLoadState("domcontentloaded");
}

export async function readLocalConfig(page: import("@playwright/test").Page) {
  return page.evaluate(() => JSON.parse(localStorage.getItem("yougen.config.v1") ?? "{}"));
}

export async function seedLocalRecoveryKeyMetadata(page: import("@playwright/test").Page) {
  // Use addInitScript (not a one-shot evaluate) so the seeded private_data is
  // re-injected before EVERY page load — including later page.goto reloads in
  // the same test. A one-shot write is clobbered when the app re-flushes its
  // local state on a subsequent reload, which is why the recovery config has
  // to be re-applied at boot.
  await page.addInitScript(() => {
    const account = "did:web:alice.example";
    const keyBytes = Array.from(new TextEncoder().encode(account));
    // Mirror of LocalStateStore::xor_encrypt (src/local_state.rs): byte-wise
    // XOR with the account-DID key, hex-encoded.
    const xorHex = (plaintext: string) =>
      Array.from(new TextEncoder().encode(plaintext))
        .map((byte, index) => (byte ^ keyBytes[index % keyBytes.length]).toString(16).padStart(2, "0"))
        .join("");
    const recoveryState = JSON.stringify({
      recovery_key_fingerprint: "sha256:e2e-local-recovery-key",
      recovery_key_rotated_at: "2026-06-12T12:00:00Z",
      sss_threshold: 3,
      sss_total: 5,
      guardians: [],
      passkey_wraps: [],
      last_rehearsed_at: "",
    });
    // mls.recovery_backup.v1 — presence of a backup_id makes
    // mls_recovery_backup_configured() true, which both bypasses the S6 create
    // gate and drives the backup prompt's "use existing key" branch.
    const backupState = JSON.stringify({ backup_id: "ck:backup:e2e-existing-0000" });
    const state = JSON.parse(localStorage.getItem("yougen.local_state.v1") ?? "{}");
    state.private_data = {
      ...(state.private_data ?? {}),
      "recovery.state.v1": xorHex(recoveryState),
      "mls.recovery_backup.v1": xorHex(backupState),
    };
    localStorage.setItem("yougen.local_state.v1", JSON.stringify(state));
  });
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(latestTestId(page, "client-shell")).toBeVisible({ timeout: 120_000 });
}

// Dismiss the "Protect your encrypted history" backup prompt (needs_mls_backup)
// when it pops up, so a subsequent interaction underneath becomes clickable.
// No-op when the modal isn't shown.
export async function dismissMlsBackupModal(page: import("@playwright/test").Page) {
  const modal = page.getByTestId("mls-backup-modal").last();
  const appeared = await modal
    .waitFor({ state: "visible", timeout: 4_000 })
    .then(() => true)
    .catch(() => false);
  if (appeared) {
    await page.getByTestId("mls-backup-dismiss").last().click();
    await expect(modal).toBeHidden({ timeout: 8_000 });
  }
}

export function registerStrandsBeforeEach() {
  test.beforeEach(async ({ page }, testInfo) => {
    await mockCokretApi(page, {
      advertiseListHandlesForSubject: !testInfo.title.startsWith(
        "account menu falls back to account localpart",
      ),
    });
    if (testInfo.title.startsWith("login page")) {
      return;
    }
    const initialDeviceId = testInfo.title.startsWith("fresh browser requires device authorization")
      ? "ck:device:01964137-0000-7000-8000-0000000000b2"
      : "ck:device:01964137-0000-7000-8000-0000000000a1";
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
          session_token: "sx:e2e-token",
        }),
      );
    });
    await page.addInitScript((deviceId) => {
      const current = localStorage.getItem("yougen.config.v1");
      const parsed = current ? JSON.parse(current) : {};
      localStorage.setItem(
        "yougen.config.v1",
        JSON.stringify({
          server_url: "https://local.host",
          account_did: "did:web:alice.example",
          session_token: "sx:e2e-token",
          ...parsed,
          device_id: deviceId,
        }),
      );
    }, initialDeviceId);
    await page.goto("/", { waitUntil: "domcontentloaded", timeout: 120_000 });
    await expect(latestTestId(page, "client-shell")).toBeVisible({ timeout: 120_000 });
  });
}
