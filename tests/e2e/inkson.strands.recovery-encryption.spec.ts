import { expect, test } from "@playwright/test";
import { mockCokretApi } from "./mockCokretApi";
import {
  registerStrandsBeforeEach,
  latestTestId,
  dismissBlockingRecoveryModal,
  refreshServer,
  gotoAndDismissRecovery,
  dismissRecoveryMissingModal,
  seedLocalRecoveryKeyMetadata,
  writeLocalConfig,
  writeSessionGrantInjection,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("first authenticated session surfaces a single recovery prompt by priority", async ({
  page,
}) => {
  await writeSessionGrantInjection(page);
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(latestTestId(page, "client-shell")).toBeVisible({ timeout: 120_000 });

  // Single-prompt model (src/account_health.rs): at most one account-health
  // prompt shows at a time, by priority. The mock account has encrypted
  // history but no local key/backup, so the highest-priority prompt is the
  // recovery-missing dialog (RecoverySetupMissing); the lower-priority
  // recovery-setup banner (RecoverySetupReminder) is suppressed while it shows.
  const missing = latestTestId(page, "mls-recovery-missing-modal");
  await expect(missing).toBeVisible();
  await expect(page.getByTestId("recovery-setup-banner")).toHaveCount(0);
  await expect(page.getByTestId("recommended-encryption-floor-modal")).toHaveCount(0);

  // Dismissing the higher-priority prompt drops to RecoverySetupReminder, which
  // proactively AUTO-OPENS the 24-word Recovery Key setup modal once (the
  // one-time new-user nudge — account_health::should_auto_prompt_recovery_setup).
  await latestTestId(page, "mls-recovery-missing-dismiss").click();
  const setupModal = latestTestId(page, "recovery-key-setup-modal");
  await expect(setupModal).toBeVisible();

  // With a real injected session grant, the setup prompt immediately generates
  // and uploads the recovery backup. Confirming the displayed 24-word key marks
  // the setup complete and suppresses the lower-priority banner.
  const generatedKeyField = latestTestId(page, "recovery-key-setup-generated-key");
  await expect(generatedKeyField).toBeVisible();
  const generatedRecoveryKey = await generatedKeyField.inputValue();
  expect(generatedRecoveryKey.trim().split(/\s+/)).toHaveLength(24);
  await latestTestId(page, "recovery-key-setup-confirm-key").fill(generatedRecoveryKey);
  await latestTestId(page, "recovery-key-setup-saved").click();
  await expect(setupModal).toBeHidden();
  await expect(page.getByTestId("recovery-setup-banner")).toHaveCount(0);

  // Reloading must not re-pop the modal once setup is confirmed.
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(latestTestId(page, "client-shell")).toBeVisible({ timeout: 120_000 });
  await dismissRecoveryMissingModal(page);
  await expect(page.getByTestId("recovery-key-setup-modal")).toHaveCount(0);
  await expect(page.getByTestId("recovery-setup-banner")).toHaveCount(0);
});

test("first registered device opens 24-word recovery setup instead of existing-device approval", async ({
  page,
}) => {
  const firstDid = "did:web:first.example";
  const firstDevice = "ak:device:01964137-0000-7000-8000-0000000000f1";

  await page.unroute("**/*");
  await mockCokretApi(page, {
    accountPrincipalId: firstDid,
    primaryHandle: "first:local.host",
    currentDeviceId: firstDevice,
    accountDevices: [
      {
        device_id: firstDevice,
        status: "unknown",
        display_name: "First browser",
        verification_state: "unverified",
      },
    ],
    enableDeviceEnrollment: true,
    includeDemoRealms: false,
    includeLowFloorRealm: true,
  });
  await page.evaluate(() => localStorage.clear());
  await page.addInitScript(() => {
    const win = window as typeof window & {
      __sawDeviceAuthorizationModal?: boolean;
      __deviceAuthorizationObserver?: MutationObserver;
    };
    const scan = () => {
      if (document.querySelector('[data-testid="device-authorization-modal"]')) {
        win.__sawDeviceAuthorizationModal = true;
      }
    };
    const start = () => {
      if (win.__deviceAuthorizationObserver) {
        scan();
        return;
      }
      const observer = new MutationObserver(scan);
      observer.observe(document.documentElement, { childList: true, subtree: true });
      win.__deviceAuthorizationObserver = observer;
      win.__sawDeviceAuthorizationModal = false;
      scan();
    };
    if (document.documentElement) {
      start();
    } else {
      document.addEventListener("DOMContentLoaded", start, { once: true });
    }
  });
  await writeLocalConfig(page, {
    account_did: firstDid,
    device_id: firstDevice,
    session_credential: "sx:e2e-first-token",
  });
  await writeSessionGrantInjection(page, {
    grant_jwt: "sx:e2e-first-token",
  });

  const deviceEnrollResponsePromise = page.waitForResponse(
    (response) =>
      response.url().includes("/_arkret/gate/account/device-enroll") &&
      response.request().method() === "POST",
  );
  const eventSubmitResponsePromise = page.waitForResponse(
    (response) =>
      response.url().endsWith("/_arkret/self/events") &&
      response.request().method() === "POST",
  );
  await page.reload({ waitUntil: "domcontentloaded" });
  const [deviceEnrollResponse, eventSubmitResponse] = await Promise.all([
    deviceEnrollResponsePromise,
    eventSubmitResponsePromise,
  ]);
  expect(deviceEnrollResponse.status()).toBe(200);
  expect(eventSubmitResponse.status()).toBe(200);
  await expect(eventSubmitResponse.json()).resolves.toMatchObject({
    status: "accepted",
    rejected: [],
  });
  await expect(latestTestId(page, "client-shell")).toBeVisible({ timeout: 120_000 });

  const setupModal = latestTestId(page, "recovery-key-setup-modal");
  await expect(setupModal).toBeVisible({ timeout: 30_000 });
  await expect(page.getByTestId("recommended-encryption-floor-modal")).toHaveCount(0);
  const generatedKeyField = latestTestId(page, "recovery-key-setup-generated-key");
  await expect(generatedKeyField).toBeVisible({ timeout: 30_000 });
  await expect(page.getByTestId("recommended-encryption-floor-modal")).toHaveCount(0);
  const generatedRecoveryKey = await generatedKeyField.inputValue();
  expect(generatedRecoveryKey.trim().split(/\s+/)).toHaveLength(24);
  await expect(page.getByTestId("device-authorization-modal")).toHaveCount(0);
  await expect
    .poll(() => page.evaluate(() => Boolean((window as any).__sawDeviceAuthorizationModal)))
    .toBe(false);
});

test("recovery key setup download filename includes account localpart", async ({ page }) => {
  await latestTestId(page, "mls-recovery-missing-dismiss").click();
  const setupModal = latestTestId(page, "recovery-key-setup-modal");
  const autoOpened = await setupModal
    .waitFor({ state: "visible", timeout: 2_000 })
    .then(() => true)
    .catch(() => false);
  if (!autoOpened) {
    await expect(latestTestId(page, "recovery-setup-banner")).toBeVisible();
    await latestTestId(page, "recovery-setup-open-recovery").click();
    await expect(setupModal).toBeVisible();
  }

  const generatedKeyField = latestTestId(page, "recovery-key-setup-generated-key");
  await expect(generatedKeyField).toBeVisible();
  const generatedRecoveryKey = await generatedKeyField.inputValue();
  expect(generatedRecoveryKey.trim().split(/\s+/)).toHaveLength(24);

  const downloadPromise = page.waitForEvent("download");
  await latestTestId(page, "recovery-key-setup-download-key").click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe("arkret-recovery-key-alice.txt");

  await latestTestId(page, "recovery-key-setup-confirm-key").fill(generatedRecoveryKey);
  await latestTestId(page, "recovery-key-setup-saved").click();
  await expect(setupModal).toBeHidden();
});

test("recovery key setup download filename stays bare without primary handle claim", async ({
  page,
}) => {
  await page.unroute("**/*");
  await mockCokretApi(page, {
    advertiseListHandlesForSubject: true,
    accountPrincipalId: "did:web:local.host:users:carol",
    primaryHandle: null,
    directoryPrimaryHandle: "carol:local.host",
  });
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(latestTestId(page, "client-shell")).toBeVisible({ timeout: 120_000 });

  await latestTestId(page, "mls-recovery-missing-dismiss").click();
  const setupModal = latestTestId(page, "recovery-key-setup-modal");
  const autoOpened = await setupModal
    .waitFor({ state: "visible", timeout: 2_000 })
    .then(() => true)
    .catch(() => false);
  if (!autoOpened) {
    await expect(latestTestId(page, "recovery-setup-banner")).toBeVisible();
    await latestTestId(page, "recovery-setup-open-recovery").click();
    await expect(setupModal).toBeVisible();
  }

  const generatedKeyField = latestTestId(page, "recovery-key-setup-generated-key");
  await expect(generatedKeyField).toBeVisible();
  const generatedRecoveryKey = await generatedKeyField.inputValue();
  expect(generatedRecoveryKey.trim().split(/\s+/)).toHaveLength(24);

  const downloadPromise = page.waitForEvent("download");
  await latestTestId(page, "recovery-key-setup-download-key").click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe("arkret-recovery-key.txt");

  await latestTestId(page, "recovery-key-setup-confirm-key").fill(generatedRecoveryKey);
  await latestTestId(page, "recovery-key-setup-saved").click();
  await expect(setupModal).toBeHidden();
});

test("dialog ignores inside drag release and protects generated recovery key", async ({ page }) => {
  await dismissBlockingRecoveryModal(page);
  await latestTestId(page, "recovery-setup-open-recovery").click();
  const modal = latestTestId(page, "recovery-key-setup-modal");
  await expect(modal).toBeVisible();
  const box = await latestTestId(page, "recovery-key-setup-banner").boundingBox();
  expect(box).not.toBeNull();

  await page.mouse.move(box!.x + box!.width / 2, box!.y + box!.height / 2);
  await page.mouse.down();
  await page.mouse.move(box!.x + box!.width + 80, box!.y + box!.height + 80);
  await page.mouse.up();
  await expect(modal).toBeVisible();

  const generatedKeyField = latestTestId(page, "recovery-key-setup-generated-key");
  await expect(generatedKeyField).toBeVisible();
  await page.mouse.click(12, 12);
  await expect(modal).toBeVisible();
  await expect(latestTestId(page, "recovery-key-setup-status")).toContainText(
    "Store these 24 words first",
  );
});

test("settings encryption links key backup diagnostics to recovery", async ({ page }) => {
  await gotoAndDismissRecovery(page, "/settings/encryption");
  const recovery = latestTestId(page, "settings-mls-recovery");
  const guidance = latestTestId(page, "key-backup-guidance");
  await expect(recovery).toBeVisible();
  await expect(guidance).toBeVisible();
  await expect(guidance.locator("summary")).toContainText(
    "Advanced key backup diagnostics",
  );
  await expect(guidance).not.toHaveAttribute("open", "");
  await guidance.locator("summary").click();
  await expect(guidance).toContainText(
    "backup id is generated when a backup is created",
  );
  await expect(latestTestId(page, "key-backup-open-recovery")).toContainText(
    "Recovery & backups",
  );
  await expect(page.getByTestId("key-backup-open-manual")).toHaveCount(0);
  await expect(page.getByTestId("key-backup-id-input")).toHaveCount(0);
  await expect(page.getByTestId("key-backup-passphrase-input")).toHaveCount(0);
  await expect(page.getByTestId("key-backup-setup")).toHaveCount(0);
});

test("recovery passkey quick unlock stays additive to the 24-word key", async ({ page }) => {
  await gotoAndDismissRecovery(page, "/settings/recovery");
  await expect(page.getByTestId("settings-nav-item-recovery")).toHaveAttribute("aria-current", "page");
  await expect(page.getByTestId("settings-nav-item-security")).toHaveCount(0);
  const recoveryPanel = latestTestId(page, "recovery-panel");
  await expect(recoveryPanel).toBeVisible();

  const passkeySection = recoveryPanel.getByTestId("passkey-recovery-section");
  await expect(passkeySection).toBeVisible();
  await expect(passkeySection).toContainText("browser-local WebAuthn PRF");
  await expect(passkeySection).toContainText("Passkey unlock is additive");
  await expect(recoveryPanel.getByTestId("passkey-wrap-key-form")).toBeVisible();
  await expect(recoveryPanel.getByTestId("passkey-wrap-key-hint")).toContainText(
    "paste your existing 24 words",
  );
  await expect(recoveryPanel.getByTestId("passkey-wrap-count")).toHaveText("0 saved");
  await expect(recoveryPanel.getByTestId("passkey-wrap-create")).toBeDisabled();
  await expect(recoveryPanel.getByTestId("passkey-wrap-unlock")).toBeDisabled();

  await recoveryPanel.getByTestId("recovery-key-regenerate").click();
  await expect(recoveryPanel.getByTestId("recovery-key-status")).toContainText(
    /Recovery Key (generated|saved)/,
  );
  const recoveryWords = (await recoveryPanel.getByTestId("recovery-key-current").textContent()) ?? "";
  expect(recoveryWords.trim().split(/\s+/)).toHaveLength(24);
  await expect(recoveryPanel.getByTestId("passkey-wrap-create")).toBeEnabled();
  await recoveryPanel.getByTestId("recovery-key-confirm-input").fill(recoveryWords);
  await recoveryPanel.getByTestId("recovery-key-clear-live").click();
  await expect(recoveryPanel.getByTestId("passkey-wrap-create")).toBeDisabled();
  await recoveryPanel.getByTestId("passkey-wrap-recovery-key").fill(recoveryWords);
  await expect(recoveryPanel.getByTestId("passkey-wrap-create")).toBeEnabled();
  await expect(recoveryPanel.getByTestId("passkey-wrap-key-hint")).toContainText(
    "Ready to create",
  );
  await expect(passkeySection).toContainText("24-word Recovery Key");
});

test("encrypted Realm creation without recovery is gated, then proceeds on override", async ({
  page,
}) => {
  // S6 (key-management §7.11): creating an e2ee Realm with no recovery path
  // configured MUST prompt the user to set up the Recovery Key first. The
  // default mock account has device authorization but no recovery configured.
  await refreshServer(page);

  await page.goto("/setup/realms", { waitUntil: "domcontentloaded" });
  const setupPanel = page.getByTestId("setup-panel");
  await expect(setupPanel).toBeVisible();
  await dismissRecoveryMissingModal(page);
  await page.getByTestId("realm-title-input").fill("Gated Encrypted Realm");
  await page.getByTestId("realm-summary-input").fill("Created to verify the recovery gate");
  await page.getByTestId("new-realm-next-button").click();
  await page.getByTestId("new-realm-next-button").click();

  // First Create click is intercepted by the recovery gate; no create event yet.
  let realmCreateRequests = 0;
  page.on("request", (request) => {
    if (
      request.url().endsWith("/_arkret/self/events") &&
      request.method() === "POST" &&
      (request.postData() ?? "").includes("ak.realm.create")
    ) {
      realmCreateRequests += 1;
    }
  });
  await page.getByTestId("create-realm-button").click();

  const gate = latestTestId(page, "encrypted-realm-recovery-gate");
  await expect(gate).toBeVisible();
  await expect(latestTestId(page, "encrypted-realm-recovery-gate-setup")).toBeVisible();
  await expect(latestTestId(page, "encrypted-realm-recovery-gate-override")).toBeVisible();
  // Creation was blocked, not submitted.
  await page.waitForTimeout(250);
  expect(realmCreateRequests).toBe(0);

  // Override (personal_node accepts the SPOF risk), then re-create.
  await latestTestId(page, "encrypted-realm-recovery-gate-override").click();
  await expect(gate).toBeHidden();

  const realmCreateRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith("/_arkret/self/events") &&
      request.method() === "POST" &&
      (request.postData() ?? "").includes("ak.realm.create"),
  );
  await page.getByTestId("create-realm-button").click();
  await realmCreateRequest;

  await expect(page.getByTestId("realm-setup-done")).toBeVisible();
});

test("mls recovery backup generates 24 recovery words", async ({ page }) => {
  await refreshServer(page);

  await page.goto("/setup/realms", { waitUntil: "domcontentloaded" });
  const setupPanel = page.getByTestId("setup-panel");
  await expect(setupPanel).toBeVisible();
  await dismissRecoveryMissingModal(page);
  await page.getByTestId("realm-title-input").fill("Recovery Words Space");
  await page.getByTestId("realm-summary-input").fill("Created to verify recovery words");
  await page.getByTestId("new-realm-next-button").click();
  await page.getByTestId("new-realm-next-button").click();
  await page.getByTestId("seed-members-input").fill("did:web:bob.example");

  // No recovery configured in the default mock account, so the S6 gate
  // intercepts the first Create; accept the override to reach the backup strand.
  await page.getByTestId("create-realm-button").click();
  await latestTestId(page, "encrypted-realm-recovery-gate-override").click();
  await expect(latestTestId(page, "encrypted-realm-recovery-gate")).toBeHidden();

  const realmCreateRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith("/_arkret/self/events") &&
      request.method() === "POST" &&
      (request.postData() ?? "").includes("ak.realm.create"),
  );
  await page.getByTestId("create-realm-button").click();
  await realmCreateRequest;

  await expect(page.getByTestId("realm-setup-done")).toBeVisible();
  const backupModal = latestTestId(page, "mls-backup-modal");
  await expect(backupModal).toBeVisible();
  await expect(latestTestId(page, "mls-backup-banner")).toBeVisible();
  // The dialog semantics live on the Dialog wrapper (mls-backup-modal), not the
  // inner content div (mls-backup-banner).
  await expect(backupModal).toHaveAttribute("role", "dialog");
  await expect(backupModal).toHaveAttribute("aria-modal", "true");
  await expect(latestTestId(page, "mls-backup-submit")).toBeVisible();
  await expect(page.getByTestId("mls-backup-passphrase")).toHaveCount(0);
  await expect(page.getByTestId("mls-backup-confirm")).toHaveCount(0);

  await latestTestId(page, "mls-backup-submit").click();
  const generatedKeyField = latestTestId(page, "mls-backup-generated-key");
  await expect(generatedKeyField).toBeVisible();
  const generatedRecoveryKey = await generatedKeyField.inputValue();
  expect(generatedRecoveryKey.trim().split(/\s+/)).toHaveLength(24);
  expect(generatedRecoveryKey).not.toMatch(/[A-Z0-9]{5}-[A-Z0-9]{5}/);
  const downloadPromise = page.waitForEvent("download");
  await latestTestId(page, "mls-backup-download-key").click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe("arkret-recovery-key-alice.txt");
  await expect(latestTestId(page, "mls-backup-generated-key-warning")).toContainText("Store these words now");
  await latestTestId(page, "mls-backup-confirm-key").fill("not the saved key");
  await latestTestId(page, "mls-backup-saved").click();
  await expect(latestTestId(page, "mls-backup-status")).toContainText("do not match");
  await expect(backupModal).toBeVisible();
  await latestTestId(page, "mls-backup-confirm-key").fill(generatedRecoveryKey);
  await expect(latestTestId(page, "mls-backup-saved")).toBeVisible();
  await latestTestId(page, "mls-backup-saved").click();
  await expect(page.getByTestId("mls-backup-modal")).toHaveCount(0);
});

test("encrypted Realm backup uses existing Recovery Key instead of generating another one", async ({
  page,
}) => {
  await seedLocalRecoveryKeyMetadata(page);
  await refreshServer(page);

  await page.goto("/setup/realms", { waitUntil: "domcontentloaded" });
  const setupPanel = page.getByTestId("setup-panel");
  await expect(setupPanel).toBeVisible();
  await dismissRecoveryMissingModal(page);
  await page.getByTestId("realm-title-input").fill("Existing Recovery Key Space");
  await page.getByTestId("realm-summary-input").fill("Created after recovery key setup");
  await page.getByTestId("new-realm-next-button").click();
  await page.getByTestId("new-realm-next-button").click();

  const realmCreateRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith("/_arkret/self/events") &&
      request.method() === "POST" &&
      (request.postData() ?? "").includes("ak.realm.create"),
  );
  await page.getByTestId("create-realm-button").click();
  // Recovery is already configured, so the S6 gate is bypassed entirely.
  await expect(page.getByTestId("encrypted-realm-recovery-gate")).toHaveCount(0);
  await realmCreateRequest;

  await expect(page.getByTestId("realm-setup-done")).toBeVisible();
  await expect(latestTestId(page, "mls-backup-modal")).toBeVisible();
  await expect(latestTestId(page, "mls-backup-existing-key")).toBeVisible();
  await expect(page.getByTestId("mls-backup-generated-key")).toHaveCount(0);
  await expect(latestTestId(page, "mls-backup-submit")).toContainText("Back up with Recovery Key");
  await expect(page.getByTestId("recommended-encryption-floor-modal")).toHaveCount(0);
});
