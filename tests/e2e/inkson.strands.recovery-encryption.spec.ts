import { expect, test } from "@playwright/test";
import {
  dismissBlockingRecoveryModal,
  gotoAndDismissRecovery,
  latestTestId,
  registerStrandsBeforeEach,
} from "./strandsHarness";

const VALID_RECOVERY_WORDS = `${"abandon ".repeat(23)}art`;

registerStrandsBeforeEach();

test("recovery exposes the 24-word credential and durable fresh-device entry", async ({
  page,
}) => {
  await gotoAndDismissRecovery(page, "/settings/recovery");

  const panel = latestTestId(page, "recovery-panel");
  await expect(panel).toBeVisible();
  await expect(panel.getByTestId("recovery-key-section")).toContainText(
    "Recovery Key (24 words)",
  );
  await expect(panel.getByTestId("fresh-device-recovery-section")).toContainText(
    "Recover this device",
  );
  await expect(panel.getByTestId("fresh-device-recovery-start")).toBeDisabled();

  await expect(panel.getByTestId("passkey-recovery-section")).toHaveCount(0);
  await expect(panel.getByTestId("social-recovery-section")).toHaveCount(0);
  await expect(panel.getByTestId("vault-section")).toHaveCount(0);
});

test("fresh-device proof is validated locally, cleared on submit, and fails closed", async ({
  page,
}) => {
  await gotoAndDismissRecovery(page, "/settings/recovery");
  const panel = latestTestId(page, "recovery-panel");
  const words = panel.getByTestId("fresh-device-recovery-words");
  const start = panel.getByTestId("fresh-device-recovery-start");

  await words.fill("not a recovery phrase");
  await start.click();
  await expect(panel.getByTestId("fresh-device-recovery-status")).toContainText(
    "exactly 24 valid Recovery Key words",
  );
  await expect(words).toHaveValue("not a recovery phrase");

  await words.fill(VALID_RECOVERY_WORDS);
  await expect(start).toBeEnabled();
  await start.click();
  await expect(words).toHaveValue("");
  await expect(panel.getByTestId("fresh-device-recovery-status")).toContainText(
    /failed safely|no active recovery policy/i,
    { timeout: 60_000 },
  );
});

test("new Recovery Key remains plaintext only through custody confirmation", async ({
  page,
}) => {
  const setup = latestTestId(page, "recovery-key-setup-modal");
  await expect(setup).toBeVisible();
  const displayed = setup.getByTestId("recovery-key-setup-generated-key");
  await expect(displayed).toBeVisible();
  const recoveryWords = (await displayed.inputValue()).trim();
  const words = recoveryWords.split(/\s+/);
  expect(words).toHaveLength(24);
  await expect(
    setup.getByTestId("recovery-key-setup-generated-key-warning"),
  ).toBeVisible();

  await setup
    .getByTestId("recovery-key-setup-confirm-key")
    .fill(words.slice(0, 23).join(" "));
  await setup.getByTestId("recovery-key-setup-saved").click();
  await expect(setup.getByTestId("recovery-key-setup-status")).toContainText(
    "23 of 24 words",
  );
  await expect(displayed).toHaveValue(recoveryWords);
});

test("security diagnostics route recovery actions to the canonical panel", async ({
  page,
}) => {
  await gotoAndDismissRecovery(page, "/settings/encryption");
  await dismissBlockingRecoveryModal(page);

  const recovery = latestTestId(page, "settings-mls-recovery");
  const guidance = latestTestId(page, "key-backup-guidance");
  await expect(recovery).toBeVisible();
  await expect(guidance).toBeVisible();
  await guidance.locator("summary").click();
  await expect(latestTestId(page, "key-backup-open-recovery")).toContainText(
    "Recovery & backups",
  );
  await expect(page.getByTestId("key-backup-id-input")).toHaveCount(0);
  await expect(page.getByTestId("key-backup-passphrase-input")).toHaveCount(0);
});
