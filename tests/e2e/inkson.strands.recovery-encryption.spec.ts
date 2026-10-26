import { byClass } from "./strandsHarness";
import { expect, test } from "@playwright/test";
import {
  dismissBlockingRecoveryModal,
  gotoAndDismissRecovery,

  registerStrandsBeforeEach,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("security diagnostics route recovery actions to the canonical panel", async ({
  page,
}) => {
  await gotoAndDismissRecovery(page, "/settings/encryption");
  await dismissBlockingRecoveryModal(page);

  const recovery = byClass(page, "settings-mls-recovery").last();
  const guidance = byClass(page, "key-backup-guidance").last();
  await expect(recovery).toBeVisible();
  await expect(guidance).toBeVisible();
  const disclosure = guidance.locator(":scope > .sapid-collapsible-trigger");
  await expect(disclosure).toHaveAttribute("aria-expanded", "false");
  await disclosure.click();
  await expect(disclosure).toHaveAttribute("aria-expanded", "true");
  await expect(byClass(page, "key-backup-open-recovery").last()).toContainText(
    "Recovery & backups",
  );
  await expect(byClass(page, "key-backup-id-input")).toHaveCount(0);
  await expect(byClass(page, "key-backup-passphrase-input")).toHaveCount(0);
});
