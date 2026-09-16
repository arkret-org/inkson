import { expect, test } from "@playwright/test";
import {
  dismissBlockingRecoveryModal,
  gotoAndDismissRecovery,
  latestTestId,
  registerStrandsBeforeEach,
} from "./strandsHarness";

registerStrandsBeforeEach();

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
