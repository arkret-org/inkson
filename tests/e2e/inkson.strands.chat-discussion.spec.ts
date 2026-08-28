import { expect, test } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  refreshServer,
  openDiscussion,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("chat fails closed until the Realm content scheme is verified", async ({
  page,
}) => {
  await refreshServer(page);
  await openDiscussion(page);

  await expect(page.getByRole("alert")).toContainText(
    "encryption_policy_pending: waiting for the verified content scheme",
  );
  await page.getByTestId("chat-input").fill("must not publish yet");
  await expect(page.getByTestId("send-chat-button")).toBeDisabled();
  await expect(page.getByTestId("chat-message")).toHaveCount(0);
});
