import { expect, test } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  refreshServer,
  openDiscussion,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("chat fails closed until this device receives Realm encryption keys", async ({
  page,
}) => {
  await refreshServer(page);
  await openDiscussion(page);

  let messageSubmissions = 0;
  page.on("request", (request) => {
    if (
      request.method() === "POST" &&
      new URL(request.url()).pathname === "/_arkret/self/events"
    ) {
      messageSubmissions += 1;
    }
  });

  await expect(page.getByRole("alert")).toContainText(
    "Waiting for this device's encryption keys. Keep this conversation open to receive the MLS Welcome.",
  );
  await page.getByTestId("chat-input").fill("must not publish yet");
  await expect(page.getByTestId("send-chat-button")).toBeDisabled();
  await expect(page.getByTestId("chat-message")).toHaveCount(0);
  await expect(page.getByTestId("chat-input")).toHaveValue("must not publish yet");
  expect(messageSubmissions).toBe(0);
});
