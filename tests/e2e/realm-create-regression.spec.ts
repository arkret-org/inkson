import { expect, test } from "@playwright/test";
import {
  dismissRecoveryMissingModal,
  registerStrandsBeforeEach,
} from "./strandsHarness";

registerStrandsBeforeEach();

async function advanceToCreate(page: import("@playwright/test").Page) {
  await page.goto("/setup/realms", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("setup-panel")).toBeVisible();
  await dismissRecoveryMissingModal(page);
  await page.getByTestId("realm-title-input").fill("Grant Regression Realm");
  await page.getByTestId("new-realm-next-button").click();
  await page.getByTestId("new-realm-next-button").click();
}

test("configured recovery session can create a Realm", async ({ page }) => {
  await advanceToCreate(page);

  const createButton = page.getByTestId("create-realm-button");
  await expect(createButton).toBeEnabled();
  const createRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith("/_arkret/self/events") &&
      request.method() === "POST" &&
      (request.postData() ?? "").includes("ak.realm.create"),
    { timeout: 60_000 },
  );

  await createButton.click();

  const request = await Promise.race([
    createRequest,
    page
      .getByTestId("realm-create-status")
      .getByText(/create failed:/i)
      .waitFor({ timeout: 60_000 })
      .then(async () => {
        throw new Error(await page.getByTestId("realm-create-status").innerText());
      }),
  ]);
  expect(JSON.stringify(request.postDataJSON())).toContain(
    "ak.realm.create",
  );
  await expect(page.getByTestId("realm-setup-done")).toBeVisible();
});

test("new Recovery Key session cannot bypass the encrypted Realm recovery gate", async ({
  page,
}) => {
  await advanceToCreate(page);

  await page.getByTestId("create-realm-button").click();

  const gate = page.getByTestId("encrypted-realm-recovery-gate");
  await expect(gate).toBeVisible();
  await expect(gate.getByTestId("encrypted-realm-recovery-gate-setup")).toBeVisible();
  await expect(gate.getByTestId("encrypted-realm-recovery-gate-override")).toHaveCount(0);
});
