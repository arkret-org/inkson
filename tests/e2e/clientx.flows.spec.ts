import { expect, test } from "@playwright/test";
import { mockContrixApi } from "./mockContrixApi";

test.beforeEach(async ({ page }) => {
  await mockContrixApi(page);
  await page.goto("/", { waitUntil: "domcontentloaded", timeout: 120_000 });
  await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
});

test("bootstrap login and sync shows the connected workspace", async ({ page }) => {
  await page.getByTestId("connect-button").click();

  await expect(page.getByTestId("status-label")).toContainText("Online");
  await expect(page.getByTestId("sync-cursor")).toContainText("sx:e2e:2");
  await expect(page.getByTestId("space-list")).toContainText("Contrix Demo Space");
  await expect(page.getByTestId("timeline")).toContainText("Shared demo Space served by mocked serverx");
  await expect(page.getByTestId("sync-metrics")).toContainText("cx:commit:e2e");
  await expect(page.getByTestId("sync-metrics")).toContainText("cx:push:e2e");
  await expect(page.getByTestId("sync-metrics")).toContainText("1");
});

test("settings can update account and device before session bootstrap", async ({ page }) => {
  await page.getByTestId("settings-nav-button").click();
  await expect(page.getByTestId("settings-panel")).toBeVisible();

  await page.getByTestId("settings-account-did-input").fill("did:web:bob.example");
  await page.getByTestId("settings-device-id-input").fill("dev_bob_1");
  await page.getByTestId("connect-button").click();

  await expect(page.getByTestId("session-panel")).toContainText("session dev_bob_1");
  await expect(page.getByTestId("right-panel")).toContainText("did:web:bob.example");
  await expect(page.getByTestId("right-panel")).toContainText("dev_bob_1");
});

test("directory search resolve and space selection flow works", async ({ page }) => {
  await page.getByTestId("directory-nav-button").click();
  await expect(page.getByTestId("directory-panel")).toBeVisible();

  await page.getByTestId("directory-search-input").fill("demo");
  await page.getByTestId("directory-search-button").click();
  await expect(page.getByTestId("directory-result")).toContainText("Contrix Demo Space");

  await page.getByTestId("directory-select-button").click();
  await page.getByTestId("resolve-selected-button").click();
  await expect(page.getByTestId("status-label")).toContainText("resolved public");
  await expect(page.getByTestId("selected-space-id")).toContainText("cx:space:01js0sp0000000000000000000");
});

test("plaintext and local MLS compose add timeline entries", async ({ page }) => {
  await page.getByTestId("composer-input").fill("plain e2e message");
  await page.getByTestId("send-button").click();
  await expect(page.getByTestId("timeline")).toContainText("plain e2e message");

  await page.getByTestId("composer-input").fill("secret e2e message");
  await page.getByTestId("encrypt-local-button").click();
  await expect(page.getByTestId("timeline")).toContainText("encrypted mls-rfc9420 epoch");
  await expect(page.getByTestId("right-panel")).toContainText("encrypted local payload");
});

test("moderation report and to-device queue action hits protocol endpoints", async ({ page }) => {
  const report = page.waitForRequest("**/api/v1/moderation/report");
  const deviceMessage = page.waitForRequest("**/api/v1/device_messages/clientx-txn-1");

  await page.getByTestId("report-queue-button").click();

  expect((await report).method()).toBe("POST");
  expect((await deviceMessage).method()).toBe("PUT");
});

test("devices panel reflects key queue push and crypto state after bootstrap", async ({ page }) => {
  await page.getByTestId("connect-button").click();
  await expect(page.getByTestId("sync-cursor")).toContainText("sx:e2e:2");

  await page.getByTestId("devices-nav-button").click();
  await expect(page.getByTestId("devices-panel")).toBeVisible();
  await expect(page.getByTestId("device-summary")).toContainText("Queue count: 1");
  await expect(page.getByTestId("device-summary")).toContainText("Push: cx:push:e2e");
  await expect(page.getByTestId("device-summary")).toContainText("Keys: session dev_clientx");
});

test("invalid server URL surfaces an error state", async ({ page }) => {
  await page.getByTestId("server-url-input").fill("not a url");
  await page.getByTestId("connect-button").click();

  await expect(page.getByTestId("status-label")).toContainText("Error: invalid URL");
});

test("release readiness panel keeps production blockers visible", async ({ page }) => {
  await page.getByTestId("readiness-nav-button").click();

  await expect(page.getByTestId("readiness-panel")).toBeVisible();
  await expect(page.getByTestId("release-summary")).toContainText("Not production-ready");
  await expect(page.getByTestId("readiness-panel")).toContainText("Production registration");
  await expect(page.getByTestId("readiness-panel")).toContainText("Contacts and friends");
  await expect(page.getByTestId("readiness-panel")).toContainText("Create space");
  await expect(page.getByTestId("readiness-panel")).toContainText("Invite, add, remove, and kick members");
  await expect(page.getByTestId("readiness-panel")).toContainText("Leave, archive, and delete space");

  await page.getByTestId("blocked-workflow-button").first().click();
  await expect(page.getByTestId("status-label")).toContainText("Blocked:");
});
