import { expect, test, type Page } from "@playwright/test";
import {
  dismissBlockingRecoveryModal,
  openSettings,
  refreshServer,
  registerStrandsBeforeEach,
} from "./strandsHarness";

registerStrandsBeforeEach();

async function openHome(page: Page) {
  await dismissBlockingRecoveryModal(page);
  await page.locator('[data-testid="sidebar"] a.sidebar-nav-item[href="/"]').click();
  await expect(page.getByTestId("dashboard-panel")).toBeVisible();
}

async function changeLanguageAndOpenHome(page: Page, language: "en" | "zh") {
  await openSettings(page);
  await page.getByTestId("settings-nav-item-theme").click();
  await page.getByTestId(`language-${language}`).click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-locale", language);
  await openHome(page);
}

function notificationWrites(page: Page) {
  const writes: string[] = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (path === "/_arkret/self/events" || path.endsWith("/realm-joins/prepare")) {
      writes.push(path);
    }
  });
  return writes;
}

test("invite preview dashboard notification defaults follow the active language", async ({ page }) => {
  const writes = notificationWrites(page);
  await refreshServer(page);
  await dismissBlockingRecoveryModal(page);
  // Recover the actual holder-private delivery through the drawer's normal
  // authenticated GET before inspecting the same durable projection on Home.
  await page.getByTestId("topbar-notifications-button").click();
  await expect(page.getByTestId("notifications-drawer")).toBeVisible();
  const recoveredInvite = page.getByTestId("notification-item").filter({
    has: page.getByTestId("invite-preview"),
  });
  await expect(recoveredInvite).toBeVisible();
  await expect(recoveredInvite.getByTestId("invite-preview-disclosed")).toBeVisible();
  await page.getByTestId("notifications-drawer-close").click();
  await expect(page.getByTestId("notifications-drawer")).toBeHidden();
  await openHome(page);
  const invitation = page.locator('[data-testid="dashboard-notification-card"][data-kind="invite"]');
  await expect(invitation).toHaveCount(1);
  await expect(invitation.getByTestId("dashboard-notification-title")).toHaveText("Realm invite");
  const originalBody = await invitation.getByTestId("dashboard-notification-body").innerText();
  const bodyMatch = /^You were invited to join (.+)\.$/.exec(originalBody);
  expect(bodyMatch).not.toBeNull();
  const realmLabel = bodyMatch![1];
  const originalId = await invitation.getAttribute("data-notification-id");
  expect(originalId).toMatch(/^invite:ak:invite:/);
  const originalUnreadCount = await page.getByTestId("dashboard-unread-notifications").innerText();

  for (const language of ["zh", "en"] as const) {
    await changeLanguageAndOpenHome(page, language);
    await expect(invitation).toHaveAttribute("data-notification-id", originalId!);
    await expect(invitation.getByTestId("dashboard-notification-title")).toHaveText(
      language === "zh" ? "Realm 邀请" : "Realm invite",
    );
    await expect(invitation.getByTestId("dashboard-notification-body")).toHaveText(
      language === "zh" ? `你收到了加入 ${realmLabel} 的邀请。` : originalBody,
    );
    await expect(page.getByTestId("dashboard-unread-notifications")).toHaveText(originalUnreadCount);
    const open = page.getByTestId("pinned-notifications-open");
    const expectedOpen = language === "zh" ? "打开通知" : "Open notifications";
    await expect(open).toHaveAttribute("title", expectedOpen);
    await expect(open).toHaveAttribute("aria-label", expectedOpen);
    await expect(page.getByTestId("pinned-notifications").locator("strong")).toHaveText(
      language === "zh" ? "通知" : "Notifications",
    );
  }
  expect(writes).toEqual([]);
});

test("dashboard notification previews stay literal across language changes", async ({ page }) => {
  const writes = notificationWrites(page);
  await refreshServer(page);
  await openHome(page);
  const message = page.locator('[data-testid="dashboard-notification-card"][data-kind="message"]');
  await expect(message).toHaveCount(1);
  const originalId = await message.getAttribute("data-notification-id");
  expect(originalId).toMatch(/^ak:notification_projection:/);
  await expect(message.getByTestId("dashboard-notification-title")).toHaveText("New message");
  await expect(message.getByTestId("dashboard-notification-body")).toHaveText(
    "Alice sent a message in Demo Realm",
  );
  const originalUnreadCount = await page.getByTestId("dashboard-unread-notifications").innerText();

  for (const language of ["zh", "en"] as const) {
    await changeLanguageAndOpenHome(page, language);
    await expect(message).toHaveAttribute("data-notification-id", originalId!);
    await expect(message.getByTestId("dashboard-notification-title")).toHaveText("New message");
    await expect(message.getByTestId("dashboard-notification-body")).toHaveText(
      "Alice sent a message in Demo Realm",
    );
    await expect(page.getByTestId("dashboard-unread-notifications")).toHaveText(originalUnreadCount);
  }
  expect(writes).toEqual([]);
});
