import { byClass } from "./strandsHarness";
import { expect, test, type Locator, type Page } from "@playwright/test";
import {
  dismissBlockingRecoveryModal,
  openSettings,
  refreshServer,
  registerStrandsBeforeEach,
} from "./strandsHarness";

registerStrandsBeforeEach();

async function openHome(page: Page) {
  await dismissBlockingRecoveryModal(page);
  await page.locator('[class~="sidebar"] a.sidebar-nav-item[href="/"]').click();
  await expect(byClass(page, "dashboard-panel")).toBeVisible();
}

async function changeLanguageAndOpenHome(page: Page, language: "en" | "zh") {
  await openSettings(page);
  await byClass(page, "settings-nav-item-theme").click();
  await byClass(page, "settings-language-choice").filter({ hasText: language === "zh" ? "中文" : "English" }).click();
  await expect(page.locator("html")).toHaveAttribute("lang", language);
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

async function notificationSource(row: Locator) {
  const source = byClass(row, "dashboard-notification-provenance");
  await expect(source).toHaveCount(1);
  const id = await source.getAttribute("id");
  expect(id).toBeTruthy();
  await expect(row).toHaveAttribute("aria-describedby", id!);
  return source;
}

test("invite preview dashboard notification defaults follow the active language", async ({ page }) => {
  const writes = notificationWrites(page);
  await refreshServer(page);
  await dismissBlockingRecoveryModal(page);
  // Recover the actual holder-private delivery through the drawer's normal
  // authenticated GET before inspecting the same durable projection on Home.
  await page.locator(".topbar .topbar-notifications-link").click();
  await expect(byClass(page, "notifications-drawer-layer")).toBeVisible();
  const recoveredInvite = byClass(page, "notification-item").filter({
    has: byClass(page, "invite-preview"),
  });
  await expect(recoveredInvite).toBeVisible();
  await expect(byClass(recoveredInvite, "invite-preview-disclosed")).toBeVisible();
  await page.locator(".notifications-drawer-actions").getByRole("button", { name: "Close", exact: true }).click();
  await expect(byClass(page, "notifications-drawer-layer")).toBeHidden();
  await openHome(page);
  const invitation = byClass(page, "dashboard-notification-card").filter({ has: byClass(page, "dashboard-notification-source-kind").filter({ hasText: /^invite$/ }) });
  await expect(invitation).toHaveCount(1);
  await expect(byClass(invitation, "dashboard-notification-title")).toHaveText("Realm invite");
  const originalBody = await byClass(invitation, "dashboard-notification-body").innerText();
  const bodyMatch = /^You were invited to join (.+)\.$/.exec(originalBody);
  expect(bodyMatch).not.toBeNull();
  const realmLabel = bodyMatch![1];
  const originalId = await byClass(await notificationSource(invitation), "dashboard-notification-source-id").textContent();
  expect(originalId).toMatch(/^invite:ak:invite:/);
  const originalUnreadCount = await byClass(page, "dashboard-unread-notifications").innerText();

  for (const language of ["zh", "en"] as const) {
    await changeLanguageAndOpenHome(page, language);
    await expect(byClass(await notificationSource(invitation), "dashboard-notification-source-id")).toHaveText(originalId!);
    await expect(byClass(invitation, "dashboard-notification-source-kind")).toHaveText("invite");
    await expect(byClass(invitation, "dashboard-notification-title")).toHaveText(
      language === "zh" ? "Realm 邀请" : "Realm invite",
    );
    await expect(byClass(invitation, "dashboard-notification-body")).toHaveText(
      language === "zh" ? `你收到了加入 ${realmLabel} 的邀请。` : originalBody,
    );
    await expect(byClass(page, "dashboard-unread-notifications")).toHaveText(originalUnreadCount);
    const open = byClass(page, "pinned-notifications-open");
    const expectedOpen = language === "zh" ? "打开通知" : "Open notifications";
    await expect(open).toHaveAttribute("aria-label", expectedOpen);
    await open.hover();
    await expect(page.getByRole("tooltip").filter({ hasText: expectedOpen })).toBeVisible();
    await page.mouse.move(0, 0);
    await expect(byClass(page, "pinned-notifications").locator(".surface-head > .dashboard-section-title")).toHaveText(
      language === "zh" ? "通知" : "Notifications",
    );
  }
  expect(writes).toEqual([]);
});

test("dashboard notification previews stay literal across language changes", async ({ page }) => {
  const writes = notificationWrites(page);
  await refreshServer(page);
  await openHome(page);
  const message = byClass(page, "dashboard-notification-card").filter({ has: byClass(page, "dashboard-notification-source-kind").filter({ hasText: /^message$/ }) });
  await expect(message).toHaveCount(1);
  const originalId = await byClass(await notificationSource(message), "dashboard-notification-source-id").textContent();
  expect(originalId).toMatch(/^ak:notification_projection:/);
  await expect(byClass(message, "dashboard-notification-title")).toHaveText("New message");
  await expect(byClass(message, "dashboard-notification-body")).toHaveText(
    "Alice sent a message in Demo Realm",
  );
  const originalUnreadCount = await byClass(page, "dashboard-unread-notifications").innerText();

  for (const language of ["zh", "en"] as const) {
    await changeLanguageAndOpenHome(page, language);
    await expect(byClass(await notificationSource(message), "dashboard-notification-source-id")).toHaveText(originalId!);
    await expect(byClass(message, "dashboard-notification-source-kind")).toHaveText("message");
    await expect(byClass(message, "dashboard-notification-title")).toHaveText("New message");
    await expect(byClass(message, "dashboard-notification-body")).toHaveText(
      "Alice sent a message in Demo Realm",
    );
    await expect(byClass(page, "dashboard-unread-notifications")).toHaveText(originalUnreadCount);
  }
  expect(writes).toEqual([]);
});
