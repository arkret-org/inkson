import { expect, test } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  latestTestId,
  refreshServer,
  writeLocalConfigAndReload,
  readLocalConfig,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("bootstrap login and sync shows the connected workspace", async ({ page }) => {
  await refreshServer(page);

  await expect(page.getByTestId("status-label")).toContainText("Online");
  await expect(page.getByTestId("sync-cursor")).toContainText("ck:cursor:e2e-2");
  await expect(page.getByTestId("realm-tree-list")).toContainText("Cokret Demo Realm");
  await expect(page.getByTestId("realm-tree-list")).toContainText("Launch Realm");
  await expect(
    page.getByTestId("realm-tree-node-button").filter({ hasText: "Cokret Demo Realm" }).locator(".sidebar-nav-icon"),
  ).toHaveAttribute("title", "Encrypted Realm");
  await expect(
    page.getByTestId("realm-tree-node-button").filter({ hasText: "Launch Realm" }).locator(".sidebar-nav-icon"),
  ).toHaveAttribute("title", "Unencrypted Realm");
  await page.getByTestId("account-menu-button").click();
  await expect(page.getByTestId("account-menu-frontier")).toContainText("ck:event:e2e");
  await expect(page.getByTestId("account-menu-push")).toBeVisible();
  await expect(page.getByTestId("account-menu-queue")).toContainText("1");
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("dashboard-panel")).toBeVisible();
  await expect(page.getByTestId("realm-tree-summary")).toContainText("Recent Realms & Spaces");
  await expect(
    page.getByTestId("dashboard-realm-tree-card").filter({ hasText: "Cokret Demo Realm" }).locator(".pill.muted.xs"),
  ).toHaveText("Realm");
  await expect(
    page.getByTestId("dashboard-realm-tree-card").filter({ hasText: "Launch Realm" }).locator(".pill.muted.xs"),
  ).toHaveText("Realm");

  await page.getByTestId("realm-tree-node-button").first().click();
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
  await expect(page.getByTestId("realm-context-bar")).not.toContainText("Space views");
  await expect(page.getByTestId("realm-context-bar")).not.toContainText("Discussion");
  await expect(page.getByTestId("realm-context-bar").getByRole("link", { name: "Board" })).toBeVisible();
  await expect(page.getByTestId("realm-context-bar")).not.toContainText("Time" + "line");
});

test("authenticated login route returns to the workspace", async ({ page }) => {
  await page.goto("/login", { waitUntil: "domcontentloaded" });

  await expect(latestTestId(page, "client-shell")).toBeVisible({ timeout: 120_000 });
  await expect(page.getByTestId("login-panel")).toHaveCount(0);
  await expect(page.getByTestId("dashboard-panel")).toBeVisible();
  await expect(page).toHaveURL(/\/$/);
});

test("login page delegates account lifecycle to coauth OIDC", async ({ page }) => {
  await page.goto("/login", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("login-panel")).toBeVisible();
  await expect(page.getByTestId("login-server-url")).toHaveValue("https://local.host");
  await expect(page.getByTestId("login-account-hint")).toHaveCount(0);
  await expect(page.getByTestId("start-server-login-button")).toBeVisible();

  await expect(page.getByTestId("create-account-link")).toHaveCount(0);
  await expect(page.getByTestId("forgot-account-link")).toHaveCount(0);

  await Promise.all([
    page.waitForURL(/https:\/\/auth\.local\.host\/authorize.*/, { waitUntil: "domcontentloaded" }),
    page.getByTestId("start-server-login-button").click(),
  ]);
  const authorizeUrl = new URL(page.url());
  expect(authorizeUrl.searchParams.get("client_id")).toBe("01GFWR28C4KNE04WG3HKXB7C9R");
  expect(authorizeUrl.searchParams.get("login_hint")).toBeNull();
  expect(authorizeUrl.searchParams.get("prompt")).toBe("login");
  expect(authorizeUrl.searchParams.get("max_age")).toBe("0");
  expect(authorizeUrl.searchParams.get("redirect_uri")).toMatch(/\/auth\/callback$/);
  await expect(page.getByText("coauth")).toBeVisible();
  await expect(page.getByText("Create account")).toBeVisible();
  await expect(page.getByText("Lost password or account")).toBeVisible();
});

test("connect refresh canonicalizes stale account DID but preserves device override", async ({ page }) => {
  const staleDid = "did:web:auth.local.host:users:01KCANONICAL";
  const deviceId = "ck:device:01964137-0000-7000-8000-0000000000b0";
  await expect(latestTestId(page, "status-label")).toContainText("Online");
  await writeLocalConfigAndReload(page, { account_did: staleDid, device_id: deviceId });
  await expect(latestTestId(page, "client-shell")).toBeVisible({ timeout: 120_000 });

  await refreshServer(page);

  await latestTestId(page, "account-menu-button").click();
  await expect(latestTestId(page, "account-menu-session-crypto")).not.toContainText(
    "session credential loaded",
  );
  await expect(latestTestId(page, "account-menu-handles")).toContainText("@alice:local.host");
  await expect(latestTestId(page, "account-menu-did")).toContainText("did:web:alice.example");
  await expect(latestTestId(page, "account-menu-device")).toHaveAttribute("title", deviceId);
  await expect.poll(() => readLocalConfig(page)).toMatchObject({
    account_did: "did:web:alice.example",
    device_id: deviceId,
  });
});

test("session refresh canonicalizes stale account DID in settings", async ({ page }) => {
  const staleDid = "did:web:auth.local.host:users:01KREFRESH";
  await writeLocalConfigAndReload(page, { account_did: staleDid });
  await expect(latestTestId(page, "client-shell")).toBeVisible({ timeout: 120_000 });

  await latestTestId(page, "account-menu-button").click();
  await expect(latestTestId(page, "account-menu-did")).toContainText("did:web:alice.example");
  await expect(latestTestId(page, "account-menu-did")).not.toContainText(staleDid);
  await latestTestId(page, "account-menu-session-refresh").click();
  await expect(latestTestId(page, "account-menu-session-state")).toContainText(
    "Session refresh ok: did:web:alice.example",
  );
  await expect(latestTestId(page, "account-menu-did")).toContainText("did:web:alice.example");
  await expect.poll(() => readLocalConfig(page)).toMatchObject({
    account_did: "did:web:alice.example",
  });
});

test("fresh browser requires device authorization before recovery or encryption prompts", async ({
  page,
}) => {
  const authModal = latestTestId(page, "device-authorization-modal");
  await expect(authModal).toBeVisible({ timeout: 30_000 });
  await expect(authModal).toContainText("Authorize this device");
  await expect(latestTestId(page, "device-authorization-open-pairing")).toBeVisible();
  await expect(page.getByTestId("recommended-encryption-floor-modal")).toHaveCount(0);
  await expect(page.getByTestId("recovery-setup-banner")).toHaveCount(0);
  await expect(page.getByTestId("recovery-key-setup-modal")).toHaveCount(0);
});
