import { chromium, expect, test } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  latestTestId,
  refreshServer,
  writeLocalConfigAndReload,
  readLocalConfig,
  addSessionGrantInjection,
  testLocalConfig,
} from "./strandsHarness";
import { mockArkretApi } from "./mockArkretApi";

registerStrandsBeforeEach();

test("bootstrap login and sync shows the connected realm", async ({ page }) => {
  await refreshServer(page);

  await expect(page.getByTestId("status-label")).toContainText("Online");
  await expect(page.getByTestId("sync-cursor")).toContainText(
    "ak:cursor:e2e-2",
  );
  await expect(page.getByTestId("realm-tree-list")).toContainText(
    "Arkret Demo Realm",
  );
  await expect(page.getByTestId("realm-tree-list")).toContainText(
    "Launch Realm",
  );
  await expect(
    page
      .getByTestId("realm-tree-node-button")
      .filter({ hasText: "Arkret Demo Realm" })
      .locator(".sidebar-nav-icon"),
  ).toHaveAttribute("title", "Encrypted Realm");
  await expect(
    page
      .getByTestId("realm-tree-node-button")
      .filter({ hasText: "Launch Realm" })
      .locator(".sidebar-nav-icon"),
  ).toHaveAttribute("title", "Unencrypted Realm");
  await page.getByTestId("account-menu-button").click();
  await expect(page.getByTestId("account-menu-display-name")).toHaveText(
    "inkson",
  );
  await expect(page.getByTestId("account-menu-account-detail")).toContainText(
    "@alice:local.host · Current device",
  );
  await expect(page.getByTestId("account-menu-device-name")).toHaveText(
    "Current device",
  );
  await expect(page.getByTestId("account-menu-frontier")).toHaveCount(0);
  await expect(page.getByTestId("account-menu-push")).toHaveCount(0);
  await expect(page.getByTestId("account-menu-queue")).toHaveCount(0);
  await expect(page.getByTestId("account-menu-crypto")).toHaveCount(0);
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("dashboard-panel")).toBeVisible();
  await expect(page.getByTestId("realm-tree-summary")).toContainText(
    "Recent Realms",
  );
  await expect(
    page
      .getByTestId("dashboard-realm-tree-card")
      .filter({ hasText: "Arkret Demo Realm" })
      .locator(".pill.muted.xs"),
  ).toHaveText("Realm");
  await expect(
    page
      .getByTestId("dashboard-realm-tree-card")
      .filter({ hasText: "Launch Realm" })
      .locator(".pill.muted.xs"),
  ).toHaveText("Realm");

  await page.getByTestId("realm-tree-node-button").first().click();
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
  await expect(page.getByTestId("current-realm-surface")).toContainText(
    "Board",
  );
  await expect(page.getByTestId("realm-context-menu-button")).toBeVisible();
});

test("a second browser tab is blocked until the active Inkson tab closes", async ({
  page,
}) => {
  const follower = await page.context().newPage();
  await mockArkretApi(follower);
  await addSessionGrantInjection(follower);
  await follower.goto("/", { waitUntil: "domcontentloaded" });

  await expect(follower.getByTestId("web-leader-follower")).toBeVisible();
  await expect(follower.getByTestId("client-shell")).toHaveCount(0);
  await expect(follower.getByText("Inkson is already open")).toBeVisible();

  await page.close();
  await follower.getByTestId("web-leader-retry").click();

  await expect(latestTestId(follower, "client-shell")).toBeVisible({
    timeout: 120_000,
  });
  await expect(follower.getByTestId("web-leader-follower")).toHaveCount(0);
});

test("exactly one follower takes over after the leader closes", async ({
  page,
}) => {
  const followers = await Promise.all([
    page.context().newPage(),
    page.context().newPage(),
  ]);
  for (const follower of followers) {
    await mockArkretApi(follower);
    await addSessionGrantInjection(follower);
    await follower.goto("/", { waitUntil: "domcontentloaded" });
    await expect(follower.getByTestId("web-leader-follower")).toBeVisible();
    await expect(follower.getByTestId("client-shell")).toHaveCount(0);
  }

  await page.close();
  await Promise.all(
    followers.map((follower) =>
      follower.reload({ waitUntil: "domcontentloaded" }),
    ),
  );

  await expect
    .poll(
      async () => {
        const states = await Promise.all(
          followers.map(async (follower) => ({
            leader: await follower.getByTestId("client-shell").count(),
            follower: await follower.getByTestId("web-leader-follower").count(),
          })),
        );
        return states;
      },
      { timeout: 120_000 },
    )
    .toEqual(
      expect.arrayContaining([
        { leader: 1, follower: 0 },
        { leader: 0, follower: 1 },
      ]),
    );
});

test("a follower takes over after the leader renderer crashes", async ({
  baseURL,
  page,
}) => {
  await page.close();
  const isolatedBrowser = await chromium.launch({
    args: ["--process-per-tab"],
  });
  const context = await isolatedBrowser.newContext();
  const [leader, follower] = await Promise.all([
    context.newPage(),
    context.newPage(),
  ]);
  const initialConfig = testLocalConfig();
  for (const tab of [leader, follower]) {
    await mockArkretApi(tab);
    await addSessionGrantInjection(tab);
    await tab.addInitScript((config) => {
      localStorage.setItem("inkson.config.v1", JSON.stringify(config));
    }, initialConfig);
  }

  await leader.goto(baseURL ?? "/", { waitUntil: "domcontentloaded" });
  await expect(latestTestId(leader, "client-shell")).toBeVisible({
    timeout: 120_000,
  });
  await follower.goto(baseURL ?? "/", { waitUntil: "domcontentloaded" });
  await expect(follower.getByTestId("web-leader-follower")).toBeVisible();

  const cdp = await context.newCDPSession(leader);
  const crashed = leader.waitForEvent("crash", { timeout: 10_000 });
  void cdp.send("Page.crash").catch(() => undefined);
  await crashed;
  await follower.getByTestId("web-leader-retry").click();

  await expect(latestTestId(follower, "client-shell")).toBeVisible({
    timeout: 120_000,
  });
  await expect(follower.getByTestId("web-leader-follower")).toHaveCount(0);
  await isolatedBrowser.close();
});

test("a browser without Web Locks fails closed before mounting writers", async ({
  browser,
}) => {
  const context = await browser.newContext();
  await context.addInitScript(() => {
    Object.defineProperty(Navigator.prototype, "locks", {
      configurable: true,
      get: () => undefined,
    });
  });
  const page = await context.newPage();
  await mockArkretApi(page);
  await addSessionGrantInjection(page);
  await page.goto("/", { waitUntil: "domcontentloaded" });

  await expect(page.getByTestId("web-leader-unavailable")).toBeVisible();
  await expect(page.getByTestId("client-shell")).toHaveCount(0);
  await expect
    .poll(() =>
      page.evaluate(() => localStorage.getItem("inkson.web_writer_lease.v1")),
    )
    .toBeNull();
  await context.close();
});

test("selected Realm security badge matches its encrypted sidebar marker", async ({
  page,
}) => {
  await refreshServer(page);

  const realmButton = page
    .getByTestId("realm-tree-node-button")
    .filter({ hasText: "Arkret Demo Realm" });
  await expect(realmButton.locator(".sidebar-nav-icon")).toHaveAttribute(
    "title",
    "Encrypted Realm",
  );
  await realmButton.click();

  await expect(page.getByTestId("kanban-panel")).toBeVisible();
  await expect(page.getByTestId("realm-security-state")).toHaveText(
    "Encrypted",
  );
});

test("authenticated login route returns to the realm", async ({ page }) => {
  await page.goto("/login", { waitUntil: "domcontentloaded" });

  await expect(latestTestId(page, "client-shell")).toBeVisible({
    timeout: 120_000,
  });
  await expect(page.getByTestId("login-panel")).toHaveCount(0);
  await expect(page.getByTestId("dashboard-panel")).toBeVisible();
  await expect(page).toHaveURL(/\/$/);
});

test("login page delegates account lifecycle to coauth OIDC", async ({
  page,
}) => {
  await page.goto("/login", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("login-panel")).toBeVisible();
  await expect(page.getByTestId("login-server-url")).toHaveValue(
    "https://local.host/",
  );
  // Neutral client: the principal-server field is a free-text URL input with a
  // custom-styled preset dropdown (no native <datalist>, no browser autofill).
  await expect(page.getByTestId("login-server-url")).not.toHaveAttribute(
    "list",
    /.*/,
  );
  await expect(
    page.locator("datalist#login-principal-server-options"),
  ).toHaveCount(0);
  // The preset list is collapsed until the toggle is clicked, then offers the
  // configured presets as one-click choices.
  await expect(page.getByTestId("login-server-options")).toHaveCount(0);
  await page.getByTestId("login-server-options-toggle").click();
  await expect(page.getByTestId("login-server-options")).toBeVisible();
  await expect(page.getByTestId("login-server-option").first()).toContainText(
    "https://local.host",
  );
  await page.getByTestId("login-server-options-toggle").click();
  await expect(page.getByTestId("login-server-options")).toHaveCount(0);
  // Account lifecycle is delegated to coauth OIDC: a single Continue action,
  // no in-app account selection.
  await expect(page.getByTestId("login-account-hint")).toHaveCount(0);
  await expect(page.getByTestId("use-different-account-button")).toHaveCount(0);
  await expect(page.getByTestId("start-server-login-button")).toBeVisible();

  await expect(page.getByTestId("create-account-link")).toHaveCount(0);
  await expect(page.getByTestId("forgot-account-link")).toHaveCount(0);

  await Promise.all([
    page.waitForURL(/https:\/\/auth\.local\.host\/authorize.*/, {
      waitUntil: "domcontentloaded",
    }),
    page.getByTestId("start-server-login-button").click(),
  ]);
  const authorizeUrl = new URL(page.url());
  expect(authorizeUrl.searchParams.get("client_id")).toBe(
    "01GFWR28C4KNE04WG3HKXB7C9R",
  );
  expect(authorizeUrl.searchParams.get("login_hint")).toBeNull();
  expect(authorizeUrl.searchParams.get("prompt")).toBe("login");
  expect(authorizeUrl.searchParams.get("max_age")).toBe("0");
  expect(authorizeUrl.searchParams.get("redirect_uri")).toMatch(
    /\/auth\/callback$/,
  );
  await expect(page.getByText("coauth")).toBeVisible();
  await expect(page.getByText("Create account")).toBeVisible();
  await expect(page.getByText("Lost password or account")).toBeVisible();
});

test("connect refresh canonicalizes stale account and device identity", async ({
  page,
}) => {
  const staleDid = "did:web:auth.local.host:users:01KCANONICAL";
  const staleDeviceId = "ak:device:01964137-0000-7000-8000-0000000000b0";
  const canonicalDeviceId = "ak:device:01964137-0000-7000-8000-0000000000a1";
  await expect(latestTestId(page, "status-label")).toContainText("Online");
  await writeLocalConfigAndReload(page, {
    full_id: staleDid,
    device_id: staleDeviceId,
  });
  await expect(latestTestId(page, "client-shell")).toBeVisible({
    timeout: 120_000,
  });

  await refreshServer(page);

  await latestTestId(page, "account-menu-button").click();
  await expect(latestTestId(page, "account-menu-display-name")).toHaveText(
    "inkson",
  );
  await expect(latestTestId(page, "account-menu-handles")).toContainText(
    "@alice:local.host",
  );
  await expect(latestTestId(page, "account-menu-did")).toContainText(
    "ak:did_core:web:alice.example",
  );
  await expect(latestTestId(page, "account-menu-device")).toHaveAttribute(
    "title",
    canonicalDeviceId,
  );
  await expect
    .poll(() => readLocalConfig(page))
    .toMatchObject({
      active_account: {
        resolution: { full_id: "did:web:alice.example" },
        device_id: canonicalDeviceId,
      },
    });
});

test("fresh browser requires device authorization before recovery or encryption prompts", async ({
  page,
}) => {
  const authModal = latestTestId(page, "device-authorization-modal");
  await expect(authModal).toBeVisible({ timeout: 30_000 });
  await expect(authModal).toContainText("Authorize this device");
  await expect(authModal).toContainText(
    "will usually show a confirmation prompt",
  );
  await expect(authModal).toContainText(
    "encrypted history and security-sensitive actions remain unavailable",
  );
  await expect(authModal).not.toContainText("Arkret v1");
  await expect(
    latestTestId(page, "device-authorization-open-pairing"),
  ).toBeVisible();
  await expect(
    page.getByTestId("recommended-encryption-floor-modal"),
  ).toHaveCount(0);
  await expect(page.getByTestId("recovery-setup-banner")).toHaveCount(0);
  await expect(page.getByTestId("recovery-key-setup-modal")).toHaveCount(0);
});
