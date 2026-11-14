import { byClass } from "./strandsHarness";
import { chromium, expect, test, type Locator, type Page } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  CURRENT_PRINCIPAL_CORE_ID,
  CURRENT_PRINCIPAL_DID,
  CURRENT_ACCOUNT_ID,
  CURRENT_ACCOUNT_RESOLUTION,

  refreshServer,
  writeLocalConfigAndReload,
  reloadWithUnacceptedDevice,
  readLocalConfig,
  addSessionGrantInjection,
  testLocalConfig,
} from "./strandsHarness";
import { deliveredMockAccountBody, mockArkretApi } from "./mockArkretApi";

registerStrandsBeforeEach();

function loginPanel(page: Page) {
  return page.locator(".auth-panel").filter({ has: page.locator(".auth-station-field") });
}

function leaderPanel(page: Page, title = "Inkson is already open") {
  return page.getByRole("status").filter({
    has: page.getByRole("heading", { name: title, exact: true }),
  });
}

function accountValue(page: Page, label: string) {
  return page.locator(".account-page__row").filter({
    has: page.locator(".account-page__key").and(page.getByText(label, { exact: true })),
  }).locator(".account-page__value > .mono");
}

async function expectCompleteDescription(page: Page, value: Locator, expected: string) {
  await expect(value).toHaveAttribute("aria-describedby", /^\S+$/);
  const id = await value.getAttribute("aria-describedby");
  await expect(page.locator(`[id=${JSON.stringify(id)}]`)).toHaveText(expected);
}

async function expectIdentityTooltip(page: Page, action: string, expected: string) {
  const button = page.locator(".account-page").getByRole("button", { name: action, exact: true });
  await button.hover();
  await expect(button).toHaveAttribute("aria-describedby", /^\S+$/);
  const id = await button.getAttribute("aria-describedby");
  const hint = page.locator(`[id=${JSON.stringify(id)}]`);
  await expect(hint).toHaveRole("tooltip");
  await expect(hint).toBeVisible();
  await expect(hint).toHaveText(expected);
}

async function expectRealmSecurity(page: Page, row: Locator, encrypted: boolean) {
  await row.locator(".sidebar-nav-icon").hover();
  await expect(row).toHaveAttribute("aria-describedby", /^\S+$/);
  const id = await row.getAttribute("aria-describedby");
  const hint = page.locator(`[id=${JSON.stringify(id)}]`);
  await expect(hint).toHaveRole("tooltip");
  await expect(hint).toBeVisible();
  await expect(hint).toHaveText(encrypted ? "Encrypted Realm" : "Unencrypted Realm");
}

async function selectRealmAtDurableCut(page: Page, button: Locator) {
  const href = await button.getAttribute("href");
  expect(href).toBeTruthy();
  const realm = decodeURIComponent(new URL(href!, page.url()).pathname.split("/").at(-1)!);
  expect(realm).toMatch(/^ak:realm:/);
  const [response] = await Promise.all([
    page.waitForResponse(response => {
      const url = new URL(response.url());
      if (response.request().method() !== "GET" || url.pathname !== "/_arkret/self/account/subscribe"
        || url.searchParams.get("replace_filter") !== "true") return false;
      const filter = JSON.parse(url.searchParams.get("filter") ?? "{}");
      return Array.isArray(filter.realm_ids) && filter.realm_ids.includes(realm);
    }),
    button.click(),
  ]);
  expect(response.status()).toBe(200);
  const frames = (await deliveredMockAccountBody(response)).trim().split("\n").map(line => JSON.parse(line));
  const frame = frames.find(frame => frame.kind === "delta" && frame.realms?.[realm]);
  expect(frame).toBeDefined();
  expect(frame.cursor).toMatch(/^ak:cursor:/);
  // A mounted shell precedes history verification. This checkpoint is emitted
  // only after the verified Account stage is committed and durable.
  await page.waitForFunction(cursor => document.querySelector('[class~="sync-cursor"]')
    ?.textContent?.trim() === `cursor ${cursor}`, frame.cursor);
}

test("bootstrap login and sync shows the connected realm", async ({ page }) => {
  await refreshServer(page);

  await expect(byClass(page, "status-label")).toContainText("Online");
  await expect(byClass(page, "sync-cursor")).toContainText(
    "ak:cursor:e2e-2",
  );
  await expect(byClass(page, "realm-tree-list")).toContainText(
    "Arkret Demo Realm",
  );
  await expect(byClass(page, "realm-tree-list")).toContainText(
    "Launch Realm",
  );
  // Realm summaries do not include encryption authority: load each detail
  // through its real demand subscription before checking its verified marker.
  await selectRealmAtDurableCut(page, byClass(page, "realm-tree-item")
    .filter({ hasText: "Arkret Demo Realm" }));
  await expect(byClass(page, "kanban-panel")).toBeVisible();
  await expectRealmSecurity(page, byClass(page, "realm-tree-item")
    .filter({ hasText: "Arkret Demo Realm" }), true);
  await selectRealmAtDurableCut(page, byClass(page, "realm-tree-item")
    .filter({ hasText: "Launch Realm" }));
  await expect(byClass(page, "kanban-panel")).toBeVisible();
  await expectRealmSecurity(page, byClass(page, "realm-tree-item")
    .filter({ hasText: "Launch Realm" }), false);
  await byClass(page, "rail-brand").click();
  await expect(byClass(page, "dashboard-panel")).toBeVisible();
  await page.locator(".rail-account").click();
  await expect(page.locator(".account-page .who")).toHaveText(
    "inkson",
  );
  await expect(page.locator(".account-page__head .handle")).toHaveCount(0);
  await expect(byClass(page, "account-page__device-name")).toHaveCount(0);
  await expect(byClass(page, "account-page-frontier")).toHaveCount(0);
  await expect(byClass(page, "account-page-push")).toHaveCount(0);
  await expect(byClass(page, "account-page-queue")).toHaveCount(0);
  await expect(byClass(page, "account-page-crypto")).toHaveCount(0);
  await page.goBack();
  await expect(byClass(page, "dashboard-panel")).toBeVisible();
  await expect(byClass(page, "realm-tree-summary")).toContainText(
    "Recent Realms",
  );
  await expect(
    byClass(page, "dashboard-realm-tree-card")
      .filter({ hasText: "Arkret Demo Realm" })
      .locator(".pill.muted.xs"),
  ).toHaveText("Realm");
  await expect(
    byClass(page, "dashboard-realm-tree-card")
      .filter({ hasText: "Launch Realm" })
      .locator(".pill.muted.xs"),
  ).toHaveText("Realm");

  await byClass(page, "realm-tree-item").first().click();
  await expect(byClass(page, "kanban-panel")).toBeVisible();
  await expect(byClass(page, "topbar-current-surface")).toContainText(
    "Board",
  );
  await expect(page.locator(".realm-nav-menu-host .sapid-popover-trigger")).toBeVisible();
});

test("a second browser tab is blocked until the active Inkson tab closes", async ({
  page,
}) => {
  const follower = await page.context().newPage();
  await mockArkretApi(follower);
  await addSessionGrantInjection(follower);
  await follower.goto("/", { waitUntil: "domcontentloaded" });

  await expect(leaderPanel(follower)).toBeVisible();
  await expect(follower.locator(".shell.app")).toHaveCount(0);
  await expect(follower.getByText("Inkson is already open")).toBeVisible();

  await page.close();
  await leaderPanel(follower).getByRole("button", { name: "Try again", exact: true }).click();

  await expect(follower.locator(".shell.app").last()).toBeVisible({
    timeout: 120_000,
  });
  await expect(leaderPanel(follower)).toHaveCount(0);
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
    await expect(leaderPanel(follower)).toBeVisible();
    await expect(follower.locator(".shell.app")).toHaveCount(0);
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
            leader: await follower.locator(".shell.app").count(),
            follower: await leaderPanel(follower).count(),
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
  try {
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
    await expect(leader.locator(".shell.app").last()).toBeVisible({
      timeout: 120_000,
    });
    await follower.goto(baseURL ?? "/", { waitUntil: "domcontentloaded" });
    await expect(leaderPanel(follower)).toBeVisible();

    // Match Playwright's Chromium crash fixture with a real renderer fault.
    const crashed = leader.waitForEvent("crash", { timeout: 10_000 });
    let dispatchError: string | undefined;
    void leader.goto("chrome://crash").catch((error: unknown) => {
      dispatchError = String(error);
    });
    try {
      await crashed;
    } catch (error) {
      throw new Error(
        `Renderer crash was not observed; navigation: ${dispatchError ?? "pending"}\n${String(error)}`,
      );
    }
    await expect(leader.evaluate(() => document.title)).rejects.toThrow(
      /(?:Page|Target) crashed/i,
    );
    await leaderPanel(follower).getByRole("button", { name: "Try again", exact: true }).click();

    await expect(follower.locator(".shell.app").last()).toBeVisible({
      timeout: 120_000,
    });
    await expect(leaderPanel(follower)).toHaveCount(0);
  } finally {
    await isolatedBrowser.close();
  }
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

  await expect(leaderPanel(page, "Inkson could not start safely")).toBeVisible();
  await expect(page.locator(".shell.app")).toHaveCount(0);
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

  const realmButton = byClass(page, "realm-tree-item")
    .filter({ hasText: "Arkret Demo Realm" });
  await selectRealmAtDurableCut(page, realmButton);
  await expect(byClass(page, "kanban-panel")).toBeVisible();
  await expectRealmSecurity(page, realmButton, true);
  await expect(page.locator(".topbar-context .security-state-badge-label")).toHaveText(
    "Encrypted",
  );
});

test("authenticated login session refresh returns to the realm", async ({ page }) => {
  await page.goto("/login", { waitUntil: "domcontentloaded" });
  await expect(loginPanel(page)).toBeVisible();
  await expect(page.locator(".auth-session-state .session-status")).toHaveText("signed-in");
  await page.locator(".auth-session-state").getByRole("button", { name: "Refresh now", exact: true }).click();

  await expect(page.locator(".shell.app").last()).toBeVisible({
    timeout: 120_000,
  });
  await expect(loginPanel(page)).toHaveCount(0);
  await expect(byClass(page, "dashboard-panel")).toBeVisible();
  await expect(page).toHaveURL(/\/$/);
});

test("login page delegates account lifecycle to coauth OIDC", async ({
  page,
}) => {
  await page.goto("/login", { waitUntil: "domcontentloaded" });
  await expect(loginPanel(page)).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Account server URL", exact: true })).toHaveValue(
    "https://local.host/",
  );
  // Neutral client: the station field is a free-text URL input with a
  // custom-styled preset dropdown (no native <datalist>, no browser autofill).
  await expect(page.getByRole("textbox", { name: "Account server URL", exact: true })).not.toHaveAttribute(
    "list",
    /.*/,
  );
  await expect(
    page.locator("datalist#login-station-options"),
  ).toHaveCount(0);
  // The preset list is collapsed until the toggle is clicked, then offers the
  // configured presets as one-click choices.
  await expect(byClass(page, "auth-combobox-menu")).toHaveCount(0);
  await byClass(page, "auth-combobox-toggle").click();
  await expect(byClass(page, "auth-combobox-menu")).toBeVisible();
  await expect(byClass(page, "auth-combobox-option").first()).toContainText(
    "https://local.host",
  );
  await byClass(page, "auth-combobox-toggle").click();
  await expect(byClass(page, "auth-combobox-menu")).toHaveCount(0);
  // Account lifecycle is delegated to coauth OIDC: a single Continue action,
  // no in-app account selection.
  await expect(byClass(page, "login-account-hint")).toHaveCount(0);
  await expect(byClass(page, "use-different-account-button")).toHaveCount(0);
  await expect(loginPanel(page).locator(".account-picker")).toHaveCount(0);
  await expect(loginPanel(page).getByRole("button", { name: "Sign in to this server", exact: true })).toBeVisible();

  await expect(byClass(page, "create-account-link")).toHaveCount(0);
  await expect(byClass(page, "forgot-account-link")).toHaveCount(0);
  await expect(loginPanel(page).getByRole("link", { name: "Create account", exact: true })).toHaveCount(0);
  await expect(loginPanel(page).getByRole("link", { name: "Lost password or account", exact: true })).toHaveCount(0);

  await Promise.all([
    page.waitForURL(/https:\/\/auth\.local\.host\/authorize.*/, {
      waitUntil: "domcontentloaded",
    }),
    loginPanel(page).getByRole("button", { name: "Sign in to this server", exact: true }).click(),
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

test("connect refresh canonicalizes a stale locator while retaining the accepted device", async ({
  page,
}) => {
  // WebVH relocation changes its locator, while the accepted SCID and
  // Account authority remain the same principal.
  const scid = CURRENT_PRINCIPAL_DID.split(":")[2];
  const staleDid = `did:webvh:${scid}:auth.local.host:users:01KCANONICAL`;
  const canonicalDeviceId = "ak:device:01964137-0000-7000-8000-0000000000a1";
  await expect(byClass(page, "status-label").last()).toContainText("Online");
  await writeLocalConfigAndReload(page, {
    did: staleDid,
    device_id: canonicalDeviceId,
  });
  await expect(page.locator(".shell.app").last()).toBeVisible({
    timeout: 120_000,
  });

  await refreshServer(page);

  await page.locator(".rail-account").last().click();
  await expect(page.locator(".account-page .who").last()).toHaveText(
    "inkson",
  );
  await expect(accountValue(page, "Handles").last()).toContainText(
    "alice:local.host",
  );
  await expectCompleteDescription(page, accountValue(page, "DID").last(), CURRENT_PRINCIPAL_CORE_ID);
  await expectCompleteDescription(page, accountValue(page, "Handles").last(), "alice:local.host");
  await expectIdentityTooltip(page, "Copy DID", CURRENT_PRINCIPAL_CORE_ID);
  await expectIdentityTooltip(page, "Copy handles", "alice:local.host");
  await expect(accountValue(page, "DID").last()).toHaveText(
    /^ak:did_core:webvh:.+\.\.\..+$/,
  );
  await expectCompleteDescription(page, byClass(page, "account-page__device-id").last(), canonicalDeviceId);
  await expectIdentityTooltip(page, "Copy device ID", canonicalDeviceId);
  await expect
    .poll(() => readLocalConfig(page))
    .toMatchObject({
      active_account: {
        authority: CURRENT_ACCOUNT_ID,
        resolution: CURRENT_ACCOUNT_RESOLUTION,
        device_id: canonicalDeviceId,
      },
    });
});

test("changing the active device requires sign-in instead of silently restoring another device", async ({
  page,
}, testInfo) => {
  const unacceptedDeviceId = "ak:device:01964137-0000-7000-8000-0000000000b0";
  let authenticatedWrites = 0;
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (
      request.method() === "POST" &&
      (path === "/_arkret/self/events" || path === "/_arkret/self/account/profile")
    ) {
      authenticatedWrites += 1;
    }
  });
  await expect(byClass(page, "status-label").last()).toContainText("Online");
  await reloadWithUnacceptedDevice(page, unacceptedDeviceId);
  const bootWitness = await page.evaluate(() => (
    window as unknown as {
      __deviceBoundaryBootWitness?: {
        deviceId: string;
        injectionDisabled: boolean;
      };
    }
  ).__deviceBoundaryBootWitness);
  await testInfo.attach("unaccepted-device-boot-boundary", {
    body: JSON.stringify(bootWitness ?? null),
    contentType: "application/json",
  });
  expect(bootWitness).toEqual({
    deviceId: unacceptedDeviceId,
    injectionDisabled: true,
  });
  await expect(loginPanel(page).last()).toBeVisible({
    timeout: 30_000,
  });
  expect((await readLocalConfig(page)).active_account.device_id).toBe(
    unacceptedDeviceId,
  );
  await expect(loginPanel(page).getByRole("button", { name: "Sign in to this server", exact: true }).last()).toBeVisible();
  await expect(loginPanel(page).getByRole("button", { name: "Sign in to this server", exact: true }).last()).toBeEnabled();
  await expect(byClass(page, "device-authorization-modal")).toHaveCount(0);
  await expect(byClass(page, "recovery-setup-banner")).toHaveCount(0);
  await expect(byClass(page, "recovery-key-setup-modal")).toHaveCount(0);
  expect(authenticatedWrites).toBe(0);
});

test("fresh browser requires device authorization before recovery prompts", async ({
  page,
}) => {
  const authModal = byClass(page, "device-authorization-modal").last();
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
    authModal.getByRole("button", { name: "Start device approval", exact: true }),
  ).toBeVisible();
  await expect(byClass(page, "recovery-setup-banner")).toHaveCount(0);
  await expect(byClass(page, "recovery-key-setup-modal")).toHaveCount(0);
});
