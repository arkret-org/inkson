# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: clientx.flows.spec.ts >> notifications are derived from index projections and respect per-space mute rules
- Location: tests\e2e\clientx.flows.spec.ts:327:1

# Error details

```
TimeoutError: page.goto: Timeout 120000ms exceeded.
Call log:
  - navigating to "http://127.0.0.1:4527/", waiting until "domcontentloaded"

```

# Page snapshot

```yaml
- generic [active] [ref=e1]:
  - generic [ref=e2]:
    - img [ref=e3]
    - heading "Dioxus" [level=2] [ref=e7]
    - heading "web | yougen" [level=2] [ref=e8]
  - generic [ref=e9]:
    - heading "Oops! The build failed." [level=1] [ref=e10]
    - paragraph [ref=e11]: "compiling yougen encountered an error:"
    - generic [ref=e12]: Failed to write executable
  - heading "docs | guides | help" [level=4] [ref=e14]:
    - link "docs" [ref=e15] [cursor=pointer]:
      - /url: https://docs.rs/dioxus/latest/dioxus/
    - text: "|"
    - link "guides" [ref=e16] [cursor=pointer]:
      - /url: https://dioxuslabs.com/learn
    - text: "|"
    - link "help" [ref=e17] [cursor=pointer]:
      - /url: https://discord.gg/KrGKhBbU6s
```

# Test source

```ts
  1   | import { expect, test } from "@playwright/test";
  2   | import { mockContrixApi } from "./mockContrixApi";
  3   | 
  4   | async function openServerSwitcher(page: import("@playwright/test").Page) {
  5   |   const menu = page.getByTestId("server-switch-menu");
  6   |   if (await menu.isVisible()) {
  7   |     return;
  8   |   }
  9   |   await page.getByTestId("server-switch-button").click();
  10  |   await expect(menu).toBeVisible();
  11  | }
  12  | 
  13  | async function refreshServer(page: import("@playwright/test").Page) {
  14  |   await openServerSwitcher(page);
  15  |   await page.getByTestId("connect-button").click();
  16  | }
  17  | 
  18  | test.beforeEach(async ({ page }, testInfo) => {
  19  |   await mockContrixApi(page);
  20  |   if (testInfo.title.startsWith("login page")) {
  21  |     return;
  22  |   }
  23  |   await page.addInitScript(() => {
  24  |     if (localStorage.getItem("yougen.config.v1")) {
  25  |       return;
  26  |     }
  27  |     localStorage.setItem(
  28  |       "yougen.config.v1",
  29  |       JSON.stringify({
  30  |         server_url: "https://local.host",
  31  |         account_did: "did:web:alice.example",
  32  |         device_id: "cx:device:01964137-0000-7000-8000-0000000000a1",
  33  |         session_token: "sx:e2e-token",
  34  |       }),
  35  |     );
  36  |   });
> 37  |   await page.goto("/", { waitUntil: "domcontentloaded", timeout: 120_000 });
      |              ^ TimeoutError: page.goto: Timeout 120000ms exceeded.
  38  |   await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
  39  | });
  40  | 
  41  | test("bootstrap login and sync shows the connected workspace", async ({ page }) => {
  42  |   await refreshServer(page);
  43  | 
  44  |   await expect(page.getByTestId("status-label")).toContainText("Online");
  45  |   await expect(page.getByTestId("sync-cursor")).toContainText("sx:e2e:2");
  46  |   await expect(page.getByTestId("space-list")).toContainText("Contrix Demo Space");
  47  |   await expect(page.getByTestId("dashboard-panel")).toBeVisible();
  48  | 
  49  |   await page.getByRole("link", { name: "Timeline" }).click();
  50  |   await expect(page.getByTestId("timeline")).toContainText("Shared demo Space served by mocked serverx");
  51  |   await page.getByTestId("account-menu-button").click();
  52  |   await expect(page.getByTestId("account-menu-frontier")).toContainText("cx:event:e2e");
  53  |   await expect(page.getByTestId("account-menu-push")).toBeVisible();
  54  |   await expect(page.getByTestId("account-menu-queue")).toContainText("1");
  55  | });
  56  | 
  57  | test("topbar account menu shows identity and sync state", async ({ page }) => {
  58  |   await refreshServer(page);
  59  |   await page.getByTestId("account-menu-button").click();
  60  |   await expect(page.getByTestId("account-menu")).toContainText("did:web:alice.example");
  61  |   await expect(page.getByTestId("account-menu")).toContainText("cx:device:");
  62  |   await expect(page.getByTestId("account-menu-frontier")).toContainText("cx:event:e2e");
  63  |   await expect(page.getByTestId("account-menu-settings")).toBeVisible();
  64  | });
  65  | 
  66  | test("workspace header collapses and sidebar edge resizes the menu", async ({ page }) => {
  67  |   const sidebar = page.getByTestId("sidebar");
  68  |   const mainView = page.getByTestId("main-view");
  69  |   const toggle = page.getByTestId("sidebar-collapse-toggle");
  70  |   const resizeHandle = page.getByTestId("sidebar-resize-handle");
  71  |   const initialBox = await sidebar.boundingBox();
  72  |   const mainBox = await mainView.boundingBox();
  73  |   const toggleBox = await toggle.boundingBox();
  74  |   const handleBox = await resizeHandle.boundingBox();
  75  | 
  76  |   expect(initialBox).not.toBeNull();
  77  |   expect(mainBox).not.toBeNull();
  78  |   expect(toggleBox).not.toBeNull();
  79  |   expect(handleBox).not.toBeNull();
  80  |   expect(toggleBox!.x).toBeLessThan(mainBox!.x + 60);
  81  | 
  82  |   await page.mouse.move(handleBox!.x + handleBox!.width / 2, handleBox!.y + 24);
  83  |   await page.mouse.down();
  84  |   await page.mouse.move(340, handleBox!.y + 24, { steps: 6 });
  85  |   await page.mouse.up();
  86  | 
  87  |   await expect
  88  |     .poll(async () => (await sidebar.boundingBox())?.width ?? 0)
  89  |     .toBeGreaterThan((initialBox?.width ?? 0) + 40);
  90  | 
  91  |   await toggle.click();
  92  |   await expect.poll(async () => (await sidebar.boundingBox())?.width ?? 0).toBeLessThan(100);
  93  |   await expect(resizeHandle).toBeHidden();
  94  | });
  95  | 
  96  | test("topbar breadcrumbs avoid duplicated route and server context", async ({ page }) => {
  97  |   await page.getByTestId("settings-nav-button").click();
  98  |   await expect(page.getByTestId("topbar-crumbs")).toContainText("Settings");
  99  |   await expect(page.getByTestId("topbar-crumbs")).not.toContainText("Settings / Settings");
  100 |   await expect(page.getByTestId("topbar-crumbs")).not.toContainText("Principal Server https://");
  101 | });
  102 | 
  103 | test("login page delegates account lifecycle to coauth OIDC", async ({ page }) => {
  104 |   await page.goto("/login", { waitUntil: "domcontentloaded" });
  105 |   await expect(page.getByTestId("login-panel")).toBeVisible();
  106 |   await expect(page.getByTestId("login-server-url")).toHaveValue("https://local.host");
  107 |   await expect(page.getByTestId("login-account-hint")).toHaveCount(0);
  108 |   await expect(page.getByTestId("start-server-login-button")).toBeVisible();
  109 | 
  110 |   await expect(page.getByTestId("create-account-link")).toHaveCount(0);
  111 |   await expect(page.getByTestId("forgot-account-link")).toHaveCount(0);
  112 | 
  113 |   await Promise.all([
  114 |     page.waitForURL(/https:\/\/auth\.local\.host\/authorize.*/, { waitUntil: "domcontentloaded" }),
  115 |     page.getByTestId("start-server-login-button").click(),
  116 |   ]);
  117 |   const authorizeUrl = new URL(page.url());
  118 |   expect(authorizeUrl.searchParams.get("client_id")).toBe("01GFWR28C4KNE04WG3HKXB7C9R");
  119 |   expect(authorizeUrl.searchParams.get("login_hint")).toBeNull();
  120 |   expect(authorizeUrl.searchParams.get("redirect_uri")).toMatch(/\/auth\/callback$/);
  121 |   await expect(page.getByText("coauth")).toBeVisible();
  122 |   await expect(page.getByText("Create account")).toBeVisible();
  123 |   await expect(page.getByText("Lost password or account")).toBeVisible();
  124 | });
  125 | 
  126 | test("connect refresh canonicalizes stale account DID but preserves device override", async ({ page }) => {
  127 |   const staleDid = "did:web:auth.local.host:users:01KCANONICAL";
  128 |   const deviceId = "cx:device:01964137-0000-7000-8000-0000000000b0";
  129 |   await page.getByTestId("settings-nav-button").click();
  130 |   await expect(page.getByTestId("settings-panel")).toBeVisible();
  131 | 
  132 |   await page.getByTestId("settings-account-did-input").fill(staleDid);
  133 |   await page.getByTestId("settings-device-id-input").fill(deviceId);
  134 |   await page.reload({ waitUntil: "domcontentloaded" });
  135 |   await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
  136 |   await page.getByTestId("settings-nav-button").click();
  137 |   await expect(page.getByTestId("settings-account-did-input")).toHaveValue(staleDid);
```