# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: clientx.flows.spec.ts >> registration wizard completes account bootstrap
- Location: tests\e2e\clientx.flows.spec.ts:57:1

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
    - generic [ref=e12]: "cargo build finished with errors for target: yougen [wasm32-unknown-unknown]"
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
  4   | test.beforeEach(async ({ page }) => {
  5   |   await mockContrixApi(page);
> 6   |   await page.goto("/", { waitUntil: "domcontentloaded", timeout: 120_000 });
      |              ^ TimeoutError: page.goto: Timeout 120000ms exceeded.
  7   |   await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
  8   | });
  9   | 
  10  | test("bootstrap login and sync shows the connected workspace", async ({ page }) => {
  11  |   await expect(page.getByTestId("web-security-banner")).toContainText("non-production");
  12  |   await page.getByTestId("connect-button").click();
  13  | 
  14  |   await expect(page.getByTestId("status-label")).toContainText("Online");
  15  |   await expect(page.getByTestId("sync-cursor")).toContainText("sx:e2e:2");
  16  |   await expect(page.getByTestId("space-list")).toContainText("Contrix Demo Space");
  17  |   await expect(page.getByTestId("dashboard-panel")).toBeVisible();
  18  | 
  19  |   await page.getByRole("link", { name: "Timeline" }).click();
  20  |   await expect(page.getByTestId("timeline")).toContainText("Shared demo Space served by mocked serverx");
  21  |   await expect(page.getByTestId("sync-metrics")).toContainText("cx:event:e2e");
  22  |   await expect(page.getByTestId("sync-metrics")).toContainText("cx:push:e2e");
  23  |   await expect(page.getByTestId("sync-metrics")).toContainText("1");
  24  | });
  25  | 
  26  | test("right panel shows space hierarchy without implicit cascade", async ({ page }) => {
  27  |   await page.getByTestId("connect-button").click();
  28  |   await expect(page.getByTestId("right-panel-space-info")).toContainText("Contrix Demo Space");
  29  |   await expect(page.getByTestId("hierarchy-no-cascade-note")).toContainText("membership");
  30  |   await expect(page.getByTestId("hierarchy-no-cascade-note")).toContainText("encryption");
  31  |   await page.getByTestId("right-panel-refresh-hierarchy").click();
  32  |   await expect(page.getByTestId("hierarchy-query-shape")).toContainText("not part of the current protocol");
  33  |   await expect(page.getByTestId("space-hierarchy-children-empty")).toContainText("No hierarchy children");
  34  | });
  35  | 
  36  | test("login page covers connection auth methods and token refresh", async ({ page }) => {
  37  |   await page.goto("/login", { waitUntil: "domcontentloaded" });
  38  |   await expect(page.getByTestId("login-panel")).toBeVisible();
  39  | 
  40  |   await page.getByTestId("test-connection-button").click();
  41  |   await expect(page.getByTestId("health-status")).toContainText("serverx");
  42  | 
  43  |   await page.getByTestId("passkey-login-button").click();
  44  |   await expect(page.getByTestId("passkey-status")).toContainText("Challenge received");
  45  | 
  46  |   await page.getByTestId("oidc-login-button").click();
  47  |   await expect(page.getByTestId("oidc-status")).toContainText("Redirect:");
  48  | 
  49  |   await page.getByTestId("dev-login-button").click();
  50  |   await expect(page.getByTestId("status-label")).toContainText("Online: dev-login");
  51  | 
  52  |   await page.goto("/login", { waitUntil: "domcontentloaded" });
  53  |   await page.getByTestId("refresh-token-button").click();
  54  |   await expect(page.getByTestId("refresh-status")).toContainText("Refreshed");
  55  | });
  56  | 
  57  | test("registration wizard completes account bootstrap", async ({ page }) => {
  58  |   await page.goto("/register", { waitUntil: "domcontentloaded" });
  59  |   await expect(page.getByTestId("register-panel")).toBeVisible();
  60  |   await expect(page.getByTestId("did-method-policy")).toContainText("did:plc");
  61  | 
  62  |   await page.getByTestId("generate-did-button").click();
  63  |   await page.getByTestId("register-handle-input").fill("new-alice.example");
  64  |   await page.getByTestId("next-to-displayname").click();
  65  |   await page.getByTestId("register-display-name").fill("New Alice");
  66  |   await page.getByTestId("register-device-label").fill("alice-laptop");
  67  |   await page.getByRole("button", { name: "Next" }).click();
  68  |   await page.getByTestId("generate-proof-button").click();
  69  |   await page.getByRole("button", { name: "Sign & Continue" }).click();
  70  |   await page.getByRole("button", { name: "Next" }).click();
  71  |   await page.getByTestId("complete-registration-button").click();
  72  | 
  73  |   await expect(page.getByTestId("registration-complete")).toContainText("Account registered successfully");
  74  |   await expect(page.getByTestId("register-summary-status")).toContainText("cx:didop:e2e");
  75  | });
  76  | 
  77  | test("registration can bind an existing protocol DID with scoped proof", async ({ page }) => {
  78  |   await page.goto("/register", { waitUntil: "domcontentloaded" });
  79  |   await page.getByTestId("register-path-bind").click();
  80  |   await page.getByTestId("bind-existing-did-input").fill("did:web:team.example");
  81  |   await page.getByTestId("bind-existing-did-button").click();
  82  |   await page.getByTestId("register-handle-input").fill("team.example");
  83  |   await page.getByTestId("next-to-displayname").click();
  84  |   await page.getByTestId("register-display-name").fill("Team Workspace");
  85  |   await page.getByTestId("register-device-label").fill("team-laptop");
  86  |   await page.getByRole("button", { name: "Next" }).click();
  87  |   await page.getByTestId("generate-proof-button").click();
  88  |   await expect(page.getByTestId("proof-challenge")).toContainText("challenge-");
  89  |   await expect(page.getByTestId("proof-verification-method")).toHaveValue("authentication");
  90  |   await page.getByRole("button", { name: "Sign & Continue" }).click();
  91  |   await page.getByRole("button", { name: "Next" }).click();
  92  | 
  93  |   const didOperation = page.waitForRequest("**/api/v1/identity/submit-did-operation");
  94  |   await page.getByTestId("complete-registration-button").click();
  95  |   const didBody = await didOperation.then((request) => request.postDataJSON());
  96  |   expect(didBody.did).toBe("did:web:team.example");
  97  |   expect(didBody.operation.type).toBe("cx.did.bind");
  98  |   expect(didBody.operation.did_method).toBe("did:web");
  99  |   expect(didBody.operation.proof.audience).toContain("127.0.0.1");
  100 |   expect(didBody.operation.proof.verification_method).toBe("authentication");
  101 |   await expect(page.getByTestId("registration-complete")).toContainText("did:web:team.example");
  102 | });
  103 | 
  104 | test("settings can update account and device before session bootstrap", async ({ page }) => {
  105 |   await page.getByTestId("settings-nav-button").click();
  106 |   await expect(page.getByTestId("settings-panel")).toBeVisible();
```