# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: clientx.flows.spec.ts >> login page exposes account creation and recovery entry points
- Location: tests\e2e\clientx.flows.spec.ts:40:1

# Error details

```
Error: locator.click: Error: strict mode violation: getByTestId('forgot-account-link') resolved to 2 elements:
    1) <a href="/recovery" data-dioxus-id="12" class="secondary auth-secondary" data-testid="forgot-account-link">Lost password or account</a> aka getByTestId('forgot-account-link').first()
    2) <a href="/recovery" data-dioxus-id="12" class="secondary auth-secondary" data-testid="forgot-account-link">Lost password or account</a> aka getByTestId('forgot-account-link').nth(1)

Call log:
  - waiting for getByTestId('forgot-account-link')

```

# Page snapshot

```yaml
- generic [active] [ref=e1]:
  - generic [ref=e5] [cursor=pointer]:
    - generic [ref=e6]:
      - img [ref=e7]
      - heading "Hot-patch success!" [level=3] [ref=e11]
    - paragraph [ref=e12]: App successfully patched in 0 ms
  - generic [ref=e13]:
    - main [ref=e14]:
      - region "Login" [ref=e16]:
        - generic [ref=e17]:
          - generic [ref=e18]: C
          - generic [ref=e19]:
            - heading "Sign in" [level=1] [ref=e20]
            - paragraph [ref=e21]: Contrix
        - generic [ref=e22]:
          - generic [ref=e23]: Principal server
          - textbox "Principal server URL" [ref=e24]: https://local.host
          - button "Continue" [ref=e25] [cursor=pointer]
          - link "Create account" [ref=e26] [cursor=pointer]:
            - /url: /register
          - link "Lost password or account" [ref=e27] [cursor=pointer]:
            - /url: /recovery
    - main [ref=e28]:
      - region "Login" [ref=e30]:
        - generic [ref=e31]:
          - generic [ref=e32]: C
          - generic [ref=e33]:
            - heading "Sign in" [level=1] [ref=e34]
            - paragraph [ref=e35]: Contrix
        - generic [ref=e36]:
          - generic [ref=e37]: Principal server
          - textbox "Principal server URL" [ref=e38]: https://local.host
          - button "Continue" [ref=e39] [cursor=pointer]
          - link "Create account" [ref=e40] [cursor=pointer]:
            - /url: /register
          - link "Lost password or account" [ref=e41] [cursor=pointer]:
            - /url: /recovery
```

# Test source

```ts
  1   | import fs from "node:fs/promises";
  2   | import { expect, test } from "@playwright/test";
  3   | import { mockContrixApi } from "./mockContrixApi";
  4   | 
  5   | test.beforeEach(async ({ page }, testInfo) => {
  6   |   await mockContrixApi(page);
  7   |   if (testInfo.title.startsWith("login page") || testInfo.title.startsWith("registration ")) {
  8   |     return;
  9   |   }
  10  |   await page.goto("/", { waitUntil: "domcontentloaded", timeout: 120_000 });
  11  |   await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
  12  | });
  13  | 
  14  | test("bootstrap login and sync shows the connected workspace", async ({ page }) => {
  15  |   await expect(page.getByTestId("web-security-banner")).toContainText("non-production");
  16  |   await page.getByTestId("connect-button").click();
  17  | 
  18  |   await expect(page.getByTestId("status-label")).toContainText("Online");
  19  |   await expect(page.getByTestId("sync-cursor")).toContainText("sx:e2e:2");
  20  |   await expect(page.getByTestId("space-list")).toContainText("Contrix Demo Space");
  21  |   await expect(page.getByTestId("dashboard-panel")).toBeVisible();
  22  | 
  23  |   await page.getByRole("link", { name: "Timeline" }).click();
  24  |   await expect(page.getByTestId("timeline")).toContainText("Shared demo Space served by mocked serverx");
  25  |   await expect(page.getByTestId("sync-metrics")).toContainText("cx:event:e2e");
  26  |   await expect(page.getByTestId("sync-metrics")).toContainText("cx:push:e2e");
  27  |   await expect(page.getByTestId("sync-metrics")).toContainText("1");
  28  | });
  29  | 
  30  | test("right panel shows space hierarchy without implicit cascade", async ({ page }) => {
  31  |   await page.getByTestId("connect-button").click();
  32  |   await expect(page.getByTestId("right-panel-space-info")).toContainText("Contrix Demo Space");
  33  |   await expect(page.getByTestId("hierarchy-no-cascade-note")).toContainText("membership");
  34  |   await expect(page.getByTestId("hierarchy-no-cascade-note")).toContainText("encryption");
  35  |   await page.getByTestId("right-panel-refresh-hierarchy").click();
  36  |   await expect(page.getByTestId("hierarchy-query-shape")).toContainText("not part of the current protocol");
  37  |   await expect(page.getByTestId("space-hierarchy-children-empty")).toContainText("No hierarchy children");
  38  | });
  39  | 
  40  | test("login page exposes account creation and recovery entry points", async ({ page }) => {
  41  |   await page.goto("/login", { waitUntil: "domcontentloaded" });
  42  |   await expect(page.getByTestId("login-panel")).toBeVisible();
  43  |   await expect(page.getByTestId("login-server-url")).toHaveValue("https://local.host");
  44  |   await expect(page.getByTestId("login-account-hint")).toHaveCount(0);
  45  |   await expect(page.getByTestId("start-server-login-button")).toBeVisible();
  46  | 
  47  |   await page.getByTestId("create-account-link").click();
  48  |   await expect(page.getByTestId("register-panel")).toBeVisible();
  49  | 
  50  |   await page.goto("/login", { waitUntil: "domcontentloaded" });
> 51  |   await page.getByTestId("forgot-account-link").click();
      |                                                 ^ Error: locator.click: Error: strict mode violation: getByTestId('forgot-account-link') resolved to 2 elements:
  52  |   await expect(page.getByTestId("register-panel")).toBeVisible();
  53  |   await expect(page.getByTestId("recovery-email-input")).toBeVisible();
  54  | 
  55  |   await page.goto("/login", { waitUntil: "domcontentloaded" });
  56  |   await page.getByTestId("start-server-login-button").click();
  57  |   await page.waitForURL(/https:\/\/auth\.local\.host\/authorize.*/);
  58  |   const authorizeUrl = new URL(page.url());
  59  |   expect(authorizeUrl.searchParams.get("client_id")).toBe("01GFWR28C4KNE04WG3HKXB7C9R");
  60  |   expect(authorizeUrl.searchParams.get("login_hint")).toBeNull();
  61  |   expect(authorizeUrl.searchParams.get("redirect_uri")).toMatch(/\/auth\/callback$/);
  62  |   await expect(page.getByText("coauth")).toBeVisible();
  63  | });
  64  | 
  65  | test("registration creates a new soland-backed did:webvh account", async ({ page }, testInfo) => {
  66  |   await page.goto("/register", { waitUntil: "domcontentloaded" });
  67  |   await expect(page.getByTestId("register-panel")).toBeVisible();
  68  |   await page.getByTestId("register-path-new-webvh").click();
  69  |   await page.getByTestId("register-username-input").fill("new-alice");
  70  |   const startRequest = page.waitForRequest("https://auth.local.host/api/v1/auth/register/webvh/start");
  71  |   await page.getByTestId("next-to-email").click();
  72  |   expect((await startRequest).postDataJSON().principal_server_url).toBe("https://local.host");
  73  |   await expect(page.getByTestId("register-status")).toContainText("soland.embedded");
  74  | 
  75  |   await page.getByTestId("register-email-input").fill("alice@example.com");
  76  |   await expect(page.getByTestId("skip-email-delivery-toggle")).toHaveCount(0);
  77  |   await page.getByTestId("send-verification-code-button").click();
  78  |   await expect(page.getByTestId("register-status")).toContainText("Test code: 123456");
  79  | 
  80  |   await page.getByTestId("register-verification-code").fill("123456");
  81  |   await page.getByTestId("verify-email-button").click();
  82  |   await expect(page.getByTestId("register-status")).toContainText("Email verified");
  83  | 
  84  |   await page.getByTestId("register-password-input").fill("correct horse battery staple");
  85  |   await page.getByTestId("register-password-confirm").fill("correct horse battery staple");
  86  |   const finishRequest = page.waitForRequest("https://auth.local.host/api/v1/auth/register/webvh/reg-webvh-1/finish");
  87  |   await page.getByTestId("complete-webvh-registration-button").click();
  88  |   const finishBody = await finishRequest.then((request) => request.postDataJSON());
  89  |   expect(finishBody.did_public_key_multibase).toMatch(/^z/);
  90  |   expect(finishBody.update_public_key_multibase).toMatch(/^z/);
  91  |   expect(finishBody.did_public_key_multibase).not.toBe(finishBody.update_public_key_multibase);
  92  |   expect(finishBody.did_key_id).toBe("did-key-1");
  93  |   expect(finishBody.update_key_id).toBe("update-key-1");
  94  |   expect(finishBody.webvh_version_time).toMatch(/Z$/);
  95  |   expect(finishBody.webvh_proof).toMatchObject({
  96  |     type: "DataIntegrityProof",
  97  |     cryptosuite: "eddsa-jcs-2022",
  98  |     proofPurpose: "authentication",
  99  |   });
  100 |   expect(finishBody.webvh_proof.verificationMethod).toContain(finishBody.update_public_key_multibase);
  101 |   expect(finishBody.webvh_proof.proofValue).toMatch(/^z/);
  102 | 
  103 |   await expect(page.getByTestId("registration-complete")).toContainText("Account registered successfully");
  104 |   await expect(page.getByTestId("registered-did-webvh")).toContainText(
  105 |     "did:webvh:zmock:local.host:webvh:new-alice",
  106 |   );
  107 |   await expect(page.getByTestId("register-did-key-id")).toContainText("#did-key-1");
  108 |   await expect(page.getByTestId("register-update-key-id")).toContainText("#update-key-1");
  109 |   await expect(page.getByTestId("register-key-log-head")).toContainText("1-zmockhead");
  110 |   await page.getByTestId("register-private-key-details").click();
  111 |   await expect(page.getByTestId("register-did-private-key-seed")).toHaveText(/[0-9a-f]{64}/);
  112 |   await expect(page.getByTestId("register-update-private-key-seed")).toHaveText(/[0-9a-f]{64}/);
  113 | 
  114 |   const downloadPromise = page.waitForEvent("download");
  115 |   await page.getByTestId("download-account-backup").click();
  116 |   const download = await downloadPromise;
  117 |   expect(download.suggestedFilename()).toBe("contrix-account-backup-new-alice.json");
  118 |   const backupPath = testInfo.outputPath(download.suggestedFilename());
  119 |   await download.saveAs(backupPath);
  120 |   const backup = JSON.parse(await fs.readFile(backupPath, "utf8"));
  121 |   expect(backup.kind).toBe("cx.yougen.account_backup.v1");
  122 |   expect(backup.account).toMatchObject({
  123 |     username: "new-alice",
  124 |     email: "alice@example.com",
  125 |     did: "did:webvh:zmock:local.host:webvh:new-alice",
  126 |     device_id: "dev_yougen",
  127 |     principal_server_url: "https://local.host",
  128 |     auth_server_url: "https://auth.local.host/",
  129 |   });
  130 |   expect(backup.did_webvh).toMatchObject({
  131 |     provider_id: "soland.embedded",
  132 |     did_key_id: "did:webvh:zmock:local.host:webvh:new-alice#did-key-1",
  133 |     update_key_id: "did:webvh:zmock:local.host:webvh:new-alice#update-key-1",
  134 |     same_key_for_controller_and_update: false,
  135 |     key_log_head: "1-zmockhead",
  136 |   });
  137 |   expect(backup.key_model).toMatchObject({
  138 |     model: "separate_did_controller_and_webvh_update_keys",
  139 |     current_did_private_key: "did:webvh:zmock:local.host:webvh:new-alice#did-key-1",
  140 |     webvh_update_private_key: "did:webvh:zmock:local.host:webvh:new-alice#update-key-1",
  141 |     same_key_material: false,
  142 |   });
  143 |   expect(backup.public_keys[0]).toMatchObject({
  144 |     kind: "did_document_controller_key",
  145 |     algorithm: "Ed25519",
  146 |     key_id: "did:webvh:zmock:local.host:webvh:new-alice#did-key-1",
  147 |     public_key_multibase: finishBody.did_public_key_multibase,
  148 |   });
  149 |   expect(backup.public_keys[0].roles).toEqual(
  150 |     expect.arrayContaining([
  151 |       "did_document.verificationMethod",
```