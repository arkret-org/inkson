import { expect, test } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  DEMO_REALM,
  latestTestId,
  dismissBlockingRecoveryModal,
  refreshServer,
  gotoAndDismissRecovery,
  openSettings,
  writeSessionGrantInjection,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("topbar account menu shows identity and sync state", async ({ page }) => {
  await refreshServer(page);
  await dismissBlockingRecoveryModal(page);
  await page.getByTestId("account-menu-button").click();
  await expect(page.getByTestId("account-menu")).toContainText("did:web:alice.example");
  await expect(page.getByTestId("account-menu")).toContainText("ck:device:");
  await expect(page.getByTestId("account-menu-copy-did")).toBeVisible();
  await expect(page.getByTestId("account-menu-copy-device")).toBeVisible();
  await page.getByTestId("account-menu-copy-did").click();
  await expect(page.getByTestId("account-menu-session-state")).toHaveText("DID copied");
  await expect(page.getByTestId("account-menu-frontier")).toContainText("ck:event:e2e");
  await expect(page.getByTestId("account-menu-settings-qr")).toBeVisible();
  await expect(page.getByTestId("account-menu-settings")).toBeVisible();
  const menuBox = await page.getByTestId("account-menu").boundingBox();
  const qrBox = await page.getByTestId("account-menu-settings-qr").boundingBox();
  const refreshBox = await page.getByTestId("account-menu-session-refresh").boundingBox();
  const logoutBox = await page.getByTestId("account-menu-session-logout").boundingBox();
  const settingsBox = await page.getByTestId("account-menu-settings").boundingBox();
  expect(menuBox).not.toBeNull();
  expect(qrBox).not.toBeNull();
  expect(refreshBox).not.toBeNull();
  expect(logoutBox).not.toBeNull();
  expect(settingsBox).not.toBeNull();
  expect(qrBox!.x + qrBox!.width).toBeGreaterThan(menuBox!.x + menuBox!.width - 48);
  expect(Math.abs(refreshBox!.y - settingsBox!.y)).toBeLessThan(2);
  expect(Math.abs(logoutBox!.y - settingsBox!.y)).toBeLessThan(2);
  expect(refreshBox!.x).toBeLessThan(logoutBox!.x);
  expect(logoutBox!.x).toBeLessThan(settingsBox!.x);
  await page.getByTestId("account-menu-settings-qr").click();
  await expect(page).toHaveURL(/\/settings$/);
  await expect(page.getByTestId("settings-panel")).toBeVisible();
});

test("account menu falls back to account localpart when handle directory lookup is not advertised", async ({
  page,
}) => {
  let handleDirectoryRequests = 0;
  const pageErrors: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/_cokret/find/directory/list-handles-for-subject") {
      handleDirectoryRequests += 1;
    }
  });
  page.on("pageerror", (error) => {
    pageErrors.push(error.message);
  });

  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(latestTestId(page, "client-shell")).toBeVisible({ timeout: 120_000 });
  await refreshServer(page);
  await dismissBlockingRecoveryModal(page);
  await latestTestId(page, "account-menu-button").click();

  await expect(latestTestId(page, "account-menu-handles")).toContainText("@alice.example:local.host");
  await expect(latestTestId(page, "account-menu-handles")).not.toContainText("unavailable");
  expect(handleDirectoryRequests).toBe(0);
  expect(pageErrors).toEqual([]);
});

test("account menu keeps account handle when handle directory returns an empty page", async ({
  page,
}) => {
  let handleDirectoryRequests = 0;
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/_cokret/find/directory/list-handles-for-subject") {
      handleDirectoryRequests += 1;
    }
  });

  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(latestTestId(page, "client-shell")).toBeVisible({ timeout: 120_000 });
  await refreshServer(page);
  await dismissBlockingRecoveryModal(page);
  await latestTestId(page, "account-menu-button").click();

  await expect(latestTestId(page, "account-menu-handles")).toContainText("@alice:local.host");
  await expect(latestTestId(page, "account-menu-handles")).not.toContainText("No handles published");
  expect(handleDirectoryRequests).toBeGreaterThan(0);
});

test("settings language selector mirrors shell direction for RTL locales", async ({ page }) => {
  await openSettings(page);
  await page.getByTestId("settings-nav-item-theme").click();
  await expect(page.getByTestId("language-settings")).toBeVisible();
  await page.getByTestId("theme-night").click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-theme", "night");
  await page.getByTestId("theme-system").click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-theme", "system");

  await page.getByTestId("language-ar").click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("dir", "rtl");
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-direction", "rtl");
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-locale", "ar");
  await expect(page.getByTestId("text-direction")).toContainText("rtl");

  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
  await expect(page.getByTestId("client-shell")).toHaveAttribute("dir", "rtl");

  await openSettings(page);
  await page.getByTestId("settings-nav-item-theme").click();
  await page.getByTestId("language-en").click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("dir", "ltr");
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-locale", "en");
});

test("settings avatar upload crops local image before publishing profile URL", async ({ page }) => {
  await openSettings(page);
  await expect(page.getByTestId("settings-avatar-card")).toBeVisible();
  await expect(page.getByTestId("settings-avatar-upload-label")).toBeVisible();
  await expect(page.getByTestId("settings-avatar-input")).toBeHidden();

  const png = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAwAAAAICAYAAADN5B7xAAAAy0lEQVR4nBXLIRXEMBBAwRURHBwRK6I4OCJWRHFwRXwRxcH18u/d8IkIbIEjMAOvwBVYgXfgE0jgG/gFRnRsHUfH7Hh1XB2r493x6UjHt+PX/yGxJY7ETLwSV2Il3olPIolv4pf/MLFNHBNz4jVxTayJ98RnIhPfid/8h8JWOAqz8CpchVV4Fz6FFL6FX/3DxrZxbMyN18a1sTbeG5+NbHw3fvsfwAYOMMELXGCBN/iAgC/48Q8H28FxMA9eB9fBOngffA5y8D34HfwBl3vzwZTfUBgAAAAASUVORK5CYII=",
    "base64",
  );
  await page.getByTestId("settings-avatar-input").setInputFiles({
    name: "avatar.png",
    mimeType: "image/png",
    buffer: png,
  });

  await expect(page.getByTestId("settings-avatar-crop-editor")).toBeVisible();
  await page.getByTestId("settings-avatar-crop-zoom").evaluate((element) => {
    const input = element as HTMLInputElement;
    input.value = "150";
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });

  const uploadRequest = page.waitForRequest("**/_cokret/self/blob/upload");
  const profileRequest = page.waitForRequest("**/_cokret/self/account/profile");
  await page.getByTestId("settings-avatar-upload-cropped").click();

  const upload = await uploadRequest;
  expect(upload.headers()["content-type"]).toContain("image/jpeg");
  expect(upload.postDataBuffer()?.length ?? 0).toBeGreaterThan(100);

  const profileBody = await profileRequest.then((request) => request.postDataJSON());
  expect(profileBody.patch.avatar_blob_ref).toBe(
    "ck:blob:sha256:01015dc8af66d01f557ea63f13538f1964848840a350c5311d1efc8ad138bb91",
  );
  await expect(page.getByTestId("settings-avatar-crop-editor")).toHaveCount(0);
});

test("light theme renders the sidebar with light navigation colors", async ({ page }) => {
  await openSettings(page);
  await page.getByTestId("settings-nav-item-theme").click();
  await page.getByTestId("theme-light").click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-theme", "light");

  const sidebarVars = await page.getByTestId("sidebar").evaluate((element) => {
    const styles = getComputedStyle(element);
    return {
      navBg: styles.getPropertyValue("--nav-bg").trim().toLowerCase(),
      navText: styles.getPropertyValue("--nav-text").trim().toLowerCase(),
    };
  });
  expect(sidebarVars).toEqual({
    navBg: "#fff9f3",
    navText: "#2f2723",
  });
});

test("topbar theme toggle takes effect on the first click from system dark", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "dark" });
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(latestTestId(page, "client-shell")).toBeVisible({ timeout: 120_000 });
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-theme", "system");

  const toggle = page.getByTestId("theme-toggle");
  await expect(toggle).toHaveAttribute("title", "Switch to light theme");
  await toggle.click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-theme", "light");
  await expect(toggle).toHaveAttribute("title", "Switch to night theme");
});

test("settings MIMI facade discovers drafts and runs interop actions", async ({ page }) => {
  await openSettings(page);
  await page.getByTestId("settings-nav-item-mimi").click();
  await expect(page.getByTestId("mimi-interop-panel")).toBeVisible();
  await expect(page.getByTestId("mimi-draft-pinning")).toHaveCount(0);

  await page.getByTestId("mimi-refresh-directory").click();
  await expect(page.getByTestId("mimi-directory-result")).toContainText("mimi://mimi.example.com");
  await expect(page.getByTestId("mimi-directory-result")).toContainText("submit_message");
  await expect(page.getByTestId("mimi-directory-result")).toContainText("identifier_query");
  await expect(page.getByTestId("mimi-directory-result")).toContainText("proxy_download");

  await page.getByTestId("mimi-group-info").click();
  await expect(page.getByTestId("mimi-action-receipt")).toContainText("group-info 01JSMIMI participants 2");

  await page.getByTestId("mimi-identifier-query").click();
  await expect(page.getByTestId("mimi-action-receipt")).toContainText("identifier mimi://remote.example/alice reachable true");

  await page.getByTestId("mimi-proxy-download").click();
  await expect(page.getByTestId("mimi-action-receipt")).toContainText(
    "proxy-download ck:blob:sha256:01015dc8af66d01f557ea63f13538f1964848840a350c5311d1efc8ad138bb91",
  );

  const submit = page.waitForRequest("**/_cokret/open/mimi/strands/01JSMIMI/messages");
  await page.getByTestId("mimi-submit-message").click();
  expect((await submit).postDataJSON().source_format).toBe("text/markdown;variant=GFM-MIMI");
  await expect(page.getByTestId("mimi-action-receipt")).toContainText("submit-message mimi-msg-e2e");
});

test("account settings split account/server info and surface personal agents", async ({ page }) => {
  await writeSessionGrantInjection(page);
  await page.reload({ waitUntil: "domcontentloaded" });
  await dismissBlockingRecoveryModal(page);

  // Account information is its own section (identity + invite locator).
  await gotoAndDismissRecovery(page, "/settings/account");
  await expect(page.getByTestId("settings-panel")).toBeVisible({ timeout: 120_000 });
  await expect(page.getByTestId("settings-nav-item-account")).toHaveAttribute("aria-current", "page");
  await expect(page.getByTestId("settings-avatar-card")).toBeVisible();
  await expect(page.getByTestId("settings-account-did")).toBeVisible();
  await expect(page.getByTestId("settings-nav-item-recovery")).toBeVisible();

  // Server information is a separate section (transport context).
  await page.getByTestId("settings-nav-item-server").click();
  await expect(page).toHaveURL(/\/settings\/server$/);
  await expect(page.getByTestId("transport-invariant")).toBeVisible();

  // My Agents lives inside account settings — no feature flag — and
  // exposes the CKP-0010 participation policy editor.
  await page.getByTestId("settings-nav-item-agents").click();
  await expect(page).toHaveURL(/\/settings\/agents$/);
  await expect(page.getByTestId("personal-agent-admin")).toBeVisible();
  await page.getByTestId("agent-admin-create-open-button").click();
  await expect(page.getByTestId("agent-admin-provision")).toBeVisible();
  const scrollLayout = await page.evaluate(() => {
    const root = document.documentElement;
    const workspace = document.querySelector(".workspace-body") as HTMLElement | null;
    if (workspace) {
      workspace.scrollTop = 200;
    }
    return {
      rootOverflowY: getComputedStyle(root).overflowY,
      bodyOverflowY: getComputedStyle(document.body).overflowY,
      viewportScrollbarGap: window.innerWidth - root.clientWidth,
      workspaceOverflowY: workspace ? getComputedStyle(workspace).overflowY : null,
      workspaceScrollTop: workspace?.scrollTop ?? 0,
    };
  });
  expect(scrollLayout.rootOverflowY).toBe("hidden");
  expect(scrollLayout.bodyOverflowY).toBe("hidden");
  expect(scrollLayout.viewportScrollbarGap).toBe(0);
  expect(scrollLayout.workspaceOverflowY).toBe("auto");
  expect(scrollLayout.workspaceScrollTop).toBeGreaterThan(0);
  await expect(page.getByTestId("agent-admin-content-preset-row")).toHaveCount(5);
  await expect(page.getByTestId("agent-admin-service-scope-row")).toHaveCount(4);
  const provisionRequest = page.waitForRequest(
    (request) =>
      request.method() === "POST" &&
      new URL(request.url()).pathname === "/_cokret/self/agents",
  );
  await page.getByTestId("agent-admin-provision-button").click();
  const provisionBody = (await provisionRequest).postDataJSON();
  expect(provisionBody.requested_scope.actions).toEqual([
    "ck.self.events.stream.subscribe",
    "ck.self.events.query.scan",
    "ck.self.events.command.submit",
  ]);
  expect(JSON.stringify(provisionBody.requested_scope.resources)).not.toContain("realm_id");
  await expect(page.getByTestId("agent-admin-pairing-card")).toBeVisible();
  const bootstrap = JSON.parse(
    (await page.getByTestId("agent-admin-pairing-bootstrap-json").innerText()).trim(),
  );
  // CKP-0008 §4.4: exactly the six pairing fields, no scope payload, no product coupling.
  expect(Object.keys(bootstrap).sort()).toEqual([
    "agent_principal_id",
    "cokret_base_url",
    "pairing_code",
    "pairing_expires_at",
    "pairing_request_id",
    "service_did",
  ]);
  expect(bootstrap.agent_principal_id).toBe("did:web:agents.example:summary");
  expect(bootstrap.pairing_code).toBe("246810");
  expect(JSON.stringify(bootstrap)).not.toContain("private_key");
  await expect(page.getByTestId("agent-state-badge")).toHaveAttribute(
    "data-state",
    "pending_runtime_key",
  );
  // Deep link is a standard HTTPS universal link (no custom scheme, no product name).
  const pairingLink = (await page.getByTestId("agent-admin-pairing-link").innerText()).trim();
  expect(pairingLink.startsWith("https://")).toBe(true);
  expect(pairingLink).toContain("/_cokret/open/agent-pairing#request=");
  expect(pairingLink.toLowerCase()).not.toContain("savfox");
  const runtimeVerificationMethod = `${bootstrap.agent_principal_id}#runtime-key-1`;
  const runtimeKeyRequest = {
    pairing_request_id: bootstrap.pairing_request_id,
    agent_principal_id: bootstrap.agent_principal_id,
    verification_method: runtimeVerificationMethod,
    public_key: {
      kty: "OKP",
      kid: runtimeVerificationMethod,
      alg: "Ed25519",
      key: Buffer.from(new Uint8Array(32).fill(9)).toString("base64url"),
    },
    proof_of_possession: {
      challenge: bootstrap.pairing_request_id,
      audience: "did:web:server.local",
      request_canonical_digest: `sha256:${"0".repeat(64)}`,
      expires_at: "2099-07-06T00:15:00.000Z",
      signature: Buffer.from(new Uint8Array(64).fill(1)).toString("base64url"),
    },
    runtime_attestation: {
      kind: "self_asserted",
    },
  };
  await page
    .getByTestId("agent-admin-runtime-key-request-json")
    .fill(
      JSON.stringify({
        ...runtimeKeyRequest,
        agent_principal_id: "did:web:agents.example:wrong-agent",
      }),
    );
  await page.getByTestId("agent-admin-approve-runtime-key-button").click();
  await expect(page.getByTestId("agent-admin-last-op")).toContainText(
    "Wrong pairing request or code",
  );
  await page
    .getByTestId("agent-admin-runtime-key-request-json")
    .fill(JSON.stringify(runtimeKeyRequest));
  await expect(page.getByTestId("agent-admin-runtime-key-request-preview")).toBeVisible();
  const pairRequest = page.waitForRequest(
    (request) =>
      request.method() === "POST" &&
      new URL(request.url()).pathname === "/_cokret/gate/account/agent-key-pair",
  );
  await page.getByTestId("agent-admin-approve-runtime-key-button").click();
  const pairBody = (await pairRequest).postDataJSON();
  expect(pairBody.agent_principal_id).toBe(bootstrap.agent_principal_id);
  expect(pairBody.pairing_request_id).toBe(bootstrap.pairing_request_id);
  expect(pairBody.verification_method).toBe(runtimeVerificationMethod);
  expect(JSON.stringify(pairBody)).not.toContain("private_key");
  await expect(page.getByTestId("agent-state-badge")).toHaveAttribute("data-state", "active");
  await expect(page.getByTestId("agent-admin-runtime-key-authorized")).toContainText(
    "ck:event:01964137",
  );
  await expect(page.getByTestId("agent-admin-participation")).toBeVisible();
  await expect(page.getByTestId("agent-admin-participation-realm-input")).toBeVisible();
  await expect(page.getByTestId("agent-admin-participation-reply")).toBeVisible();
  await expect(page.getByTestId("agent-admin-participation-mention")).toBeVisible();
});

test("expired personal agent pairing shows actionable runtime key error", async ({ page }) => {
  await writeSessionGrantInjection(page);
  await page.reload({ waitUntil: "domcontentloaded" });
  await dismissBlockingRecoveryModal(page);

  await gotoAndDismissRecovery(page, "/settings/agents");
  await expect(page.getByTestId("personal-agent-admin")).toBeVisible();
  await page.getByTestId("agent-admin-create-open-button").click();
  await page.getByTestId("agent-admin-provision-button").click();
  await expect(page.getByTestId("agent-admin-pairing-card")).toBeVisible();
  await expect(page.getByTestId("agent-admin-pairing-card")).toContainText("Expired");

  const bootstrap = JSON.parse(
    (await page.getByTestId("agent-admin-pairing-bootstrap-json").innerText()).trim(),
  );
  const runtimeVerificationMethod = `${bootstrap.agent_principal_id}#runtime-key-1`;
  await page.getByTestId("agent-admin-runtime-key-request-json").fill(
    JSON.stringify({
      pairing_request_id: bootstrap.pairing_request_id,
      agent_principal_id: bootstrap.agent_principal_id,
      verification_method: runtimeVerificationMethod,
      public_key: {
        kty: "OKP",
        kid: runtimeVerificationMethod,
        alg: "Ed25519",
        key: Buffer.from(new Uint8Array(32).fill(9)).toString("base64url"),
      },
      proof_of_possession: {
        challenge: bootstrap.pairing_request_id,
        audience: "did:web:server.local",
        request_canonical_digest: `sha256:${"0".repeat(64)}`,
        expires_at: "2099-07-06T00:15:00.000Z",
        signature: Buffer.from(new Uint8Array(64).fill(1)).toString("base64url"),
      },
    }),
  );
  await page.getByTestId("agent-admin-approve-runtime-key-button").click();
  await expect(page.getByTestId("agent-admin-last-op")).toContainText("Pairing expired");
});

test("diagnostic and preview surfaces stay behind clear user-facing states", async ({ page }) => {
  await page.goto("/directory", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("directory-panel")).toBeVisible();
  await expect(page.getByTestId("directory-three-axes-banner")).not.toHaveAttribute("open", "");
  await expect(page.getByTestId("directory-advanced-diagnostics")).not.toHaveAttribute("open", "");

  await page.goto("/agents", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("deferred-feature-gate")).toHaveAttribute("data-feature", "experimental-agents");

  await page.goto("/call", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("call-panel")).toContainText("Signaling ready");
  await expect(page.getByTestId("deferred-feature-gate")).toHaveAttribute("data-feature", "experimental-webrtc");
});
