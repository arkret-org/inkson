import { createHash } from "node:crypto";
import { expect, test } from "@playwright/test";
import { CURRENT_STATION_ID, DEMO_REALM, validateMockSchema } from "./mockArkretApi";
import {
  registerStrandsBeforeEach,
  latestTestId,
  dismissBlockingRecoveryModal,
  gotoAndDismissRecovery,
  openServerSwitcher,
  refreshServer,
  openSettings,
  writeLocalConfig,
  submittedEvent,
  assertRealmTreeSeeded,
} from "./strandsHarness";

registerStrandsBeforeEach();

async function rejectCircleControl(page: import("@playwright/test").Page, kind: string) {
  const outcome = { status: "rejected", reason_code: "capability_denied" };
  validateMockSchema("schemas/authority-commit-operations.schema.json#/$defs/self_submit_outcome", outcome);
  await page.route("**/_arkret/self/events", async route => {
    const event = submittedEvent(route.request().postDataJSON());
    if (event?.kind !== kind) { await route.fallback(); return; }
    expect(event.scope_ref.kind).toBe("circle");
    expect(event.scope_ref.circle_id).toBe("ak:circle:AVhDoodj6EFMf5ZQ1JXfSmM5ZNZrK3ekqYa4-EOvqSiE");
    expect(event.producer_proof).toBeTruthy();
    if (kind === "ak.circle.history_access") {
      expect(event.payload.from).toBe("all_history_for_current_members");
      expect(event.payload.to).toBe("since_join");
      expect(event.payload.patch).toBeUndefined();
    }
    if (kind === "ak.circle.update") {
      expect(event.payload.patch.title).toBe("Ops Circle");
      expect(event.payload.patch.history_access).toBeUndefined();
      expect(event.payload.patch.mls_group_id).toBeUndefined();
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(outcome) });
  });
}


test("ordinary Circle list fails closed when the response contains a Sidecar profile", async ({
  page,
}) => {
  await gotoAndDismissRecovery(
    page,
    `/realms/${DEMO_REALM}/circles`,
  );
  const panel = page.getByTestId("circles-panel");
  await expect(panel).toBeVisible();
  await expect(panel.getByTestId("circle-list-item")).toHaveCount(1);
  await expect(panel).toContainText("Demo Circle");
  await expect(panel).not.toContainText("Alice AI Sidecar");
});

test("Circle creation fails closed without a durable governance checkpoint", async ({
  page,
}) => {
  await gotoAndDismissRecovery(
    page,
    `/realms/${DEMO_REALM}/circles`,
  );
  const panel = page.getByTestId("circles-panel");
  await panel.getByTestId("circle-create-open").click();
  await page.getByTestId("circle-create-title").fill("Incident Response");
  await page.getByTestId("circle-create-submit").click();

  await expect(panel.getByRole("status")).toContainText(
    "membership authoring requires a complete verified parent Realm cut",
  );
  await expect(page).toHaveURL(/\/realms\/.*\/circles$/);
  await expect(panel.getByTestId("circle-detail")).not.toContainText(
    "Incident Response",
  );
});

test("Circle creation exposes matching configurable boundaries", async ({ page }) => {
  await gotoAndDismissRecovery(page, `/realms/${DEMO_REALM}/circles`);
  await page.getByTestId("circle-create-open").click();
  const modal = page.getByTestId("circle-create-modal");
  await modal.getByTestId("circle-create-title").fill("运营协作");
  await modal.getByTestId("circle-create-short-name").fill("Ops");
  await modal.getByLabel("Circle directory visibility").selectOption("realm_members");
  await modal.getByLabel("Circle join rule").selectOption("knock");
  await modal.getByLabel("Circle history").selectOption("all_history_for_current_members");
  await expect(modal.locator(".circle-boundary-preview")).toContainText("RealmMembers");
  await expect(modal.locator(".circle-boundary-preview")).toContainText("Knock");
  await expect(modal.locator(".circle-boundary-preview")).toContainText("AllHistoryForCurrentMembers");
  await expect(modal.getByTestId("circle-create-submit")).toBeEnabled();
  await modal.getByTestId("circle-create-short-name").fill("运营");
  await expect(modal.getByTestId("circle-create-submit")).toBeDisabled();
});

test("Circle detail exposes edit and protects irreversible retirement", async ({ page }, testInfo) => {
  await gotoAndDismissRecovery(page, `/realms/${DEMO_REALM}/circles/ak:circle:AVhDoodj6EFMf5ZQ1JXfSmM5ZNZrK3ekqYa4-EOvqSiE`);
  const detail = page.getByTestId("circle-detail");
  await expect(detail.getByTestId("circle-self-membership")).toHaveText("Leave Circle");
  await expect(detail.getByTestId("circle-identity-badge")).toContainText("Demo");
  await detail.getByTestId("circle-edit").locator("summary").first().click();
  await expect(detail.getByLabel("Circle title")).toHaveValue("Demo Circle");
  await detail.getByLabel("Circle title").fill("Ops Circle");
  await rejectCircleControl(page, "ak.circle.update");
  await detail.getByTestId("circle-edit-save").click();
  await expect(page.getByTestId("circle-status")).toContainText("Circle update failed");
  await expect(detail.getByRole("heading", { name: "Demo Circle", exact: true })).toBeVisible();
  await expect(detail.getByRole("option", { name: "Invite", exact: true })).toHaveCount(0);
  await detail.getByTestId("circle-terminal-actions").locator("summary").first().click();
  await expect(detail.getByTestId("circle-tombstone")).toBeDisabled();
  await detail.getByTestId("circle-tombstone-confirm").check();
  await expect(detail.getByTestId("circle-tombstone")).toBeEnabled();
  await rejectCircleControl(page, "ak.circle.tombstone");
  await detail.getByTestId("circle-tombstone").click();
  await expect(page.getByTestId("circle-status")).toContainText("Circle retirement failed");
  await expect(detail).toContainText("Active");
  await detail.getByTestId("circle-tombstone-confirm").uncheck();
  await expect(detail.getByTestId("circle-tombstone")).toBeDisabled();
  await expect(detail.getByTestId("circle-history-restrict")).toHaveCount(0);
  await detail.getByTestId("circle-edit").locator("summary").first().click();
  await detail.getByRole("heading", { name: "Demo Circle", exact: true }).scrollIntoViewIfNeeded();
  expect(await page.getByTestId("circles-panel").evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath("circle-detail.png") });
});

test("Circle history can only tighten after explicit confirmation", async ({ page }) => {
  const realm = DEMO_REALM;
  const circle = "ak:circle:AVhDoodj6EFMf5ZQ1JXfSmM5ZNZrK3ekqYa4-EOvqSiE";
  const actor = { kind: "account", account_id: { principal_id: "ak:did_core:web:alice.example", station_id: CURRENT_STATION_ID } };
  const response = { realm_id: realm, circles: [{ circle_id: circle, realm_id: realm, title: "History Circle", display: { short_name: "History", color_token: "blue", symbol: { glyph: "ring" } }, directory_visibility: "members", join_rule: "invite", history_access: "all_history_for_current_members", state: "active", viewer_membership: "join", member_ids: [actor], created_by: actor, created_at: "2026-06-23T00:00:00.000Z" }] };
  validateMockSchema("schemas/circle-operations.schema.json#/$defs/circle_list", response);
  await page.route("**/_arkret/self/circles?**", async route => {
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(response) });
  });
  await gotoAndDismissRecovery(page, `/realms/${realm}/circles/${circle}`);
  const detail = page.getByTestId("circle-detail");
  await expect(detail).toContainText("Not end-to-end encrypted");
  await detail.getByTestId("circle-terminal-actions").locator("summary").first().click();
  await expect(detail.getByTestId("circle-history-restrict")).toBeDisabled();
  await detail.getByTestId("circle-history-confirm").check();
  await expect(detail.getByTestId("circle-history-restrict")).toBeEnabled();
  await rejectCircleControl(page, "ak.circle.history_access");
  await detail.getByTestId("circle-history-restrict").click();
  await expect(page.getByTestId("circle-status")).toContainText("History change failed");
  await expect(detail).toContainText("AllHistoryForCurrentMembers");
});

for (const [joinRule, action] of [["public", "Join Circle"], ["knock", "Request to join"], ["invite", null]] as const) {
  test(`Circle directory ${joinRule} offers only its permitted self action`, async ({ page }) => {
    const realm = DEMO_REALM;
    const circle = "ak:circle:AVhDoodj6EFMf5ZQ1JXfSmM5ZNZrK3ekqYa4-EOvqSiE";
    const response = { realm_id: realm, circles: [{ circle_id: circle, realm_id: realm, visibility: "realm_members", display: { color_token: "slate", symbol: { glyph: "ring" } }, member_count_bucket: "2-3", join_rule: joinRule, opaque_commitment: createHash("sha256").update(`ak.circle.preview.v1\0${realm}\0${circle}`).digest("hex") }] };
    validateMockSchema("schemas/circle-operations.schema.json#/$defs/circle_list", response);
    await page.route("**/_arkret/self/circles?**", async route => {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(response) });
    });
    await gotoAndDismissRecovery(page, `/realms/${realm}/circles/${circle}`);
    const detail = page.getByTestId("circle-detail");
    await expect(detail).toContainText("Private details are visible after joining");
    await expect(detail).not.toContainText("Demo Circle");
    await expect(page.getByTestId("circle-preview-item").getByTestId("circle-identity-badge")).toHaveText("◯");
    await expect(detail.getByTestId("circle-edit")).toHaveCount(0);
    if (action) {
      await expect(detail.getByTestId("circle-self-membership")).toHaveText(action);
      let membershipWrites = 0;
      page.on("request", request => {
        if (request.method() === "POST" && /\/circles\/[^/]+\/members$/.test(new URL(request.url()).pathname)) membershipWrites += 1;
      });
      await detail.getByTestId("circle-self-membership").click();
      if (joinRule === "public") {
        await expect(page.getByTestId("circle-status")).toContainText("Membership update failed");
        expect(membershipWrites).toBe(0);
      } else {
        await expect(page.getByTestId("circle-status")).toContainText("Join request submitted");
        expect(membershipWrites).toBe(1);
      }
    } else {
      await expect(detail.getByTestId("circle-self-membership")).toHaveCount(0);
      await expect(detail).toContainText("A Circle manager must grant access");
    }
  });
}

test("Realm row menu reaches the Circle directory", async ({ page }) => {
  // Navigation needs the bounded list, not a forged signed detail snapshot.
  const frames = [
    { kind: "delta", cursor: "ak:cursor:circle-menu", realm_list: {
      snapshot_cursor: "ak:cursor:circle-list", snapshot_revision: 1,
      items: [{ realm_id: DEMO_REALM, revision: 1, activity_position: 1, membership: "join", title: "Arkret Demo Realm" }],
    } },
    { kind: "catchup_complete", cursor: "ak:cursor:circle-menu" },
  ];
  for (const frame of frames) validateMockSchema("schemas/account-subscribe-frame.schema.json", frame);
  await page.route("**/_arkret/self/account/subscribe?**", async route => {
    await route.fulfill({ status: 200, contentType: "application/x-ndjson", body: frames.map(frame => JSON.stringify(frame)).join("\n") + "\n" });
  });
  await page.reload();
  await assertRealmTreeSeeded(page);
  const row = latestTestId(page, "client-shell").locator(".sidebar-row").filter({ hasText: "Arkret Demo Realm" }).first();
  await row.hover();
  await row.getByTestId("realm-tree-row-menu-button").click();
  await row.getByTestId("realm-tree-row-circles-action").click();
  await expect(page).toHaveURL(/\/realms\/.*\/circles$/);
  await expect(page.getByTestId("circles-panel")).toBeVisible();
});

test("realm sidebar separates contact-based direct chats", async ({ page }) => {
  const shell = latestTestId(page, "client-shell");
  await expect(shell.getByTestId("realm-tree-list")).toContainText(
    "Arkret Demo Realm",
  );
  await expect(shell.getByTestId("realm-sidebar-toolbar")).toBeVisible();
  await expect(shell.getByTestId("realm-sidebar-search-input")).toBeVisible();
  await expect(shell.getByTestId("sidebar-new-realm-cta")).toBeVisible();
  await expect(
    shell.getByTestId("realm-sidebar-manage-home-button"),
  ).toBeVisible();
  await dismissBlockingRecoveryModal(page);
  await shell.getByTestId("realm-sidebar-manage-home-button").click();
  await expect(page).toHaveURL(/\/realms\/manage$/);
  const realmsManagePage = shell.getByTestId("realms-manage-page");
  await expect(realmsManagePage).toBeVisible();
  await expect(realmsManagePage).toContainText("Arkret Demo Realm");
  await expect(realmsManagePage.locator(".realm-manage-hero")).toHaveCount(0);
  await expect(realmsManagePage.locator('input[type="checkbox"]')).toHaveCount(
    0,
  );
  await expect(realmsManagePage).not.toContainText(/\d+\s+rows/);
  const firstRealmRow = realmsManagePage
    .getByTestId("realms-manage-row")
    .first();
  await expect(
    firstRealmRow.getByTestId("realms-manage-row-open"),
  ).toBeHidden();
  await firstRealmRow.hover();
  await expect(
    firstRealmRow.getByTestId("realms-manage-row-open"),
  ).toBeVisible();
  await expect(
    firstRealmRow.getByTestId("realms-manage-row-settings"),
  ).toBeVisible();
  await expect(
    firstRealmRow.getByTestId("realms-manage-row-leave"),
  ).toBeVisible();

  await shell.getByTestId("realm-sidebar-tab-direct").click();

  await expect(
    shell.getByTestId("contacts-sidebar-search-input"),
  ).toBeVisible();
  await expect(shell.getByTestId("sidebar-new-contact-cta")).toBeVisible();
  await expect(shell.getByTestId("contacts-sidebar-summary")).toHaveCount(0);
  const selfRow = shell.getByTestId("contact-sidebar-self-row");
  await expect(selfRow).toContainText("alice:local.host");
  await expect(shell.getByTestId("contact-sidebar-self-badge")).toHaveText(
    "ME",
  );
  const selfAvatar = selfRow.locator(
    ".contact-sidebar-user-avatar .generated-avatar",
  );
  const topbarAvatar = shell.getByTestId("topbar-account-avatar");
  await expect(selfAvatar.locator("svg")).toBeVisible();
  await expect(topbarAvatar.locator("svg")).toBeVisible();
  expect(await selfAvatar.locator("svg").innerHTML()).toBe(
    await topbarAvatar.locator("svg").innerHTML(),
  );
  await expect(selfRow).not.toContainText("Agents 1");
  await expect(
    shell.getByTestId("contact-sidebar-self-agent-toggle"),
  ).toBeVisible();
  await expect(shell.locator(".contact-sidebar-group").first()).toHaveAttribute(
    "data-testid",
    "contact-sidebar-self-group",
  );
  await expect(shell.getByTestId("contact-sidebar-self-agents")).toContainText(
    "Alice Assistant",
  );
  const ownAgentRow = shell
    .getByTestId("contact-sidebar-agent-row")
    .filter({ hasText: "Alice Assistant" });
  await expect(
    ownAgentRow.locator(".contact-sidebar-agent-avatar img"),
  ).toHaveCount(1);
  await expect(ownAgentRow).not.toContainText("active");
  await expect(ownAgentRow).not.toContainText("paused");
  await expect(ownAgentRow).toHaveCSS("min-height", "34px");
  await expect(
    shell.getByTestId("contact-sidebar-agent-toggle").first(),
  ).toContainText("Agents 1");
  await shell.getByTestId("contact-sidebar-agent-toggle").first().click();
  await expect(
    shell.getByTestId("contact-sidebar-contact-agents"),
  ).toContainText("Bob Helper");
  await expect(
    shell
      .getByTestId("contact-sidebar-agent-row")
      .filter({ hasText: "Bob Helper" })
      .locator(".contact-sidebar-agent-avatar img"),
  ).toHaveCount(1);
  const bobContactRow = shell
    .getByTestId("direct-conversation-row")
    .filter({ hasText: "ak:did_core:web:bob.example" });
  await expect(bobContactRow).toContainText("DM");
  await expect(bobContactRow).toHaveAttribute(
    "aria-label",
    "Chat with ak:did_core:web:bob.example",
  );
  await expect(
    shell
      .getByTestId("direct-conversation-row")
      .filter({ hasText: "ak:did_core:web:carol.example" }),
  ).toContainText("pending");
  await bobContactRow.click();
  await expect(page).toHaveURL(
    /\/direct\/ak:realm:AUEAoXMJeJWBETvkqm7gk4imduk7g-l8bim19OPFQDaO\/ak:strand:Ae9PN2rTd0Dojs9yS8iLnfheJtjSEZ3mgDDyONpztHUd$/,
  );
  await shell.getByTestId("realm-sidebar-tab-direct").click();
  await shell
    .getByTestId("contact-sidebar-agent-row")
    .filter({ hasText: "Bob Helper" })
    .click();
  await expect(page).toHaveURL(/\/direct\/ak:realm:[^/]+\/ak:strand:[^/]+$/);
  await shell.getByTestId("realm-sidebar-tab-direct").click();
  await shell.getByTestId("realm-sidebar-manage-home-button").click();
  await expect(page).toHaveURL(/\/contacts\/manage$/);
  const contactsManagePage = shell.getByTestId("contacts-manage-page");
  await expect(contactsManagePage).toBeVisible();
  await expect(contactsManagePage).toContainText("ak:did_core:web:bob.example");
  await expect(contactsManagePage.locator(".realm-manage-hero")).toHaveCount(0);
  await expect(
    contactsManagePage.locator('input[type="checkbox"]'),
  ).toHaveCount(0);
});

test("owned agent opens an independent two-principal Direct Conversation Realm", async ({
  page,
}) => {
  const shell = latestTestId(page, "client-shell");
  await dismissBlockingRecoveryModal(page);
  await shell.getByTestId("realm-sidebar-tab-direct").click();
  let directRequestBody: Record<string, unknown> | null = null;
  let sidecarEnsureCount = 0;
  await page.route(
    "**/_arkret/self/direct-conversations/resolve",
    async (route) => {
      directRequestBody = await route.request().postDataJSON();
      await route.fallback();
    },
  );
  await page.route("**/_arkret/self/agent-sidecars:ensure", async (route) => {
    sidecarEnsureCount += 1;
    await route.fallback();
  });
  const directResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith("/_arkret/self/direct-conversations/resolve"),
    { timeout: 20_000 },
  );
  const ownedAgentRow = shell
    .getByTestId("contact-sidebar-agent-row")
    .filter({ hasText: "Alice Assistant" });
  await ownedAgentRow.click();
  await expect((await directResponse).ok()).toBeTruthy();
  expect(directRequestBody).toEqual({
    peer: {
      agent_id: "ak:did_core:web:agents.example:assistant",
      controller_account_id: {
        principal_id: "ak:did_core:web:alice.example",
        station_id: CURRENT_STATION_ID,
      },
      kind: "agent",
    },
  });
  await expect(page).toHaveURL(
    /\/direct\/ak:realm:AbhO_nhWEZ7jojF3JULUGyzIUTiHNshUWblbkJCr7NbP\/ak:strand:ASy992JMe_xzh5pluAqo5YuyCnAfDdFni4lmeHQldlUM$/,
  );
  await expect(shell.getByTestId("chat-panel")).toHaveCount(1);
  await expect(shell.getByTestId("sidecar-context-strip")).toHaveCount(0);
  await page.waitForTimeout(250);
  expect(sidecarEnsureCount).toBe(0);
});

test("new space strand uses sidebar realm context without home realm picker", async ({
  page,
}) => {
  await refreshServer(page);
  const shell = latestTestId(page, "client-shell");
  await expect(shell.getByTestId("realm-tree-list")).toContainText(
    "Arkret Demo Realm",
  );
  await dismissBlockingRecoveryModal(page);

  const demoRealmRow = shell
    .locator(".sidebar-row")
    .filter({ hasText: "Arkret Demo Realm" })
    .first();
  await expect(demoRealmRow).toBeVisible();
  await demoRealmRow.hover();
  await demoRealmRow.getByTestId("realm-tree-row-menu-button").click();
  await demoRealmRow.getByTestId("realm-tree-row-add-action").click();

  await expect(page).toHaveURL(/\/setup\/new-space$/);
  const setupPanel = page.getByTestId("setup-panel");
  await expect(setupPanel.getByTestId("space-create-strand")).toBeVisible();
  await expect(setupPanel).not.toContainText("Home Realm");
  await expect(setupPanel.getByTestId("new-space-realm-input")).toHaveCount(0);

  await setupPanel.getByTestId("new-space-title-input").fill("Scoped Space");
  await expect(setupPanel.getByTestId("new-space-submit-button")).toBeEnabled();
});

test("realm header collapses and sidebar edge resizes the menu", async ({
  page,
}) => {
  const sidebar = page.getByTestId("sidebar");
  const mainView = page.getByTestId("main-view");
  const toggle = page.getByTestId("sidebar-collapse-toggle");
  const resizeHandle = page.getByTestId("sidebar-resize-handle");
  const initialBox = await sidebar.boundingBox();
  const mainBox = await mainView.boundingBox();
  const toggleBox = await toggle.boundingBox();
  const handleBox = await resizeHandle.boundingBox();

  expect(initialBox).not.toBeNull();
  expect(mainBox).not.toBeNull();
  expect(toggleBox).not.toBeNull();
  expect(handleBox).not.toBeNull();
  expect(toggleBox!.x).toBeLessThan(mainBox!.x + 60);

  await page.mouse.move(handleBox!.x + handleBox!.width / 2, handleBox!.y + 24);
  await page.mouse.down();
  await page.mouse.move(340, handleBox!.y + 24, { steps: 6 });
  await page.mouse.up();

  await expect
    .poll(async () => (await sidebar.boundingBox())?.width ?? 0)
    .toBeGreaterThan(initialBox?.width ?? 0);
  const resizedWidth = (await sidebar.boundingBox())?.width ?? 0;

  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(latestTestId(page, "client-shell")).toBeVisible({
    timeout: 120_000,
  });
  await expect
    .poll(
      async () => (await page.getByTestId("sidebar").boundingBox())?.width ?? 0,
    )
    .toBeGreaterThan(300);
  const reloadedWidth =
    (await page.getByTestId("sidebar").boundingBox())?.width ?? 0;
  expect(Math.abs(reloadedWidth - resizedWidth)).toBeLessThan(24);

  await toggle.click();
  await expect
    .poll(async () => (await sidebar.boundingBox())?.width ?? 0)
    .toBeLessThan(100);
  await expect(resizeHandle).toBeHidden();
});

test("loopback proxy server aliases are normalized to local.host", async ({
  page,
}) => {
  await writeLocalConfig(page, { server_url: "http://127.0.0.1:8787/" });
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(latestTestId(page, "client-shell")).toBeVisible({
    timeout: 120_000,
  });

  await openServerSwitcher(page);
  await expect(page.getByTestId("principal-context")).toContainText(
    "https://local.host",
  );
  await expect(page.getByTestId("server-url-input")).toHaveCount(0);
  await expect(page.getByTestId("connect-button")).toHaveCount(0);
  await expect(page.getByTestId("topbar-crumbs")).not.toContainText(
    "https://local.host",
  );
});

test("topbar breadcrumbs avoid duplicated route and server context", async ({
  page,
}) => {
  await openSettings(page);
  await expect(page.getByTestId("topbar-crumbs")).toContainText("Settings");
  await expect(page.getByTestId("topbar-crumbs")).not.toContainText(
    "Settings / Settings",
  );
  await expect(page.getByTestId("topbar-crumbs")).not.toContainText(
    "Station https://",
  );
});

test("dashboard summarizes unread notifications from sync projection", async ({
  page,
}) => {
  await refreshServer(page);

  await expect(page.getByTestId("dashboard-unread-notifications")).toHaveText(
    "2",
  );
  await expect(page.getByTestId("pinned-notifications")).toContainText(
    "New message",
  );
  await expect(page.getByTestId("pinned-notifications")).toContainText(
    "New invite",
  );
});

test("server switcher hides custom endpoint controls", async ({ page }) => {
  await openServerSwitcher(page);

  await expect(page.getByTestId("server-url-input")).toHaveCount(0);
  await expect(page.getByTestId("connect-button")).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Services" })).toHaveCount(0);
});

test("server switcher keeps only server choices after expand", async ({
  page,
}) => {
  await openServerSwitcher(page);

  await expect(page.getByTestId("server-switch-menu")).toBeVisible();
  await expect(page.getByTestId("server-option")).toHaveCount(1);
  await expect(page.getByTestId("server-switch-menu")).toContainText(
    "https://local.host",
  );
  await expect(page.getByTestId("server-switch-menu")).not.toContainText(
    "Current data home",
  );
  await expect(page.getByTestId("principal-context")).not.toContainText(
    "Refresh",
  );
});
