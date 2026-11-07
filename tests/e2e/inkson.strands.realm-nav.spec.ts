import { createHash } from "node:crypto";
import { expect, test } from "@playwright/test";
import {
  CURRENT_STATION_ID, CURRENT_ACCOUNT_ID, CURRENT_ACCOUNT_ACTOR_ID,
  CURRENT_ASSISTANT_ACCOUNT_ID, BOB_ACCOUNT_ID, BOB_HELPER_ACCOUNT_ID,
  DIRECT_BOB_HELPER_REALM, DIRECT_BOB_HELPER_STRAND, DEMO_REALM, INVITED_REALM,
  DEMO_PARENT_MEMBERSHIP_REVISION, validateMockSchema,
} from "./mockArkretApi";
import {
  registerStrandsBeforeEach,
  latestByClass,
  svgDrawingMarkup,
  dismissBlockingRecoveryModal,
  gotoAndDismissRecovery,
  refreshServer,
  openSettings,
  writeLocalConfig,
  submittedEvent,
  assertRealmTreeSeeded,
} from "./strandsHarness";

registerStrandsBeforeEach();

async function rejectCircleControl(page: import("@playwright/test").Page, kind: string) {
  const outcome = { status: "rejected", reason_code: "capability_denied" };
  validateMockSchema("schemas/authority-commit-operations.schema.json#/$defs/self_submit_response_body", outcome);
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
  const panel = page.locator("[class~=\"circle-realm\"]");
  await expect(panel).toBeVisible();
  await expect(panel.locator("[class~=\"circle-list-item\"]")).toHaveCount(1);
  await expect(panel).toContainText("Demo Circle");
  await expect(panel).not.toContainText("Alice AI Sidecar");
});

test("Circle creation fails closed without a complete verified parent Realm cut", async ({
  page,
}) => {
  // This canonical Realm is deliberately absent from the Account baseline.
  const response = { realm_id: INVITED_REALM, circles: [] };
  validateMockSchema("schemas/circle-operations.schema.json#/$defs/circle_list", response);
  await page.route("**/_arkret/self/circles?**", async route => {
    if (new URL(route.request().url()).searchParams.get("realm_id") !== INVITED_REALM) {
      await route.fallback(); return;
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(response) });
  });
  const writes: string[] = [];
  page.on("request", request => {
    const path = new URL(request.url()).pathname;
    if (request.method() === "POST" &&
      (["/_arkret/self/events", "/_arkret/self/event-batches", "/_arkret/self/circles"].includes(path) ||
        /^\/_arkret\/self\/circles\/[^/]+\/members$/.test(path))) {
      writes.push(request.url());
    }
  });
  await gotoAndDismissRecovery(
    page,
    `/realms/${INVITED_REALM}/circles`,
  );
  const panel = page.locator("[class~=\"circle-realm\"]");
  await panel.locator("[class~=\"circles-new\"]").click();
  await page.locator(".circle-create-title input").fill("Incident Response");
  await page.locator("[class~=\"circle-create\"]").click();

  await expect(panel.getByRole("status")).toContainText(
    "membership authoring requires a complete verified parent Realm cut",
  );
  await expect(page).toHaveURL(/\/realms\/.*\/circles$/);
  await expect(panel).not.toContainText("Incident Response");
  await expect(panel.locator("[class~=\"circle-list-item\"]")).toHaveCount(0);
  await expect(panel.locator("[class~=\"circle-detail\"]")).not.toContainText("Incident Response");
  expect(writes).toEqual([]);
});

test("Circle creation exposes matching configurable boundaries", async ({ page }) => {
  await gotoAndDismissRecovery(page, `/realms/${DEMO_REALM}/circles`);
  await page.locator("[class~=\"circles-new\"]").click();
  const modal = page.locator("[class~=\"circle-create-modal\"]");
  await modal.locator(".circle-create-title input").fill("运营协作");
  await modal.locator(".circle-create-short input").fill("Ops");
  await modal.getByRole("combobox", { name: "Circle directory visibility", exact: true }).click();
  await page.getByRole("option", { name: "Preview for Realm members", exact: true }).click();
  await modal.getByRole("combobox", { name: "Circle join rule", exact: true }).click();
  await page.getByRole("option", { name: "Request approval", exact: true }).click();
  await modal.getByRole("combobox", { name: "Circle history", exact: true }).click();
  await page.getByRole("option", { name: "All history for current members", exact: true }).click();
  await expect(modal.locator(".circle-boundary-preview")).toContainText("RealmMembers");
  await expect(modal.locator(".circle-boundary-preview")).toContainText("Knock");
  await expect(modal.locator(".circle-boundary-preview")).toContainText("AllHistoryForCurrentMembers");
  await expect(modal.locator("[class~=\"circle-create\"]")).toBeEnabled();
  await modal.locator(".circle-create-short input").fill("运营");
  await expect(modal.locator("[class~=\"circle-create\"]")).toBeDisabled();
});

test("Circle detail exposes edit and protects irreversible retirement", async ({ page }, testInfo) => {
  await gotoAndDismissRecovery(page, `/realms/${DEMO_REALM}/circles/ak:circle:AVhDoodj6EFMf5ZQ1JXfSmM5ZNZrK3ekqYa4-EOvqSiE`);
  const detail = page.locator("[class~=\"circle-detail\"]");
  await expect(detail.getByRole("button", { name: "Leave Circle", exact: true })).toHaveText("Leave Circle");
  await expect(detail.locator("[class~=\"circle-identity-badge\"]")).toContainText("Demo");
  await detail.locator("[class~=\"circle-edit\"]").locator(".circle-details-summary").click();
  await expect(detail.getByLabel("Title", { exact: true })).toHaveValue("Demo Circle");
  await detail.getByLabel("Title", { exact: true }).fill("Ops Circle");
  await rejectCircleControl(page, "ak.circle.update");
  await detail.locator("[class~=\"circle-edit-save\"]").click();
  await expect(page.locator("[class~=\"circle-status\"]")).toContainText("Circle update failed");
  await expect(detail.getByRole("heading", { name: "Demo Circle", exact: true })).toBeVisible();
  await expect(detail.getByRole("option", { name: "Invite", exact: true })).toHaveCount(0);
  await detail.locator("[class~=\"circle-terminal-actions\"]").locator(".circle-details-summary").click();
  await expect(detail.locator("[class~=\"circle-tombstone\"]")).toBeDisabled();
  await detail.locator(".circle-terminal-confirm input").check();
  await expect(detail.locator("[class~=\"circle-tombstone\"]")).toBeEnabled();
  await rejectCircleControl(page, "ak.circle.tombstone");
  await detail.locator("[class~=\"circle-tombstone\"]").click();
  await expect(page.locator("[class~=\"circle-status\"]")).toContainText("Circle retirement failed");
  await expect(detail).toContainText("Active");
  await detail.locator(".circle-terminal-confirm input").uncheck();
  await expect(detail.locator("[class~=\"circle-tombstone\"]")).toBeDisabled();
  await expect(detail.locator("[class~=\"circle-history-restrict\"]")).toHaveCount(0);
  await detail.locator("[class~=\"circle-edit\"]").locator(".circle-details-summary").click();
  await detail.getByRole("heading", { name: "Demo Circle", exact: true }).scrollIntoViewIfNeeded();
  expect(await page.locator("[class~=\"circle-realm\"]").evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
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
  const detail = page.locator("[class~=\"circle-detail\"]");
  await expect(detail).toContainText("Not end-to-end encrypted");
  await detail.locator("[class~=\"circle-terminal-actions\"]").locator(".circle-details-summary").click();
  await expect(detail.locator("[class~=\"circle-history-restrict\"]")).toBeDisabled();
  await detail.locator(".circle-history-confirm input").check();
  await expect(detail.locator("[class~=\"circle-history-restrict\"]")).toBeEnabled();
  await rejectCircleControl(page, "ak.circle.history_access");
  await detail.locator("[class~=\"circle-history-restrict\"]").click();
  await expect(page.locator("[class~=\"circle-status\"]")).toContainText("History change failed");
  await expect(detail).toContainText("AllHistoryForCurrentMembers");
});

test("Circle member removal sends the exact signed leave Event and refreshes members", async ({ page }) => {
  const circle = "ak:circle:AVhDoodj6EFMf5ZQ1JXfSmM5ZNZrK3ekqYa4-EOvqSiE";
  const writes: Array<Record<string, any>> = [];
  await page.route("**/_arkret/self/circles/*/members/**", async route => {
    if (route.request().method() === "DELETE") {
      const body = route.request().postDataJSON();
      validateMockSchema("schemas/circle-operations.schema.json#/$defs/circle_member_delete_request_body", body);
      const event = body.member_event.event;
      expect(event.kind).toBe("ak.circle.member.state");
      expect(event.actor_id).toEqual(CURRENT_ACCOUNT_ACTOR_ID);
      expect(event.scope_ref).toEqual({ kind: "circle", realm_id: DEMO_REALM, circle_id: circle });
      expect(event.payload).toMatchObject({ circle_id: circle, member_id: CURRENT_ACCOUNT_ACTOR_ID, membership: "leave", expected_membership: "join" });
      expect(event.producer_proof).toBeTruthy();
      expect(JSON.parse(decodeURIComponent(new URL(route.request().url()).pathname.split("/members/")[1]))).toEqual(CURRENT_ACCOUNT_ACTOR_ID);
      writes.push(event);
    }
    await route.fallback();
  });
  await gotoAndDismissRecovery(page, `/realms/${DEMO_REALM}/circles/${circle}`);
  const detail = page.locator("[class~=\"circle-detail\"]");
  await expect(detail.locator(".circle-member-row")).toHaveCount(1);
  await detail.locator(".circle-member-row").getByRole("button", { name: "Remove", exact: true }).click();
  await expect(page.locator("[class~=\"circle-status\"]")).toContainText("Member access removed");
  await expect(detail.locator(".circle-member-row")).toHaveCount(0);
  expect(writes).toHaveLength(1);
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
    const detail = page.locator("[class~=\"circle-detail\"]");
    await expect(detail).toContainText("Private details are visible after joining");
    await expect(detail).not.toContainText("Demo Circle");
    await expect(page.locator(".circle-list .circle-list-item .circle-identity-badge")).toHaveText("◯");
    await expect(detail.locator("[class~=\"circle-edit\"]")).toHaveCount(0);
    if (action) {
      await expect(detail.getByRole("button", { name: action, exact: true })).toHaveText(action);
      let membershipWrites = 0;
      const memberEvents: Array<Record<string, any>> = [];
      page.on("request", request => {
        if (request.method() === "POST" && /\/circles\/[^/]+\/members$/.test(new URL(request.url()).pathname)) {
          membershipWrites += 1;
          memberEvents.push(request.postDataJSON().member_event.event);
        }
      });
      await detail.getByRole("button", { name: action, exact: true }).click();
      if (joinRule === "public") {
        await expect(page.locator("[class~=\"circle-status\"]")).toContainText("Membership updated");
        expect(membershipWrites).toBe(1);
        expect(memberEvents).toHaveLength(1);
        const event = memberEvents[0];
        expect(event.actor_id).toEqual(CURRENT_ACCOUNT_ACTOR_ID);
        expect(event.scope_ref).toEqual({ kind: "circle", realm_id: realm, circle_id: circle });
        expect(event.payload).toMatchObject({
          circle_id: circle, member_id: CURRENT_ACCOUNT_ACTOR_ID, membership: "join",
          parent_membership_revision: DEMO_PARENT_MEMBERSHIP_REVISION,
        });
        expect(event.producer_proof).toBeTruthy();
      } else {
        await expect(page.locator("[class~=\"circle-status\"]")).toContainText("Join request submitted");
        expect(membershipWrites).toBe(1);
      }
    } else {
      await expect(detail.getByRole("button", { name: /^(Join Circle|Request to join)$/, exact: true })).toHaveCount(0);
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
  const row = page.locator(".shell.app").last().locator(".sidebar-row").filter({ hasText: "Arkret Demo Realm" }).first();
  await row.hover();
  await row.getByRole("button", { name: "Realm actions", exact: true }).click();
  await row.getByRole("link", { name: "Circles", exact: true }).click();
  await expect(page).toHaveURL(/\/realms\/.*\/circles$/);
  await expect(page.locator("[class~=\"circle-realm\"]")).toBeVisible();
});

test("Contacts list selects human and agent details before opening their direct conversations", async ({ page }) => {
  await dismissBlockingRecoveryModal(page);
  await page.locator(".rail-contacts").click();
  const list = page.locator(".contact-list-items");
  await expect(list).toContainText("Alice Assistant");
  await expect(list).toContainText("Bob Helper");
  const bobPrincipalToken = BOB_ACCOUNT_ID.principal_id.split(":").at(-1)!;
  const bobDisplayLabel = `ak:did_core:webvh:${bobPrincipalToken.slice(0, 8)}...${bobPrincipalToken.slice(-6)}`;
  await list.locator(".contact-list-item").filter({ hasText: bobDisplayLabel }).click();
  const detail = page.locator(".contacts-detail-pane .contact-row");
  await expect(detail).toHaveAccessibleDescription(`Principal: ${BOB_ACCOUNT_ID.principal_id} · Station: ${BOB_ACCOUNT_ID.station_id}`);
  const humanRequest = page.waitForRequest(request => request.method() === "POST" && new URL(request.url()).pathname === "/_arkret/self/direct-conversations/resolve");
  await detail.locator(".contact-message").click();
  expect((await humanRequest).postDataJSON().peer).toEqual({ kind: "human", account_id: BOB_ACCOUNT_ID });
  await expect(page).toHaveURL(/\/direct\//);
  await page.locator(".rail-brand").click();
  await expect(page.locator(".dashboard-panel")).toBeVisible();
  await page.locator(".rail-contacts").click();
  await list.locator(".contact-agent-list-item").filter({ hasText: "Bob Helper" }).click();
  await expect(page.locator(".contact-agent-detail")).toContainText("Bob Helper");
  const agentRequest = page.waitForRequest(request => request.method() === "POST" && new URL(request.url()).pathname === "/_arkret/self/direct-conversations/resolve");
  await page.locator(".contact-agent-message").click();
  expect((await agentRequest).postDataJSON().peer).toEqual({
    kind: "agent", actor_id: { kind: "account", account_id: BOB_HELPER_ACCOUNT_ID }, controller_account_id: BOB_ACCOUNT_ID,
  });
  await expect(page).toHaveURL(`/direct/${DIRECT_BOB_HELPER_REALM}/${DIRECT_BOB_HELPER_STRAND}`);
});

test("owned agent opens an independent two-principal Direct Conversation Realm", async ({
  page,
}) => {
  const shell = page.locator(".shell.app").last();
  await dismissBlockingRecoveryModal(page);
  await shell.locator(".rail-contacts").click();
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
  const ownedAgentRow = shell.locator(".contact-agent-list-item").filter({ hasText: "Alice Assistant" });
  await ownedAgentRow.click();
  await shell.locator(".contact-agent-message").click();
  await expect((await directResponse).ok()).toBeTruthy();
  expect(directRequestBody).toEqual({
    peer: {
      kind: "agent",
      actor_id: { kind: "account", account_id: CURRENT_ASSISTANT_ACCOUNT_ID },
      controller_account_id: CURRENT_ACCOUNT_ID,
    },
  });
  await expect(page).toHaveURL(
    /\/direct\/ak:realm:AbhO_nhWEZ7jojF3JULUGyzIUTiHNshUWblbkJCr7NbP\/ak:strand:ASy992JMe_xzh5pluAqo5YuyCnAfDdFni4lmeHQldlUM$/,
  );
  await expect(shell.locator("[class~=\"chat-panel\"]")).toHaveCount(1);
  await expect(shell.locator("[class~=\"sidecar-context-strip\"]")).toHaveCount(0);
  await page.waitForTimeout(250);
  expect(sidecarEnsureCount).toBe(0);
});

test("new space strand uses sidebar realm context without home realm picker", async ({
  page,
}) => {
  await refreshServer(page);
  await assertRealmTreeSeeded(page);
  const shell = page.locator(".shell.app").last();
  await expect(shell.locator("[class~=\"realm-tree-list\"]")).toContainText(
    "Arkret Demo Realm",
  );
  await dismissBlockingRecoveryModal(page);

  const demoRealmRow = shell
    .locator(".sidebar-row")
    .filter({ hasText: "Arkret Demo Realm" })
    .first();
  await expect(demoRealmRow).toBeVisible();
  await demoRealmRow.hover();
  await demoRealmRow.getByRole("button", { name: "Realm actions", exact: true }).click();
  await demoRealmRow.getByRole("button", { name: "New Space", exact: true }).click();

  await expect(page).toHaveURL(/\/setup\/new-space$/);
  const setupPanel = page.locator("[class~=\"setup-panel\"]");
  await expect(setupPanel.locator("[class~=\"space-create-strand\"]")).toBeVisible();
  await expect(setupPanel).not.toContainText("Home Realm");
  await expect(setupPanel.locator("[class~=\"new-space-realm-input\"]")).toHaveCount(0);

  await setupPanel.locator(".new-space-title-input input").fill("Scoped Space");
  await expect(setupPanel.locator("[class~=\"new-space-submit-button\"]")).toBeEnabled();
});

test("icon rail retains its width and omits the server picker", async ({ page }) => {
  const rail = page.locator(".navigation-rail");
  const width = (await rail.boundingBox())!.width;
  await expect(page.locator(".server-switch-button, .sidebar-resize-handle, .sidebar-collapse-toggle")).toHaveCount(0);
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(rail).toBeVisible();
  expect((await rail.boundingBox())!.width).toBe(width);
});

test("topbar breadcrumbs avoid duplicated route and server context", async ({
  page,
}) => {
  await openSettings(page);
  await expect(page.locator(".topbar-context")).toContainText("Settings");
  await expect(page.locator(".topbar-context")).not.toContainText(
    "Settings / Settings",
  );
  await expect(page.locator(".topbar-context")).not.toContainText(
    "Station https://",
  );
});

test("dashboard summarizes unread notifications from sync projection", async ({
  page,
}) => {
  await expect(page.locator("[class~=\"dashboard-unread-notifications\"].val")).toHaveText(
    "2",
  );
  const cursorIndicator = page.locator("[class~=\"sync-cursor\"]");
  await expect(cursorIndicator).toHaveText(/^cursor \S+$/);
  const savedCursor = (await cursorIndicator.textContent() ?? "").slice("cursor ".length);
  const refreshDescribe = page.waitForRequest(request =>
    request.method() === "GET" &&
    new URL(request.url()).pathname === "/_arkret/describe"
  );
  // Inspect the first subscription after this refresh's describe, including a
  // missing after; filtering by the expected cursor would hide a fresh baseline.
  const resumedSubscription = refreshDescribe.then(() =>
    page.waitForRequest(request =>
      request.method() === "GET" &&
      new URL(request.url()).pathname === "/_arkret/self/account/subscribe"
    )
  );
  await refreshServer(page);
  const request = await resumedSubscription;
  expect(new URL(request.url()).searchParams.get("after")).toBe(savedCursor);

  await expect(page.locator("[class~=\"dashboard-unread-notifications\"].val")).toHaveText(
    "2",
  );
  await expect(page.locator("[class~=\"pinned-notifications\"]")).toContainText(
    "New message",
  );
  await expect(page.locator("[class~=\"pinned-notifications\"]")).toContainText(
    "Realm invite",
  );
});

test("server identity lives on the account page", async ({ page }) => {
  await dismissBlockingRecoveryModal(page);
  await page.locator(".navigation-rail .rail-account").click();
  await expect(page.locator(".account-page__server")).toHaveText("https://local.host");
  await expect(page.locator(".server-switch-menu, .server-switch-button")).toHaveCount(0);
});
