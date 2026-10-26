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

test("realm sidebar separates contact-based direct chats", async ({ page }) => {
  const shell = page.locator(".shell.app").last();
  await expect(shell.locator("[class~=\"realm-tree-list\"]")).toContainText(
    "Arkret Demo Realm",
  );
  await expect(shell.locator(".sidebar-tab-toolbar")).toBeVisible();
  await expect(shell.locator(".sidebar-tab-search input")).toBeVisible();
  await expect(shell.locator(".add-realm-cta")).toBeVisible();
  await expect(
    shell.locator(".manage-home-link"),
  ).toBeVisible();
  await dismissBlockingRecoveryModal(page);
  await shell.locator(".manage-home-link").click();
  await expect(page).toHaveURL(/\/realms\/manage$/);
  const realmsManagePage = shell.locator(".realm-manage-page");
  await expect(realmsManagePage).toBeVisible();
  await expect(realmsManagePage).toContainText("Arkret Demo Realm");
  await expect(realmsManagePage.locator(".realm-manage-hero")).toHaveCount(0);
  await expect(realmsManagePage.locator('input[type="checkbox"]')).toHaveCount(
    0,
  );
  await expect(realmsManagePage).not.toContainText(/\d+\s+rows/);
  const firstRealmRow = realmsManagePage
    .locator(".realm-manage-row")
    .first();
  await expect(
    firstRealmRow.getByRole("link", { name: "Open Realm", exact: true }),
  ).toBeHidden();
  await firstRealmRow.hover();
  await expect(
    firstRealmRow.getByRole("link", { name: "Open Realm", exact: true }),
  ).toBeVisible();
  await expect(
    firstRealmRow.getByRole("link", { name: "Settings", exact: true }),
  ).toBeVisible();
  await expect(
    firstRealmRow.getByRole("button", { name: "Leave", exact: true }),
  ).toBeVisible();

  await shell.getByRole("button", { name: "Contacts", exact: true }).click();

  await expect(
    shell.locator(".sidebar-tab-search input"),
  ).toBeVisible();
  await expect(shell.locator(".add-contact-cta")).toBeVisible();
  await expect(shell.locator("[class~=\"contacts-sidebar-summary\"]")).toHaveCount(0);
  const selfRow = shell.locator("[class~=\"contact-sidebar-self-row\"]");
  await expect(selfRow).toContainText("alice:local.host");
  await expect(shell.locator("[class~=\"contact-sidebar-self-badge\"]")).toHaveText(
    "ME",
  );
  const selfAvatar = selfRow.locator("svg.contact-sidebar-user-avatar.generated-avatar");
  const topbarAvatar = shell.locator(".topbar-account-avatar svg.generated-avatar, svg.topbar-account-avatar.generated-avatar");
  await expect(selfAvatar).toBeVisible();
  await expect(topbarAvatar).toBeVisible();
  expect(await svgDrawingMarkup(selfAvatar)).toBe(
    await svgDrawingMarkup(topbarAvatar),
  );
  await expect(selfRow).not.toContainText("Agents 1");
  await expect(
    shell.locator("[class~=\"contact-sidebar-self-agent-toggle\"]"),
  ).toBeVisible();
  await expect(shell.locator(".contact-sidebar-group").first()).toHaveClass(/\bcontact-sidebar-self-group\b/);
  await expect(shell.locator("[class~=\"contact-sidebar-self-agents\"]")).toContainText(
    "Alice Assistant",
  );
  const ownAgentRow = shell
    .locator("[class~=\"contact-sidebar-agent-row\"]")
    .filter({ hasText: "Alice Assistant" });
  await expect(
    ownAgentRow.locator("img.contact-sidebar-agent-avatar, .contact-sidebar-agent-avatar img"),
  ).toHaveCount(1);
  await expect(ownAgentRow).not.toContainText("active");
  await expect(ownAgentRow).not.toContainText("paused");
  await expect(ownAgentRow).toHaveCSS("min-height", "34px");
  await expect(
    shell.locator("[class~=\"contact-sidebar-agent-toggle\"]").first(),
  ).toContainText("Agents 1");
  await shell.locator("[class~=\"contact-sidebar-agent-toggle\"]").first().click();
  await expect(
    shell.locator("[class~=\"contact-sidebar-contact-agents\"]"),
  ).toContainText("Bob Helper");
  await expect(
    shell
      .locator("[class~=\"contact-sidebar-agent-row\"]")
      .filter({ hasText: "Bob Helper" })
      .locator("img.contact-sidebar-agent-avatar, .contact-sidebar-agent-avatar img"),
  ).toHaveCount(1);
  const bobPrincipalToken = BOB_ACCOUNT_ID.principal_id.split(":").at(-1)!;
  const bobDisplayLabel = `ak:did_core:webvh:${bobPrincipalToken.slice(0, 8)}...${bobPrincipalToken.slice(-6)}`;
  const bobContactRow = shell.getByRole("button", { name: `Chat with ${bobDisplayLabel}`, exact: true });
  await expect(bobContactRow).toHaveAccessibleDescription(
    `Principal: ${BOB_ACCOUNT_ID.principal_id} · Station: ${BOB_ACCOUNT_ID.station_id}`,
  );
  await expect(bobContactRow).toContainText("DM");
  await expect(bobContactRow).toHaveAttribute(
    "aria-label",
    `Chat with ${bobDisplayLabel}`,
  );
  await expect(
    shell
      .locator("[class~=\"direct-conversation-row\"]")
      .filter({ hasText: "ak:did_core:web:carol.example" }),
  ).toContainText("pending");
  const isDirectResolver = (request: import("@playwright/test").Request) =>
    request.method() === "POST" &&
    new URL(request.url()).pathname === "/_arkret/self/direct-conversations/resolve";
  // The active Direct view revalidates its own authority. Track the real
  // requests through either terminal network event: retiring the view can
  // abort a response after headers, without resolving Response.finished().
  const pendingHumanResolvers = new Set<import("@playwright/test").Request>();
  const failedHumanResolvers = new Set<import("@playwright/test").Request>();
  const observeHumanResolver = (request: import("@playwright/test").Request) => {
    if (isDirectResolver(request)) pendingHumanResolvers.add(request);
  };
  const finishHumanResolver = (request: import("@playwright/test").Request) => {
    pendingHumanResolvers.delete(request);
  };
  const failHumanResolver = (request: import("@playwright/test").Request) => {
    if (!pendingHumanResolvers.has(request)) return;
    failedHumanResolvers.add(request);
    pendingHumanResolvers.delete(request);
  };
  page.on("request", observeHumanResolver);
  page.on("requestfinished", finishHumanResolver);
  page.on("requestfailed", failHumanResolver);
  const humanRequest = page.waitForRequest(isDirectResolver);
  await bobContactRow.click();
  const resolvedHumanRequest = await humanRequest;
  expect(resolvedHumanRequest.postDataJSON().peer).toEqual({
    kind: "human", account_id: BOB_ACCOUNT_ID,
  });
  const humanResponse = await resolvedHumanRequest.response();
  expect(humanResponse?.status()).toBe(200);
  expect(await humanResponse!.finished()).toBeNull();
  await expect(page).toHaveURL(
    /\/direct\/ak:realm:AUEAoXMJeJWBETvkqm7gk4imduk7g-l8bim19OPFQDaO\/ak:strand:Ae9PN2rTd0Dojs9yS8iLnfheJtjSEZ3mgDDyONpztHUd$/,
  );
  await page.locator("[class~=\"sidebar\"] a.sidebar-nav-item[href=\"/\"]").click();
  await expect(page.locator("[class~=\"dashboard-panel\"]")).toBeVisible();
  await expect.poll(() => pendingHumanResolvers.size).toBe(0);
  // Only normal Chromium cancellation may retire a background revalidation;
  // other network errors must remain visible failures.
  for (const failed of failedHumanResolvers) {
    expect(failed.failure()?.errorText).toBe("net::ERR_ABORTED");
  }
  page.off("request", observeHumanResolver);
  page.off("requestfinished", finishHumanResolver);
  page.off("requestfailed", failHumanResolver);
  await shell.getByRole("button", { name: "Contacts", exact: true }).click();
  // Do not filter by the expected peer: a wrong actual request must fail.
  const helperRequest = page.waitForRequest(isDirectResolver);
  await shell
    .locator("[class~=\"contact-sidebar-agent-row\"]")
    .filter({ hasText: "Bob Helper" })
    .click();
  expect((await helperRequest).postDataJSON().peer).toEqual({
    kind: "agent", actor_id: { kind: "account", account_id: BOB_HELPER_ACCOUNT_ID },
    controller_account_id: BOB_ACCOUNT_ID,
  });
  await expect(page).toHaveURL(`/direct/${DIRECT_BOB_HELPER_REALM}/${DIRECT_BOB_HELPER_STRAND}`);
  await shell.getByRole("button", { name: "Contacts", exact: true }).click();
  await shell.locator(".manage-home-link").click();
  await expect(page).toHaveURL(/\/contacts\/manage$/);
  const contactsManagePage = shell.locator(".realm-manage-page");
  await expect(contactsManagePage).toBeVisible();
  const recipientDescription = `Principal: ${BOB_ACCOUNT_ID.principal_id} · Station: ${BOB_ACCOUNT_ID.station_id}`;
  const managedBob = contactsManagePage.locator(".contacts-manage-row").filter({
    has: page.getByText(recipientDescription, { exact: true }),
  });
  await expect(managedBob).toHaveAccessibleDescription(recipientDescription);
  await expect(managedBob).toContainText(bobDisplayLabel);
  await expect(contactsManagePage.locator(".realm-manage-hero")).toHaveCount(0);
  await expect(
    contactsManagePage.locator('input[type="checkbox"]'),
  ).toHaveCount(0);
});

test("owned agent opens an independent two-principal Direct Conversation Realm", async ({
  page,
}) => {
  const shell = page.locator(".shell.app").last();
  await dismissBlockingRecoveryModal(page);
  await shell.getByRole("button", { name: "Contacts", exact: true }).click();
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
    .locator("[class~=\"contact-sidebar-agent-row\"]")
    .filter({ hasText: "Alice Assistant" });
  await ownedAgentRow.click();
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

test("realm header collapses and sidebar edge resizes the menu", async ({
  page,
}) => {
  const sidebar = page.locator("[class~=\"sidebar\"]");
  const mainView = page.locator(".main.realm");
  const toggle = page.locator("[class~=\"sidebar-collapse-toggle\"]");
  const resizeHandle = page.locator("[class~=\"sidebar-resize-handle\"]");
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
  await expect(page.locator(".shell.app").last()).toBeVisible({
    timeout: 120_000,
  });
  await expect
    .poll(
      async () => (await page.locator("[class~=\"sidebar\"]").boundingBox())?.width ?? 0,
    )
    .toBeGreaterThan(300);
  const reloadedWidth =
    (await page.locator("[class~=\"sidebar\"]").boundingBox())?.width ?? 0;
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
  await expect(page.locator(".shell.app").last()).toBeVisible({
    timeout: 120_000,
  });

  await openServerSwitcher(page);
  await expect(page.locator(".server-switch-menu")).toContainText(
    "https://local.host",
  );
  await expect(page.locator("[class~=\"server-url-input\"]")).toHaveCount(0);
  await expect(page.locator("[class~=\"connect-button\"]")).toHaveCount(0);
  await expect(page.locator(".topbar-context")).not.toContainText(
    "https://local.host",
  );
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

test("server switcher hides custom endpoint controls", async ({ page }) => {
  await openServerSwitcher(page);

  await expect(page.locator("[class~=\"server-url-input\"]")).toHaveCount(0);
  await expect(page.locator("[class~=\"connect-button\"]")).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Services" })).toHaveCount(0);
});

test("server switcher keeps only server choices after expand", async ({
  page,
}) => {
  await openServerSwitcher(page);

  await expect(page.locator("[class~=\"server-switch-menu\"]")).toBeVisible();
  await expect(page.locator("[class~=\"server-option\"]")).toHaveCount(1);
  await expect(page.locator("[class~=\"server-switch-menu\"]")).toContainText(
    "https://local.host",
  );
  await expect(page.locator("[class~=\"server-switch-menu\"]")).not.toContainText(
    "Current data home",
  );
  await expect(page.locator(".server-switch-menu")).not.toContainText(
    "Refresh",
  );
});
