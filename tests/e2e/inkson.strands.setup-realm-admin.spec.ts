import { inputByClass } from "./uiControl";
import { byClass } from "./strandsHarness";
import { expect, test } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  CURRENT_PRINCIPAL_CORE_ID,

  dismissBlockingRecoveryModal,
  refreshServer,
  gotoAndDismissRecovery,
  dismissRecoveryMissingModal,
  dismissMlsBackupModal,
  CURRENT_STATION_ID,
  DEMO_REALM,
  submittedEvent,
  readLocalConfig,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("setup realm form stays in the main realm layout", async ({ page }) => {
  await refreshServer(page);
  await page.goto("/setup/realms", { waitUntil: "domcontentloaded" });
  await expect(byClass(page, "setup-panel")).toBeVisible();
  await expect(byClass(page, "realm-setup-guide")).toHaveCount(0);

  const titleInput = inputByClass(page, "realm-title-input");
  await expect(titleInput).toHaveJSProperty("required", true);
  await expect(titleInput).toHaveAttribute("aria-required", "true");
  const titleId = await titleInput.getAttribute("id");
  expect(titleId).toBeTruthy();
  const titleLabel = page.locator(`label[for="${titleId}"]`);
  await expect(titleLabel).toHaveText("Realm title");
  expect(await titleLabel.evaluate((label) => getComputedStyle(label, "::after").content)).toContain("*");

  const fieldTops = await page.evaluate(() => ({
    alias: document
      .querySelector('[class~="realm-alias-input"]')
      ?.getBoundingClientRect().top,
    summary: document
      .querySelector('[class~="realm-summary-input"]')
      ?.getBoundingClientRect().top,
  }));
  expect(fieldTops.alias).toBeDefined();
  expect(fieldTops.summary).toBeDefined();
  expect(fieldTops.alias!).toBeLessThan(fieldTops.summary!);

  const activeStepButton = page.locator(
    '.setup-step-list button.setup-step.active',
  );
  await expect(activeStepButton).toHaveCount(1);
  await expect(activeStepButton).toHaveJSProperty("tagName", "BUTTON");
  const activeStepStyle = await activeStepButton.evaluate((button) => {
    const style = getComputedStyle(button);
    return {
      display: style.display,
      borderRadius: style.borderRadius,
      backgroundImage: style.backgroundImage,
    };
  });
  expect(activeStepStyle.display).toBe("grid");
  expect(activeStepStyle.borderRadius).toBe("8px");
  expect(activeStepStyle.backgroundImage).toContain("linear-gradient");

  const stepTops = await page
    .locator(".setup-step-list button")
    .evaluateAll((buttons) =>
      buttons.map((button) => button.getBoundingClientRect().top),
    );
  expect(stepTops).toHaveLength(4);
  expect(Math.max(...stepTops) - Math.min(...stepTops)).toBeLessThanOrEqual(1);

  const measureLayout = () =>
    page.evaluate(() => {
      const rectOf = (selector: string) => {
        const rect = document.querySelector(selector)?.getBoundingClientRect();
        return rect
          ? {
              left: rect.left,
              right: rect.right,
              top: rect.top,
              width: rect.width,
            }
          : null;
      };
      return {
        sidebar: rectOf('[class~="sidebar"]'),
        main: rectOf('.main.realm'),
        setup: rectOf('[class~="setup-panel"]'),
        header: rectOf(".realm-header"),
      };
    });

  const assertRealmLayout = (
    layout: Awaited<ReturnType<typeof measureLayout>>,
  ) => {
    expect(layout.sidebar).not.toBeNull();
    expect(layout.main).not.toBeNull();
    expect(layout.setup).not.toBeNull();
    expect(layout.header).not.toBeNull();

    expect(layout.sidebar!.top).toBeLessThanOrEqual(2);
    expect(layout.main!.top).toBeLessThanOrEqual(2);
    expect(
      Math.abs(layout.main!.top - layout.sidebar!.top),
    ).toBeLessThanOrEqual(2);
    expect(Math.abs(layout.header!.top - layout.main!.top)).toBeLessThanOrEqual(
      2,
    );

    const horizontalOverlap = Math.max(
      0,
      Math.min(layout.setup!.right, layout.sidebar!.right) -
        Math.max(layout.setup!.left, layout.sidebar!.left),
    );
    expect(horizontalOverlap).toBeLessThanOrEqual(2);
    expect(layout.setup!.left).toBeGreaterThanOrEqual(layout.main!.left - 2);
    expect(layout.setup!.right).toBeLessThanOrEqual(layout.main!.right + 2);
    expect(layout.setup!.top).toBeGreaterThan(layout.header!.top);
    expect(layout.setup!.width).toBeGreaterThan(640);
  };

  const layout = await measureLayout();
  assertRealmLayout(layout);
  await test.info().attach("setup-basics", { body: await page.screenshot(), contentType: "image/png" });
});

test("setup, onboarding, and Board entry works", async ({ page }) => {
  await refreshServer(page);
  await expect(byClass(page, "sync-cursor")).toContainText(
    "ak:cursor:e2e-2",
  );

  await page.goto("/onboarding", { waitUntil: "domcontentloaded" });
  await expect(byClass(page, "onboarding-panel")).toBeVisible();
  await dismissRecoveryMissingModal(page);
  const accountFlow = byClass(page, "onboarding-panel");
  await expect(accountFlow.getByText(
    /^Your account is linked to ak:did_core:webvh:.+\.\.\..+\.$/,
  )).toBeVisible();
  expect((await readLocalConfig(page)).active_account.authority.principal_id).toBe(
    CURRENT_PRINCIPAL_CORE_ID,
  );
  await expect(accountFlow).toContainText("You're all set");
  await accountFlow
    .getByRole("button", { name: "Continue", exact: true })
    .click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.locator(".shell.app")).toBeVisible();

  await page.getByRole("navigation", { name: "Main navigation", exact: true }).getByRole("link", { name: "New Realm", exact: true }).click();
  const setupPanel = byClass(page, "setup-panel");
  await expect(setupPanel).toBeVisible();
  await dismissRecoveryMissingModal(page);
  await expect(page.locator(".realm-header .topbar-context-title")).toContainText("New Realm");
  await expect(setupPanel.getByRole("link", { name: "Search" })).toHaveCount(0);
  await expect(setupPanel.getByRole("link", { name: "Settings" })).toHaveCount(
    0,
  );
  await expect(
    setupPanel.getByRole("button", { name: "Apply Policy" }),
  ).toHaveCount(0);
  await expect(
    setupPanel.getByRole("button", { name: "Add Member" }),
  ).toHaveCount(0);
  await expect(
    setupPanel.getByRole("button", { name: "Remove Member" }),
  ).toHaveCount(0);
  await expect(
    setupPanel.getByRole("button", { name: "Delete Space" }),
  ).toHaveCount(0);

  await inputByClass(page, "realm-title-input").fill("Setup Strand Space");
  await inputByClass(page, "realm-summary-input")
    .fill("Created from inkson realm setup");
  await byClass(page, "new-realm-next-button").click();
  const boundaryPanel = byClass(page, "realm-lifecycle-strand");
  await expect(byClass(page, "realm-discoverability-input")).toBeVisible();
  await expect(byClass(page, "realm-mls-activation-input")).toBeVisible();
  await expect(byClass(page, "realm-encryption-profile-input")).toHaveCount(0);
  await expect(byClass(page, "realm-content-scheme-input")).toHaveCount(0);
  await expect(
    boundaryPanel.locator(".setup-step-panel > .event-head"),
  ).toHaveCount(0);
  const primaryAxisCards = boundaryPanel.locator(
    ".setup-step-panel > .setup-axis-grid > .setup-axis-card",
  );
  await expect(primaryAxisCards).toHaveCount(5);
  await expect(primaryAxisCards.locator(".help-tip")).toHaveCount(5);
  await expect(primaryAxisCards.locator(".muted")).toHaveCount(0);
  await test.info().attach("setup-boundary", { body: await page.screenshot(), contentType: "image/png" });
  for (const field of [
    "realm-discoverability-input",
    "realm-policy-join-rule-input",
    "realm-policy-history-access-input",
    "realm-mls-activation-input",
    "realm-security-class-input",
  ]) {
    await expect(byClass(boundaryPanel, field)).toBeVisible();
  }
  const advanced = byClass(boundaryPanel, "realm-advanced-config");
  const advancedTrigger = advanced.locator("button.sapid-collapsible-trigger");
  await expect(advancedTrigger).toHaveAttribute("aria-expanded", "false");
  await expect(byClass(advanced, "realm-federation-policy-input")).toBeHidden();
  await expect(byClass(advanced, "realm-hash-profile-input")).toBeHidden();
  await advancedTrigger.click();
  await expect(advancedTrigger).toHaveAttribute("aria-expanded", "true");
  await expect(advanced.locator(".setup-axis-card")).toHaveCount(2);
  await expect(advanced.locator(".help-tip")).toHaveCount(2);
  await expect(byClass(advanced, "realm-federation-policy-input")).toBeVisible();
  await expect(byClass(advanced, "realm-hash-profile-input")).toBeVisible();
  await advancedTrigger.click();
  await expect(advancedTrigger).toHaveAttribute("aria-expanded", "false");
  await expect(byClass(advanced, "realm-federation-policy-input")).toBeHidden();
  await expect(byClass(advanced, "realm-hash-profile-input")).toBeHidden();
  await expect(
    boundaryPanel.getByText("Who can discover that this Realm exists?"),
  ).toBeHidden();
  const discoverabilityHelp = boundaryPanel
    .locator(".setup-axis-card")
    .filter({ hasText: "Discoverability" })
    .locator(".help-tip");
  await expect(discoverabilityHelp).toHaveAccessibleName(/Who can discover that this Realm exists\?.*Visible in Search/);
  await discoverabilityHelp.hover();
  await expect(page.getByRole("tooltip")).toContainText(/Who can discover that this Realm exists\?.*Visible in Search/);
  await page.mouse.move(0, 0);
  await expect(page.getByRole("tooltip")).toBeHidden();
  // This test exercises plaintext Realm/Space navigation. MLS activation is
  // a separate accepted Genesis flow, not a create-time profile or a mock
  // server claim.
  await byClass(page, "realm-mls-activation-input").click();
  await page.getByRole("option", { name: "Not now" }).click();
  await byClass(page, "new-realm-next-button").click();
  await expect(
    setupPanel.getByRole("button", { name: "Create Realm" }),
  ).toBeVisible();
  await expect(
    setupPanel.getByRole("button", { name: "Create Space" }),
  ).toHaveCount(0);
  const realmCreateRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith("/_arkret/self/events") &&
      request.method() === "POST" &&
      (request.postData() ?? "").includes("ak.realm.create"),
  );
  const plaintextPolicyRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith("/_arkret/self/events") &&
      request.method() === "POST" &&
      (request.postData() ?? "").includes(
        "ak.realm.plaintext_visible_services",
      ),
  );
  await byClass(page, "create-realm-button").click();
  const [realmCreateBody, plaintextPolicyBody] = await Promise.all([
    realmCreateRequest.then((request) => request.postDataJSON()),
    plaintextPolicyRequest.then((request) => request.postDataJSON()),
  ]);
  expect(JSON.stringify(realmCreateBody)).toContain("ak.realm.create");
  expect(JSON.stringify(plaintextPolicyBody)).toContain(
    CURRENT_STATION_ID,
  );
  await expect(byClass(page, "realm-lifecycle-strand")).toContainText(
    /Created ak:realm:/,
  );
  await expect(byClass(page, "realm-lifecycle-strand")).toContainText(
    "canonical policy listed / invite / since_join",
  );
  await expect(byClass(page, "realm-setup-done")).toBeVisible();
  await expect(
    byClass(byClass(page, "realm-lifecycle-strand"), "selected-realm-id"),
  ).toContainText("ak:realm:");

  await byClass(page, "realm-setup-done")
    .getByRole("link", { name: "Open Realm", exact: true })
    .click();
  await expect(byClass(page, "kanban-panel")).toBeVisible();
  await expect(byClass(page, "sidebar")).toContainText("Setup Strand Space");
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.locator(".shell.app")).toBeVisible({
    timeout: 120_000,
  });
  // The reload re-runs account-health detection; dismiss any account-health
  // modal that re-appears so it doesn't block the Board.
  await dismissRecoveryMissingModal(page);
  await dismissMlsBackupModal(page);
  await expect(byClass(page, "sidebar")).toContainText("Setup Strand Space");
  await expect(byClass(page, "kanban-panel")).toBeVisible();
  await byClass(page, "account-menu-button").click();
  await expect(byClass(page, "who")).toHaveText(
    "inkson",
  );
});

test("realm profile fills the current canonical metadata values", async ({
  page,
}) => {
  await refreshServer(page);
  await expect(byClass(page, "sync-cursor")).toContainText(
    "ak:cursor:e2e-2",
  );
  await gotoAndDismissRecovery(
    page,
    `/realms/${DEMO_REALM}/settings/profile`,
  );

  await expect(page.locator(".realm-settings-content > .event").filter({ has: page.locator(".event-head", { hasText: /^Realm Profile$/ }) })).toBeVisible();
  await expect(inputByClass(page, "realm-name-input")).toHaveValue(
    "Arkret Demo Realm",
  );
  await expect(inputByClass(page, "realm-summary-input")).toHaveValue(
    "Shared demo Realm served by mocked server",
  );
});

test("realm admin page handles metadata, modal member invite, epoch rotation and archive", async ({
  page,
}) => {
  await gotoAndDismissRecovery(
    page,
    `/realms/${DEMO_REALM}/settings`,
  );
  await expect(byClass(page, "realm-settings")).toBeVisible();
  await expect(byClass(page, "realm-admin-overview").last()).toContainText(
    "Realm settings",
  );
  await expect(byClass(page, "admin-discussion-admission")).toHaveCount(0);
  await expect(byClass(page, "realm-admin-advanced-sections")).toHaveCount(
    0,
  );
  const adminSections = page.locator(".realm-settings .settings-sidebar-column");
  await expect(
    adminSections.getByRole("link", { name: "Members" }),
  ).toHaveCount(0);
  await expect(
    adminSections.getByRole("button", { name: "Members", exact: true }),
  ).toHaveCount(0);
  await expect(
    adminSections.getByRole("button", { name: "Profile", exact: true }),
  ).toBeVisible();
  await expect(
    adminSections.getByRole("button", { name: "Access", exact: true }),
  ).toBeVisible();
  await expect(
    adminSections.getByRole("button", { name: "Security & MLS", exact: true }),
  ).toBeVisible();
  await expect(
    adminSections.getByRole("button", { name: "Federation", exact: true }),
  ).toBeVisible();
  await expect(
    adminSections.getByRole("button", { name: "Repair & Danger", exact: true }),
  ).toBeVisible();

  await gotoAndDismissRecovery(
    page,
    `/realms/${DEMO_REALM}/members`,
  );
  await expect(page).toHaveURL(
    new RegExp(`/realms/${DEMO_REALM}/members$`),
  );
  await dismissBlockingRecoveryModal(page);
  await expect(byClass(page, "realm-members-panel").last()).toBeVisible();
  await expect(byClass(page, "realm-settings")).toHaveCount(0);

  await gotoAndDismissRecovery(
    page,
    `/realms/${DEMO_REALM}/settings/profile`,
  );
  await expect(page.locator(".realm-settings-content > .event").filter({ has: page.locator(".event-head", { hasText: /^Realm Profile$/ }) })).toBeVisible();
  await inputByClass(page, "realm-name-input").fill("Updated Demo Realm");
  await inputByClass(page, "realm-summary-input").fill("Updated realm summary");
  await expect(byClass(page, "realm-avatar-blob-ref-input")).toHaveCount(0);
  await expect(page.locator(".avatar-uploader-preview svg, .avatar-uploader-preview img")).toBeVisible();
  await expect(page.locator(".avatar-uploader-preview")).toBeVisible();
  await expect(page.locator("button.realm-avatar-input")).toBeVisible();
  await expect(page.locator('input[type="file"]:visible')).toHaveCount(0);
  await byClass(page, "update-metadata-button").click();
  await expect(page.locator(".realm-settings-content > .write-status")).toContainText(
    "profile updated",
  );

  await gotoAndDismissRecovery(
    page,
    `/realms/${DEMO_REALM}/settings/access`,
  );
  await expect(page.locator(".realm-settings-content > .event").filter({ has: page.locator(".event-head", { hasText: /^Realm Profile$/ }) })).toHaveCount(0);
  await expect(inputByClass(page, "realm-name-input")).toHaveCount(0);
  await expect(page.locator(".realm-settings-content .event").filter({ has: page.locator(".event-head", { hasText: /^Join Policy$/ }) })).toBeVisible();
  await expect(
    page.getByRole("checkbox", { name: "Tighten to since joining", exact: true }),
  ).toBeVisible();

  await gotoAndDismissRecovery(
    page,
    `/realms/${DEMO_REALM}/members`,
  );
  await expect(byClass(page, "member-list-card")).toBeVisible();
  await byClass(page, "open-invite-modal-button").click();
  await expect(byClass(page, "invite-member-modal")).toBeVisible();
  const inviteBackdrop = byClass(page, "invite-member-modal");
  const inviteDialog = page.getByRole("dialog", { name: "Invite member" });
  const viewport = page.viewportSize();
  const dialogBox = await inviteDialog.boundingBox();
  expect(viewport).not.toBeNull();
  expect(dialogBox).not.toBeNull();
  const outside = { x: viewport!.width - 12, y: viewport!.height - 12 };
  expect(outside.x > dialogBox!.x + dialogBox!.width || outside.y > dialogBox!.y + dialogBox!.height).toBe(true);
  await page.mouse.move(dialogBox!.x + 12, dialogBox!.y + 12);
  await page.mouse.down();
  await page.mouse.move(
    outside.x,
    outside.y,
  );
  await page.mouse.up();
  await expect(inviteBackdrop).toBeVisible();
  await page.mouse.click(
    outside.x,
    outside.y,
  );
  await expect(inviteBackdrop).toHaveCount(0);
  await byClass(page, "open-invite-modal-button").click();
  await expect(byClass(page, "invite-member-modal")).toBeVisible();
  await inputByClass(page, "invite-target-input")
    .fill(
      "http://127.0.0.1:8787/_arkret/open/invite-locators/resolve#token=e2e-invite-locator-token-00000001",
    );
  const inviteCommit = page.waitForRequest(
    (request) =>
      request.url().endsWith("/_arkret/self/events") &&
      request.method() === "POST" &&
      (request.postData() ?? "").includes("ak.invite.create"),
  );
  await byClass(page, "send-invite-button").click();
  const inviteBody = submittedEvent(
    await inviteCommit.then((request) => request.postDataJSON()),
  );
  expect(inviteBody.kind).toBe("ak.invite.create");
  expect(inviteBody.payload.invite_id).toBeUndefined();
  expect(inviteBody.payload.invitee_account_id).toEqual({
    principal_id: "ak:did_core:web:carol.example",
    station_id: CURRENT_STATION_ID,
  });
  expect(inviteBody.payload.invite_delivery_target).toBeUndefined();
  expect(inviteBody.payload.introduction_evidence_digest).toMatch(/^sha256:/);
  await expect(page.locator(".realm-members-panel > .write-status")).toContainText(
    "invited ak:did_core:web:carol.example",
  );
  // The invite modal closes itself once the create event is accepted.
  await expect(byClass(page, "invite-member-modal")).toHaveCount(0);

  await gotoAndDismissRecovery(
    page,
    `/realms/${DEMO_REALM}/settings/security`,
  );
  await byClass(page, "rotate-realm-epoch").click();
  // rotation is now a real local `self_update_commit`
  // published as `ak.mls.commit`. The e2e fixture has no local MLS group
  // state for this realm, so the rotate must fail closed with a status
  // message instead of calling the former non-spec /_arkret/self/mls/rotate
  // shim.
  await expect(page.locator(".realm-settings-content > .write-status")).toContainText(
    "rotate failed",
  );

  await gotoAndDismissRecovery(
    page,
    `/realms/${DEMO_REALM}/settings/repair`,
  );
  await byClass(page, "archive-realm-button").click();
  await expect(byClass(page, "realm-danger-confirm-modal")).toBeVisible();
  await expect(byClass(page, "realm-danger-confirm-submit")).toBeDisabled();
  await inputByClass(page, "realm-danger-confirm-input")
    .fill(DEMO_REALM);
  await expect(byClass(page, "realm-danger-confirm-submit")).toBeEnabled();
  await byClass(page, "realm-danger-confirm-submit").click();
  await expect(page.locator(".realm-settings-content > .write-status")).toContainText(
    "archive event submitted",
  );
});

test("visual smoke renders core client pages on desktop and mobile", async ({
  page,
}) => {
  await refreshServer(page);
  for (const [route, testId] of [
    ["/", "dashboard-panel"],
    ["/kanban", "kanban-panel"],
    ["/settings", "settings-page"],
  ] as const) {
    await page.goto(route, { waitUntil: "domcontentloaded" });
    await expect(byClass(page, testId)).toBeVisible();
    const shot = await page.screenshot();
    expect(shot.length).toBeGreaterThan(10_000);
  }

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/kanban", { waitUntil: "domcontentloaded" });
  await expect(byClass(page, "mobile-shellbar")).toBeVisible();
  await expect(byClass(page, "kanban-panel")).toBeVisible();
  await expect(byClass(page, "kanban-board-grid")).toBeVisible();
  const mobileShot = await page.screenshot();
  expect(mobileShot.length).toBeGreaterThan(10_000);
});
