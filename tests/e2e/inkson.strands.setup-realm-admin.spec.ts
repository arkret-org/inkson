import { expect, test } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  latestTestId,
  dismissBlockingRecoveryModal,
  refreshServer,
  gotoAndDismissRecovery,
  dismissRecoveryMissingModal,
  dismissMlsBackupModal,
  CURRENT_PRINCIPAL_SERVER_ID,
  submittedEvent,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("setup realm form stays in the main realm layout", async ({ page }) => {
  await refreshServer(page);
  await page.goto("/setup/realms", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("setup-panel")).toBeVisible();
  await expect(page.getByTestId("realm-setup-guide")).toHaveCount(0);

  const titleInput = page.getByTestId("realm-title-input");
  await expect(titleInput).toHaveAttribute("required", "true");
  await expect(titleInput).toHaveAttribute("aria-required", "true");
  await expect(page.locator('label[for="realm-title-input-input"]')).toHaveText(
    /Realm title\s*\*/,
  );

  const fieldTops = await page.evaluate(() => ({
    alias: document
      .querySelector('[data-testid="realm-alias-input"]')
      ?.getBoundingClientRect().top,
    summary: document
      .querySelector('[data-testid="realm-summary-input"]')
      ?.getBoundingClientRect().top,
  }));
  expect(fieldTops.alias).toBeDefined();
  expect(fieldTops.summary).toBeDefined();
  expect(fieldTops.alias!).toBeLessThan(fieldTops.summary!);

  const activeStepButton = page.locator(
    '.setup-step-list button[data-style="primary"]',
  );
  await expect(activeStepButton).toHaveCount(1);
  await expect(activeStepButton).toHaveClass(/\bdx-button\b/);
  const activeStepStyle = await activeStepButton.evaluate((button) => {
    const style = getComputedStyle(button);
    return {
      display: style.display,
      borderRadius: style.borderRadius,
      backgroundImage: style.backgroundImage,
    };
  });
  expect(activeStepStyle.display).toBe("flex");
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
        sidebar: rectOf('[data-testid="sidebar"]'),
        main: rectOf('[data-testid="main-view"]'),
        setup: rectOf('[data-testid="setup-panel"]'),
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
});

test("setup, onboarding, and Board entry works", async ({ page }) => {
  await refreshServer(page);
  await expect(page.getByTestId("sync-cursor")).toContainText(
    "ak:cursor:e2e-2",
  );

  await page.goto("/onboarding", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("onboarding-panel")).toBeVisible();
  await dismissRecoveryMissingModal(page);
  await expect(page.getByTestId("account-strand")).toContainText(
    "Your account is linked to ak:did_core:web:alice.example",
  );

  await page.getByTestId("sidebar-new-realm-cta").click();
  const setupPanel = page.getByTestId("setup-panel");
  await expect(setupPanel).toBeVisible();
  await dismissRecoveryMissingModal(page);
  await expect(page.getByTestId("realm-title")).toContainText("New Realm");
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

  await page.getByTestId("realm-title-input").fill("Setup Strand Space");
  await page
    .getByTestId("realm-summary-input")
    .fill("Created from inkson realm setup");
  await page.getByTestId("new-realm-next-button").click();
  const boundaryPanel = page.getByTestId("realm-lifecycle-strand");
  await expect(page.getByTestId("realm-discoverability-input")).toBeVisible();
  await expect(
    boundaryPanel.locator(".setup-step-panel > .event-head"),
  ).toHaveCount(0);
  const primaryAxisCards = boundaryPanel.locator(
    ".setup-step-panel > .setup-axis-grid > .setup-axis-card",
  );
  await expect(primaryAxisCards).toHaveCount(6);
  await expect(primaryAxisCards.locator(".help-tip")).toHaveCount(6);
  await expect(primaryAxisCards.locator(".muted")).toHaveCount(0);
  await expect(
    boundaryPanel.getByText("Who can discover that this Realm exists?"),
  ).toHaveCount(0);
  const discoverabilityHelp = boundaryPanel
    .locator(".setup-axis-card")
    .filter({ hasText: "Discoverability" })
    .locator(".help-tip");
  await expect(discoverabilityHelp).toHaveAttribute(
    "title",
    /Who can discover that this Realm exists\?.*Visible in Search/,
  );
  await page.getByTestId("new-realm-next-button").click();
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
  await page.getByTestId("create-realm-button").click();
  const [realmCreateBody, plaintextPolicyBody] = await Promise.all([
    realmCreateRequest.then((request) => request.postDataJSON()),
    plaintextPolicyRequest.then((request) => request.postDataJSON()),
  ]);
  expect(JSON.stringify(realmCreateBody)).toContain("ak.realm.create");
  expect(JSON.stringify(plaintextPolicyBody)).toContain(
    CURRENT_PRINCIPAL_SERVER_ID,
  );
  await expect(page.getByTestId("realm-lifecycle-strand")).toContainText(
    /Created ak:realm:/,
  );
  await expect(page.getByTestId("realm-lifecycle-strand")).toContainText(
    "canonical policy listed / invite / all_history_for_current_members",
  );
  await expect(page.getByTestId("realm-setup-done")).toBeVisible();
  await expect(
    page.getByTestId("realm-lifecycle-strand").getByTestId("selected-realm-id"),
  ).toContainText("ak:realm:");

  await page
    .getByTestId("realm-setup-done")
    .getByRole("link", { name: "Open Realm", exact: true })
    .click();
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
  await expect(page.getByTestId("sidebar")).toContainText("Setup Strand Space");
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("client-shell")).toBeVisible({
    timeout: 120_000,
  });
  // The reload re-runs account-health detection; dismiss any account-health
  // modal that re-appears so it doesn't block the Board.
  await dismissRecoveryMissingModal(page);
  await dismissMlsBackupModal(page);
  await expect(page.getByTestId("sidebar")).toContainText("Setup Strand Space");
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
  await page.getByTestId("account-menu-button").click();
  await expect(page.getByTestId("account-menu-display-name")).toHaveText(
    "inkson",
  );
});

test("realm profile fills the current canonical metadata values", async ({
  page,
}) => {
  await refreshServer(page);
  await expect(page.getByTestId("sync-cursor")).toContainText(
    "ak:cursor:e2e-2",
  );
  await gotoAndDismissRecovery(
    page,
    "/realms/ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk/settings/profile",
  );

  await expect(page.getByTestId("realm-profile")).toBeVisible();
  await expect(page.getByTestId("realm-name-input")).toHaveValue(
    "Arkret Demo Realm",
  );
  await expect(page.getByTestId("realm-summary-input")).toHaveValue(
    "Shared demo Realm served by mocked server",
  );
});

test("realm admin page handles metadata, modal member invite, epoch rotation and archive", async ({
  page,
}) => {
  await gotoAndDismissRecovery(
    page,
    "/realms/ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk/settings",
  );
  await expect(latestTestId(page, "realm-admin-panel")).toBeVisible();
  await expect(latestTestId(page, "realm-admin-overview")).toContainText(
    "Realm settings",
  );
  await expect(page.getByTestId("admin-discussion-admission")).toHaveCount(0);
  await expect(page.getByTestId("realm-admin-advanced-sections")).toHaveCount(
    0,
  );
  const adminSections = latestTestId(page, "realm-admin-sections");
  await expect(
    adminSections.getByRole("link", { name: "Members" }),
  ).toHaveCount(0);
  await expect(
    adminSections.getByRole("link", { name: "Profile" }).last(),
  ).toBeVisible();
  await expect(
    adminSections.getByRole("link", { name: "Access" }).last(),
  ).toBeVisible();
  await expect(
    adminSections.getByRole("link", { name: "Security & MLS" }).last(),
  ).toBeVisible();
  await expect(
    adminSections.getByRole("link", { name: "Federation" }).last(),
  ).toBeVisible();
  await expect(
    adminSections.getByRole("link", { name: "Repair & Danger" }).last(),
  ).toBeVisible();

  await gotoAndDismissRecovery(
    page,
    "/realms/ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk/members",
  );
  await expect(page).toHaveURL(
    /\/realms\/ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk\/members$/,
  );
  await dismissBlockingRecoveryModal(page);
  await expect(latestTestId(page, "realm-members-panel")).toBeVisible();
  await expect(page.getByTestId("realm-admin-panel")).toHaveCount(0);

  await gotoAndDismissRecovery(
    page,
    "/realms/ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk/settings/profile",
  );
  await expect(page.getByTestId("realm-profile")).toBeVisible();
  await page.getByTestId("realm-name-input").fill("Updated Demo Realm");
  await page.getByTestId("realm-summary-input").fill("Updated realm summary");
  await expect(page.getByTestId("realm-avatar-blob-ref-input")).toHaveCount(0);
  await expect(page.getByTestId("realm-avatar")).toBeVisible();
  await expect(page.getByTestId("realm-avatar-upload-label")).toBeVisible();
  await expect(page.getByTestId("realm-avatar-input")).toBeHidden();
  await page.getByTestId("update-metadata-button").click();
  await expect(page.getByTestId("realm-admin-status")).toContainText(
    "profile updated",
  );

  await gotoAndDismissRecovery(
    page,
    "/realms/ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk/settings/access",
  );
  await expect(page.getByTestId("realm-profile")).toHaveCount(0);
  await expect(page.getByTestId("realm-name-input")).toHaveCount(0);
  await expect(page.getByTestId("join-policy")).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Tighten to since joining" }),
  ).toBeVisible();

  await gotoAndDismissRecovery(
    page,
    "/realms/ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk/members",
  );
  await expect(page.getByTestId("member-table")).toBeVisible();
  await page.getByTestId("open-invite-modal-button").click();
  await expect(page.getByTestId("invite-member-modal")).toBeVisible();
  const inviteBackdrop = page.getByTestId("invite-member-modal");
  const inviteDialog = page.getByRole("dialog", { name: "Invite member" });
  const backdropBox = await inviteBackdrop.boundingBox();
  const dialogBox = await inviteDialog.boundingBox();
  expect(backdropBox).not.toBeNull();
  expect(dialogBox).not.toBeNull();
  await page.mouse.move(dialogBox!.x + 12, dialogBox!.y + 12);
  await page.mouse.down();
  await page.mouse.move(
    backdropBox!.x + backdropBox!.width - 12,
    backdropBox!.y + backdropBox!.height - 12,
  );
  await page.mouse.up();
  await expect(inviteBackdrop).toBeVisible();
  await page.mouse.click(
    backdropBox!.x + backdropBox!.width - 12,
    backdropBox!.y + backdropBox!.height - 12,
  );
  await expect(inviteBackdrop).toHaveCount(0);
  await page.getByTestId("open-invite-modal-button").click();
  await expect(page.getByTestId("invite-member-modal")).toBeVisible();
  await page
    .getByTestId("invite-target-input")
    .fill(
      "http://127.0.0.1:8787/_arkret/open/invite-locators/resolve#token=e2e-invite-locator-token-00000001",
    );
  const inviteCommit = page.waitForRequest(
    (request) =>
      request.url().endsWith("/_arkret/self/events") &&
      request.method() === "POST" &&
      (request.postData() ?? "").includes("ak.invite.create"),
  );
  await page.getByTestId("send-invite-button").click();
  const inviteBody = submittedEvent(
    await inviteCommit.then((request) => request.postDataJSON()),
  );
  expect(inviteBody.kind).toBe("ak.invite.create");
  expect(inviteBody.payload.invite_id).toBeUndefined();
  expect(inviteBody.payload.invitee).toBe("ak:did_core:web:carol.example");
  expect(inviteBody.payload.invite_delivery_target).toEqual(
    expect.objectContaining({
      recipient_service_id: CURRENT_PRINCIPAL_SERVER_ID,
      service_resolution: expect.objectContaining({
        current_record_url: expect.stringMatching(/^https:\/\//),
      }),
    }),
  );
  expect(inviteBody.payload.introduction_evidence_digest).toMatch(/^sha256:/);
  expect(inviteBody.payload.x_member_delivery_binding).toBeUndefined();
  await expect(page.getByTestId("realm-members-status")).toContainText(
    "invited ak:did_core:web:carol.example",
  );
  // The invite modal closes itself once the create event is accepted.
  await expect(page.getByTestId("invite-member-modal")).toHaveCount(0);

  await gotoAndDismissRecovery(
    page,
    "/realms/ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk/settings/security",
  );
  await page.getByTestId("rotate-realm-epoch").click();
  // YOU-01-009: rotation is now a real local `self_update_commit`
  // published as `ak.mls.commit`. The e2e fixture has no local MLS group
  // state for this realm, so the rotate must fail closed with a status
  // message instead of calling the former non-spec /_arkret/self/mls/rotate
  // shim.
  await expect(page.getByTestId("realm-admin-status")).toContainText(
    "rotate failed",
  );

  await gotoAndDismissRecovery(
    page,
    "/realms/ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk/settings/repair",
  );
  await page.getByTestId("archive-realm-button").click();
  await expect(page.getByTestId("realm-danger-confirm-modal")).toBeVisible();
  await expect(page.getByTestId("realm-danger-confirm-submit")).toBeDisabled();
  await page
    .getByTestId("realm-danger-confirm-input")
    .fill("ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk");
  await expect(page.getByTestId("realm-danger-confirm-submit")).toBeEnabled();
  await page.getByTestId("realm-danger-confirm-submit").click();
  await expect(page.getByTestId("realm-admin-status")).toContainText(
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
    ["/settings", "settings-panel"],
  ] as const) {
    await page.goto(route, { waitUntil: "domcontentloaded" });
    await expect(page.getByTestId(testId)).toBeVisible();
    const shot = await page.screenshot();
    expect(shot.length).toBeGreaterThan(10_000);
  }

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/kanban", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("mobile-shellbar")).toBeVisible();
  const mobileShot = await page.screenshot();
  expect(mobileShot.length).toBeGreaterThan(10_000);
});
