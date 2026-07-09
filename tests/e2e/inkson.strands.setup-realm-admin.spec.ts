import { expect, test } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  latestTestId,
  dismissBlockingRecoveryModal,
  refreshServer,
  gotoAndDismissRecovery,
  dismissRecoveryMissingModal,
  dismissMlsBackupModal,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("setup realm form stays in the main workspace layout", async ({ page }) => {
  await refreshServer(page);
  await page.goto("/setup/realms", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("setup-panel")).toBeVisible();

  const measureLayout = () => page.evaluate(() => {
    const rectOf = (selector: string) => {
      const rect = document.querySelector(selector)?.getBoundingClientRect();
      return rect
        ? { left: rect.left, right: rect.right, top: rect.top, width: rect.width }
        : null;
    };
    return {
      sidebar: rectOf('[data-testid="sidebar"]'),
      main: rectOf('[data-testid="main-view"]'),
      setup: rectOf('[data-testid="setup-panel"]'),
      header: rectOf(".workspace-header"),
    };
  });

  const assertWorkspaceLayout = (layout: Awaited<ReturnType<typeof measureLayout>>) => {
    expect(layout.sidebar).not.toBeNull();
    expect(layout.main).not.toBeNull();
    expect(layout.setup).not.toBeNull();
    expect(layout.header).not.toBeNull();

    expect(layout.sidebar!.top).toBeLessThanOrEqual(2);
    expect(layout.main!.top).toBeLessThanOrEqual(2);
    expect(Math.abs(layout.main!.top - layout.sidebar!.top)).toBeLessThanOrEqual(2);
    expect(Math.abs(layout.header!.top - layout.main!.top)).toBeLessThanOrEqual(2);

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
  assertWorkspaceLayout(layout);

  await page.evaluate(() => {
    const accountKey = "did:web:alice.example";
    const encrypted = [...new TextEncoder().encode("ar")]
      .map((byte, index) => {
        const keyByte = accountKey.charCodeAt(index % accountKey.length);
        return (byte ^ keyByte).toString(16).padStart(2, "0");
      })
      .join("");
    const state = JSON.parse(localStorage.getItem("inkson.local_state.v1") ?? "{}");
    state.private_data = { ...(state.private_data ?? {}), locale: encrypted };
    localStorage.setItem("inkson.local_state.v1", JSON.stringify(state));
  });
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-direction", "rtl");
  await expect(page.getByTestId("setup-panel")).toBeVisible();
  assertWorkspaceLayout(await measureLayout());
});

test("setup, onboarding, and Board entry works", async ({ page }) => {
  await refreshServer(page);
  await expect(page.getByTestId("sync-cursor")).toContainText("ak:cursor:e2e-2");

  await page.goto("/onboarding", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("onboarding-panel")).toBeVisible();
  await dismissRecoveryMissingModal(page);
  await page.getByTestId("register-account-button").click();
  await expect(page.getByTestId("account-strand")).toContainText("registered alice.example");

  await page.getByTestId("sidebar-new-realm-cta").click();
  const setupPanel = page.getByTestId("setup-panel");
  await expect(setupPanel).toBeVisible();
  await dismissRecoveryMissingModal(page);
  await expect(page.getByTestId("realm-title")).toContainText("New Realm");
  await expect(setupPanel.getByRole("link", { name: "Search" })).toHaveCount(0);
  await expect(setupPanel.getByRole("link", { name: "Settings" })).toHaveCount(0);
  await expect(setupPanel.getByRole("button", { name: "Apply Policy" })).toHaveCount(0);
  await expect(setupPanel.getByRole("button", { name: "Add Member" })).toHaveCount(0);
  await expect(setupPanel.getByRole("button", { name: "Remove Member" })).toHaveCount(0);
  await expect(setupPanel.getByRole("button", { name: "Delete Space" })).toHaveCount(0);

  await page.getByTestId("realm-title-input").fill("Setup Strand Space");
  await page.getByTestId("realm-summary-input").fill("Created from inkson workspace setup");
  await page.getByTestId("new-realm-next-button").click();
  await expect(page.getByTestId("realm-lifecycle-strand")).toContainText("three independent axes");
  await page.getByTestId("new-realm-next-button").click();
  await page.getByTestId("seed-members-input").fill("did:web:bob.example");
  await expect(setupPanel.getByRole("button", { name: "Create Realm" })).toBeVisible();
  await expect(setupPanel.getByRole("button", { name: "Create Space" })).toHaveCount(0);
  const realmCreateRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith("/_arkret/self/events") &&
      request.method() === "POST" &&
      (request.postData() ?? "").includes("ck.realm.create"),
  );
  const plaintextPolicyRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith("/_arkret/self/events") &&
      request.method() === "POST" &&
      (request.postData() ?? "").includes("ck.realm.plaintext_visible_services"),
  );
  await page.getByTestId("create-realm-button").click();
  // S6 gate (no recovery configured in the default mock account): accept the
  // override, then re-create so the queued requests fire.
  await latestTestId(page, "encrypted-realm-recovery-gate-override").click();
  await expect(latestTestId(page, "encrypted-realm-recovery-gate")).toBeHidden();
  await page.getByTestId("create-realm-button").click();
  const [realmCreateBody, plaintextPolicyBody] = await Promise.all([
    realmCreateRequest.then((request) => request.postDataJSON()),
    plaintextPolicyRequest.then((request) => request.postDataJSON()),
  ]);
  expect(JSON.stringify(realmCreateBody)).toContain("ck.realm.create");
  expect(JSON.stringify(plaintextPolicyBody)).toContain("did:web:server.local");
  await expect(page.getByTestId("realm-lifecycle-strand")).toContainText(/created ck:realm:/);
  await expect(page.getByTestId("realm-lifecycle-strand")).toContainText("canonical policy listed / invite / shared");
  await expect(page.getByTestId("realm-setup-done")).toBeVisible();
  await expect(latestTestId(page, "mls-backup-modal")).toBeVisible();
  await expect(latestTestId(page, "mls-backup-banner")).toBeVisible();
  await latestTestId(page, "mls-backup-submit").click();
  const generatedKeyField = latestTestId(page, "mls-backup-generated-key");
  await expect(generatedKeyField).toBeVisible();
  const generatedRecoveryKey = await generatedKeyField.inputValue();
  await latestTestId(page, "mls-backup-confirm-key").fill(generatedRecoveryKey);
  await latestTestId(page, "mls-backup-saved").click();
  await expect(page.getByTestId("mls-backup-modal")).toHaveCount(0);
  await expect(page.getByTestId("realm-lifecycle-strand").getByTestId("selected-realm-id")).toContainText("ak:realm:");

  await page.getByTestId("realm-setup-done").getByRole("link", { name: "Open Realm", exact: true }).click();
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
  await expect(page.getByTestId("sidebar")).toContainText("Setup Strand Space");
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
  // The reload re-runs account-health detection; dismiss any account-health
  // modal that re-appears so it doesn't block the Board.
  await dismissRecoveryMissingModal(page);
  await dismissMlsBackupModal(page);
  await expect(page.getByTestId("sidebar")).toContainText("Setup Strand Space");
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
  await page.getByTestId("account-menu-button").click();
  await expect(page.getByTestId("account-menu-frontier")).toContainText("ak:event:");
});

test("realm admin page handles metadata, modal member invite, epoch rotation and archive", async ({ page }) => {
  await gotoAndDismissRecovery(page, "/realms/ck:realm:0196419b-0000-7000-8000-000000000000/settings");
  await expect(latestTestId(page, "realm-admin-panel")).toBeVisible();
  await expect(latestTestId(page, "realm-admin-overview")).toContainText("Realm settings");
  await expect(page.getByTestId("admin-discussion-admission")).toHaveCount(0);
  await expect(page.getByTestId("realm-admin-advanced-sections")).toHaveCount(0);
  const adminSections = latestTestId(page, "realm-admin-sections");
  await expect(adminSections.getByRole("link", { name: "Members" })).toHaveCount(0);
  await expect(adminSections.getByRole("link", { name: "Profile" }).last()).toBeVisible();
  await expect(adminSections.getByRole("link", { name: "Access" }).last()).toBeVisible();
  await expect(adminSections.getByRole("link", { name: "Security & MLS" }).last()).toBeVisible();
  await expect(adminSections.getByRole("link", { name: "Federation" }).last()).toBeVisible();
  await expect(adminSections.getByRole("link", { name: "Repair & Danger" }).last()).toBeVisible();

  await gotoAndDismissRecovery(page, "/realms/ck:realm:0196419b-0000-7000-8000-000000000000/settings/members");
  await expect(page).toHaveURL(/\/realms\/ck:realm:0196419b-0000-7000-8000-000000000000\/members$/);
  await dismissBlockingRecoveryModal(page);
  await expect(latestTestId(page, "realm-members-panel")).toBeVisible();
  await expect(page.getByTestId("realm-admin-panel")).toHaveCount(0);

  await gotoAndDismissRecovery(page, "/realms/ck:realm:0196419b-0000-7000-8000-000000000000/settings/profile");
  await expect(page.getByTestId("realm-profile")).toBeVisible();
  await page.getByTestId("realm-name-input").fill("Updated Demo Realm");
  await page.getByTestId("realm-summary-input").fill("Updated realm summary");
  await expect(page.getByTestId("realm-avatar-blob-ref-input")).toHaveCount(0);
  await expect(page.getByTestId("realm-avatar")).toBeVisible();
  await expect(page.getByTestId("realm-avatar-upload-label")).toBeVisible();
  await expect(page.getByTestId("realm-avatar-input")).toBeHidden();
  await page.getByTestId("update-metadata-button").click();
  await expect(page.getByTestId("realm-admin-status")).toContainText("profile updated");

  await gotoAndDismissRecovery(page, "/realms/ck:realm:0196419b-0000-7000-8000-000000000000/settings/access");
  await expect(page.getByTestId("realm-profile")).toHaveCount(0);
  await expect(page.getByTestId("realm-name-input")).toHaveCount(0);
  await expect(page.getByTestId("join-policy")).toBeVisible();
  await expect(page.getByTestId("history-visibility")).toBeVisible();

  await gotoAndDismissRecovery(page, "/realms/ck:realm:0196419b-0000-7000-8000-000000000000/members");
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
  await page.mouse.move(backdropBox!.x + backdropBox!.width - 12, backdropBox!.y + backdropBox!.height - 12);
  await page.mouse.up();
  await expect(inviteBackdrop).toBeVisible();
  await page.mouse.click(backdropBox!.x + backdropBox!.width - 12, backdropBox!.y + backdropBox!.height - 12);
  await expect(inviteBackdrop).toHaveCount(0);
  await page.getByTestId("open-invite-modal-button").click();
  await expect(page.getByTestId("invite-member-modal")).toBeVisible();
  await page
    .getByTestId("invite-target-input")
    .fill(
      "http://127.0.0.1:8787/_arkret/open/invite-locators/resolve#token=e2e-invite-locator-token-00000001",
    );
  const inviteCommit = page.waitForRequest("**/_arkret/self/events");
  await page.getByTestId("send-invite-button").click();
  const inviteBody = await inviteCommit.then((request) => request.postDataJSON());
  expect(inviteBody.kind).toBe("ck.invite.create");
  expect(inviteBody.payload.invite_id).toMatch(/^ck:invite:/);
  expect(inviteBody.payload.invitee).toBe("did:web:carol.example");
  expect(inviteBody.payload.invite_delivery_target).toEqual({
    recipient_service_did: "did:web:server.local",
  });
  expect(inviteBody.payload.introduction_evidence_digest).toMatch(/^sha256:/);
  expect(inviteBody.payload.x_member_delivery_binding).toBeUndefined();
  await expect(page.getByTestId("realm-members-status")).toContainText("invited carol:example.com");
  // The invite modal closes itself once the create event is accepted.
  await expect(page.getByTestId("invite-member-modal")).toHaveCount(0);

  await gotoAndDismissRecovery(page, "/realms/ck:realm:0196419b-0000-7000-8000-000000000000/settings/security");
  await page.getByTestId("rotate-realm-epoch").click();
  // YOU-01-009: rotation is now a real local `self_update_commit`
  // published as `ck.mls.commit`. The e2e fixture has no local MLS group
  // state for this realm, so the rotate must fail closed with a status
  // message instead of calling the former non-spec /_arkret/self/mls/rotate
  // shim.
  await expect(page.getByTestId("realm-admin-status")).toContainText("rotate failed");

  await gotoAndDismissRecovery(page, "/realms/ck:realm:0196419b-0000-7000-8000-000000000000/settings/repair");
  await page.getByTestId("archive-realm-button").click();
  await expect(page.getByTestId("realm-danger-confirm-modal")).toBeVisible();
  await expect(page.getByTestId("realm-danger-confirm-submit")).toBeDisabled();
  await page
    .getByTestId("realm-danger-confirm-input")
    .fill("ak:realm:0196419b-0000-7000-8000-000000000000");
  await expect(page.getByTestId("realm-danger-confirm-submit")).toBeEnabled();
  await page.getByTestId("realm-danger-confirm-submit").click();
  await expect(page.getByTestId("realm-admin-status")).toContainText("archive event submitted");
});

test("visual smoke renders core client pages on desktop and mobile", async ({ page }) => {
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
