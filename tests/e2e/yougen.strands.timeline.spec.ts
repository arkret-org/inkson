import { expect, test } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  latestTestId,
  refreshServer,
  openTimeline,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("timeline keeps auxiliary panels above the message input", async ({ page }) => {
  await openTimeline(page);
  await expect(page.getByTestId("composer")).toBeVisible();
  await expect(page.getByTestId("moderation-appeal-entrypoint")).toHaveCount(0);
  await expect(page.getByTestId("composer-input")).toBeVisible();

  const metrics = await page.evaluate(() => {
    const timeline = document.querySelector('[data-testid="timeline"]')?.getBoundingClientRect();
    const workspace = document.querySelector(".workspace-body")?.getBoundingClientRect();
    const composer = document.querySelector('[data-testid="composer"]')?.getBoundingClientRect();
    const input = document.querySelector('[data-testid="composer-input"]')?.getBoundingClientRect();

    return timeline && workspace && composer && input
      ? {
          timelineTop: timeline.top,
          workspaceBottom: workspace.bottom,
          composerTop: composer.top,
          composerBottom: composer.bottom,
          inputTop: input.top,
        }
      : null;
  });

  expect(metrics).not.toBeNull();
  expect(metrics!.composerTop).toBeGreaterThanOrEqual(metrics!.timelineTop);
  expect(metrics!.inputTop).toBeGreaterThanOrEqual(metrics!.composerTop);
  expect(metrics!.composerBottom).toBeGreaterThan(metrics!.inputTop);
  expect(metrics!.composerBottom).toBeLessThanOrEqual(metrics!.workspaceBottom);
  expect(metrics!.workspaceBottom - metrics!.composerBottom).toBeLessThanOrEqual(72);
});

test("accessibility smoke exposes landmarks and live timeline feed", async ({ page }) => {
  await expect(page.getByTestId("sidebar")).toHaveAttribute("role", "navigation");
  await expect(page.getByTestId("main-view")).toHaveAttribute("role", "main");
  await expect(page.getByTestId("account-menu-button")).toHaveAttribute("aria-label", "Account menu");

  await openTimeline(page);
  await expect(page.getByTestId("timeline")).toHaveAttribute("role", "feed");
  await expect(page.getByTestId("timeline")).toHaveAttribute("aria-live", "polite");

  const sendRequest = page.waitForRequest("**/_cokret/self/events");
  await page.getByTestId("composer-input").fill("a11y smoke message");
  await page.getByTestId("send-button").click();
  await sendRequest;

  await expect(page.getByTestId("timeline-event").last()).toHaveAttribute("role", "article");
  await expect(page.getByTestId("timeline-event").last()).toHaveAttribute("aria-label", /Timeline event from/);
});

test("timeline mark-read sends public receipt and stores private marker", async ({ page }) => {
  await openTimeline(page);
  const sendRequest = page.waitForRequest("**/_cokret/self/events");
  await latestTestId(page, "composer-input").fill("read marker target");
  await latestTestId(page, "send-button").click();
  expect((await sendRequest).headers()["x-cokret-request-id"]).toBeTruthy();
  await expect(latestTestId(page, "write-status")).toContainText("persisted");
  await expect(page.getByTestId("timeline-event").filter({ hasText: "read marker target" }).last()).toBeVisible();

  const receiptRequest = page.waitForRequest("**/_cokret/self/ephemeral");
  await page.getByTestId("timeline-event").filter({ hasText: "read marker target" }).last().getByTestId("mark-read-button").click();
  const receiptBody = await receiptRequest.then((request) => request.postDataJSON());

  expect(receiptBody.kind).toBe("ck.receipt.read");
  expect(receiptBody.realm_id).toBe("ck:realm:0196419b-0000-7000-8000-000000000000");
  expect(receiptBody.payload.receipt_type).toBe("read");
  expect(receiptBody.payload.schema).toBe("ck.schema.read_receipt.v1");
  expect(receiptBody.payload.event_id).toContain("ck:event");
  await expect(page.getByTestId("read-receipt-status")).toContainText("ck.receipt.read");
  await expect(page.getByTestId("read-cursor-status")).toContainText("Read marker:");
  await expect(page.getByTestId("read-cursor-badge")).toContainText("Read marker here");
});

test("timeline blob strand verifies hashes and authenticated downloads", async ({ page }) => {
  await refreshServer(page);
  await openTimeline(page);

  const uploadRequest = page.waitForRequest("**/_cokret/self/blob/upload");
  await page.getByTestId("attach-blob-button").click();
  expect((await uploadRequest).headers()["authorization"]).toContain("Bearer");
  await expect(page.getByTestId("blob-status")).toContainText("upload hash ok");
  await expect(page.getByTestId("blob-status")).toContainText("no token in media URL");
  await expect(page.getByTestId("blob-policy-panel")).toContainText("unsafe or opaque type opens as attachment");
  await expect(page.getByTestId("blob-policy-panel")).toContainText(
    "Ref: ck:blob:sha256:01015dc8af66d01f557ea63f13538f1964848840a350c5311d1efc8ad138bb91",
  );

  const downloadRequest = page.waitForRequest("**/_cokret/self/blob/get?blob_ref=*");
  await page.getByTestId("verify-blob-download").click();
  const download = await downloadRequest;
  expect(download.headers()["authorization"]).toContain("Bearer");
  expect(download.url()).not.toContain("access_token");
  expect(download.url()).not.toContain("Bearer");
  await expect(page.getByTestId("blob-status")).toContainText("download verified digest");
});

test("mobile viewport collapses shell chrome and keeps timeline usable", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/timeline", { waitUntil: "domcontentloaded" });

  await expect(page.getByTestId("client-shell")).toBeVisible();
  await expect(page.getByTestId("sidebar")).toBeHidden();
  await expect(page.getByTestId("mobile-shellbar")).toBeVisible();
  await page.getByTestId("mobile-nav-toggle").click();
  await expect(page.getByTestId("mobile-nav-drawer")).toContainText("Spaces");
  await expect(page.getByTestId("main-view")).toBeVisible();
  await expect(page.getByTestId("composer-input")).toBeVisible();
});
