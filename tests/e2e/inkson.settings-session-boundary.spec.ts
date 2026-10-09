import { expect, test, type Request } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  gotoAndDismissRecovery,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("root logout suppresses a pending settings query in the same page instance", async ({
  page,
}, testInfo) => {
  await gotoAndDismissRecovery(page, "/settings/mimi");
  const marker = "old-session-mimi-query-late-500";
  let releaseQuery!: () => void;
  const heldQuery = new Promise<void>((resolve) => { releaseQuery = resolve; });
  let queryRequest: Request | undefined;
  let responseStatus: number | undefined;
  let failureText: string | undefined;
  let fulfillError: string | undefined;
  let routeSettled = false;

  page.on("response", (response) => {
    if (response.request() === queryRequest) responseStatus = response.status();
  });
  page.on("requestfailed", (request) => {
    if (request === queryRequest) failureText = request.failure()?.errorText;
  });
  await page.route("**/_arkret/open/mimi/identifiers/query", async (route) => {
    queryRequest = route.request();
    await heldQuery;
    try {
      await route.fulfill({
        status: 500,
        contentType: "application/json",
        body: JSON.stringify({ error: { code: "internal_error", message: marker } }),
      });
    } catch (error) {
      // The Settings scope can cancel its fetch during logout. Keep this
      // observable rather than pretending the canceled HTTP response completed.
      fulfillError = String(error);
    } finally {
      routeSettled = true;
    }
  });
  const timeOrigin = await page.evaluate(() => {
    const state = { observedMimiError: false, observedReceipt: false };
    // The panel begins with a localized "no receipt" placeholder, not an
    // empty string. A result must change that original content to count.
    const initialReceipt = document.querySelector(
      '[data-testid="mimi-query-receipt"]',
    )?.textContent;
    Object.assign(window, { __settingsLogoutWitness: state });
    const inspect = () => {
      state.observedMimiError ||= !!document.querySelector(
        '[data-testid="toast-item"][data-i18n-key="feedback.mimi_failed"]',
      );
      const receipt = document.querySelector(
        '[data-testid="mimi-query-receipt"]',
      );
      state.observedReceipt ||= receipt !== null && receipt.textContent !== initialReceipt;
    };
    new MutationObserver(inspect).observe(document.documentElement, {
      childList: true,
      subtree: true,
      characterData: true,
      attributes: true,
    });
    inspect();
    return performance.timeOrigin;
  });

  try {
    await page.getByTestId("mimi-identifier-query").click();
    await expect.poll(() => !!queryRequest).toBe(true);
    await expect(page.getByTestId("mimi-identifier-query")).toBeDisabled();
    await page.getByTestId("account-menu-button").click();
    await page.getByTestId("account-menu-session-logout").click();
    await expect(page).toHaveURL(/\/login(?:[?#]|$)/);
    await expect(page.getByTestId("login-panel")).toBeVisible();
    await expect(page.getByTestId("settings-panel")).toHaveCount(0);
    releaseQuery();
    await expect.poll(() => routeSettled).toBe(true);
    await expect.poll(() => responseStatus !== undefined || failureText !== undefined).toBe(true);
    if (failureText === undefined) {
      expect(fulfillError).toBeUndefined();
      expect(responseStatus).toBe(500);
    } else {
      expect(failureText).not.toBe("");
    }
    // Allow the fulfilled promise and the toast host's render cycle to run.
    await page.waitForTimeout(500);
    const witness = await page.evaluate(() => ({
      timeOrigin: performance.timeOrigin,
      state: (window as unknown as {
        __settingsLogoutWitness?: {
          observedMimiError: boolean;
          observedReceipt: boolean;
        };
      }).__settingsLogoutWitness,
    }));
    expect(witness.timeOrigin).toBe(timeOrigin);
    expect(witness.state).toEqual({ observedMimiError: false, observedReceipt: false });
    await expect(page.getByTestId("login-panel")).toBeVisible();
    await expect(page.getByTestId("mimi-query-receipt")).toHaveCount(0);
    await expect(page.locator('[data-i18n-key="feedback.mimi_failed"]')).toHaveCount(0);
    await testInfo.attach("settings-logout-network-outcome", {
      body: JSON.stringify({ responseStatus, failureText, fulfillError, samePage: true }),
      contentType: "application/json",
    });
  } finally {
    releaseQuery();
  }
});
