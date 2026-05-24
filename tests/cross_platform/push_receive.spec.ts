// Cross-platform scenario: desktop push receive smoke.
//
// Local desktop browsers cannot receive a real APNs/FCM/WebPush delivery
// without provider credentials, TLS origin policy, and OS notification
// entitlements. This smoke pins the browser contract yougen relies on after
// the provider wakes the app: a service worker receives an opaque
// `background_sync_needed` payload and can signal the foreground page without
// exposing message/title/sender/collapse metadata.

import { expect, test } from "@playwright/test";
import {
  ensureServiceWorkerAvailable,
  gotoOrSkip,
  waitForBundleReady,
} from "./_helpers";

const PUSH_SW_PATH = "/yougen-cross-platform-push-sw.js";
const LEAK_FIELDS = [
  "body",
  "message_body",
  "space_title",
  "title",
  "sender",
  "collapse_key",
];

const PUSH_WORKER_SCRIPT = `
  const LEAK_FIELDS = ${JSON.stringify(LEAK_FIELDS)};

  self.addEventListener("install", (event) => {
    event.waitUntil(self.skipWaiting());
  });

  self.addEventListener("activate", (event) => {
    event.waitUntil(self.clients.claim());
  });

  function receiveEnvelope(payload) {
    const incoming = payload && typeof payload === "object" ? payload : {};
    const outbound = {
      type: "yougen.push.receive",
      reason: incoming.reason === "background_sync_needed"
        ? "background_sync_needed"
        : "background_sync_needed",
    };
    return {
      ...outbound,
      leaked: LEAK_FIELDS.filter((field) => Object.prototype.hasOwnProperty.call(outbound, field)),
      hasDisplayText: LEAK_FIELDS.some((field) => Object.prototype.hasOwnProperty.call(outbound, field)),
      receivedProbeKeys: LEAK_FIELDS.filter((field) => Object.prototype.hasOwnProperty.call(incoming, field)),
    };
  }

  async function notifyClients(payload) {
    const clients = await self.clients.matchAll({ includeUncontrolled: true, type: "window" });
    const message = receiveEnvelope(payload);
    for (const client of clients) {
      client.postMessage(message);
    }
  }

  self.addEventListener("push", (event) => {
    let payload = {};
    try {
      payload = event.data ? event.data.json() : {};
    } catch (_) {
      payload = {};
    }
    event.waitUntil(notifyClients(payload));
  });

  self.addEventListener("message", (event) => {
    if (event.data && event.data.type === "simulate-push") {
      const pending = notifyClients(event.data.payload || {});
      if (typeof event.waitUntil === "function") {
        event.waitUntil(pending);
      }
    }
  });
`;

test.describe("desktop push receive smoke", () => {
  test.beforeEach(async ({ context, page }) => {
    await context.route(`**${PUSH_SW_PATH}`, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/javascript",
        body: PUSH_WORKER_SCRIPT,
      });
    });
    await gotoOrSkip(page, "/");
    await waitForBundleReady(page);
    await ensureServiceWorkerAvailable(page);
  });

  test("background_sync_needed wakeup reaches the foreground without readable content", async ({
    page,
  }) => {
    const received = await page.evaluate(
      async ({ path }) => {
        const registration = await navigator.serviceWorker.register(path, {
          scope: "/",
        });
        const ready = await navigator.serviceWorker.ready;
        let worker = ready.active || registration.active || registration.waiting || registration.installing;
        if (!worker) {
          throw new Error("service worker did not become active");
        }

        if (worker.state !== "activated") {
          await new Promise<void>((resolve) => {
            worker.addEventListener(
              "statechange",
              () => {
                if (worker.state === "activated") {
                  resolve();
                }
              },
              { once: false },
            );
          });
          worker = ready.active || registration.active || worker;
        }

        return await new Promise<{
          reason: string | null;
          leaked: string[];
          hasDisplayText: boolean;
          receivedProbeKeys: string[];
        }>((resolve, reject) => {
          const timeout = setTimeout(() => reject(new Error("push receive timeout")), 10_000);
          navigator.serviceWorker.addEventListener("message", function onMessage(event) {
            if (event.data?.type !== "yougen.push.receive") {
              return;
            }
            clearTimeout(timeout);
            navigator.serviceWorker.removeEventListener("message", onMessage);
            resolve({
              reason: event.data.reason ?? null,
              leaked: Array.isArray(event.data.leaked) ? event.data.leaked : [],
              hasDisplayText: event.data.hasDisplayText === true,
              receivedProbeKeys: Array.isArray(event.data.receivedProbeKeys)
                ? event.data.receivedProbeKeys
                : [],
            });
          });
          worker.postMessage({
            type: "simulate-push",
            payload: {
              reason: "background_sync_needed",
              body: "hidden body",
              message_body: "hidden message",
              space_title: "hidden space",
              title: "hidden title",
              sender: "did:web:alice.example",
              collapse_key: "cx:event:1",
            },
          });
        });
      },
      { path: PUSH_SW_PATH },
    );

    expect(received.reason).toBe("background_sync_needed");
    expect(received.receivedProbeKeys.sort()).toEqual([...LEAK_FIELDS].sort());
    expect(received.leaked).toEqual([]);
    expect(received.hasDisplayText).toBe(false);
  });
});
