// Cross-platform scenario: desktop push receive smoke.
//
// Local desktop browsers cannot receive a real APNs/FCM/WebPush delivery
// without provider credentials, TLS origin policy, and OS notification
// entitlements. This smoke pins the browser contract inkson relies on after
// the provider wakes the app: a service worker receives an opaque
// `background_sync_needed` payload and can signal the foreground page without
// exposing message/title/sender/collapse metadata.

import { expect, test, type Page } from "@playwright/test";
import {
  ensureServiceWorkerAvailable,
  gotoOrSkip,
  waitForBundleReady,
} from "./_helpers";

const PUSH_SW_PATH = "/inkson-cross-platform-push-sw.js";
const LEAK_FIELDS = [
  "body",
  "message_body",
  "realm_title",
  "title",
  "sender",
  "collapse_key",
  "note",
  "target_ref",
  "scheduled_send_id",
  "expiry_target_ref",
  "scheduled_body",
  "draft_content",
] as const;
const WAKEUP_KINDS = [
  "reminder",
  "scheduled_send",
  "expiry_invalidation",
] as const;

type LeakField = (typeof LEAK_FIELDS)[number];
type WakeupKind = (typeof WAKEUP_KINDS)[number];
type ReceivedPush = {
  reason: string | null;
  wakeupKind: string | null;
  leaked: string[];
  hasDisplayText: boolean;
  receivedProbeKeys: string[];
};

const READABLE_PROBES: Record<LeakField, string> = {
  body: "hidden body",
  message_body: "hidden message",
  realm_title: "hidden realm",
  title: "hidden title",
  sender: "did:web:alice.example",
  collapse_key: "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
  note: "private reminder note",
  target_ref: "ak:message:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
  scheduled_send_id:
    "ak:scheduled_send:01904100-0000-7000-8000-000000000003",
  expiry_target_ref: "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
  scheduled_body: "hidden scheduled send body",
  draft_content: "hidden draft content",
};

const PUSH_WORKER_SCRIPT = `
  const LEAK_FIELDS = ${JSON.stringify(LEAK_FIELDS)};
  const WAKEUP_KINDS = new Set(${JSON.stringify(WAKEUP_KINDS)});

  self.addEventListener("install", (event) => {
    event.waitUntil(self.skipWaiting());
  });

  self.addEventListener("activate", (event) => {
    event.waitUntil(self.clients.claim());
  });

  function receiveEnvelope(payload) {
    const incoming = payload && typeof payload === "object" ? payload : {};
    const outbound = {
      type: "inkson.push.receive",
      reason: incoming.reason === "background_sync_needed"
        ? "background_sync_needed"
        : "background_sync_needed",
    };
    if (WAKEUP_KINDS.has(incoming.wakeup_kind)) {
      outbound.wakeupKind = incoming.wakeup_kind;
    }
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

async function simulatePushReceive(
  page: Page,
  payload: Record<string, string>,
): Promise<ReceivedPush> {
  return await page.evaluate(
    async ({ path, payload }) => {
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
        wakeupKind: string | null;
        leaked: string[];
        hasDisplayText: boolean;
        receivedProbeKeys: string[];
      }>((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error("push receive timeout")), 10_000);
        navigator.serviceWorker.addEventListener("message", function onMessage(event) {
          if (event.data?.type !== "inkson.push.receive") {
            return;
          }
          clearTimeout(timeout);
          navigator.serviceWorker.removeEventListener("message", onMessage);
          resolve({
            reason: event.data.reason ?? null,
            wakeupKind: event.data.wakeupKind ?? null,
            leaked: Array.isArray(event.data.leaked) ? event.data.leaked : [],
            hasDisplayText: event.data.hasDisplayText === true,
            receivedProbeKeys: Array.isArray(event.data.receivedProbeKeys)
              ? event.data.receivedProbeKeys
              : [],
          });
        });
        worker.postMessage({
          type: "simulate-push",
          payload,
        });
      });
    },
    { path: PUSH_SW_PATH, payload },
  );
}

function expectBlindWakeup(received: ReceivedPush, wakeupKind?: WakeupKind): void {
  expect(received.reason).toBe("background_sync_needed");
  expect(received.wakeupKind).toBe(wakeupKind ?? null);
  expect(received.receivedProbeKeys.sort()).toEqual([...LEAK_FIELDS].sort());
  expect(received.leaked).toEqual([]);
  expect(received.hasDisplayText).toBe(false);
}

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
    const received = await simulatePushReceive(page, {
      reason: "background_sync_needed",
      ...READABLE_PROBES,
    });

    expectBlindWakeup(received);
  });

  for (const wakeupKind of WAKEUP_KINDS) {
    test(`${wakeupKind} wakeup reaches the foreground without readable content`, async ({
      page,
    }) => {
      const received = await simulatePushReceive(page, {
        reason: "background_sync_needed",
        wakeup_kind: wakeupKind,
        ...READABLE_PROBES,
      });

      expectBlindWakeup(received, wakeupKind);
    });
  }
});
