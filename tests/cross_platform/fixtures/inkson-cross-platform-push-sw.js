// Same push-receive smoke served over real HTTP in every browser engine.
const LEAK_FIELDS = ["body", "message_body", "realm_title", "title", "sender", "collapse_key", "note", "target_ref", "scheduled_send_id", "expiry_target_ref", "scheduled_body", "draft_content"];
const WAKEUP_KINDS = new Set(["reminder", "scheduled_send", "expiry_invalidation"]);

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
