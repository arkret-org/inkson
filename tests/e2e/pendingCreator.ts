import type { Page } from "@playwright/test";

// Inspect holder-local persistence only to distinguish a pending resource from
// an unregistered fixture ID. This supplies neither accepted Full nor authority.
export async function hasPendingRealmCreate(
  page: Page,
  eventId: string,
  accountId: { principal_id: string; station_id: string },
  deviceId: string,
): Promise<boolean> {
  return page.evaluate(async ({ eventId, accountId, deviceId }) => {
    if (!eventId.startsWith("ak:event:")) return false;
    const result = <T>(request: IDBRequest<T>): Promise<T> => new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    const databases = await indexedDB.databases();
    if (!databases.some(database => database.name === "inkson.secret.inkson")) return false;
    const db = await result(indexedDB.open("inkson.secret.inkson", 1));
    try {
      const tx = db.transaction(["entries", "wrapping_keys"], "readonly");
      const entries = tx.objectStore("entries");
      const [key, names, encrypted] = await Promise.all([
        result(tx.objectStore("wrapping_keys").get("primary")) as Promise<CryptoKey>,
        result(entries.getAllKeys()),
        result(entries.getAll()),
      ]);
      if (!key || key.extractable) throw new Error("pending creator vault has no non-extractable wrapping key");
      const sameActor = (actor: Record<string, any> | undefined) =>
        actor?.kind === "account"
        && actor.account_id?.principal_id === accountId.principal_id
        && actor.account_id?.station_id === accountId.station_id;
      // These values are two copies of the same SDK-serialized local unit.
      // Compare all JSON fields independently of object member ordering.
      const equalJson = (left: unknown, right: unknown): boolean => {
        if (left === right) return true;
        if (left === null || right === null || typeof left !== "object" || typeof right !== "object") return false;
        if (Array.isArray(left) || Array.isArray(right)) {
          return Array.isArray(left) && Array.isArray(right) && left.length === right.length
            && left.every((value, index) => equalJson(value, right[index]));
        }
        const a = left as Record<string, unknown>, b = right as Record<string, unknown>;
        const keys = Object.keys(a);
        return keys.length === Object.keys(b).length
          && keys.every(key => Object.hasOwn(b, key) && equalJson(a[key], b[key]));
      };
      for (let index = 0; index < names.length; index += 1) {
        const name = String(names[index]);
        if (!name.startsWith("inkson.outbound.v1::") || !name.endsWith(".standard")) continue;
        const entry = encrypted[index] as { iv: Uint8Array; ct: Uint8Array };
        const plaintext = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: Uint8Array.from(entry.iv).buffer }, key, Uint8Array.from(entry.ct).buffer,
        );
        const state = JSON.parse(new TextDecoder().decode(plaintext));
        for (const record of state.creator_bootstrap_records ?? []) {
          const intent = record.intent;
          if (record.state !== "genesis_intent_persisted"
            || intent?.scope_create_event_id !== eventId
            || !sameActor(intent.owner_actor_id)
            || intent.creator_device_id !== deviceId
            || intent.effective_scope?.kind !== "realm") continue;
          const unit = intent.signed_scope_create_unit;
          const event = unit?.events?.[0]?.event;
          if (unit?.unit_kind !== "ordinary_realm_bootstrap"
            || event?.event_id !== eventId || event.kind !== "ak.realm.create"
            || event.scope_ref?.kind !== "realm_genesis" || !sameActor(event.actor_id)
            || Object.hasOwn(event, "realm_id")
            || intent.effective_scope.realm_id !== `ak:realm:${eventId.slice("ak:event:".length)}`) continue;
          const queued = (state.items ?? []).find((item: Record<string, any>) =>
            item.submission?.event_id === eventId
            && item.submission.state?.state === "queued"
            && ["queued", "forwarding"].includes(item.status)
            && equalJson(item.submission.request, unit));
          if (queued) return true;
        }
      }
      return false;
    } finally {
      db.close();
    }
  }, { eventId, accountId, deviceId });
}
