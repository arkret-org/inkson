import { createHash, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import type { Page } from "@playwright/test";
import { CURRENT_ACCOUNT_ID } from "./mockArkretApi";

// Read only this isolated test account's existing wrapped secret. It never
// leaves memory or uses a localStorage fallback, key export, or fixture file.
export async function openFixtureClientUiValue(page: Page, value: unknown): Promise<unknown> {
  const binary = process.env.INKSON_WIRE_BIN;
  if (!binary) throw new Error("The client UI contract requires an explicit prebuilt Wire binary");
  const account = {
    principal_id: CURRENT_ACCOUNT_ID.principal_id,
    station_id: CURRENT_ACCOUNT_ID.station_id,
  };
  const digest = createHash("sha256").update(JSON.stringify(account)).digest("base64url");
  const binding = `__fixtureClientUi${randomUUID().replaceAll("-", "")}`;
  await page.exposeBinding(binding, (source, accountSecret: unknown) => {
    if (source.frame !== page.mainFrame() || typeof accountSecret !== "string"
        || !/^[A-Za-z0-9_-]{43}$/.test(accountSecret)) {
      throw new Error("The fixture account secret has an invalid source or shape");
    }
    return verifyClientUiValue(binary, account, accountSecret, value);
  });
  return page.evaluate(async ({ key, binding }) => {
    const database = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open("inkson.secret.inkson", 1);
      request.onupgradeneeded = () => {
        request.transaction?.abort();
        reject(new Error("The fixture's existing secure store is required"));
      };
      request.onerror = () => reject(new Error("The fixture secure store could not be opened"));
      request.onblocked = () => reject(new Error("The fixture secure store is blocked"));
      request.onsuccess = () => resolve(request.result);
    });
    try {
      const transaction = database.transaction(["entries", "wrapping_keys"], "readonly");
      const read = <T>(request: IDBRequest<T>) => new Promise<T>((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(new Error("The fixture secure-store read failed"));
      });
      const [entry, wrappingKey] = await Promise.all([
        read(transaction.objectStore("entries").get(key)),
        read(transaction.objectStore("wrapping_keys").get("primary")),
      ]);
      if (!entry || !(entry.iv instanceof Uint8Array) || !(entry.ct instanceof Uint8Array)
          || !(wrappingKey instanceof CryptoKey) || wrappingKey.extractable) {
        throw new Error("The fixture requires its real wrapped account secret and non-extractable key");
      }
      const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: entry.iv }, wrappingKey, entry.ct);
      const secret = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
      // The evaluated call returns preferences only, so its trace result does
      // not contain the secret. The Node binding uses an in-memory stdin pipe.
      return await (window as unknown as Record<string, (secret: string) => Promise<unknown>>)[binding](secret);
    } finally {
      database.close();
    }
  }, { key: `inkson.mls_snapshot.account_secret.v1.${digest}`, binding });
}

function verifyClientUiValue(
  binary: string, account: typeof CURRENT_ACCOUNT_ID, accountSecret: string, value: unknown,
): Promise<unknown> {
  // Unlike the general fixture runner, use a pipe rather than a temporary
  // input file. No secret, envelope, or stderr is attached to test artifacts.
  return new Promise((resolve, reject) => {
    const child = spawn(binary, ["open-fixture-client-ui-value"], {
      stdio: ["pipe", "pipe", "pipe"], windowsHide: true,
    });
    let settled = false;
    let output = "";
    const timer = setTimeout(() => fail("Fixture client UI verification timed out"), 60_000);
    function fail(message: string) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.kill();
      reject(new Error(message));
    }
    child.on("error", () => fail("Fixture client UI verifier could not start"));
    child.stdin.on("error", () => fail("Fixture client UI verifier input failed"));
    child.stderr.resume();
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      output += chunk;
      if (output.length > 16_384) fail("Fixture client UI verification exceeded its output bound");
    });
    child.on("close", status => {
      if (settled) return;
      if (status !== 0) return fail("Fixture client UI value failed SDK authentication");
      try {
        const plaintext: unknown = JSON.parse(output);
        settled = true;
        clearTimeout(timer);
        resolve(plaintext);
      } catch {
        fail("Fixture client UI verification returned invalid JSON");
      }
    });
    child.stdin.end(JSON.stringify({
      account_id: account, key: "ak.client.ui_state", account_secret: accountSecret, value,
    }));
  });
}
