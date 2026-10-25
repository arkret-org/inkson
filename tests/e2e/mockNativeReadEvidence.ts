import type { Route } from "@playwright/test";
import { ARCHIVAL_READ_CREDENTIAL, nativeReadTranscripts, NATIVE_READ_OPERATIONS } from "../contract/nativeReadEvidence";

const stable = (value: unknown): string => JSON.stringify(value, (_key, item) =>
  item && typeof item === "object" && !Array.isArray(item)
    ? Object.fromEntries(Object.entries(item).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)) : item);

// Explicit archival replay: no authority is minted, refreshed, or transferred
// to the ordinary UI mock account. Only the exact captured selector is served.
export function nativeReadReplay(
  operation: (method: string, path: string) => { operation_id: string; request?: { schema_ref: string | null } },
  validate: (reference: string, value: unknown) => void,
  json: (route: Route, value: unknown) => Promise<unknown>,
  reject: (route: Route, code: string, detail: string) => Promise<unknown>,
) {
  const records = new Map(nativeReadTranscripts().map(row => [row.operation_id, row]));
  return async (route: Route, url: URL): Promise<boolean> => {
    const descriptor = operation(route.request().method(), url.pathname);
    const id = descriptor.operation_id;
    if (!NATIVE_READ_OPERATIONS.has(id)) return false;
    if (!descriptor.request) throw new Error(`missing native read request contract: ${id}`);
    const row = records.get(id)!;
    const headers = route.request().headers();
    if (headers["arkret-operation"] === undefined) {
      await reject(route, "operation_selector_required", "exact operation selector required"); return true;
    }
    if (headers["arkret-operation"] !== id) {
      await reject(route, "unsupported_operation_version", "selector must identify this exact supported operation once"); return true;
    }
    if (!id.startsWith("ak.open.") && headers.authorization !== ARCHIVAL_READ_CREDENTIAL) {
      await reject(route, "unauthenticated", "archival fixture credential required"); return true;
    }
    let body: unknown;
    try {
      body = row.method === "GET" ? null : route.request().postDataJSON();
      if (descriptor.request.schema_ref) validate(descriptor.request.schema_ref, body);
      const expectedKeys = [...new URL(`https://native-read-archive.example${row.path}`).searchParams.keys()].sort();
      if (stable([...url.searchParams.keys()].sort()) !== stable(expectedKeys)) throw new Error("query fields differ");
    } catch {
      await reject(route, "schema_violation", "invalid native read selector shape"); return true;
    }
    if (url.hostname !== "native-read-archive.example" || `${url.pathname}${url.search}` !== row.path || stable(body) !== stable(row.request_body)) {
      await reject(route, "temporarily_unavailable", "no archived authority material for this exact request"); return true;
    }
    await json(route, structuredClone(row.response_body));
    return true;
  };
}
