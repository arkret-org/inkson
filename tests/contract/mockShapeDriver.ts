// Drives the e2e mock's route handler without a browser and without a WASM
// build.
//
// `mockArkretApi` registers exactly one catch-all `page.route("**/*", …)`
// handler and validates every JSON body it fulfils against the embedded
// OpenAPI inventory before handing it back. That validation is the only thing
// standing between the hand-written mock and the spec — and until now the only
// way to reach it was a Playwright run, which first spends twenty minutes
// building the client to WASM. So one stale field could hide every field
// behind it, and each layer cost a full build to discover.
//
// The page and the route below are the smallest stand-ins the handler actually
// uses (`request().method/url/postDataJSON/postData/headers`, `fulfill`,
// `continue`). Feeding it one synthetic request per registered operation runs
// the same validation in seconds.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const inventoryPath = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "e2e",
  "mock-operation-inventory.json",
);

export type MockOperation = {
  method: string;
  path_template: string;
  operation_id: string;
  responses: Record<string, { schema_ref: string | null }>;
};

export function mockOperations(): MockOperation[] {
  return (
    JSON.parse(readFileSync(inventoryPath, "utf8")) as {
      operations: MockOperation[];
    }
  ).operations;
}

/// Well-formed stand-ins for every `{param}` the inventory's path templates
/// use. They only have to satisfy the identifier patterns the mock parses
/// them with; nothing here is asserted against.
const PATH_PARAMETERS: Record<string, string> = {
  account_data_key: "ak.account.invite_delivery",
  actor_id: "ak:did_core:web:alice.example",
  agent_id: "ak:did_core:web:agents.example:assistant",
  applet_id: "ak:applet:01964137-0000-7000-8000-0000000000a2",
  backup_id: "ak:backup:01964137-0000-7000-8000-0000000000b1",
  circle_id: "ak:circle:AY61QviMxoJ0ALEn5U39bA7Qbi1BxHCrOq4950m2JRjM",
  event_id: "ak:event:AUftf_3k2fRKMG0NFlHe5iEMBOUpxMwYMRu-yhMJl-yz",
  morph_id: "ak:morph:AY61QviMxoJ0ALEn5U39bA7Qbi1BxHCrOq4950m2JRjM",
  principal_id: "ak:did_core:web:alice.example",
  protocol: "mimi",
  realm_id: "ak:realm:AfZipd5actne33fQKtrLCK5Q658LZby1JgRICH16UNjo",
  realm_id_or_alias: "ak:realm:AfZipd5actne33fQKtrLCK5Q658LZby1JgRICH16UNjo",
  receipt_id: "ak:receipt:01964137-0000-7000-8000-0000000000c1",
  recovery_session_id: "ak:recovery_session:01964137-0000-7000-8000-0000000000d1",
  service_id: "ak:did_core:key:z6MkixsGj3MVGKMug2VMC2JbtzX3UjaAcfRs7G1RjbSnZJaH",
  sidecar_id: "ak:sidecar:AY61QviMxoJ0ALEn5U39bA7Qbi1BxHCrOq4950m2JRjM",
  snapshot_id: "ak:realm_snapshot:AUjRA6G8R-TXotecelrSOdg_YXeFYRh1NE-aQ34q9sOu",
  strand_id: "ak:strand:AQAG6N7vDa1nxssksTCIdqNm-FTDJoKuBrHIclJ7FBy0",
  transaction_id: "ak:transaction:01964137-0000-7000-8000-0000000000e1",
};

export function concretePath(pathTemplate: string): string {
  return pathTemplate.replace(/\{([^}]+)\}/g, (_match, name: string) => {
    const value = PATH_PARAMETERS[name];
    if (!value) {
      throw new Error(
        `mock shape driver has no stand-in for path parameter {${name}}; add one to PATH_PARAMETERS`,
      );
    }
    // Deliberately not percent-encoded: these identifiers carry `:` on the
    // wire and the mock parses the raw segment.
    return value;
  });
}

export type FulfilledResponse = {
  status: number;
  contentType: string;
  body: unknown;
  headers?: Record<string, string>;
};

type RouteHandler = (route: unknown) => unknown | Promise<unknown>;

/// A `Page` with just enough surface for `mockArkretApi` to install itself.
export function captureRouteHandler(): {
  page: unknown;
  handler: () => RouteHandler;
} {
  let captured: RouteHandler | undefined;
  const register = async (_pattern: unknown, handler: RouteHandler) => { captured = handler; };
  const context = { route: register, addInitScript: async () => {} };
  const page = {
    route: register,
    addInitScript: async () => {},
    on: () => {},
    context: () => context,
  };
  return {
    page,
    handler: () => {
      if (!captured) {
        throw new Error("mockArkretApi registered no route handler");
      }
      return captured;
    },
  };
}

/// Invoke the captured handler for one request. Returns what it fulfilled, or
/// `null` when it deferred to the network (`route.continue()`).
export async function driveOnce(
  handler: RouteHandler,
  request: { url: string; method: string; postData?: unknown; headers?: Record<string, string>; onFulfill?: () => void },
): Promise<FulfilledResponse | null> {
  let fulfilled: FulfilledResponse | null = null;
  const fakeRequest = {
    url: () => request.url,
    method: () => request.method,
    headers: () => request.headers ?? ({ authorization: "Bearer sx:e2e-token" }),
    postData: () =>
      request.postData === undefined ? null : JSON.stringify(request.postData),
    postDataJSON: () => request.postData ?? {},
  };
  const route = {
    request: () => fakeRequest,
    fulfill: async (response: { status?: number; body?: unknown; json?: unknown; contentType?: string; headers?: Record<string, string> }) => {
      let body: unknown;
      try {
        body = response.json !== undefined ? response.json : response.body === undefined ? undefined : Buffer.isBuffer(response.body) ? response.body : JSON.parse(String(response.body));
      } catch {
        body = response.body;
      }
      request.onFulfill?.();
      fulfilled = { status: response.status ?? 200, contentType: response.contentType ?? response.headers?.["content-type"] ?? (response.json !== undefined ? "application/json" : ""), body,
        ...(response.headers ? { headers: response.headers } : {}) };
    },
    continue: async () => {},
    abort: async () => {},
  };
  await handler(route);
  return fulfilled;
}
