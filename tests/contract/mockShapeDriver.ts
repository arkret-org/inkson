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
  account_data_key: "ak.notifications.projection.v1",
  actor_id: "ak:did_core:web:alice.example",
  agent_id: "ak:did_core:web:agents.example:assistant",
  applet_id: "ak:applet:AY61QviMxoJ0ALEn5U39bA7Qbi1BxHCrOq4950m2JRjM",
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
  body: unknown;
};

type RouteHandler = (route: unknown) => unknown | Promise<unknown>;

/// A `Page` with just enough surface for `mockArkretApi` to install itself.
export function captureRouteHandler(): {
  page: unknown;
  handler: () => RouteHandler;
} {
  let captured: RouteHandler | undefined;
  const page = {
    route: async (_pattern: unknown, handler: RouteHandler) => {
      captured = handler;
    },
    addInitScript: async () => {},
    on: () => {},
    context: () => ({ route: async () => {}, addInitScript: async () => {} }),
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
  request: { url: string; method: string; postData?: unknown },
): Promise<FulfilledResponse | null> {
  let fulfilled: FulfilledResponse | null = null;
  const fakeRequest = {
    url: () => request.url,
    method: () => request.method,
    headers: () => ({ authorization: "Bearer sx:e2e-token" }),
    postData: () =>
      request.postData === undefined ? null : JSON.stringify(request.postData),
    postDataJSON: () => request.postData ?? {},
  };
  const route = {
    request: () => fakeRequest,
    fulfill: async (response: { status?: number; body?: string }) => {
      let body: unknown;
      try {
        body = response.body === undefined ? undefined : JSON.parse(response.body);
      } catch {
        body = response.body;
      }
      fulfilled = { status: response.status ?? 200, body };
    },
    continue: async () => {},
    abort: async () => {},
  };
  await handler(route);
  return fulfilled;
}

/// The mock rejects a body the moment it does not match the spec, and every
/// such rejection carries one of these two markers. Anything else the driver
/// provokes — a branch that wants a request body it was not given, an
/// assertion about a field the driver did not send — is the driver's problem,
/// not a drift between the mock and the spec.
export function isShapeViolation(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return (
    message.includes("mock response violates") ||
    message.includes("validation failed at instance") ||
    message.includes("forbids a JSON body") ||
    message.includes("requires a JSON body") ||
    message.includes("retired field")
  );
}

/// Trim a violation to the part that names what drifted. The mock echoes the
/// whole rejected body into the message, which can run to tens of kilobytes.
export function violationSummary(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  const instance = message.match(
    /validation failed at instance '([^']*)' against '([^']*)' \(([^)]*)\)(?::\s*(.*))?/,
  );
  if (instance) {
    const [, path, against, keyword, detail] = instance;
    return `${path} against ${against} (${keyword})${detail ? `: ${detail.split("\n")[0]}` : ""}`;
  }
  const violates = message.match(/mock response violates ([^:]+):/);
  if (violates) {
    return `${violates[1]}: <body elided>`;
  }
  return message.split("\n")[0];
}

/// The full rejection text, which embeds the body the mock tried to serve.
/// Comparing this across two different synthetic requests is what separates a
/// hard-coded response (identical both times, so a real drift) from one
/// assembled out of the request (different both times, so the driver's own
/// filler is what got rejected).
///
/// Volatile values are erased first. Some responses come from `inkson-wire`,
/// which stamps `Utc::now()` and signs it — so the same hard-coded shape comes
/// back with different bytes on every call and would be misread as
/// request-dependent. That is not hypothetical: it is how the service
/// resolution and governance dependency fixtures stayed stale while this gate
/// read green.
export function violationFingerprint(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message
    .replace(/\d{4}-\d{2}-\d{2}T[\d:.]+Z/g, "<timestamp>")
    .replace(/\b[0-9a-f]{64}\b/g, "<digest>")
    .replace(/"jws":"[^"]*"/g, '"jws":"<jws>"');
}
