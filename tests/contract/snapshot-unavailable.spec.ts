import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  DEMO_REALM,
  mockArkretApi,
  validateMockResponseForOperation,
  validateMockSchema,
} from "../e2e/mockArkretApi";
import { captureRouteHandler, mockOperations } from "./mockShapeDriver";

const HEAD = "ak.self.realm_state_snapshot.read.manifest_head.v1";
const BY_REF = "ak.self.realm_state_snapshot.read.by_ref.v1";
const BASE = "https://local.host/_arkret/self/realm-state-snapshot";
const UNKNOWN_REALM = "ak:realm:AUEAoXMJeJWBETvkqm7gk4imduk7g-l8bim19OPFQDaO";
const MISSING_SNAPSHOT = "ak:realm_snapshot:AUjRA6G8R-TXotecelrSOdg_YXeFYRh1NE-aQ34q9sOu";
const problemSchema = "schemas/http-problem-details.schema.json";
const registryPath = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "arkret-spec", "spec", "v1", "artifacts", "registry", "error-code-registry.json");
const registry = JSON.parse(readFileSync(registryPath, "utf8")) as {
  codes: Array<{ code: string; status: string; http_status: number; type_uri: string; title: string }>;
};
const descriptor = registry.codes.find((entry) => entry.code === "realm_state_snapshot_unavailable" && entry.status === "active")!;

type Handler = ReturnType<ReturnType<typeof captureRouteHandler>["handler"]>;
type Response = { status: number; contentType: string; body: Record<string, unknown> };

async function install(): Promise<Handler> {
  const { page, handler } = captureRouteHandler();
  await mockArkretApi(page as never);
  return handler();
}

async function driveSnapshot(handler: Handler, url: string): Promise<Response> {
  let fulfilled: Response | undefined;
  await handler({
    request: () => ({
      method: () => "GET",
      url: () => url,
      headers: () => ({ authorization: "Bearer sx:e2e-token" }),
      postData: () => null,
      postDataJSON: () => ({}),
    }),
    fulfill: async (response: { status: number; contentType: string; body: string }) => {
      fulfilled = { status: response.status, contentType: response.contentType, body: JSON.parse(response.body) };
    },
    continue: async () => {},
    abort: async () => {},
  });
  expect(fulfilled, "the real mock snapshot route must fulfill").toBeDefined();
  return fulfilled!;
}

function assertUnavailable(response: Response) {
  expect(descriptor.http_status).toBe(503);
  expect(response.status).toBe(descriptor.http_status);
  expect(response.contentType).toBe("application/problem+json");
  expect(Object.keys(response.body).sort()).toEqual(["detail", "status", "title", "type"]);
  expect(response.body).toMatchObject({ status: descriptor.http_status, type: descriptor.type_uri, title: descriptor.title });
  expect(response.body.detail).toEqual(expect.any(String));
  expect(() => validateMockSchema(problemSchema, response.body)).not.toThrow();
}

test("Unknown Realm snapshot reads emit only the registered unavailable HTTP Problem", async () => {
  const handler = await install();
  for (const path of ["head", MISSING_SNAPSHOT]) {
    assertUnavailable(await driveSnapshot(handler, `${BASE}/${path}?realm_id=${UNKNOWN_REALM}`));
  }
});

test("Known snapshot reads preserve the exact success artifact and never replace a missing reference with the head", async () => {
  const handler = await install();
  const head = await driveSnapshot(handler, `${BASE}/head?realm_id=${DEMO_REALM}`);
  expect(head.status).toBe(200);
  expect(head.contentType).toBe("application/json");
  expect(head.body.realm_id).toBe(DEMO_REALM);
  expect(head.body.snapshot_id).toEqual(expect.any(String));
  expect(head.body.snapshot_id).not.toBe(MISSING_SNAPSHOT);
  const exact = await driveSnapshot(handler, `${BASE}/${head.body.snapshot_id}?realm_id=${DEMO_REALM}`);
  expect(exact).toEqual(head);
  assertUnavailable(await driveSnapshot(handler, `${BASE}/${MISSING_SNAPSHOT}?realm_id=${DEMO_REALM}`));
});

test("Snapshot unavailable validation rejects status, registry, content type and producer closure drift without widening other operations", async () => {
  const handler = await install();
  const canonical = (await driveSnapshot(handler, `${BASE}/head?realm_id=${UNKNOWN_REALM}`)).body;
  const operations = mockOperations();
  for (const operationId of [HEAD, BY_REF]) {
    const operation = operations.find((entry) => entry.operation_id === operationId)!;
    expect(operation).toBeDefined();
    const validate = (status: number, body: unknown, contentType = "application/problem+json") =>
      validateMockResponseForOperation(operation, status, body, contentType);
    expect(() => validate(503, canonical)).not.toThrow();
    for (const wrongStatus of [200, 404, 500, 502]) {
      expect(() => validate(wrongStatus, canonical)).toThrow();
    }
    expect(() => validate(404, { error: { code: "not_found" } }, "application/json")).toThrow("has no OpenAPI response");
    for (const body of [
      { ...canonical, status: 404 },
      { ...canonical, type: "https://arkret.org/problems/unregistered_snapshot_failure" },
      { ...canonical, type: "https://arkret.org/problems/service_unavailable", title: "Service unavailable" },
      { ...canonical, title: "Different title" },
      { ...canonical, detail: "" },
      { ...canonical, detail: undefined },
      { ...canonical, code: "unregistered_snapshot_failure" },
      { ...canonical, error: { code: "not_found" } },
      { ...canonical, unregistered_extension: true },
      { ...canonical, retry_after_ms: 1000 },
    ]) {
      expect(() => validate(503, body)).toThrow();
    }
    expect(() => validate(503, canonical, "application/json")).toThrow("application/problem+json");
    expect(() => validate(503, canonical, "text/plain")).toThrow("application/problem+json");
    expect(() => validate(503, undefined)).toThrow();
  }
  const unrelated = operations.find((operation) => operation.operation_id !== HEAD && operation.operation_id !== BY_REF && !operation.responses["503"] && !operation.responses.default)!;
  expect(unrelated).toBeDefined();
  expect(() => validateMockResponseForOperation(unrelated, 503, canonical, "application/problem+json")).toThrow("has no OpenAPI response");
});
