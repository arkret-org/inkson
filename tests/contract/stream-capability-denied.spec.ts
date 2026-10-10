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

const OPERATION = "ak.self.committed_event.read.scan.v1";
const URL = "https://local.host/_arkret/self/streams/scan";
const UNKNOWN_REALM = "ak:realm:AUEAoXMJeJWBETvkqm7gk4imduk7g-l8bim19OPFQDaO";
const registryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "arkret-spec", "spec", "v1", "artifacts", "registry");
const registry = JSON.parse(readFileSync(resolve(registryRoot, "error-code-registry.json"), "utf8")) as {
  codes: Array<{ code: string; status: string; http_status: number; type_uri: string; title: string }>;
};
const mapping = JSON.parse(readFileSync(resolve(registryRoot, "operations-error-mapping.json"), "utf8")) as {
  rules: { universal_codes: string };
  operations: Array<{ operation_id: string; operation_specific: string[] }>;
};
const descriptor = registry.codes.filter((entry) => entry.code === "capability_denied" && entry.status === "active");

type Handler = ReturnType<ReturnType<typeof captureRouteHandler>["handler"]>;
type Response = { status: number; contentType: string; body: Record<string, any> };

const scanRequest = (realm: string) => ({
  realm_id: realm,
  stream_ref: { kind: "realm", realm_id: realm },
  after_position: null,
  limit: 1000,
});

async function driveScan(handler: Handler, body: unknown): Promise<Response> {
  let fulfilled: Response | undefined;
  await handler({
    request: () => ({
      method: () => "POST",
      url: () => URL,
      headers: () => ({ authorization: "Bearer sx:e2e-token" }),
      postData: () => JSON.stringify(body),
      postDataJSON: () => body,
    }),
    fulfill: async (response: { status: number; contentType: string; body: string }) => {
      fulfilled = { status: response.status, contentType: response.contentType, body: JSON.parse(response.body) };
    },
    continue: async () => {},
    abort: async () => {},
  });
  expect(fulfilled, "the real stream scan route must fulfill").toBeDefined();
  return fulfilled!;
}

test("Unapproved stream scans emit a registered closed capability Problem while accepted native scans keep their exact committed rows", async () => {
  expect(descriptor).toHaveLength(1);
  const code = descriptor[0];
  expect(code.http_status).toBe(403);
  const operationMapping = mapping.operations.filter((entry) => entry.operation_id === OPERATION);
  expect(operationMapping).toHaveLength(1);
  expect(operationMapping[0].operation_specific).not.toContain("not_found");
  expect(mapping.rules.universal_codes.match(/[a-z][a-z0-9_]+/g)).toContain(code.code);
  const { page, handler } = captureRouteHandler();
  await mockArkretApi(page as never);
  const route = handler();
  const request = scanRequest(UNKNOWN_REALM);
  expect(() => validateMockSchema("schemas/authority-commit-operations.schema.json#/$defs/stream_scan_request", request)).not.toThrow();
  const denied = await driveScan(route, request);
  expect(denied.status).toBe(code.http_status);
  expect(denied.contentType).toBe("application/problem+json");
  expect(Object.keys(denied.body).sort()).toEqual(["detail", "status", "title", "type"]);
  expect(denied.body).toMatchObject({ status: code.http_status, type: code.type_uri, title: code.title });
  expect(() => validateMockSchema("schemas/http-problem-details.schema.json", denied.body)).not.toThrow();
  // No empty scan, floor or Current rows are invented for the unapproved stream.
  expect(denied.body).not.toHaveProperty("committed_events");
  expect(denied.body).not.toHaveProperty("readable_floor");
  const knownRequest = scanRequest(DEMO_REALM);
  const accepted = await driveScan(route, knownRequest);
  expect(accepted.status).toBe(200);
  expect(accepted.contentType).toBe("application/json");
  expect(() => validateMockSchema("schemas/authority-commit-operations.schema.json#/$defs/stream_scan_outcome", accepted.body)).not.toThrow();
  expect(accepted.body.committed_events.length).toBeGreaterThan(0);
  expect(accepted.body.readable_floor.floor_commit_id).toBe(accepted.body.committed_events[0].commit.commit_id);
  expect(accepted.body.readable_floor.oldest_position).toBe(accepted.body.committed_events[0].commit.stream_position);
  for (const [index, row] of accepted.body.committed_events.entries()) {
    expect(row.commit.realm_id).toBe(DEMO_REALM);
    expect(row.commit.stream_ref).toEqual(knownRequest.stream_ref);
    expect(row.commit.signature.sig).toEqual(expect.any(String));
    expect(row.event.event_id).toBe(row.commit.event_ref);
    if (index > 0) {
      const previous = accepted.body.committed_events[index - 1].commit;
      expect(row.commit.stream_position).toBe(previous.stream_position + 1);
      expect(row.commit.previous_commit_ref).toBe(previous.commit_id);
    }
  }
  expect(await driveScan(route, knownRequest)).toEqual(accepted);
  const operations = mockOperations();
  const operation = operations.find((entry) => entry.operation_id === OPERATION)!;
  const validate = (status: number, body: unknown, contentType = "application/problem+json") =>
    validateMockResponseForOperation(operation, status, body, contentType);
  expect(() => validate(403, denied.body)).not.toThrow();
  for (const wrongStatus of [200, 404, 500, 503]) {
    expect(() => validate(wrongStatus, denied.body)).toThrow();
  }
  expect(() => validate(404, { error: { code: "not_found" } }, "application/json")).toThrow("has no OpenAPI response");
  for (const body of [
    { ...denied.body, status: 404 },
    { ...denied.body, type: "https://arkret.org/problems/unregistered_scan_failure" },
    { ...denied.body, type: "https://arkret.org/problems/not_found", title: "Not found" },
    { ...denied.body, title: "Wrong title" },
    { ...denied.body, detail: "" },
    { ...denied.body, detail: undefined },
    { ...denied.body, error: { code: "capability_denied" } },
    { ...denied.body, code: "unregistered_scan_failure" },
    { ...denied.body, unregistered_extension: true },
  ]) {
    expect(() => validate(403, body)).toThrow();
  }
  expect(() => validate(403, denied.body, "application/json")).toThrow("application/problem+json");
  expect(() => validate(403, denied.body, "text/plain")).toThrow("application/problem+json");
  const unrelated = operations.find((entry) => entry.operation_id !== OPERATION && !entry.responses["403"] && !entry.responses.default)!;
  expect(unrelated).toBeDefined();
  expect(() => validateMockResponseForOperation(unrelated, 403, denied.body, "application/problem+json")).toThrow("has no OpenAPI response");
});
