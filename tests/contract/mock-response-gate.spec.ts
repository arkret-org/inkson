import { expect, test } from "@playwright/test";
import { Buffer } from "node:buffer";
import { buildMockProblem, guardMockRoute, mockArkretApi, validateMockTransportResponse, DEMO_REALM } from "../e2e/mockArkretApi";
import { captureRouteHandler, driveOnce, mockOperations } from "./mockShapeDriver";

const circles = { method: "GET", url: "https://local.host/_arkret/self/circles" };
const stream = { method: "GET", url: "https://local.host/_arkret/self/committed-events/subscribe" };
const blob = { method: "GET", url: "https://local.host/_arkret/self/blob/get" };
const signal = { method: "GET", url: "https://local.host/_arkret/self/signal/subscribe" };
const validJson = { status: 200, contentType: "application/json", body: JSON.stringify({ realm_id: DEMO_REALM, circles: [] }) };

test("Account fixture observation preserves the exact validated NDJSON delivery", async () => {
  const captured = captureRouteHandler();
  const observed: Array<{ body: string; url: string }> = [];
  await mockArkretApi(captured.page as never, {
    observeAccountSubscribe: (body, url) => observed.push({ body, url: url.href }),
  });
  const response = await driveOnce(captured.handler(), {
    method: "GET",
    url: "https://local.host/_arkret/self/account/subscribe?catchup=true",
  });
  expect(response?.status).toBe(200);
  expect(response?.contentType).toBe("application/x-ndjson");
  expect(observed).toHaveLength(1);
  expect(observed[0].url).toBe("https://local.host/_arkret/self/account/subscribe?catchup=true");
  expect(observed[0].body).toBe(response?.body);
  expect(observed[0].body.trim().split("\n").map(line => JSON.parse(line)))
    .toEqual(expect.arrayContaining([expect.objectContaining({ kind: "catchup_complete" })]));
  captured.close();
});


async function emit(request: Parameters<typeof driveOnce>[1], response: any) {
  const captured = captureRouteHandler();
  await (captured.page as any).route("**/*", async (route: any) => guardMockRoute(route).fulfill(response));
  let emitted = 0;
  try {
    const value = await driveOnce(captured.handler(), { ...request, onFulfill: () => { emitted += 1; } });
    return { value, emitted };
  } catch (error) {
    expect(emitted, "a rejected response must never reach the underlying Route").toBe(0);
    throw error;
  }
}

test("raw fulfill cannot bypass JSON status, media, fields, or operation ownership", async () => {
  expect((await emit(circles, validJson)).emitted).toBe(1);
  for (const response of [
    { ...validJson, status: 201 }, { ...validJson, contentType: "text/plain" },
    { ...validJson, body: JSON.stringify({ realm_id: DEMO_REALM, circles: [], result: [] }) },
    { ...validJson, body: undefined }, { ...validJson, body: "{" },
    { ...validJson, body: Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]) },
    { status: 404 }, { status: 404, contentType: "application/json", body: '{"error":{"code":"not_found"}}' },
    { ...validJson, json: {} }, { ...validJson, path: "uninspected.json" },
  ]) await expect(emit(circles, response)).rejects.toThrow();
  await expect(emit({ ...circles, url: "https://local.host/_arkret/not-registered" }, validJson)).rejects.toThrow("embedded OpenAPI operations");
});

test("raw fulfill validates every NDJSON frame, delimiters and media", async () => {
  const frame = { kind: "catchup_complete", cursor: "ak:cursor:contract_stream" };
  const valid = { status: 200, contentType: "application/x-ndjson", body: `${JSON.stringify(frame)}\n${JSON.stringify(frame)}\n` };
  expect((await emit(stream, valid)).emitted).toBe(1);
  for (const body of ["", JSON.stringify(frame), `${JSON.stringify(frame)}\n{broken}\n`,
    `${JSON.stringify(frame)}\n${JSON.stringify({ ...frame, obsolete: true })}\n`]) {
    await expect(emit(stream, { ...valid, body })).rejects.toThrow();
  }
  await expect(emit(stream, { ...valid, contentType: "application/json" })).rejects.toThrow();
});

test("raw fulfill separates binary responses, no-content responses and Problems", async () => {
  expect((await emit(blob, { status: 200, contentType: "image/png", body: Buffer.from([137, 80, 78, 71]) })).emitted).toBe(1);
  expect((await emit(blob, { status: 200, contentType: "application/json", body: Buffer.from('{"file_content":true}') })).emitted).toBe(1);
  await expect(emit(blob, { status: 200, contentType: "image/png", body: "not binary" })).rejects.toThrow();
  await expect(emit(blob, { status: 200, body: Buffer.from([1]) })).rejects.toThrow();
  const unregister = { method: "POST", url: "https://local.host/_arkret/edge/push/unregister-device" };
  expect((await emit(unregister, { status: 204 })).emitted).toBe(1);
  await expect(emit(unregister, { status: 204, body: "{}", contentType: "application/json" })).rejects.toThrow();
  const denied = { status: 403, contentType: "application/problem+json", json: buildMockProblem("capability_denied", "denied") };
  expect((await emit(signal, denied)).emitted).toBe(1);
  await expect(emit(signal, { ...denied, contentType: "application/json" })).rejects.toThrow();
  await expect(emit(signal, { ...denied, status: 401 })).rejects.toThrow();
});

test("locator bearer responses require exact cache prevention at the raw boundary", async () => {
  const captured = captureRouteHandler();
  await mockArkretApi(captured.page as never);
  const request = { method: "POST", url: "https://local.host/_arkret/self/invite-locators", postData: { ttl_seconds: 900, one_time_use: false } };
  const response = await driveOnce(captured.handler(), request);
  expect(response?.headers?.["cache-control"]).toBe("private, no-store");
  const operation = mockOperations().find(op => op.operation_id === "ak.self.invite_locator.command.issue.v1")!;
  for (const headers of [{}, { "cache-control": "public" }]) {
    expect(() => validateMockTransportResponse(operation, { status: 200, contentType: "application/json", json: response?.body, headers })).toThrow("Cache-Control");
  }
});

test("provided HTTP headers cannot bypass length and unsupported-schema checks", () => {
  const operation = mockOperations().find(op => op.operation_id === "ak.self.blob.upload.create.v1")!;
  expect(() => validateMockTransportResponse(operation, { status: 200, contentType: "application/json", headers: { "x-arkret-request-id": "x".repeat(129) } })).toThrow("maxLength");
  const future = { ...operation, responses: { "200": { schema_ref: null, headers: { "future": { required: true, schema: { allOf: [{ const: "x" }] } } } } } };
  expect(() => validateMockTransportResponse(future, { status: 200, headers: { future: "x" } })).toThrow("unsupported header constraint");
});

test("later Page route overrides remain behind the same response gate", async () => {
  const captured = captureRouteHandler();
  await mockArkretApi(captured.page as never);
  await (captured.page as any).route("**/_arkret/self/circles", (route: any) => route.fulfill({ status: 200, contentType: "application/json", body: '{"old_row":[]}' }));
  let emitted = 0;
  await expect(driveOnce(captured.handler(), { ...circles, onFulfill: () => { emitted += 1; } })).rejects.toThrow();
  expect(emitted).toBe(0);
  await (captured.page as any).route("**/_arkret/self/circles", (route: any) => route.fulfill({ json: { realm_id: DEMO_REALM, circles: [] } }));
  expect((await driveOnce(captured.handler(), circles))?.status).toBe(200);
});

test("BrowserContext overrides also fail before unvalidated response emission", async () => {
  const captured = captureRouteHandler();
  await mockArkretApi(captured.page as never);
  await (captured.page as any).context().route("**/_arkret/self/circles", (route: any) => route.fulfill({ json: { old_rows: [] } }));
  let emitted = 0;
  await expect(driveOnce(captured.handler(), { ...circles, onFulfill: () => { emitted += 1; } })).rejects.toThrow();
  expect(emitted).toBe(0);
});

test("Problem producer extensions and reason ownership cannot hide behind RFC tolerance", async () => {
  const request = { method: "GET", url: "https://local.host/_arkret/self/agents" };
  const missing = buildMockProblem("not_found", "unavailable");
  for (const extra of [{ errcode: "not_found" }, { old_result: {} }, { reason_code: "sidecar_create_denied" }]) {
    await expect(emit(request, { status: 404, contentType: "application/problem+json", json: { ...missing, ...extra } })).rejects.toThrow();
  }
});


test("declared endpoint Problem schemas cannot be replaced by generic registry validation", async () => {
  const peerSubmit = { method: "POST", url: "https://local.host/_arkret/peer/events" };
  await expect(emit(peerSubmit, { status: 409, contentType: "application/problem+json",
    json: buildMockProblem("dependency_missing", "exact dependencies unavailable") })).rejects.toThrow();
});
