import { expect, test } from "@playwright/test";
import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { PRESEEDED_BACKUP_UNLOCK_FIXTURE, mockArkretApi, validateMockResponseForOperation } from "../e2e/mockArkretApi";
import { captureRouteHandler, driveOnce, mockOperations } from "./mockShapeDriver";
import { gateLogoutRequest } from "./gateLogoutProbe";
import { IMPLEMENTED_REMAINING_OPERATIONS } from "./remainingOperationProbes";
import { NATIVE_READ_OPERATIONS } from "./nativeReadEvidence";
import { UNIMPLEMENTED_OPERATIONS, UNIMPLEMENTED_PROBLEM_OPERATIONS } from "./mockOperationCoverage";

type Request = Parameters<typeof driveOnce>[1];
let seeded: Parameters<typeof driveOnce>[0];
let ordinary: Parameters<typeof driveOnce>[0];
const request = () => gateLogoutRequest({ target: PRESEEDED_BACKUP_UNLOCK_FIXTURE, body: { request_id: Buffer.alloc(16, 7).toString("base64url") } });
test.beforeAll(async () => {
  const enabled = captureRouteHandler();
  await mockArkretApi(enabled.page as never, { preseedRecoveryMaterial: true });
  seeded = enabled.handler();
  const disabled = captureRouteHandler();
  await mockArkretApi(disabled.page as never);
  ordinary = disabled.handler();
});

test("explicit preseeded recovery backup terminates its canonical signed challenge request with a closed unavailable Problem", async () => {
  let emitted = 0;
  const response = await driveOnce(seeded, { ...request(), onFulfill: () => { emitted += 1; } });
  expect(emitted).toBe(1);
  expect(response?.status).toBe(503);
  expect(response?.contentType).toBe("application/problem+json");
  expect(response?.body).toEqual({
    type: "https://arkret.org/problems/temporarily_unavailable", title: "Temporarily unavailable", status: 503,
    detail: "The explicitly preseeded backup unlock service is temporarily unavailable in this fixture.",
  });
  expect(response?.body).not.toHaveProperty("challenge");
  expect(response?.body).not.toHaveProperty("challenge_id");
});

test("ordinary scenarios retain their unimplemented native unlock authority boundary", async () => {
  expect(UNIMPLEMENTED_OPERATIONS.has(PRESEEDED_BACKUP_UNLOCK_FIXTURE.operation)).toBe(true);
  let emitted = 0;
  await expect(driveOnce(ordinary, { ...request(), onFulfill: () => { emitted += 1; } })).rejects.toThrow(`mock operation is not implemented: ${PRESEEDED_BACKUP_UNLOCK_FIXTURE.operation}`);
  expect(emitted).toBe(0);
});

const invalid: Array<[string, () => Request]> = [
  ["method", () => ({ ...request(), method: "GET" })],
  ["origin", () => { const value = request(); return { ...value, url: value.url.replace("local.host", "foreign.example") }; }],
  ["selector", () => { const value = request(); return { ...value, headers: { ...value.headers, "arkret-operation": "ak.self.keys.backups.read.list.v1" } }; }],
  ["grant", () => { const value = request(); return { ...value, headers: { ...value.headers, authorization: "DPoP sx:foreign" } }; }],
  ["missing body", () => ({ ...request(), postData: undefined })],
  ["missing request identifier", () => ({ ...request(), postData: {} })],
  ["invalid request identifier", () => ({ ...request(), postData: { request_id: "not+base64" } })],
  ["unknown field", () => ({ ...request(), postData: { ...request().postData as object, obsolete: true } })],
  ["empty proof", () => { const value = request(); return { ...value, headers: { ...value.headers, dpop: "" } }; }],
  ["another signing device", () => gateLogoutRequest({ target: PRESEEDED_BACKUP_UNLOCK_FIXTURE, body: request().postData, seed: Buffer.alloc(32, 1) })],
  ["wrong proof URL", () => gateLogoutRequest({ target: PRESEEDED_BACKUP_UNLOCK_FIXTURE, body: request().postData, claims: { htu: "https://local.host/foreign" } })],
  ["wrong proof method", () => gateLogoutRequest({ target: PRESEEDED_BACKUP_UNLOCK_FIXTURE, body: request().postData, claims: { htm: "GET" } })],
  ["wrong proof token", () => gateLogoutRequest({ target: PRESEEDED_BACKUP_UNLOCK_FIXTURE, body: request().postData, claims: { ath: "foreign" } })],
  ["expired proof", () => gateLogoutRequest({ target: PRESEEDED_BACKUP_UNLOCK_FIXTURE, body: request().postData, claims: { iat: 0 } })],
];
for (const [name, build] of invalid) test(`preseeded unlock rejects ${name} without emitting a response`, async () => {
  let emitted = 0;
  await expect(driveOnce(seeded, { ...build(), onFulfill: () => { emitted += 1; } })).rejects.toThrow();
  expect(emitted).toBe(0);
});

test("review credits only the explicit unavailable transport scenario, never native unlock authority", () => {
  const review = JSON.parse(readFileSync(new URL("./mock-operation-review.json", import.meta.url), "utf8"));
  const operation = review.operations.find((row: any) => row.operation_id === PRESEEDED_BACKUP_UNLOCK_FIXTURE.operation);
  expect(operation.mock_implementation).toBe("missing");
  expect(operation.native_authority_contract).toBe("not_run");
  expect(operation.conditional_mock_transport_fixture).toEqual({
    scenario: "preseedRecoveryMaterial", outcome: "temporarily_unavailable", http_status: 503,
    mock_test: "tests/contract/backup-unlock-unavailable.spec.ts", native_authority_contract: "not_run",
  });
});

const OPERATION = "ak.self.keys.backups.command.issue_unlock_challenge.v1";
const BACKUPS = "https://local.host/_arkret/self/keys/backups";

test("unimplemented native backup challenges refuse without minting authority or changing summaries", async () => {
  const captured = captureRouteHandler();
  await mockArkretApi(captured.page as any, { preseedRecoveryMaterial: true });
  const handler = captured.handler();
  const before = await driveOnce(handler, { method: "GET", url: BACKUPS });
  const backupId = (before!.body as any).backups[0].backup_id;
  const response = await driveOnce(handler, {
    method: "POST", url: `${BACKUPS}/${backupId}/unlock-challenge`,
    postData: { request_id: Buffer.alloc(16, 1).toString("base64url") },
  });
  expect(response!.status).toBe(501);
  expect(response!.contentType).toBe("application/problem+json");
  expect(response!.body).toMatchObject({ type: "https://arkret.org/problems/not_implemented", title: "Not implemented", status: 501 });
  expect(Object.keys(response!.body as object).sort()).toEqual(["detail", "status", "title", "type"]);
  for (const field of ["nonce", "challenge", "challenge_id", "proof", "signature"]) {
    expect(response!.body).not.toHaveProperty(field);
  }
  const operation = mockOperations().find(row => row.operation_id === OPERATION)!;
  expect(() => validateMockResponseForOperation(operation, 200, response!.body, "application/json")).toThrow();
  expect(await driveOnce(handler, { method: "GET", url: BACKUPS })).toEqual(before);
});

test("a refusal does not grant native backup coverage or suppress other missing operations", async () => {
  const review = JSON.parse(readFileSync(new URL("./mock-operation-review.json", import.meta.url), "utf8"));
  expect(review.operations.find((row: any) => row.operation_id === OPERATION)).toMatchObject({ verification_need: "native_authority", mock_test: null });
  expect(IMPLEMENTED_REMAINING_OPERATIONS.has(OPERATION)).toBe(false);
  expect(NATIVE_READ_OPERATIONS.has(OPERATION)).toBe(false);
  expect(UNIMPLEMENTED_OPERATIONS.has(OPERATION)).toBe(true);
  expect(UNIMPLEMENTED_PROBLEM_OPERATIONS.has(OPERATION)).toBe(true);
  const captured = captureRouteHandler();
  await mockArkretApi(captured.page as any);
  await expect(driveOnce(captured.handler(), {
    method: "POST", url: `${BACKUPS}/ak:backup:01964137-0000-7000-8000-0000000000b1/unlock`, postData: {},
  })).rejects.toThrow("mock operation is not implemented");
});
