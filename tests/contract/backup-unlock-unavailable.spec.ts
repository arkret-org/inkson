import { expect, test } from "@playwright/test";
import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { PRESEEDED_BACKUP_UNLOCK_FIXTURE, mockArkretApi } from "../e2e/mockArkretApi";
import { captureRouteHandler, driveOnce } from "./mockShapeDriver";
import { gateLogoutRequest } from "./gateLogoutProbe";
import { UNIMPLEMENTED_OPERATIONS } from "./mockOperationCoverage";

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
