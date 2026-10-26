import { expect, test } from "@playwright/test";
import { Buffer } from "node:buffer";
import { GATE_LOGOUT_FIXTURE, mockArkretApi, validateMockTransportResponse } from "../e2e/mockArkretApi";
import { captureRouteHandler, driveOnce, mockOperations } from "./mockShapeDriver";
import { gateLogoutRequest } from "./gateLogoutProbe";

type Request = Parameters<typeof driveOnce>[1];
let handler: Parameters<typeof driveOnce>[0];
test.beforeAll(async () => {
  const captured = captureRouteHandler();
  await mockArkretApi(captured.page as never);
  handler = captured.handler();
});

test("canonical account logout accepts only the registered DPoP holder and closed DTO", async () => {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    let emitted = 0;
    const response = await driveOnce(handler, { ...gateLogoutRequest(), onFulfill: () => { emitted += 1; } });
    expect(emitted).toBe(1);
    expect(response).toEqual({ status: 200, contentType: "application/json", body: { revoked: true } });
  }
});

const requestCases: Array<[string, (request: Request) => Request]> = [
  ["wrong authority", request => ({ ...request, url: request.url.replace("auth.local.host", "local.host") })],
  ["insecure authority", request => ({ ...request, url: request.url.replace("https:", "http:") })],
  ["query on the canonical authority URL", request => ({ ...request, url: request.url + "?alternate=true" })],
  ["wrong method", request => ({ ...request, method: "GET" })],
  ["wrong operation", request => ({ ...request, headers: { ...request.headers, "arkret-operation": "ak.gate.account.command.register.v1" } })],
  ["wrong grant", request => ({ ...request, headers: { ...request.headers, authorization: "DPoP sx:foreign-token" } })],
  ["bearer instead of DPoP", request => ({ ...request, headers: { ...request.headers, authorization: `Bearer ${GATE_LOGOUT_FIXTURE.grant}` } })],
  ["wrong media type", request => ({ ...request, headers: { ...request.headers, "content-type": "text/plain" } })],
  ["unknown body field", request => ({ ...request, postData: { obsolete: true } })],
  ["array body", request => ({ ...request, postData: [] })],
  ["null body", request => ({ ...request, postData: null })],
  ["missing body", request => { const { postData: _, ...missing } = request; return missing; }],
  ["missing proof", request => ({ ...request, headers: { ...request.headers, dpop: "" } })],
  ["malformed proof", request => ({ ...request, headers: { ...request.headers, dpop: "not.a.jwt" } })],
  ["changed signature", request => {
    const parts = request.headers!.dpop.split(".");
    const bytes = Buffer.from(parts[2], "base64url"); bytes[0] ^= 1; parts[2] = bytes.toString("base64url");
    return { ...request, headers: { ...request.headers, dpop: parts.join(".") } };
  }],
  ["padded proof segment", request => ({ ...request, headers: { ...request.headers, dpop: request.headers!.dpop + "=" } })],
];

for (const [name, change] of requestCases) test(`account logout rejects ${name} before emitting a response`, async () => {
  let emitted = 0;
  await expect(driveOnce(handler, { ...change(gateLogoutRequest()), onFulfill: () => { emitted += 1; } })).rejects.toThrow();
  expect(emitted).toBe(0);
});

const proofCases: Array<[string, Parameters<typeof gateLogoutRequest>[0]]> = [
  ["another correctly signing device", { seed: Buffer.alloc(32, 1) }],
  ["wrong JOSE type", { header: { typ: "JWT" } }],
  ["wrong JOSE algorithm", { header: { alg: "EdDSA" } }],
  ["unregistered JOSE field", { header: { kid: "foreign" } }],
  ["private JWK material", { header: { jwk: { kty: "OKP", crv: "Ed25519", x: GATE_LOGOUT_FIXTURE.publicKey, d: "private" } } }],
  ["proof method mismatch", { claims: { htm: "GET" } }],
  ["proof target mismatch", { claims: { htu: "https://local.host/_arkret/gate/account/logout" } }],
  ["proof token mismatch", { claims: { ath: "foreign" } }],
  ["expired proof", { claims: { iat: Math.floor(Date.now() / 1000) - 300 } }],
  ["future proof", { claims: { iat: Math.floor(Date.now() / 1000) + 300 } }],
  ["noninteger issuance", { claims: { iat: 1.5 } }],
  ["string issuance", { claims: { iat: "now" } }],
  ["blank proof identifier", { claims: { jti: "  " } }],
  ["nonstring proof identifier", { claims: { jti: 1 } }],
  ["missing token hash", { claims: { ath: undefined } }],
];

for (const [name, options] of proofCases) test(`account logout rejects ${name} even with a real signature`, async () => {
  let emitted = 0;
  await expect(driveOnce(handler, { ...gateLogoutRequest(options), onFulfill: () => { emitted += 1; } })).rejects.toThrow();
  expect(emitted).toBe(0);
});

test("account logout response gate rejects legacy fields and non-Boolean outcomes", () => {
  const operation = mockOperations().find(row => row.operation_id === GATE_LOGOUT_FIXTURE.operation)!;
  for (const revoked of [true, false]) expect(() => validateMockTransportResponse(operation, { status: 200, contentType: "application/json", json: { revoked } })).not.toThrow();
  for (const body of [{}, { revoked: "true" }, { revoked: 1 }, { revoked: null }, { revoked_count: 1, revoked_session_grant_ids: [] }, { revoked: true, extra: true }]) {
    expect(() => validateMockTransportResponse(operation, { status: 200, contentType: "application/json", json: body })).toThrow();
  }
});
