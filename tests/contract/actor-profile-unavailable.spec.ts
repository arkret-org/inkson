import { expect, test } from "@playwright/test";
import { Buffer } from "node:buffer";
import {
  ACTOR_PROFILE_UNAVAILABLE_FIXTURE, BOB_ACCOUNT_ID, CURRENT_ACCOUNT_ACTOR_ID,
  DEMO_REALM, INVITED_REALM, PRINCIPAL_CONTROL_REALM, mockArkretApi,
} from "../e2e/mockArkretApi";
import { captureRouteHandler, driveOnce } from "./mockShapeDriver";
import { gateLogoutRequest } from "./gateLogoutProbe";

type Request = Parameters<typeof driveOnce>[1];
let handler: Parameters<typeof driveOnce>[0];
const actor = { kind: "account", account_id: BOB_ACCOUNT_ID };
const request = (body: unknown = { realm_id: DEMO_REALM, actor_ids: [actor] }) =>
  gateLogoutRequest({ target: ACTOR_PROFILE_UNAVAILABLE_FIXTURE, body });

test.beforeAll(async () => {
  const captured = captureRouteHandler();
  await mockArkretApi(captured.page as never, { invitePreview: "disclosed" });
  handler = captured.handler();
});

test("live profile lookup accounts for every actor without inventing accepted profile evidence", async () => {
  const actors = [actor, CURRENT_ACCOUNT_ACTOR_ID];
  let emitted = 0;
  const response = await driveOnce(handler, {
    ...request({ realm_id: DEMO_REALM, actor_ids: actors }), onFulfill: () => { emitted += 1; },
  });
  expect(emitted).toBe(1);
  expect(response).toEqual({ status: 200, contentType: "application/json", body: {
    profiles: [], failures: actors.map(actor_id => ({ actor_id, reason: "profile_unavailable" })),
  } });
});

for (const [name, realm] of [
  ["unknown shared Realm", "ak:realm:AUEAoXMJeJWBETvkqm7gk4imduk7g-l8bim19OPFQDaO"],
  ["not-yet-joined invite Realm", INVITED_REALM],
  ["Principal Control Realm", PRINCIPAL_CONTROL_REALM],
] as const) test(`live profile lookup returns non-enumerating not_found for ${name}`, async () => {
  const response = await driveOnce(handler, request({ realm_id: realm, actor_ids: [actor] }));
  expect(response?.status).toBe(404);
  expect(response?.contentType).toBe("application/problem+json");
  expect(String((response?.body as Record<string, unknown>).type)).toContain("not_found");
  expect(response?.body).not.toHaveProperty("profiles");
});

const invalid: Array<[string, () => Request]> = [
  ["wrong method", () => ({ ...request(), method: "GET" })],
  ["wrong authority", () => { const value = request(); return { ...value, url: value.url.replace("local.host", "foreign.example") }; }],
  ["query on canonical URL", () => { const value = request(); return { ...value, url: value.url + "?actor=other" }; }],
  ["wrong selector", () => { const value = request(); return { ...value, headers: { ...value.headers, "arkret-operation": "ak.self.identity.read.resolution_audit.v1" } }; }],
  ["wrong grant", () => { const value = request(); return { ...value, headers: { ...value.headers, authorization: "DPoP sx:other" } }; }],
  ["wrong media type", () => { const value = request(); return { ...value, headers: { ...value.headers, "content-type": "text/plain" } }; }],
  ["missing proof", () => { const value = request(); return { ...value, headers: { ...value.headers, dpop: "" } }; }],
  ["other signing key", () => gateLogoutRequest({ target: ACTOR_PROFILE_UNAVAILABLE_FIXTURE, body: request().postData, seed: Buffer.alloc(32, 1) })],
  ["proof method mismatch", () => gateLogoutRequest({ target: ACTOR_PROFILE_UNAVAILABLE_FIXTURE, body: request().postData, claims: { htm: "GET" } })],
  ["proof URL mismatch", () => gateLogoutRequest({ target: ACTOR_PROFILE_UNAVAILABLE_FIXTURE, body: request().postData, claims: { htu: "https://local.host/other" } })],
  ["proof token mismatch", () => gateLogoutRequest({ target: ACTOR_PROFILE_UNAVAILABLE_FIXTURE, body: request().postData, claims: { ath: "other" } })],
  ["stale proof", () => gateLogoutRequest({ target: ACTOR_PROFILE_UNAVAILABLE_FIXTURE, body: request().postData, claims: { iat: 0 } })],
  ["empty actor batch", () => request({ realm_id: DEMO_REALM, actor_ids: [] })],
  ["missing body", () => ({ ...request(), postData: undefined })],
  ["repeated actor", () => request({ realm_id: DEMO_REALM, actor_ids: [actor, actor] })],
  ["too many actors", () => request({ realm_id: DEMO_REALM, actor_ids: Array.from({ length: 65 }, () => actor) })],
  ["unknown body field", () => request({ realm_id: DEMO_REALM, actor_ids: [actor], obsolete: true })],
  ["missing Realm", () => request({ actor_ids: [actor] })],
  ["invalid ActorId", () => request({ realm_id: DEMO_REALM, actor_ids: ["bob"] })],
];
for (const [name, build] of invalid) test(`live profile lookup rejects ${name} before a response`, async () => {
  let emitted = 0;
  await expect(driveOnce(handler, { ...build(), onFulfill: () => { emitted += 1; } })).rejects.toThrow();
  expect(emitted).toBe(0);
});
