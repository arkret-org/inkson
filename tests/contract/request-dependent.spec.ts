import { expect, test } from "@playwright/test";
import { CURRENT_ACCOUNT_ACTOR_ID, DEMO_REALM, mockArkretApi, validateMockSchema } from "../e2e/mockArkretApi";
import { captureRouteHandler, driveOnce } from "./mockShapeDriver";

async function fixture() {
  const { page, handler } = captureRouteHandler();
  await mockArkretApi(page as never);
  return handler();
}

test("invite locator revoke preserves the actual locator in the closed current outcome", async () => {
  const handler = await fixture();
  for (const locatorId of [
    "ak:invite_locator:01964137-0000-7000-8000-0000000000b1",
    "ak:invite_locator:01964137-0000-7000-8000-0000000000c1",
  ]) {
    const body = { locator_id: locatorId };
    validateMockSchema("schemas/principal-locator.schema.json#/$defs/invite_locator_revoke_request_body", body);
    const result = await driveOnce(handler, {
      method: "POST", url: "https://local.host/_arkret/self/invite-locators/revoke", postData: body,
    });
    expect(result?.status).toBe(200);
    expect(result?.body).toEqual({ locator_id: locatorId, revoked_at: "2026-10-20T00:00:00.000Z" });
    expect(() => validateMockSchema("schemas/principal-locator.schema.json#/$defs/invite_locator_revoke_response_body", {
      ...(result?.body as Record<string, unknown>), status: "revoked",
    })).toThrow();
  }
});

test("effective grants accept the actual subject_actor_id query and expose closed empty current rows", async () => {
  const handler = await fixture();
  const query = new URLSearchParams({ realm_id: DEMO_REALM, subject_actor_id: JSON.stringify(CURRENT_ACCOUNT_ACTOR_ID) });
  const result = await driveOnce(handler, { method: "GET", url: `https://local.host/_arkret/self/authz/effective-grants?${query}` });
  expect(result?.status).toBe(200);
  expect(result?.body).toMatchObject({ grants: [], state_digest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/) });
});

test("ICE response preserves the typed Account actor from the actual request", async () => {
  const handler = await fixture();
  const body = { realm_id: DEMO_REALM, call_id: "ak:call:AbhvODyrIRCskAIoS9IXLjMfD-Zsr8lwDpiCU_zLR4it", actor_id: CURRENT_ACCOUNT_ACTOR_ID,
    device_id: "ak:device:01964137-0000-7000-8000-0000000000a1", mode: "p2p" };
  validateMockSchema("schemas/media-operations.schema.json#/$defs/media_ice_configuration_request_body", body);
  const result = await driveOnce(handler, { method: "POST", url: "https://local.host/_arkret/self/rtc/ice-config", postData: body });
  expect(result?.status).toBe(200);
  expect(result?.body).toMatchObject({ realm_id: body.realm_id, call_id: body.call_id, actor_id: body.actor_id, device_id: body.device_id });
  // The shared builder verifies the real signature. This is not TURN admission.
});

test("invite policy saves and reads the same closed holder-private policy", async () => {
  const handler = await fixture();
  const url = "https://local.host/_arkret/self/invite-receive-policy";
  const before = await driveOnce(handler, { method: "GET", url });
  const policy = { ...(before?.body as Record<string, unknown>), explicit_address_behavior: "notify", denied_actor_ids: [] };
  const written = await driveOnce(handler, { method: "PUT", url, postData: policy });
  expect(written?.status).toBe(200);
  expect(written?.body).toEqual(policy);
  const read = await driveOnce(handler, { method: "GET", url });
  expect(read?.body).toEqual(policy);
  await expect(driveOnce(handler, { method: "PUT", url, postData: { ...policy, retired_policy_member: true } })).rejects.toThrow();
  expect((await driveOnce(handler, { method: "GET", url }))?.body).toEqual(policy);
});
