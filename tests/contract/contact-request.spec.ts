import { expect, test } from "@playwright/test";
import { CURRENT_PRINCIPAL_DID, inksonWire, mockArkretApi, validateMockSchema } from "../e2e/mockArkretApi";
import { captureRouteHandler, driveOnce } from "./mockShapeDriver";

const URL = "https://local.host/_arkret/self/contacts/request";
const SEED = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const DEVICE = "ak:device:01964137-0000-7000-8000-0000000000a1";
// A separate native WebVH/PCR anchor for the explicitly addressed peer.
// This fixture does not claim remote Station admission or a bilateral round.
const peerAnchor = inksonWire<Record<string, any>>("mock-realm-fixture", {
  salt: 10, title: "Contact peer anchor", seed_b64url: Buffer.alloc(32, 4).toString("base64url"),
});
const prepare = {
  phase: "prepare", operation_id: "ak:operation:01964137-0000-7000-8000-0000000000f2",
  idempotency_key: "contact-request-contract",
  peer: { kind: "human", account_id: peerAnchor.identity.account_id },
  granted_to_peer_scopes: ["invite", "direct_message", "voice_call", "video_call", "presence"],
  introduction_evidence: { kind: "explicit_address" },
  message: "  Hello from the exact reserved draft  ",
};

test("Contact operation id preserves the current prefixed UUIDv7 contract", () => {
  const schema = "schemas/principal-operations.schema.json#/$defs/operation_id";
  expect(() => validateMockSchema(schema, prepare.operation_id)).not.toThrow();
  for (const invalid of [
    prepare.operation_id.replace("ak:operation:", ""),
    prepare.operation_id.replace("ak:operation:", "ak:operation:contact.request."),
    "ak:operation:01964137-0000-4000-8000-0000000000f2",
  ]) expect(() => validateMockSchema(schema, invalid)).toThrow();
});

async function fixture(options: Parameters<typeof mockArkretApi>[1] = {}) {
  const { page, handler } = captureRouteHandler();
  await mockArkretApi(page as never, { currentDeviceSigningSeedB64url: SEED, ...options });
  const response = await driveOnce(handler(), { url: URL, method: "POST", postData: prepare });
  expect(response?.status).toBe(200);
  const prepared = response?.body as Record<string, any>;
  expect(prepared.status).toBe("prepared");
  // Decode and sign with the same SDK draft and Inkson device signer as the client.
  const signed = inksonWire<Record<string, any>>("contact-request-sign", {
    prepared, seed_b64url: SEED, holder_did: CURRENT_PRINCIPAL_DID, device_id: DEVICE,
  });
  const commit = {
    phase: "commit", operation_id: prepare.operation_id, idempotency_key: prepare.idempotency_key,
    reservation_handle: prepared.reservation_handle, signed_event: signed,
  };
  return { handler: handler(), prepared, signed, commit };
}

test("Contact request consumes a real SDK draft and signed receipt with exact replay", async () => {
  const { handler, prepared, signed, commit } = await fixture();
  expect(signed.payload.peer).toEqual(prepare.peer);
  expect(signed.payload.granted_to_peer_scopes).toEqual(prepare.granted_to_peer_scopes);
  expect(signed.payload.message).toBe(prepare.message.trim());
  const repeatedPrepare = await driveOnce(handler, { url: URL, method: "POST", postData: prepare });
  expect(repeatedPrepare?.body).toEqual(prepared);
  const accepted = await driveOnce(handler, { url: URL, method: "POST", postData: commit });
  const outcome = accepted?.body as Record<string, any>;
  expect(outcome.status).toBe("accepted");
  expect(outcome.request_acceptance_receipt.core.request_event_ref).toBe(signed.event_id);
  expect(inksonWire("contact-request-verify", { outcome, event: signed })).toEqual({ verified: true });
  expect((await driveOnce(handler, { url: URL, method: "POST", postData: commit }))?.body).toEqual(outcome);
  const list = (await driveOnce(handler, { url: "https://local.host/_arkret/self/contacts", method: "GET" }))?.body as any;
  const rows = list.contacts.filter((row: any) => row.request_event_ref === signed.event_id);
  expect(rows).toHaveLength(1);
  expect(rows[0]).toMatchObject({ peer: prepare.peer, state: "pending_outgoing" });
  expect(rows[0].request_message).toBeUndefined();
  expect(rows[0].granted_by_peer_scopes).toEqual([]);
  expect(rows[0].bidirectional_scopes).toEqual([]);
  expect((await driveOnce(handler, { url: URL, method: "POST", postData: {
    ...prepare, operation_id: "ak:operation:01964137-0000-7000-8000-0000000000f3", idempotency_key: "another-request",
  } }))?.body).toMatchObject({ status: "failed", reason: "contact_round_conflict" });
  const conflicting = { ...commit, idempotency_key: "different-idempotency" };
  expect((await driveOnce(handler, { url: URL, method: "POST", postData: conflicting }))?.body).toMatchObject({
    status: "failed", reason: "contact_idempotency_conflict",
  });
});

test("Contact mock rejects a changed reserved Event and untrusted device signature", async () => {
  const { handler, commit, prepared } = await fixture();
  const changed = structuredClone(commit);
  changed.signed_event.payload.message = "Replaced after reservation";
  await expect(driveOnce(handler, { url: URL, method: "POST", postData: changed })).rejects.toThrow("reserved Event");
  const wrong = inksonWire("contact-request-sign", {
    prepared, seed_b64url: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
    holder_did: CURRENT_PRINCIPAL_DID, device_id: DEVICE,
  });
  await expect(driveOnce(handler, { url: URL, method: "POST", postData: { ...commit, signed_event: wrong } })).rejects.toThrow("signature is invalid");
  const list = (await driveOnce(handler, { url: "https://local.host/_arkret/self/contacts", method: "GET" }))?.body as any;
  expect(list.contacts.some((row: any) => row.peer.account_id?.principal_id === prepare.peer.account_id.principal_id)).toBe(false);
});

test("Contact receipt rejects modified core, signature and exact request binding", async () => {
  const { handler, signed, commit } = await fixture();
  const outcome = (await driveOnce(handler, { url: URL, method: "POST", postData: commit }))?.body as any;
  for (const mutation of ["core", "signature", "event"] as const) {
    const changed = structuredClone(outcome);
    const event = structuredClone(signed);
    if (mutation === "core") changed.request_acceptance_receipt.core.source_checkpoint = `sha256:${"a".repeat(64)}`;
    if (mutation === "signature") changed.request_acceptance_receipt.signature.jws = "eyJhbGciOiJFZERTQSJ9..c2ln";
    if (mutation === "event") event.event_id = "ak:event:Ad0EZUHcfLJv92Of4w-RJec6fkNlWP11fsQAQ4dqUOHS";
    expect(() => inksonWire("contact-request-verify", { outcome: changed, event })).toThrow();
  }
});

test("Contact terminal failure remains typed, replayable and creates no outgoing row", async () => {
  const { handler, commit } = await fixture({ contactRequestOutcome: "failed" });
  const failed = await driveOnce(handler, { url: URL, method: "POST", postData: commit });
  expect(failed?.body).toMatchObject({ status: "failed", result_kind: "request", reason: "contact_round_conflict" });
  expect((await driveOnce(handler, { url: URL, method: "POST", postData: commit }))?.body).toEqual(failed?.body);
  const list = (await driveOnce(handler, { url: "https://local.host/_arkret/self/contacts", method: "GET" }))?.body as any;
  expect(list.contacts.some((row: any) => row.peer.account_id?.principal_id === prepare.peer.account_id.principal_id)).toBe(false);
});

test("Contact request first acceptance refuses an expired reservation", async () => {
  const { prepared, commit } = await fixture();
  const expired = structuredClone(prepared);
  expired.expires_at = "2000-01-01T00:00:00.000Z";
  const key = inksonWire<{ public_key_b64url: string }>("did-key-from-seed", { seed_b64url: SEED });
  expect(() => inksonWire("contact-request-commit", {
    prepared: expired,
    body: commit,
    producer_verification_method: `${CURRENT_PRINCIPAL_DID}#${DEVICE}`,
    producer_public_key_b64url: key.public_key_b64url,
  })).toThrow("reservation expired");
});
