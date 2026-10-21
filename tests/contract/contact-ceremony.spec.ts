import { expect, test } from "@playwright/test";
import {
  CURRENT_ACCOUNT_ID, CURRENT_PRINCIPAL_DID, PRINCIPAL_CONTROL_REALM,
  inksonWire, mockArkretApi,
} from "../e2e/mockArkretApi";
import { captureRouteHandler, driveOnce } from "./mockShapeDriver";

const seed = Buffer.alloc(32, 1).toString("base64url");
const device = "ak:device:01964137-0000-7000-8000-0000000000a1";
const peerSeed = Buffer.alloc(32, 4).toString("base64url");
const peer = inksonWire<Record<string, any>>("mock-realm-fixture", {
  salt: 10, title: "incoming Contact source", seed_b64url: peerSeed,
});
const build = () => inksonWire<Record<string, any>>("contact-ceremony-fixture", {
  requester: { account_id: peer.identity.account_id, realm_id: peer.identity.principal_control_realm_id,
    verification_method: `${peer.identity.did}#${device}`, seed_b64url: peerSeed },
  responder: { account_id: CURRENT_ACCOUNT_ID, realm_id: PRINCIPAL_CONTROL_REALM,
    verification_method: `${CURRENT_PRINCIPAL_DID}#${device}`, seed_b64url: seed },
});

test("bounded Contact current and original scope grants verify with real SDK consumers", () => {
  expect(inksonWire("contact-ceremony-verify", build())).toEqual({
    verified: true, response: true, reject: true, scope_update: true, tombstone: true,
  });
});

for (const target of ["receipt", "producer", "source", "round", "predecessor", "current", "history", "response_lineage"] as const) {
  test(`bilateral Contact rejects tampered ${target}`, () => {
    const m = build();
    const f = m.ceremony;
    if (target === "receipt") f.response.response_receipt.request_receipt.core.source_checkpoint = `sha256:${"a".repeat(64)}`;
    if (target === "producer") f.response.signed_event.producer_proof.jws = "eyJhbGciOiJFZERTQSJ9..c2ln";
    if (target === "source") f.scope_update.lineage.signature.jws = "eyJhbGciOiJFZERTQSJ9..c2ln";
    if (target === "round") f.round.contact_round.sorted_pair_member_ids.reverse();
    if (target === "predecessor") f.tombstone.signed_event.payload.predecessor_event_ref = f.request.signed_event.event_id;
    if (target === "current") f.round.current_proofs[1] = f.round.current_proofs[0];
    if (target === "history") m.history.has_more = true;
    if (target === "response_lineage") f.response_lineage.signature.jws = "eyJhbGciOiJFZERTQSJ9..c2ln";
    expect(() => inksonWire("contact-ceremony-verify", m)).toThrow();
  });
}

async function install() {
  const material = build();
  const captured = captureRouteHandler();
  await mockArkretApi(captured.page as never, { contactCeremony: material, currentDeviceSigningSeedB64url: seed });
  const handler = captured.handler();
  const invoke = (kind: string, body: unknown) => driveOnce(handler, {
    url: `https://local.host/_arkret/self/contacts/${kind === "response" ? "respond" : kind.replace("_", "-")}`,
    method: "POST", postData: body,
  });
  const prepare = (kind: string, ordinal: number) => {
    const f = material.ceremony;
    return { phase: "prepare", operation_id: `ak:operation:01964137-0000-7000-8000-0000000000${ordinal}`,
      idempotency_key: `ceremony-${ordinal}`, peer: material.requester,
      ...(kind === "response" || kind === "reject" ? { request_event_ref: f.request.signed_event.event_id, action: kind === "response" ? "accept" : "reject" }
        : { contact_round_id: f.round.contact_round_id, version: kind === "scope_update" ? 2 : 3,
          predecessor_event_ref: kind === "scope_update" ? f.response.signed_event.event_id : f.scope_update.signed_event.event_id }),
      ...(kind === "response" ? { granted_to_peer_scopes: ["invite", "direct_message"] } : {}),
      ...(kind === "scope_update" ? { granted_to_peer_scopes: ["direct_message"] } : {}),
      ...(kind === "tombstone" ? { block_peer: false } : {}),
    };
  };
  const finish = async (kind: string, ordinal: number) => {
    const body = prepare(kind, ordinal);
    const prepared = (await invoke(kind, body))?.body as Record<string, any>;
    expect(prepared.status).toBe("prepared");
    expect((await invoke(kind, body))?.body).toEqual(prepared);
    const signed_event = inksonWire("contact-request-sign", { prepared, seed_b64url: seed,
      holder_did: CURRENT_PRINCIPAL_DID, device_id: device });
    const commit = { phase: "commit", operation_id: body.operation_id, idempotency_key: body.idempotency_key,
      reservation_handle: prepared.reservation_handle, signed_event };
    const accepted = (await invoke(kind, commit))?.body as Record<string, any>;
    expect(accepted).toMatchObject({ status: "accepted", result_kind: kind });
    expect((await invoke(kind, commit))?.body).toEqual(accepted);
    expect((await invoke(kind, { ...commit, idempotency_key: "changed" }))?.body).toMatchObject({ status: "failed", reason: "contact_idempotency_conflict" });
    return accepted;
  };
  const rows = async () => ((await driveOnce(handler, { url: "https://local.host/_arkret/self/contacts", method: "GET" }))?.body as any)
    .contacts.filter((row: any) => row.peer.account_id?.principal_id === material.requester.account_id.principal_id);
  return { material, prepare, invoke, finish, rows };
}

test("mock accepts response, scope narrowing and terminal with exact replay and bilateral material", async () => {
  const f = await install();
  expect(await f.rows()).toMatchObject([{ state: "pending_incoming" }]);
  const response = await f.finish("response", 11);
  expect(response.normal_response_acceptance_receipt.request_receipt).toEqual(f.material.ceremony.request.request_receipt);
  expect(await f.rows()).toMatchObject([{ state: "accepted", bidirectional_scopes: ["invite", "direct_message"] }]);
  await f.finish("scope_update", 12);
  expect(await f.rows()).toMatchObject([{ state: "accepted", bidirectional_scopes: ["direct_message"] }]);
  await f.finish("tombstone", 13);
  expect(await f.rows()).toMatchObject([{ state: "tombstoned", bidirectional_scopes: [] }]);
  expect((await f.invoke("scope_update", f.prepare("scope_update", 14)))?.body).toMatchObject({ status: "failed", reason: "contact_terminal" });
});

test("mock rejection binds the original incoming receipt without granting an accepted round", async () => {
  const f = await install();
  const reject = await f.finish("reject", 21);
  expect(reject.reject_acceptance_receipt.request_receipt).toEqual(f.material.ceremony.request.request_receipt);
  expect(await f.rows()).toMatchObject([{ state: "rejected", bidirectional_scopes: [] }]);
  expect((await f.invoke("response", f.prepare("response", 22)))?.body).toMatchObject({ status: "failed", reason: "contact_lineage_conflict" });
});
