import { expect, test } from "@playwright/test";
import { CURRENT_ACCOUNT_ACTOR_ID, CURRENT_ACCOUNT_ID, CURRENT_PRINCIPAL_DID, DEMO_REALM,
  mockArkretApi, inksonWire, buildMockProblem, validateMockTransportResponse } from "../e2e/mockArkretApi";
import { captureRouteHandler, driveOnce, mockOperations } from "./mockShapeDriver";
import { MOCK_INSTALLS } from "./mockOperationCoverage";
import { accountDataRequest, additionalOperationProbe, AVATAR, BLOCKLIST_KEY,
  IMPLEMENTED_REMAINING_OPERATIONS, pairingProbeState, readCursorRequest, remainingFixture } from "./remainingOperationProbes";

for (const [index, install] of MOCK_INSTALLS.entries()) {
  for (const id of IMPLEMENTED_REMAINING_OPERATIONS) {
    test(`remaining valid request and response contract: ${id}, install ${index}`, async () => {
      const captured = captureRouteHandler(); await mockArkretApi(captured.page as never, install);
      const operation = mockOperations().find(item => item.operation_id === id)!;
      const request = (await additionalOperationProbe(operation, captured.handler()))!;
      let emitted = 0;
      const response = await driveOnce(captured.handler(), { ...request, onFulfill: () => { emitted += 1; } });
      expect(response?.status).toBe(200); expect(emitted).toBe(1);
      if (operation.method === "HEAD") {
        expect(response?.body).toBeUndefined(); expect(Number(response?.headers?.["content-length"])).toBeGreaterThan(0);
        expect(() => validateMockTransportResponse(operation, { status: 200, headers: response?.headers, body: "forbidden" })).toThrow();
      } else {
        expect(response?.body).toBeTruthy();
        expect(() => validateMockTransportResponse(operation, { status: 200, headers: response?.headers, contentType: "application/json",
          json: { ...(response?.body as any), obsolete_result: {} } })).toThrow();
      }
      if (id === "ak.self.morph.read.list.v1") expect((response?.body as any).morphs).toHaveLength(1);
      if (id === "ak.self.read_cursor.read.list.v1") expect((response?.body as any).markers).toHaveLength(1);
      if (id === "ak.self.account_data.read.list.v1") expect((response?.body as any).account_data_entries.some((entry: any) => entry.account_data_key === BLOCKLIST_KEY)).toBe(true);
      if (id === "ak.self.realm.read.export.v1") expect((response?.body as any).events.length).toBeGreaterThan(1);
      if (id === "ak.self.realm.resource.get.v1") expect((response?.body as any).member_ids).toContainEqual(CURRENT_ACCOUNT_ACTOR_ID);
      if (id === "ak.root.identity.log.read.list.v1") expect((response?.body as any).entries[0]).toEqual(remainingFixture().identity.inception_log_entry);
      if (id === "ak.open.realm_authority.read.bundle.v1") expect((response?.body as any).current_assertion.nonce).toBe((request.postData as any).nonce);
    });
  }
}

test("account data preserves opaque bytes, CAS conflicts, tombstone high water and recreation", async () => {
  const captured = captureRouteHandler(); await mockArkretApi(captured.page as never);
  const address = `https://local.host/_arkret/self/account_data/${BLOCKLIST_KEY}`;
  const send = (method: string, postData?: any) => driveOnce(captured.handler(), { method, url: address, postData });
  const unset = await send("GET");
  expect(unset?.status).toBe(404); expect((unset?.body as any).current_revision).toBe(0);
  expect(unset?.body).not.toHaveProperty("current_entry");
  const firstRequest = accountDataRequest(0);
  const first = await send("PUT", firstRequest);
  const exact = await send("PUT", firstRequest); expect(exact?.body).toEqual(first?.body);
  expect(first?.status).toBe(200); expect((first?.body as any).revision).toBe(1);
  expect((first?.body as any).content).toEqual(firstRequest.set_event.event.payload.encrypted_payload);
  expect((first?.body as any).content).not.toHaveProperty("entries");
  const stale = await send("PUT", accountDataRequest(0));
  expect(stale?.status).toBe(409); expect((stale?.body as any).current_entry).toEqual(first?.body);
  const removed = await send("DELETE", accountDataRequest(1, true));
  expect(removed?.body).toEqual({ account_data_key: BLOCKLIST_KEY, revision: 2 });
  const missing = await send("GET"); expect(missing?.status).toBe(404);
  expect((missing?.body as any).current_revision).toBe(2); expect(missing?.body).not.toHaveProperty("current_entry");
  const oldWrite = await send("PUT", accountDataRequest(1));
  expect(oldWrite?.status).toBe(409); expect((oldWrite?.body as any).current_revision).toBe(2);
  expect(oldWrite?.body).not.toHaveProperty("current_entry");
  const recreated = await send("PUT", accountDataRequest(2));
  expect((recreated?.body as any).revision).toBe(3);
  expect((await send("PUT", firstRequest))?.body).toEqual(first?.body);
  expect((await send("GET"))?.body).toEqual(recreated?.body);
});

test("account-data writes reject legacy fields, changed signatures and Station-only keys without mutation", async () => {
  const captured = captureRouteHandler(); await mockArkretApi(captured.page as never);
  const address = `https://local.host/_arkret/self/account_data/${BLOCKLIST_KEY}`;
  const valid = accountDataRequest(0);
  for (const invalid of [{ ...valid, expected_server_revision: 0 }, (() => {
    const copy = structuredClone(valid); copy.set_event.event.payload.expected_server_revision = 10; return copy;
  })(), (() => { const copy = structuredClone(valid); copy.set_event.event.producer_proof.jws = "corrupt"; return copy; })()]) {
    let emitted = 0;
    await expect(driveOnce(captured.handler(), { method: "PUT", url: address, postData: invalid,
      onFulfill: () => { emitted += 1; } })).rejects.toThrow(); expect(emitted).toBe(0);
  }
  const forbidden = await driveOnce(captured.handler(), { method: "PUT",
    url: "https://local.host/_arkret/self/account_data/ak.account.invite_delivery",
    postData: accountDataRequest(0, false, "ak.account.invite_delivery") });
  expect(forbidden?.status).toBe(403);
  const current = await driveOnce(captured.handler(), { method: "GET", url: address });
  expect((current?.body as any).current_revision).toBe(0);
});

test("read cursor uses committed coordinates before HLC and refuses unknown coordinates", async () => {
  const captured = captureRouteHandler(); await mockArkretApi(captured.page as never);
  const url = "https://local.host/_arkret/self/read-cursors";
  const original = readCursorRequest();
  const first = await driveOnce(captured.handler(), { method: "POST", url, postData: original });
  expect(first?.status).toBe(200);
  const retry = await driveOnce(captured.handler(), { method: "POST", url, postData: readCursorRequest() });
  expect(retry?.body).toEqual(first?.body);
  const later = remainingFixture().committed_events.find((full: any) => JSON.stringify(full.commit.stream_ref) === JSON.stringify(remainingFixture().committed_events[0].commit.stream_ref)
    && BigInt(full.commit.stream_position) > BigInt(remainingFixture().committed_events[0].commit.stream_position));
  expect(later).toBeTruthy();
  const advanced = await driveOnce(captured.handler(), { method: "POST", url,
    postData: readCursorRequest({ event_id: later.event.event_id, hlc: "000000000000-0000-00000000" }) });
  expect((advanced?.body as any).position.event_id).toBe(later.event.event_id);
  const old = await driveOnce(captured.handler(), { method: "POST", url,
    postData: readCursorRequest({ event_id: remainingFixture().committed_events[0].event.event_id, hlc: "ffffffffffff-ffff-ffffffff" }) });
  expect(old?.body).toEqual(advanced?.body);
  const unknown = inksonWire<any>("mock-realm-fixture", { salt: 13, title: "Unheld position" });
  const ambiguous = readCursorRequest({ event_id: unknown.committed_events[0].event.event_id, hlc: "ffffffffffff-ffff-ffffffff" });
  const denied = await driveOnce(captured.handler(), { method: "POST", url, postData: ambiguous });
  expect(denied?.status).toBe(503);
  const listed = await driveOnce(captured.handler(), { method: "GET", url });
  expect((listed?.body as any).markers).toEqual([advanced?.body]);
});

test("Agent participation uses per-scope decimal CAS and round-trips the selection", async () => {
  const captured = captureRouteHandler(); await mockArkretApi(captured.page as never);
  const operation = mockOperations().find(item => item.operation_id === "ak.self.agent.participation.resource.replace.v1")!;
  const request = (await additionalOperationProbe(operation, captured.handler()))!;
  const accepted = await driveOnce(captured.handler(), request); expect(accepted?.status).toBe(200);
  const first = (accepted?.body as any).participation_entries[0];
  expect(first.version).toBe("1"); expect(first.next_replace_input).toEqual({ expected_version: "1" });
  const stale = await driveOnce(captured.handler(), request); expect(stale?.status).toBe(409);
  const queried = await driveOnce(captured.handler(), { method: "GET", url: request.url });
  expect(queried?.body).toEqual(accepted?.body);
  const strandRequest = { ...request, postData: { ...(request.postData as any), expected_version: "0",
    target_scope: { kind: "strand", realm_id: DEMO_REALM, strand_id: remainingFixture().ids.review } } };
  const scoped = await driveOnce(captured.handler(), strandRequest); expect(scoped?.status).toBe(200);
  expect((scoped?.body as any).participation_entries).toHaveLength(2);
  const foreign = inksonWire<any>("mock-realm-fixture", { salt: 11, title: "Unknown scope", board: true });
  const absent = await driveOnce(captured.handler(), { ...strandRequest, postData: { ...(strandRequest.postData as any),
    target_scope: { kind: "strand", realm_id: DEMO_REALM, strand_id: foreign.ids.review } } });
  expect(absent?.status).toBe(404);
  expect((await driveOnce(captured.handler(), { method: "GET", url: request.url }))?.body).toEqual(scoped?.body);
});

test("HEAD validates representation headers and forbids a body for success and failure", async () => {
  const captured = captureRouteHandler(); await mockArkretApi(captured.page as never);
  const address = `https://local.host/_arkret/self/blob/get?blob_ref=${encodeURIComponent(AVATAR)}`;
  const head = await driveOnce(captured.handler(), { method: "HEAD", url: address });
  const get = await driveOnce(captured.handler(), { method: "GET", url: address });
  expect(Number(head?.headers?.["content-length"])).toBe((get?.body as Buffer).length);
  expect(head?.headers?.["content-type"]).toBe(get?.contentType);
  const absent = await driveOnce(captured.handler(), { method: "HEAD", url: `https://local.host/_arkret/self/blob/get?blob_ref=ak:blob:sha256:${"0".repeat(64)}` });
  expect(absent?.status).toBe(404); expect(absent?.body).toBeUndefined();
  const operation = mockOperations().find(item => item.operation_id === "ak.self.blob.resource.head.v1")!;
  expect(() => validateMockTransportResponse(operation, { status: 404, json: { old: true } })).toThrow("forbids a body");
  expect(() => validateMockTransportResponse(operation, { status: 499 })).toThrow("error status");
});

test("public bundle binds the exact nonce and never discloses Human PCR authority", async () => {
  const captured = captureRouteHandler(); await mockArkretApi(captured.page as never);
  const url = "https://local.host/_arkret/open/realm-authority/bundle";
  for (const byte of [2, 3]) {
    const nonce = Buffer.alloc(32, byte).toString("base64url");
    const response = await driveOnce(captured.handler(), { method: "POST", url, postData: { realm_id: DEMO_REALM, nonce } });
    expect(response?.status).toBe(200); expect((response?.body as any).current_assertion.nonce).toBe(nonce);
    expect((response?.body as any).genesis_event).toEqual(remainingFixture().committed_events[0].event);
  }
  const privateRead = await driveOnce(captured.handler(), { method: "POST", url,
    postData: { realm_id: remainingFixture().identity.principal_control_realm_id, nonce: Buffer.alloc(32).toString("base64url") } });
  expect(privateRead?.status).toBe(404); expect(privateRead?.body).not.toHaveProperty("genesis_event");
  await expect(driveOnce(captured.handler(), { method: "POST", url, postData: { realm_id: DEMO_REALM, nonce: "too-short" } })).rejects.toThrow();
});

test("private Account Data Problem extensions are operation-owned and closed", () => {
  const operation = mockOperations().find(item => item.operation_id === "ak.self.account_data.resource.get.v1")!;
  const problem = { ...buildMockProblem("not_found", "unset"), account_data_key: BLOCKLIST_KEY, current_revision: 0 };
  expect(() => validateMockTransportResponse(operation, { status: 404, contentType: "application/problem+json", json: problem })).not.toThrow();
  for (const mutation of [{ ...problem, current_entry: null }, { ...problem, obsolete_alias: true },
    { ...problem, current_revision: undefined }]) expect(() => validateMockTransportResponse(operation,
      { status: 404, contentType: "application/problem+json", json: mutation })).toThrow();
  const unrelated = mockOperations().find(item => item.operation_id === "ak.self.circle.resource.get.v1")!;
  expect(() => validateMockTransportResponse(unrelated, { status: 404, contentType: "application/problem+json", json: problem })).toThrow();
});

test("runtime pairing verifies PoP, preserves retry identity, hides misses and invalidates renewed handles", async () => {
  const captured = captureRouteHandler(); await mockArkretApi(captured.page as never);
  const state = await pairingProbeState(captured.handler());
  const send = (suffix: string, postData: any) => driveOnce(captured.handler(), { method: "POST", url: `https://local.host/_arkret/open/agent-pairing/${suffix}`, postData });
  const pendingMissing = await send("runtime-key-requests/status", state.credential);
  expect(pendingMissing?.status).toBe(404); expect(pendingMissing?.headers?.["retry-after"]).toBe("1");
  const first = await send("runtime-key-requests", state.candidate); expect(first?.status).toBe(200);
  const fresh = inksonWire<any>("mock-runtime-candidate", { bootstrap: state.bootstrap });
  const replay = await send("runtime-key-requests", fresh); expect(replay?.body).toEqual(first?.body);
  const other = inksonWire<any>("mock-runtime-candidate", { bootstrap: state.bootstrap, seed: 45 });
  const conflict = await send("runtime-key-requests", other); expect(conflict?.status).toBe(409);
  expect((conflict?.body as any).reason_code).toBe("agent_runtime_request_conflict");
  const poll = await send("runtime-key-requests/status", state.credential);
  expect(poll?.status).toBe(200); expect(poll?.headers?.["retry-after"]).toBe("1");
  expect((poll?.body as any).approval_request_id).toBe((first?.body as any).approval_request_id);
  expect(poll?.body).not.toHaveProperty("authorized_event_ref"); expect((poll?.body as any).runtime_state).toBe("replacing");
  const badCode = await send("runtime-key-requests/status", { ...state.credential, pairing_code: "00000000" });
  expect(badCode?.body).toEqual(pendingMissing?.body);
  const tampered = structuredClone(state.candidate); tampered.proof_of_possession.signature = Buffer.alloc(64, 0).toString("base64url");
  await expect(send("runtime-key-requests", tampered)).rejects.toThrow();
  const badAudience = structuredClone(state.candidate); badAudience.proof_of_possession.audience_id = state.credential.agent_id;
  await expect(send("runtime-key-requests", badAudience)).rejects.toThrow();
  await pairingProbeState(captured.handler());
  const old = await send("resolve", { pairing_token: state.token }); expect(old?.status).toBe(404);
  const leaked = await send(`resolve?pairing_token=${state.token}`, { pairing_token: state.token }); expect(leaked?.status).toBe(422);
});

test("Blob GET and HEAD agree on known bytes and unknown references", async () => {
  const captured = captureRouteHandler(); await mockArkretApi(captured.page as never);
  const url = `https://local.host/_arkret/self/blob/get?blob_ref=${AVATAR}`;
  const get = await driveOnce(captured.handler(), { method: "GET", url });
  const head = await driveOnce(captured.handler(), { method: "HEAD", url });
  expect(get?.status).toBe(200); expect(head?.status).toBe(200);
  expect(Number(head?.headers?.["content-length"])).toBe(Buffer.byteLength(get?.body as Buffer));
  const unknown = url.replace(AVATAR, `ak:blob:sha256:${"0".repeat(64)}`);
  expect((await driveOnce(captured.handler(), { method: "GET", url: unknown }))?.status).toBe(404);
  const missing = await driveOnce(captured.handler(), { method: "HEAD", url: unknown });
  expect(missing?.status).toBe(404); expect(missing?.body).toBeUndefined();
});
