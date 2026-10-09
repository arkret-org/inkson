import { expect, test } from "@playwright/test";
import { createHash } from "node:crypto";
import { inksonWire, mockArkretApi, validateMockSchema } from "../e2e/mockArkretApi";
import { captureRouteHandler, driveOnce } from "./mockShapeDriver";

type Fixture = {
  snapshot: Record<string, any>;
  committed_events: Array<{ event: Record<string, any>; commit: Record<string, any> }>;
  signer_facts: Array<Record<string, any>>;
  source_authorization: { event: Record<string, any>; commit: Record<string, any> };
  identity: { did: string; account_id: { principal_id: string; station_id: string }; principal_control_realm_id: string; inception_log_entry: Record<string, any>; resolution: Record<string, any> };
  account_entry: Record<string, any>;
  ids: Record<string, string>;
  public_blobs?: Record<string, string>;
  managed_agent: Record<string, any>;
};

const build = () => inksonWire<Fixture>("mock-realm-fixture", {
  salt: 9, title: "Contract Realm", board: true,
});
const verify = (fixture: Fixture) => inksonWire("mock-realm-verify", fixture);
const scanRequest = (fixture: Fixture) => ({
  realm_id: fixture.snapshot.realm_id,
  stream_ref: fixture.committed_events[0].commit.stream_ref,
  after_position: null,
  limit: 100,
});
const scan = (fixture: Fixture, request = scanRequest(fixture)) =>
  inksonWire<Record<string, any>>("mock-realm-scan", { fixture, request });
const changedSignature = (signature: string) =>
  `${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;

function decodeStreamFrames(body: unknown): Array<Record<string, any>> {
  // driveOnce parses a single JSON frame, but retains multi-frame NDJSON.
  const frames: unknown[] = typeof body === "string"
    ? body.trim().split("\n").filter(line => line.trim()).map(line => JSON.parse(line))
    : [body];
  if (frames.length === 0 || frames.some(frame =>
    frame === null || typeof frame !== "object" || Array.isArray(frame))) {
    throw new Error("Expected stream frames as JSON objects or NDJSON objects");
  }
  return frames as Array<Record<string, any>>;
}

function signerRequest(fixture: Fixture) {
  const fact = fixture.signer_facts[1];
  const full = fixture.committed_events.find(({ event }) => event.event_id === fact.event_id)!;
  return {
    request_id: "ak:request:01904100-0000-7000-8000-000000000001",
    realm_id: fixture.snapshot.realm_id,
    recipient_account_id: fixture.identity.account_id,
    queries: [{
      verification_mode: "historical_event", sender_kind: "account_device",
      actor: fact.actor, device_id: fact.device_id, verification_method: fact.verification_method,
      committed_event_ref: {
        event_id: full.event.event_id, commit_id: full.commit.commit_id,
        stream_ref: full.commit.stream_ref, stream_position: full.commit.stream_position,
      },
    }],
  };
}

test("Native Realm fixture verifies WebVH inception and scans original committed Events at the snapshot cut", () => {
  const fixture = build();
  expect(fixture.identity.did).toMatch(/^did:webvh:/);
  expect(verify(fixture)).toEqual({ verified: true });
  const outcome = scan(fixture);
  expect(outcome.committed_events).toEqual(fixture.committed_events);
  expect(outcome.truncated).toBe(false);
  expect(outcome.readable_floor).toMatchObject({
    oldest_position: 0, floor_commit_id: fixture.committed_events[0].commit.commit_id,
    floor_reason: "stream_start",
  });
  const last = fixture.committed_events.at(-1)!;
  expect(fixture.snapshot.visible_stream_heads).toEqual([{
    stream_ref: last.commit.stream_ref, stream_position: last.commit.stream_position,
    commit_id: last.commit.commit_id,
  }]);
});

test("Encrypted native Realm has authenticated public MLS material and exact Genesis current", () => {
  const fixture = inksonWire<Fixture>("mock-realm-fixture", {
    salt: 9, title: "Encrypted Contract Realm", board: true, encrypted: true,
  });
  expect(verify(fixture)).toEqual({ verified: true });
  const genesis = fixture.committed_events.filter(full => full.event.kind === "ak.mls.genesis");
  expect(genesis).toHaveLength(1);
  const full = genesis[0];
  const payload = full.event.payload;
  for (const reference of [payload.group_info_ref, payload.ratchet_tree_ref]) {
    const encoded = fixture.public_blobs?.[reference];
    expect(typeof encoded).toBe("string");
    const bytes = Buffer.from(encoded!, "base64url");
    expect(bytes.length).toBeGreaterThan(0);
    expect(reference).toBe(`ak:blob:sha256:${createHash("sha256").update(bytes).digest("hex")}`);
  }
  expect(payload.creator_leaf_authority.authorization_event_ref).toBe(fixture.source_authorization.event.event_id);
  expect(payload.creator_leaf_authority.endpoint).toEqual({
    kind: "device", device_id: fixture.source_authorization.event.payload.device_id,
  });
  const fact = fixture.signer_facts.find(fact => fact.event_id === full.event.event_id)!;
  expect(payload.creator_leaf_authority.leaf_signature_key_b64u).toBe(fact.key.public_key_b64u);
  const rows = fixture.snapshot.current_state_entries.filter((row: any) => row.selector.kind === "mls_group");
  expect(rows).toHaveLength(1);
  expect(rows[0].source_stream_ref).toEqual(full.commit.stream_ref);
  expect(rows[0].revision).toEqual({ commit_id: full.commit.commit_id, stream_position: full.commit.stream_position });
  expect(rows[0].value).toMatchObject({
    genesis_event_ref: full.event.event_id, current_mls_commit_event_ref: full.event.event_id,
    epoch: 0, public_tree_ref: payload.ratchet_tree_ref,
  });
  expect(scan(fixture).committed_events).toEqual(fixture.committed_events);
});

test("Encrypted native Realm rejects altered public MLS bytes and Genesis authority/current bindings", () => {
  const fixture = inksonWire<Fixture>("mock-realm-fixture", {
    salt: 9, title: "Encrypted Contract Negatives", board: true, encrypted: true,
  });
  const genesisIndex = fixture.committed_events.findIndex(full => full.event.kind === "ak.mls.genesis");
  expect(genesisIndex).toBeGreaterThanOrEqual(0);
  for (const mutation of ["group info bytes", "tree bytes", "missing tree", "creator authorization", "creator device", "creator leaf", "current epoch", "current source", "current public tree"] as const) {
    const changed = structuredClone(fixture);
    const payload = changed.committed_events[genesisIndex].event.payload;
    if (mutation === "group info bytes" || mutation === "tree bytes") {
      const reference = mutation === "group info bytes" ? payload.group_info_ref : payload.ratchet_tree_ref;
      const bytes = Buffer.from(changed.public_blobs![reference], "base64url");
      bytes[0] ^= 1;
      changed.public_blobs![reference] = bytes.toString("base64url");
    }
    if (mutation === "missing tree") delete changed.public_blobs![payload.ratchet_tree_ref];
    if (mutation === "creator authorization") payload.creator_leaf_authority.authorization_event_ref = fixture.committed_events[0].event.event_id;
    if (mutation === "creator device") payload.creator_leaf_authority.endpoint.device_id = "ak:device:01964137-0000-7000-8000-0000000000a2";
    if (mutation === "creator leaf") payload.creator_leaf_authority.leaf_signature_key_b64u = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";
    const current = changed.snapshot.current_state_entries.find((row: any) => row.selector.kind === "mls_group");
    if (mutation === "current epoch") current.value.epoch += 1;
    if (mutation === "current source") current.revision = structuredClone(fixture.snapshot.current_state_entries[0].revision);
    if (mutation === "current public tree") current.value.public_tree_ref = payload.group_info_ref;
    expect(() => verify(changed), mutation).toThrow();
  }
  expect(verify(fixture)).toEqual({ verified: true });
});

test("Managed Agent native fixture retains its real source chain and full Account membership", () => {
  const fixture = build();
  expect(verify(fixture)).toEqual({ verified: true });
  const agent = fixture.managed_agent;
  expect(agent.did).toMatch(/^did:webvh:/);
  expect(agent.account_id.station_id).toBe(fixture.identity.account_id.station_id);
  expect(agent.account_id.principal_id).not.toBe(fixture.identity.account_id.principal_id);
  // Root RealmCreate omits realm_id on the wire to avoid a content-ID cycle.
  expect(agent.genesis.commit.realm_id).toBe(agent.principal_control_realm_id);
  expect(agent.genesis.event.event_id.replace(/^ak:event:/, "ak:realm:")).toBe(agent.principal_control_realm_id);
  expect(agent.genesis.commit.event_ref).toBe(agent.genesis.event.event_id);
  expect(agent.runtime_authorization.event.realm_id).toBe(agent.principal_control_realm_id);
  expect(agent.runtime_authorization.commit.previous_commit_ref).toBe(agent.genesis.commit.commit_id);
  const actor = { kind: "account", account_id: agent.account_id };
  expect(agent.runtime_authorization.event.actor_id).toEqual(actor);
  expect(agent.runtime_authorization.event.executed_by).toEqual({ kind: "account", account_id: fixture.identity.account_id });
  expect(agent.runtime_authorization.event.authorization_ref).toBe(agent.controller_authorization_ref);
  const joined = fixture.committed_events.find(full => full.event.kind === "ak.member.state"
    && full.event.payload.member_id?.account_id?.principal_id === agent.account_id.principal_id)!;
  expect(joined).toBeDefined();
  expect(joined.event.payload.member_id).toEqual(actor);
  expect(joined.event.payload.agent_controller_binding.controller_account_id).toEqual(fixture.identity.account_id);
  const controllerJoin = fixture.committed_events.find(full => full.event.event_id ===
    joined.event.payload.agent_controller_binding.controller_membership_generation_ref)!;
  expect(controllerJoin.event.payload.member_id).toEqual({ kind: "account", account_id: fixture.identity.account_id });
  const current = fixture.snapshot.current_state_entries.find((row: any) => row.selector.kind === "member_state"
    && row.selector.actor_id?.account_id?.principal_id === agent.account_id.principal_id);
  expect(current).toBeDefined();
  expect(current.selector.actor_id).toEqual(actor);
  expect(current.value.membership).toBe("join");
  expect(current.source_stream_ref).toEqual(joined.commit.stream_ref);
  expect(current.revision).toEqual({ commit_id: joined.commit.commit_id, stream_position: joined.commit.stream_position });
  expect(scan(fixture).committed_events).toEqual(fixture.committed_events);
});

test("Managed Agent native verification rejects altered delegation, possession and member source evidence", () => {
  const fixture = build();
  for (const mutation of ["inception bytes", "binding bytes", "delegation", "possession signature", "source commit", "runtime commit", "member Account", "member source", "controller generation"] as const) {
    const changed = structuredClone(fixture);
    const agent = changed.managed_agent;
    if (mutation === "inception bytes") agent.inception_log_entry.versionId = "1-forged";
    if (mutation === "binding bytes") agent.binding_log_entry.versionId = "2-forged";
    if (mutation === "delegation") agent.controller_authorization_ref = `${agent.did}#other-controller`;
    if (mutation === "possession signature") agent.runtime_proof.signature = changedSignature(agent.runtime_proof.signature);
    if (mutation === "source commit") agent.provision.commit.event_ref = fixture.committed_events[0].event.event_id;
    if (mutation === "runtime commit") agent.runtime_authorization.commit.signature.sig = changedSignature(agent.runtime_authorization.commit.signature.sig);
    const current = changed.snapshot.current_state_entries.find((row: any) => row.selector.kind === "member_state"
      && row.selector.actor_id?.account_id?.principal_id === agent.account_id.principal_id);
    if (mutation === "member Account") current.selector.actor_id.account_id.station_id = fixture.identity.account_id.principal_id;
    if (mutation === "member source") current.revision = structuredClone(fixture.snapshot.current_state_entries[0].revision);
    if (mutation === "controller generation") {
      const joined = changed.committed_events.find(full => full.event.kind === "ak.member.state"
        && full.event.payload.member_id?.account_id?.principal_id === agent.account_id.principal_id)!;
      joined.event.payload.agent_controller_binding.controller_membership_generation_ref = fixture.committed_events[0].event.event_id;
    }
    expect(() => verify(changed), mutation).toThrow();
  }
  expect(verify(fixture)).toEqual({ verified: true });
});

test("Historical signer query resolves only the exact accepted Event and Commit", () => {
  const fixture = build();
  const request = signerRequest(fixture);
  const outcome = inksonWire<Record<string, any>>("mock-realm-signer-keys", { fixture, request });
  expect(outcome).toMatchObject({
    request_id: request.request_id, realm_id: request.realm_id,
    recipient_account_id: request.recipient_account_id,
    results: [{ status: "resolved", selector: request.queries[0],
      key: fixture.signer_facts[1].key, accepted_at: fixture.signer_facts[1].accepted_at }],
  });
  const changed = structuredClone(request);
  changed.queries[0].committed_event_ref.commit_id = fixture.committed_events[0].commit.commit_id;
  expect(inksonWire<Record<string, any>>("mock-realm-signer-keys", {
    fixture, request: changed,
  }).results).toEqual([{ status: "unavailable", selector: changed.queries[0] }]);
});

test("Native read entry rejects changed signatures, source authorization and historical key facts", () => {
  const fixture = build();
  for (const mutation of ["snapshot signature", "commit signature", "producer signature", "source authorization", "historical key", "inception"] as const) {
    const changed = structuredClone(fixture);
    if (mutation === "snapshot signature") changed.snapshot.signature.sig = changedSignature(changed.snapshot.signature.sig);
    if (mutation === "commit signature") changed.committed_events[1].commit.signature.sig = changedSignature(changed.committed_events[1].commit.signature.sig);
    if (mutation === "producer signature") {
      const proof = changed.committed_events[1].event.producer_proof;
      const parts = proof.jws.split(".");
      parts[2] = changedSignature(parts[2]);
      proof.jws = parts.join(".");
    }
    if (mutation === "source authorization") changed.source_authorization.commit.event_ref = fixture.committed_events[0].event.event_id;
    if (mutation === "historical key") changed.signer_facts[1].key.public_key_b64u = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";
    if (mutation === "inception") changed.identity.inception_log_entry.versionId = "1-forged";
    expect(() => scan(changed), mutation).toThrow();
  }
  expect(verify(fixture)).toEqual({ verified: true });
});

test("Native fixture rejects forged producer Events, current rows and stream continuity", () => {
  const fixture = build();
  for (const mutation of ["original Event", "current value", "current revision", "predecessor"] as const) {
    const changed = structuredClone(fixture);
    if (mutation === "original Event") changed.committed_events[1].event.created_at = "2026-09-19T00:00:01.000Z";
    if (mutation === "current value") changed.snapshot.current_state_entries[0].value = { title: "Unsigned replacement" };
    if (mutation === "current revision") changed.snapshot.current_state_entries[0].revision.stream_position += 1;
    if (mutation === "predecessor") changed.committed_events[1].commit.previous_commit_ref = null;
    expect(() => verify(changed), mutation).toThrow();
  }
  expect(scan(fixture).committed_events).toEqual(fixture.committed_events);
});

test("Native scan and historical signer query reject a different Realm or recipient Account", () => {
  const fixture = build();
  const other = inksonWire<Fixture>("mock-realm-fixture", { salt: 10, title: "Other Realm" });
  expect(() => scan(fixture, { ...scanRequest(fixture), realm_id: other.snapshot.realm_id })).toThrow();
  const request = signerRequest(fixture);
  const wrongRecipient = structuredClone(request);
  wrongRecipient.recipient_account_id.principal_id = "ak:did_core:web:mallory.example";
  expect(() => inksonWire("mock-realm-signer-keys", { fixture, request: wrongRecipient })).toThrow();
  const wrongRealm = { ...request, realm_id: other.snapshot.realm_id };
  expect(() => inksonWire("mock-realm-signer-keys", { fixture, request: wrongRealm })).toThrow();
});

async function mockReadFixture() {
  const captured = captureRouteHandler();
  await mockArkretApi(captured.page as never);
  const fixture = inksonWire<Fixture>("mock-realm-fixture", {
    salt: 9, title: "Arkret Demo Realm", board: true,
  });
  return { fixture, route: captured.handler() };
}

test("Exact managed Agent current read proves never-written at the unchanged verified Realm head", async () => {
  const { fixture, route } = await mockReadFixture();
  const original = structuredClone(fixture);
  const request = {
    realm_id: fixture.snapshot.realm_id,
    selector: { kind: "agent_interaction", agent_account_id: fixture.managed_agent.account_id },
  };
  const outcome = inksonWire<Record<string, any>>("mock-exact-current", { fixture, request });
  expect(outcome).toEqual({
    status: "never_written", realm_id: request.realm_id,
    governance_generation: fixture.snapshot.governance_generation,
    effective_stream_head: fixture.snapshot.visible_stream_heads.find((head: any) => head.stream_ref.kind === "realm"
      && head.stream_ref.realm_id === request.realm_id),
    selector: request.selector,
  });
  expect(() => validateMockSchema("schemas/exact-current-results-read.schema.json#/$defs/exact_current_results_read_outcome", outcome)).not.toThrow();
  const response = await driveOnce(route, {
    url: "https://local.host/_arkret/self/current-results/exact", method: "POST", postData: request,
  });
  expect(response?.status).toBe(200);
  expect(response?.body).toEqual(outcome);
  expect(fixture).toEqual(original);
  expect(scan(fixture).committed_events).toEqual(original.committed_events);
  expect(verify(fixture)).toEqual({ verified: true });
});

test("Exact current read rejects foreign Realm, Agent Account, selector and altered head evidence", () => {
  const fixture = build();
  const request = {
    realm_id: fixture.snapshot.realm_id,
    selector: { kind: "agent_interaction", agent_account_id: fixture.managed_agent.account_id },
  };
  const other = inksonWire<Fixture>("mock-realm-fixture", { salt: 10, title: "Other current Realm" });
  for (const invalid of [
    { ...request, realm_id: other.snapshot.realm_id },
    { ...request, selector: { ...request.selector, agent_account_id: fixture.identity.account_id } },
    { ...request, selector: { ...request.selector, agent_account_id: {
      ...fixture.managed_agent.account_id, station_id: fixture.identity.account_id.principal_id,
    } } },
    { ...request, selector: { kind: "moderation_state", target_ref: fixture.snapshot.realm_id } },
  ]) {
    expect(() => inksonWire("mock-exact-current", { fixture, request: invalid })).toThrow();
  }
  for (const mutation of ["generation", "head", "member Account"] as const) {
    const changed = structuredClone(fixture);
    if (mutation === "generation") changed.snapshot.governance_generation += 1;
    if (mutation === "head") changed.snapshot.visible_stream_heads[0].stream_position += 1;
    if (mutation === "member Account") {
      const current = changed.snapshot.current_state_entries.find((row: any) => row.selector.kind === "member_state"
        && row.selector.actor_id?.account_id?.principal_id === changed.managed_agent.account_id.principal_id);
      current.selector.actor_id.account_id.station_id = fixture.identity.account_id.principal_id;
    }
    expect(() => inksonWire("mock-exact-current", { fixture: changed, request }), mutation).toThrow();
  }
});

test("Mock read routes preserve the native snapshot, original Event and exact signer query", async () => {
  const { fixture, route } = await mockReadFixture();
  const realmQuery = `?realm_id=${encodeURIComponent(fixture.snapshot.realm_id)}`;
  for (const path of ["head", encodeURIComponent(fixture.snapshot.snapshot_id)]) {
    const response = await driveOnce(route, {
      url: `https://local.host/_arkret/self/realm-state-snapshot/${path}${realmQuery}`, method: "GET",
    });
    expect(response?.status).toBe(200);
    expect(response?.body).toEqual(fixture.snapshot);
  }
  const scanned = await driveOnce(route, {
    url: "https://local.host/_arkret/self/streams/scan", method: "POST", postData: scanRequest(fixture),
  });
  expect(scanned?.status).toBe(200);
  expect((scanned?.body as any).committed_events).toEqual(fixture.committed_events);
  const full = fixture.committed_events[1];
  const event = await driveOnce(route, {
    url: `https://local.host/_arkret/self/committed-events/${encodeURIComponent(full.event.event_id)}`, method: "GET",
  });
  expect(event?.status).toBe(200);
  expect(event?.body).toEqual(full);
  const queried = await driveOnce(route, {
    url: "https://local.host/_arkret/self/signer-keys/query", method: "POST", postData: signerRequest(fixture),
  });
  expect(queried?.status).toBe(200);
  expect((queried?.body as any).results[0]).toMatchObject({ status: "resolved", key: fixture.signer_facts[1].key });
  const request = { request_id: "ak:request:01904100-0000-7000-8000-000000000002", account_id: fixture.identity.account_id };
  const principal = await driveOnce(route, {
    url: "https://local.host/_arkret/self/account/current-principal", method: "POST", postData: request,
  });
  expect(principal?.status).toBe(200);
  expect(principal?.body).toEqual({
    ...request, principal_control_realm_id: fixture.identity.principal_control_realm_id,
    resolution_projection: fixture.identity.resolution,
  });
});

test("Mock account and committed Event streams retain the native Realm cut without mixing root Events", async () => {
  const { fixture, route } = await mockReadFixture();
  const account = await driveOnce(route, {
    url: "https://local.host/_arkret/self/account/subscribe", method: "GET",
  });
  expect(account?.status).toBe(200);
  const accountFrames = decodeStreamFrames(account?.body);
  const realm = accountFrames.find(frame => frame.kind === "delta").realms[fixture.snapshot.realm_id];
  expect(realm.committed_events).toEqual(fixture.committed_events);
  expect(realm.current).toEqual(fixture.account_entry.current);
  const stream = await driveOnce(route, {
    url: `https://local.host/_arkret/self/committed-events/subscribe?realm_ids=${encodeURIComponent(fixture.snapshot.realm_id)}`,
    method: "GET",
  });
  expect(stream?.status).toBe(200);
  const frames = decodeStreamFrames(stream?.body);
  expect(frames.filter(frame => frame.kind === "committed_event").map(frame => frame.payload)).toEqual(fixture.committed_events);
  expect(frames.at(-1)).toMatchObject({ kind: "catchup_complete" });
});

test("Account subscription emits schema-valid delta frames and catchup completion only when requested", async () => {
  const { route } = await mockReadFixture();
  for (const after of [undefined, "ak:cursor:e2e-2"]) {
    for (const catchup of [undefined, "true", "false"]) {
      const parameters = new URLSearchParams();
      if (after !== undefined) parameters.set("after", after);
      if (catchup !== undefined) parameters.set("catchup", catchup);
      const response = await driveOnce(route, {
        url: `https://local.host/_arkret/self/account/subscribe?${parameters}`, method: "GET",
      });
      expect(response?.status).toBe(200);
      const frames = decodeStreamFrames(response?.body);
      expect(frames.map(frame => frame.kind), `after=${after}, catchup=${catchup}`).toEqual(
        catchup === "true" ? ["delta", "catchup_complete"] : ["delta"],
      );
      for (const frame of frames) {
        expect(frame.cursor).toBe("ak:cursor:e2e-2");
        expect(() => validateMockSchema("schemas/account-subscribe-frame.schema.json", frame)).not.toThrow();
      }
    }
  }
});
