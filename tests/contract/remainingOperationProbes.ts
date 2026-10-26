import { CURRENT_ACCOUNT_ACTOR_ID, CURRENT_ACCOUNT_ID, CURRENT_ASSISTANT_CORE_ID, CURRENT_PRINCIPAL_DID,
  DEMO_REALM, inksonWire, validateMockSchema } from "../e2e/mockArkretApi";
import { driveOnce, type MockOperation } from "./mockShapeDriver";
import { gateLogoutRequest } from "./gateLogoutProbe";

type Handler = Parameters<typeof driveOnce>[0];
type Request = Parameters<typeof driveOnce>[1];
export const BLOCKLIST_KEY = "ak.account.blocklist";
export const MORPH_ID = "ak:morph:AQUeFABQK9MQb8JmkZyP7wD2QfYOSDaCH1LDepfyMD-G";
export const AVATAR = "ak:blob:sha256:431ced6916a2a21a156e38701afe55bbd7f88969fbbfc56d7fe099d47f265460";
export const DEVICE_ID = "ak:device:01964137-0000-7000-8000-0000000000a1";
let fixture: any;
export const remainingFixture = () => fixture ??= inksonWire<any>("mock-realm-fixture", { salt: 9, title: "Arkret Demo Realm", board: true });
export const IMPLEMENTED_REMAINING_OPERATIONS = new Set([
  "ak.gate.account.command.logout.v1",
  "ak.open.agent_pairing.read.resolve.v1", "ak.open.agent_pairing.command.submit_runtime_key_request.v1",
  "ak.open.agent_pairing.read.runtime_key_request_status.v1",
  "ak.edge.applet.read.ping.v1", "ak.edge.applet.read.describe.v1", "ak.edge.applet.read.protocol_metadata.v1",
  "ak.edge.applet.realm.read.resolve.v1", "ak.edge.applet.third_party_locations.read.list.v1",
  "ak.peer.committed_event.read.scan.v1", "ak.peer.strand.watch.read.current.v1",
  "ak.open.realm_authority.read.bundle.v1", "ak.root.identity.document.resource.get.v1",
  "ak.root.identity.log.read.list.v1", "ak.root.identity.receipts.read.list.v1",
  "ak.self.account_data.read.list.v1", "ak.self.account_data.resource.replace.v1", "ak.self.account_data.resource.delete.v1",
  "ak.self.circle.resource.get.v1", "ak.self.blob.resource.head.v1", "ak.self.events.read.delivery_status.v1",
  "ak.self.realm.resource.get.v1", "ak.self.realm.read.export.v1", "ak.self.realm_link.read.list.v1",
  "ak.self.realm_organization.read.list.v1", "ak.self.morph.read.list.v1", "ak.self.morph.resource.get.v1",
  "ak.self.read_cursor.read.list.v1", "ak.self.read_cursor.command.advance.v1", "ak.self.agent.participation.resource.replace.v1",
]);

export function accountDataRequest(revision: number, deletion = false, key = BLOCKLIST_KEY): any {
  const encrypted = deletion ? undefined : inksonWire<any>("mock-account-data-value", {
    account_id: CURRENT_ACCOUNT_ID, key: BLOCKLIST_KEY, plaintext: { entries: [] },
  });
  return inksonWire("mock-operation-request", { operation: "account_data",
    realm_id: remainingFixture().identity.principal_control_realm_id,
    controller_account_id: CURRENT_ACCOUNT_ID, controller_did: CURRENT_PRINCIPAL_DID, delete: deletion,
    payload: { key, expected_server_revision: revision, ...(deletion ? { tombstone: true } : { encrypted_payload: encrypted }) },
  });
}

export function readCursorRequest(position?: any): any {
  const current = remainingFixture();
  return inksonWire("mock-operation-request", { operation: "read_cursor",
    controller_account_id: CURRENT_ACCOUNT_ID, controller_did: CURRENT_PRINCIPAL_DID,
    payload: { schema: "ak.schema.read_cursor.v1", actor_id: CURRENT_ACCOUNT_ACTOR_ID, device_id: DEVICE_ID,
      realm_id: DEMO_REALM, read_scope: { kind: "realm" },
      position: position ?? { event_id: current.committed_events[0].event.event_id, hlc: "01970e589d21-0001-a13f9c2e" } },
  });
}

export async function additionalOperationProbe(operation: MockOperation, handler: Handler): Promise<Request | undefined> {
  const id = operation.operation_id;
  if (!IMPLEMENTED_REMAINING_OPERATIONS.has(id) && id !== "ak.self.account_data.resource.get.v1") return undefined;
  if (id === "ak.gate.account.command.logout.v1") return gateLogoutRequest();
  const host = id.startsWith("ak.edge.applet.") ? "applet.example" : "local.host";
  const request: Request = { url: `https://${host}${operation.path_template}`, method: operation.method,
    headers: { "arkret-operation": id, authorization: "Bearer sx:e2e-token" } };
  if (id.startsWith("ak.open.agent_pairing.")) {
    const state = await pairingProbeState(handler);
    request.headers = { "arkret-operation": id };
    request.postData = id.endsWith("read.resolve.v1") ? { pairing_token: state.token }
      : id.endsWith("submit_runtime_key_request.v1") ? state.candidate : state.credential;
    if (id.endsWith("runtime_key_request_status.v1")) {
      const submitted = await driveOnce(handler, { method: "POST", url: "https://local.host/_arkret/open/agent-pairing/runtime-key-requests", postData: state.candidate });
      if (submitted?.status !== 200) throw new Error("runtime candidate setup failed");
    }
    return request;
  }
  if (id.startsWith("ak.edge.applet.")) {
    request.headers = { "arkret-operation": id };
    request.url = request.url.replace("{protocol}", "contract").replace("{realm_id_or_alias}", "contract-room");
    if (id === "ak.edge.applet.third_party_locations.read.list.v1") request.url += "?protocol=contract&external_id=contract-room";
    return request;
  }
  if (id === "ak.peer.committed_event.read.scan.v1" || id === "ak.peer.strand.watch.read.current.v1") {
    request.headers = { "arkret-operation": id, "source-service-id": CURRENT_ACCOUNT_ID.station_id, "destination-service-id": CURRENT_ACCOUNT_ID.station_id };
    request.postData = id === "ak.peer.strand.watch.read.current.v1" ? { realm_id: DEMO_REALM,
      strand_id: remainingFixture().ids.review, watcher_actor_id: CURRENT_ACCOUNT_ACTOR_ID }
      : { realm_id: DEMO_REALM, stream_ref: remainingFixture().committed_events[0].commit.stream_ref, after_position: null, limit: 100 };
    validateMockSchema(id === "ak.peer.strand.watch.read.current.v1" ? "schemas/service-operation-dtos.schema.json#/$defs/StrandWatchCurrentRequestBody"
      : "schemas/authority-commit-operations.schema.json#/$defs/stream_scan_request_body", request.postData);
    return request;
  }
  if (id.startsWith("ak.root.identity.")) {
    request.url += `?did=${encodeURIComponent(CURRENT_PRINCIPAL_DID)}`; return request;
  }
  if (id.startsWith("ak.self.account_data.")) {
    const address = `https://local.host/_arkret/self/account_data/${encodeURIComponent(BLOCKLIST_KEY)}`;
    const current = await driveOnce(handler, { method: "GET", url: address });
    let revision = Number((current?.body as any)?.revision ?? (current?.body as any)?.current_revision ?? 0);
    if (id === "ak.self.account_data.resource.replace.v1") {
      request.url = address; request.postData = accountDataRequest(revision);
    } else {
      if (current?.status !== 200) {
        const written = await driveOnce(handler, { method: "PUT", url: address, postData: accountDataRequest(revision) });
        if (written?.status !== 200) throw new Error("blocklist precondition failed");
        revision += 1;
      }
      if (id === "ak.self.account_data.resource.delete.v1") { request.url = address; request.postData = accountDataRequest(revision, true); }
      else if (id === "ak.self.account_data.resource.get.v1") request.url = address;
    }
    if (request.postData) validateMockSchema(`schemas/account-data-operations.schema.json#/$defs/account_data_${request.method === "DELETE" ? "delete" : "replace"}_request_body`, request.postData);
    return request;
  }
  if (id === "ak.self.circle.resource.get.v1") {
    const response = await driveOnce(handler, { method: "GET", url: `https://local.host/_arkret/self/circles?realm_id=${encodeURIComponent(DEMO_REALM)}` });
    request.url = request.url.replace("{circle_id}", encodeURIComponent((response?.body as any).circles[0].circle_id)); return request;
  }
  if (id === "ak.self.blob.resource.head.v1") { request.url += `?blob_ref=${encodeURIComponent(AVATAR)}`; return request; }
  if (id === "ak.self.events.read.delivery_status.v1") {
    request.postData = { event_id: remainingFixture().committed_events[0].event.event_id };
    validateMockSchema("schemas/service-operation-dtos.schema.json#/$defs/EventDeliveryStatusRequestBody", request.postData); return request;
  }
  if (id === "ak.self.read_cursor.command.advance.v1") {
    request.postData = readCursorRequest();
    validateMockSchema("schemas/read-cursor-operations.schema.json#/$defs/read_cursor_advance_request_body", request.postData); return request;
  }
  if (id === "ak.self.read_cursor.read.list.v1") {
    const advanced = await driveOnce(handler, { method: "POST", url: request.url, postData: readCursorRequest() });
    if (advanced?.status !== 200) throw new Error("read cursor precondition failed");
    request.url += `?realm_id=${encodeURIComponent(DEMO_REALM)}`; return request;
  }
  if (id === "ak.self.agent.participation.resource.replace.v1") {
    request.url = request.url.replace("{agent_id}", encodeURIComponent(CURRENT_ASSISTANT_CORE_ID));
    const current = await driveOnce(handler, { method: "GET", url: request.url });
    const entry = (current?.body as any)?.participation_entries.find((entry: any) => entry.target_scope.realm_id === DEMO_REALM);
    request.postData = { target_scope: { kind: "realm", realm_id: DEMO_REALM }, expected_version: entry?.version ?? "0",
      selection: { message_creation_allowed: true, reaction_addition_allowed: true, reaction_removal_allowed: true,
        third_party_mention_delivery_allowed: false, acting_on_behalf_allowed: false } };
    validateMockSchema("schemas/principal-operations.schema.json#/$defs/agent_participation_replace_request_body", request.postData); return request;
  }
  if (id === "ak.open.realm_authority.read.bundle.v1") {
    request.postData = { realm_id: DEMO_REALM, nonce: Buffer.alloc(32, 2).toString("base64url") }; return request;
  }
  request.url = request.url.replace("{realm_id}", encodeURIComponent(DEMO_REALM)).replace("{morph_id}", encodeURIComponent(MORPH_ID));
  return request;
}

export async function pairingProbeState(handler: Handler) {
  const renewed = await driveOnce(handler, { method: "POST", url: `https://local.host/_arkret/self/agents/${encodeURIComponent(CURRENT_ASSISTANT_CORE_ID)}/renew-pairing` });
  if (renewed?.status !== 200) throw new Error("pairing renewal setup failed");
  const material = renewed.body as any;
  const token = Buffer.from(`fixture-pairing-token:${material.pairing_request_id}`).toString("base64url");
  const resolved = await driveOnce(handler, { method: "POST", url: "https://local.host/_arkret/open/agent-pairing/resolve", postData: { pairing_token: token } });
  if (resolved?.status !== 200) throw new Error("pairing bootstrap setup failed");
  const bootstrap = resolved.body as any;
  const candidate = inksonWire<any>("mock-runtime-candidate", { bootstrap });
  return { token, bootstrap, candidate, credential: { pairing_request_id: bootstrap.pairing_request_id, pairing_code: bootstrap.pairing_code, agent_id: bootstrap.agent_id } };
}
