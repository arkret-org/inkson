import { additionalOperationProbe } from "./remainingOperationProbes";
import { expect } from "@playwright/test";
import {
  BOB_ACCOUNT_ID, CURRENT_ACCOUNT_ACTOR_ID, CURRENT_ACCOUNT_ID, CURRENT_ASSISTANT_ACCOUNT_ID, CURRENT_ASSISTANT_CORE_ID,
  CURRENT_PRINCIPAL_DID, DEMO_INVITE_ID, DEMO_PARENT_MEMBERSHIP_REVISION, DEMO_REALM,
  INVITED_REALM, inksonWire, validateMockSchema,
} from "../e2e/mockArkretApi";
import { concretePath, driveOnce, type MockOperation } from "./mockShapeDriver";

type Handler = Parameters<typeof driveOnce>[0];
export type ProbeRequest = Parameters<typeof driveOnce>[1];
const requestId = "ak:request:01964137-0000-7000-8000-000000000002";
const native = () => inksonWire<Record<string, any>>("mock-realm-fixture", { salt: 9, title: "Arkret Demo Realm", board: true });
let cachedNative: Record<string, any> | undefined;

export const VALID_REQUEST_OPERATIONS = new Set([
  "ak.self.circle.member.command.add.v1", "ak.self.circle.member.resource.delete.v1",
  "ak.self.agent.command.deactivate.v1", "ak.self.agent.command.pause.v1", "ak.self.agent.command.resume.v1", "ak.self.media.read.ice_config.v1",
  "ak.self.invite_receive_policy.resource.replace.v1",
]);

export async function operationProbe(operation: MockOperation, handler: Handler): Promise<ProbeRequest> {
  if (operation.operation_id === "ak.self.blob.resource.get.v1") return { method: "GET", url: "https://local.host/_arkret/self/blob/get?blob_ref=ak:blob:sha256:431ced6916a2a21a156e38701afe55bbd7f88969fbbfc56d7fe099d47f265460" };
  const additional = await additionalOperationProbe(operation, handler);
  if (additional) return additional;
  const directory = operation.path_template.startsWith("/_arkret/find/directory/");
  const path = concretePath(operation.path_template.replaceAll("{agent_id}", CURRENT_ASSISTANT_CORE_ID));
  const request: ProbeRequest = {
    url: `https://${directory ? "directory.example" : "local.host"}${path}`,
    method: operation.method,
    ...(operation.method === "GET" || operation.method === "HEAD" ? {} : { postData: {
      actor_id: CURRENT_ACCOUNT_ACTOR_ID, handle: "bob:local.host", limit: 1, realm_id: DEMO_REALM,
      locator_id: "ak:invite_locator:01964137-0000-7000-8000-0000000000b1",
      events: [{ realm_id: DEMO_REALM }],
    } }),
    headers: { "arkret-operation": operation.operation_id, ...(directory ? {} : { authorization: "Bearer sx:e2e-token" }) },
  };
  if (directory) {
    if (path.endsWith("/search-realms")) request.postData = { query: "demo", limit: 1 };
    if (path.endsWith("/resolve-realm")) request.postData = { realm_id: DEMO_REALM };
    return request;
  }
  if (operation.operation_id.startsWith("ak.self.circle.member.")) {
    const listed = await driveOnce(handler, { method: "GET", url: `https://local.host/_arkret/self/circles?realm_id=${encodeURIComponent(DEMO_REALM)}` });
    const currentCircle = (listed?.body as Record<string, any>).circles[0];
    const circle = currentCircle.circle_id;
    const deletion = operation.method === "DELETE";
    const configuration = { operation: "circle_member", realm_id: DEMO_REALM,
      controller_account_id: CURRENT_ACCOUNT_ID, controller_did: CURRENT_PRINCIPAL_DID,
      payload: { circle_id: circle, member_id: CURRENT_ACCOUNT_ACTOR_ID, membership: "join",
        parent_membership_revision: DEMO_PARENT_MEMBERSHIP_REVISION, expected_membership: currentCircle.viewer_membership ?? null } };
    const joined = inksonWire<Record<string, any>>("mock-operation-request", configuration);
    const collection = `https://local.host/_arkret/self/circles/${encodeURIComponent(circle)}/members`;
    request.url = collection;
    request.postData = joined;
    if (deletion) {
      expect((await driveOnce(handler, { method: "POST", url: collection, postData: joined }))?.status).toBe(200);
      request.postData = inksonWire("mock-operation-request", { ...configuration, delete: true,
        payload: { circle_id: circle, member_id: CURRENT_ACCOUNT_ACTOR_ID, membership: "leave", expected_membership: "join" } });
      const actor = inksonWire<{ canonical: string }>("canonical-json", { value: CURRENT_ACCOUNT_ACTOR_ID }).canonical;
      request.url += `/${encodeURIComponent(actor)}`;
    }
    validateMockSchema(`schemas/circle-operations.schema.json#/$defs/circle_member_${deletion ? "delete_" : ""}request_body`, request.postData);
    return request;
  }
  switch (operation.operation_id) {
    case "ak.self.agent.command.pause.v1":
    case "ak.self.agent.command.resume.v1":
    case "ak.self.agent.command.deactivate.v1": {
      const agentUrl = `https://local.host/_arkret/self/agents/${encodeURIComponent(CURRENT_ASSISTANT_CORE_ID)}`;
      const action = operation.operation_id.split(".").at(-2)!;
      let current = (await driveOnce(handler, { method: "GET", url: agentUrl }))?.body as Record<string, any>;
      if (action === "resume") {
        const paused = await operationProbe({ ...operation, operation_id: "ak.self.agent.command.pause.v1" }, handler);
        expect((await driveOnce(handler, paused))?.status).toBe(200);
        current = (await driveOnce(handler, { method: "GET", url: agentUrl }))?.body as Record<string, any>;
      }
      request.url = `${agentUrl}/${action}`;
      request.postData = inksonWire("mock-operation-request", { operation: "agent_lifecycle", transition: action,
        controller_account_id: CURRENT_ACCOUNT_ID, controller_did: CURRENT_PRINCIPAL_DID,
        agent_account_id: CURRENT_ASSISTANT_ACCOUNT_ID, principal_control_realm_id: current.key_state.principal_control_realm_id,
        controller_authorization_ref: current.key_state.controller_authorization_ref,
        previous_status: current.agent.lifecycle, ...(action === "resume" ? {} : { reason: "contract lifecycle" }) });
      validateMockSchema(`schemas/agent-operations.schema.json#/$defs/agent_${action}_request_body`, request.postData);
      break;
    }
    case "ak.self.media.read.ice_config.v1":
      request.postData = { realm_id: DEMO_REALM, call_id: "ak:call:AbhvODyrIRCskAIoS9IXLjMfD-Zsr8lwDpiCU_zLR4it",
        actor_id: CURRENT_ACCOUNT_ACTOR_ID, device_id: "ak:device:01964137-0000-7000-8000-0000000000a1", mode: "p2p" };
      validateMockSchema("schemas/media-operations.schema.json#/$defs/media_ice_configuration_request_body", request.postData);
      break;
    case "ak.self.invite_receive_policy.resource.replace.v1":
      request.postData = (await driveOnce(handler, { method: "GET", url: request.url }))?.body;
      validateMockSchema("schemas/invite-receive-policy.schema.json", request.postData);
      break;
    case "ak.open.invite_locator.read.resolve.v1": request.postData = { locator_token: "e2e_invite_locator_token_00000001" }; break;
    case "ak.self.invite_locator.command.issue.v1": request.postData = { ttl_seconds: 900, one_time_use: false }; break;
    case "ak.self.invite_locator.command.rotate.v1": request.postData = {}; break;
    case "ak.self.keys.read.lookup.v1": request.postData = { device_keys: [{ account_id: CURRENT_ACCOUNT_ID, device_ids: ["ak:device:01964137-0000-7000-8000-0000000000a1"] }] }; break;
    case "ak.self.direct_conversation.read.resolve.v1": request.postData = { peer: { kind: "human", account_id: BOB_ACCOUNT_ID } }; break;
    case "ak.self.current_principal.read.resolve.v1": request.postData = { request_id: requestId, account_id: CURRENT_ACCOUNT_ID }; break;
    case "ak.self.current_state.read.exact.v1":
      cachedNative ??= native();
      request.postData = { realm_id: DEMO_REALM, selector: { kind: "agent_interaction", agent_account_id: cachedNative.managed_agent.account_id } };
      break;
    case "ak.self.committed_event.read.scan.v1":
      cachedNative ??= native();
      request.postData = { realm_id: DEMO_REALM, stream_ref: cachedNative.committed_events[0].commit.stream_ref, after_position: null, limit: 100 };
      break;
    case "ak.self.strand.watch.read.current.v1":
      cachedNative ??= native();
      request.postData = { realm_id: DEMO_REALM, strand_id: cachedNative.ids.review, watcher_actor_id: CURRENT_ACCOUNT_ACTOR_ID };
      break;
    case "ak.self.signer_keys.read.resolve.v1": {
      cachedNative ??= native();
      const fact = cachedNative.signer_facts[1];
      const full = cachedNative.committed_events.find((full: any) => full.event.event_id === fact.event_id);
      request.postData = { request_id: requestId, realm_id: DEMO_REALM, recipient_account_id: CURRENT_ACCOUNT_ID, queries: [{
        verification_mode: "historical_event", sender_kind: "account_device", actor: fact.actor,
        device_id: fact.device_id, verification_method: fact.verification_method,
        committed_event_ref: { event_id: full.event.event_id, commit_id: full.commit.commit_id, stream_ref: full.commit.stream_ref, stream_position: full.commit.stream_position },
      }] };
      break;
    }
    case "ak.self.committed_event.resource.get.v1":
      cachedNative ??= native();
      request.url = `https://local.host/_arkret/self/committed-events/${encodeURIComponent(cachedNative.source_create.event.event_id)}`;
      break;
    case "ak.self.events.command.submit.v1":
      cachedNative ??= native();
      request.postData = { event: cachedNative.committed_events.find((full: any) => full.event.kind === "ak.member.state").event };
      break;
    case "ak.self.realm_join.command.prepare.v1":
    case "ak.self.realm_join.read.preview.v1":
      request.postData = { request_id: requestId, target: { realm_id: INVITED_REALM, invite_id: DEMO_INVITE_ID } };
      break;
    default:
      request.url += `?realms=${encodeURIComponent(DEMO_REALM)}&subject=ak:did_core:web:bob.example`;
  }
  return request;
}
