import type { Route } from "@playwright/test";

// Fixture state and callbacks are private test plumbing, never protocol DTOs.
type Context = {
  accountId: any; actor: any; did: string; deviceId: string; seed: string;
  realmId: string; principalRealmId: string; demo: any;
  nativeFixtures: Map<string, any>; agents: Map<string, any>; pairingBootstraps: Map<string, any>;
  agentProjection: (id: string) => any; agentAxes: (id: string) => any;
  circle: (id: string) => any | undefined;
  stationAccountData: () => any | null;
  accountDataRules: any[];
  native: (command: string, value: any) => any;
  validate: (reference: string, value: any) => void;
  json: (route: Route, value: any, status?: number) => Promise<any>;
  problem: (route: Route, code: string, detail: string, extensions?: any, headers?: Record<string, string>) => Promise<any>;
  operation: (method: string, path: string) => string;
  appletResolution: () => any; appletDescribe: (resolution: any) => any;
};

const ACCOUNT_DATA = "schemas/account-data-operations.schema.json#/$defs/";
const canonical = (value: any): string => JSON.stringify(value, (_key, item) =>
  item && typeof item === "object" && !Array.isArray(item)
    ? Object.fromEntries(Object.entries(item).sort(([left], [right]) => left.localeCompare(right))) : item);

export function remainingOperationMock(context: Context) {
  const candidates = new Map<string, any>();
  const acceptedPrivateEvents = new Map<string, { bytes: string; outcome: any }>();
  const entries = new Map<string, any>();
  const revisions = new Map<string, number>();
  const markers = new Map<string, any>();
  const participation = new Map<string, Map<string, any>>();
  const morphs = new Map<string, any>();
  const stamp = "2026-09-19T00:00:00.000Z";
  // A UI projection fixture is not asserted to be signed native history.
  const morphId = "ak:morph:AQUeFABQK9MQb8JmkZyP7wD2QfYOSDaCH1LDepfyMD-G";
  const morph = { morph_id: morphId, realm_id: context.realmId, morph_kind: "document",
    title: "Contract document", state: "active", created_by: context.actor, created_at: stamp,
    updated_by: context.actor, updated_at: stamp };
  morphs.set(morphId, { document: { ...morph, body: { blocks: [] } }, versions: [], relations: [], comments: [] });
  const verify = (event: any) => context.native("mock-operation-verify", {
    event, controller_account_id: context.accountId, controller_did: context.did,
    device_id: context.deviceId, seed_b64url: context.seed,
  });
  const liveEntries = () => {
    const result = new Map(entries);
    const station = context.stationAccountData();
    if (station) result.set("ak.account.invite_delivery", { account_data_key: "ak.account.invite_delivery",
      revision: 1, content: station, updated_at: station.updated_at });
    return result;
  };
  const revisionProblem = (route: Route, code: string, key: string, current?: any) =>
    context.problem(route, code, code === "not_found" ? "account data is not set" : "account data revision changed", {
      account_data_key: key, current_revision: current?.revision ?? revisions.get(key) ?? 0,
      ...(current ? { current_entry: current } : {}),
    });

  return async (route: Route, url: URL): Promise<boolean> => {
    const method = route.request().method();
    const operation = context.operation(method, url.pathname);
    const respond = async (value: any, status = 200) => { await context.json(route, value, status); return true; };
    const fail = async (code: string, detail: string) => { await context.problem(route, code, detail); return true; };
    const body = () => route.request().postDataJSON();
    const knownRealm = (id: string) => context.nativeFixtures.get(id);

    if (operation === "ak.edge.applet.read.ping.v1" || operation === "ak.edge.applet.read.describe.v1"
        || operation === "ak.edge.applet.read.protocol_metadata.v1"
        || operation === "ak.edge.applet.realm.read.resolve.v1" || operation === "ak.edge.applet.third_party_locations.read.list.v1"
        || (operation === "ak.server.read.describe.v1" && url.hostname === "applet.example")) {
      if (url.hostname !== "applet.example") return fail("not_found", "Applet metadata belongs to its own Service");
      const resolution = context.appletResolution();
      if (operation.endsWith("protocol_metadata.v1")) {
        if (decodeURIComponent(url.pathname.split("/").at(-1)!) !== "contract") return fail("not_found", "protocol not found");
        return respond({ protocol: "contract", display_name: "Contract protocol",
          field_definitions: { external_id: { required: true, value_kind: "string" } } });
      }
      if (operation === "ak.edge.applet.realm.read.resolve.v1" || operation === "ak.edge.applet.third_party_locations.read.list.v1") {
        let external = decodeURIComponent(url.pathname.split("/").at(-1)!);
        if (operation === "ak.edge.applet.third_party_locations.read.list.v1") {
          const request = Object.fromEntries(url.searchParams);
          context.validate("schemas/applet-edge-operations.schema.json#/$defs/third_party_query", request);
          if (request.protocol !== "contract") return respond({ exists: false });
          external = request.external_id;
        }
        return respond([context.realmId, "contract-room"].includes(external)
          ? { exists: true, realm_id: context.realmId, title: "Contract Realm", external_ref: { protocol: "contract", external_id: "contract-room" } }
          : { exists: false });
      }
      if (operation.endsWith("ping.v1")) return respond({ applet_id: "ak:applet:01964137-0000-7000-8000-0000000000a2",
        service_id: resolution.service_id, protocol_version: "1.0" });
      return respond(context.appletDescribe(resolution));
    }

    if (operation.startsWith("ak.open.agent_pairing.")) {
      const status = operation === "ak.open.agent_pairing.read.runtime_key_request_status.v1";
      const headers = status ? { "retry-after": "1" } : undefined;
      const missing = async () => { await context.problem(route, "not_found", "pairing request not found", undefined, headers); return true; };
      // Secrets belong exclusively to the body, including on error paths.
      if (url.search) { await context.problem(route, "schema_violation", "pairing secrets must be sent in the JSON body", undefined, headers); return true; }
      const request = body();
      const resolve = operation === "ak.open.agent_pairing.read.resolve.v1";
      const schema = resolve ? "agent_pairing_resolve_request_body" : status ? "agent_runtime_approval_status_request_body" : "agent_runtime_approval_request_body";
      context.validate(`schemas/agent-operations.schema.json#/$defs/${schema}`, request);
      const bootstrap = resolve ? context.pairingBootstraps.get(request.pairing_token)
        : [...context.pairingBootstraps.values()].find(item => item.pairing_request_id === request.pairing_request_id && item.agent_id === request.agent_id && item.pairing_code === request.pairing_code);
      if (!bootstrap || context.agentAxes(bootstrap.agent_id).lifecycle === "deactivated" || Date.parse(bootstrap.pairing_expires_at) <= Date.now()) return missing();
      if (resolve) return respond(bootstrap);
      const current = candidates.get(bootstrap.pairing_request_id);
      if (status) {
        if (!current) return missing();
        await route.fulfill({ status: 200, headers, json: { ...context.agentAxes(bootstrap.agent_id),
          readiness: context.agentProjection(bootstrap.agent_id).readiness,
          presence: context.agentProjection(bootstrap.agent_id).presence, approval_request_id: current.approval_request_id } });
        return true;
      }
      const verified = context.native("mock-runtime-candidate", { bootstrap, request });
      if (current && current.binding_digest !== verified.binding_digest) {
        await context.problem(route, "conflict", "pairing handle already has a different candidate", { reason_code: "agent_runtime_request_conflict" }); return true;
      }
      const candidate = { ...verified, request, approval_request_id: current?.approval_request_id ?? `approval-${bootstrap.pairing_request_id}` };
      candidates.set(bootstrap.pairing_request_id, candidate);
      return respond({ approval_request_id: candidate.approval_request_id, status: context.agentAxes(bootstrap.agent_id).lifecycle });
    }

    if (operation === "ak.self.account_data.read.list.v1") {
      return respond({ account_data_entries: [...liveEntries().values()].sort((a, b) => a.account_data_key.localeCompare(b.account_data_key)) });
    }
    if (["ak.self.account_data.resource.get.v1", "ak.self.account_data.resource.replace.v1", "ak.self.account_data.resource.delete.v1"].includes(operation)) {
      const key = decodeURIComponent(url.pathname.split("/").at(-1)!);
      const current = liveEntries().get(key);
      if (method === "GET") {
        if (current) return respond(current);
        await revisionProblem(route, "not_found", key); return true;
      }
      const deletion = method === "DELETE";
      const request = body();
      context.validate(`${ACCOUNT_DATA}account_data_${deletion ? "delete" : "replace"}_request_body`, request);
      const event = request.set_event.event;
      verify(event);
      if (canonical(event.actor_id) !== canonical(context.actor) || event.realm_id !== context.principalRealmId
          || canonical(event.scope_ref) !== canonical({ kind: "realm", realm_id: context.principalRealmId })
          || event.payload.key !== key) return fail("param_invalid", "account data owner, PCR or key mismatch");
      const rule = context.accountDataRules.find(row => {
        const pieces = String(row.key_pattern).split(/(<[^>]+>)/).map((part: string) => part.startsWith("<") ? "[^/]+" : part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
        return new RegExp(`^${pieces.join("")}$`).test(key);
      });
      if (!rule || !rule.writer_authorities.includes("holder_event") || !rule.holder_self_operations.includes(deletion ? "delete" : "put")
          || (deletion && rule.deletion_mode !== "physical_delete")) return fail("capability_denied", "registered holder operation is not allowed");
      if (!deletion && rule.storage === "encrypted_account_data") {
        const encrypted = event.payload.encrypted_payload;
        context.validate("schemas/account-data-encrypted-value.schema.json", encrypted);
        if (canonical(encrypted.aad.actor_id) !== canonical(context.actor) || encrypted.aad.account_data_key !== key
            || Object.hasOwn(event.payload, "body")) return fail("param_invalid", "encrypted value AAD does not bind its owner and key");
      }
      const prior = acceptedPrivateEvents.get(event.event_id);
      if (prior) {
        if (prior.bytes !== canonical(event)) return fail("duplicate_conflict", "Event identity has different bytes");
        return respond(prior.outcome);
      }
      if (event.payload.source_pending_event_id !== undefined) return fail("failed_precondition", "fixture has no pending-intent consumption ledger");
      const revision = current?.revision ?? revisions.get(key) ?? 0;
      if (event.payload.expected_server_revision !== revision) {
        await revisionProblem(route, "cas_conflict", key, current); return true;
      }
      const next = revision + 1;
      if (!Number.isSafeInteger(next)) return fail("failed_precondition", "fixture revision exceeds safe range");
      revisions.set(key, next);
      const outcome = deletion ? { account_data_key: key, revision: next } : { account_data_key: key, revision: next,
        content: event.payload.encrypted_payload ?? event.payload.body, updated_at: event.payload.updated_at ?? event.created_at };
      acceptedPrivateEvents.set(event.event_id, { bytes: canonical(event), outcome });
      if (deletion) entries.delete(key); else entries.set(key, outcome);
      return respond(outcome);
    }

    if (["ak.peer.committed_event.read.scan.v1", "ak.peer.strand.watch.read.current.v1"].includes(operation)) {
      const headers = route.request().headers();
      if (["authorization", "dpop", "cookie"].some(key => headers[key] !== undefined)) return fail("capability_denied", "participant credentials must not be forwarded to peer operations");
      if (headers["source-service-id"] !== context.accountId.station_id || headers["destination-service-id"] !== context.accountId.station_id) return fail("not_found", "peer fixture has no authenticated relation to that Station");
      const request = body();
      const watch = operation === "ak.peer.strand.watch.read.current.v1";
      context.validate(watch ? "schemas/service-operation-dtos.schema.json#/$defs/StrandWatchCurrentRequestBody"
        : "schemas/authority-commit-operations.schema.json#/$defs/stream_scan_request_body", request);
      const fixture = knownRealm(request.realm_id);
      if (!fixture) return fail("not_found", "Realm not found");
      if (watch) {
        if (canonical(request.watcher_actor_id) !== canonical(context.actor)) return fail("not_found", "watcher not found");
        return respond(context.native("mock-strand-watch-current", { fixture, request }));
      }
      const scan = context.native("mock-realm-scan", { fixture, request });
      const producer_signer_facts = scan.committed_events.filter((full: any) => full.commit.producer_signer_fact_digest != null).map((full: any) => {
        const fact = fixture.signer_facts.find((fact: any) => fact.event_id === full.event.event_id);
        if (!fact) throw new Error("native peer fixture is missing its original signer fact");
        return { target: { event_id: full.event.event_id, commit_id: full.commit.commit_id,
          stream_ref: full.commit.stream_ref, stream_position: full.commit.stream_position }, producer_signer_fact: fact };
      });
      return respond({ ...scan, producer_signer_facts });
    }

    if (operation === "ak.self.circle.resource.get.v1") {
      const id = decodeURIComponent(url.pathname.split("/").at(-1)!);
      const value = context.circle(id);
      return value ? respond(value) : fail("not_found", "circle not found");
    }
    if (operation === "ak.self.blob.resource.head.v1") {
      const reference = url.searchParams.get("blob_ref");
      const encoded = reference ? context.demo.public_blobs?.[reference] : undefined;
      const avatar = "ak:blob:sha256:431ced6916a2a21a156e38701afe55bbd7f88969fbbfc56d7fe099d47f265460";
      if (!reference || (!encoded && reference !== avatar)) {
        await route.fulfill({ status: 404, contentType: "application/problem+json" }); return true;
      }
      const bytes = encoded ? Buffer.from(encoded, "base64url") : Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=", "base64");
      await route.fulfill({ status: 200, headers: { "content-length": String(bytes.length), "content-type": encoded ? "application/octet-stream" : "image/png" } });
      return true;
    }

    if (["ak.self.realm.resource.get.v1", "ak.self.realm.read.export.v1", "ak.self.realm_link.read.list.v1",
      "ak.self.realm_organization.read.list.v1", "ak.self.morph.read.list.v1", "ak.self.morph.resource.get.v1"].includes(operation)) {
      const realmId = decodeURIComponent(url.pathname.split("/")[4]);
      const fixture = knownRealm(realmId);
      if (!fixture) return fail("not_found", "Realm not found");
      const source = fixture.committed_events as any[];
      if (operation === "ak.self.realm.resource.get.v1") {
        const memberships = fixture.snapshot.current_state_entries.filter((entry: any) => entry.selector.kind === "member_state");
        const members = memberships.filter((entry: any) => entry.value.membership === "join").map((entry: any) => entry.selector.actor_id);
        return respond({ realm_id: realmId, owner_id: source[0].event.actor_id.account_id.principal_id,
          member_ids: members, deleted: false, archived: false, frozen: false });
      }
      if (operation === "ak.self.realm.read.export.v1") return respond({ schema: "ak.export.realm.v1", realm_id: realmId,
        generated_at: new Date().toISOString(), operations: [], events: source.map(full => ({ event_id: full.event.event_id,
          realm_id: realmId, event_kind: full.event.kind, sender: full.event.actor_id, payload: full.event.payload, created_at: full.event.created_at })) });
      if (["ak.self.realm_link.read.list.v1", "ak.self.realm_organization.read.list.v1"].includes(operation)
          && source.some((full: any) => /realm[._](link|organization)|organization[._](relationship|binding)/.test(full.event.kind))) {
        throw new Error("relationship projection requires an accepted non-empty relationship fixture");
      }
      if (operation === "ak.self.realm_link.read.list.v1") {
        const direction = url.searchParams.get("direction") ?? "both";
        if (!["outbound", "inbound", "both"].includes(direction)) return fail("param_invalid", "unknown link direction");
        return respond({ realm_id: realmId, direction, links: [] });
      }
      if (operation === "ak.self.realm_organization.read.list.v1") return respond({ realm_id: realmId, relationships: [], declared_organization_hint_ids: [] });
      const current = [...morphs.values()].filter(item => item.document.realm_id === realmId);
      if (operation === "ak.self.morph.read.list.v1") return respond({ realm_id: realmId, morphs: current.map(item => {
        const { body: _body, updated_by: _updatedBy, ...projection } = item.document; return projection;
      }), total_count: current.length, has_more: false });
      const found = morphs.get(decodeURIComponent(url.pathname.split("/").at(-1)!));
      return found?.document.realm_id === realmId ? respond(found) : fail("not_found", "Morph not found");
    }
    if (operation === "ak.self.events.read.delivery_status.v1") {
      const request = body(); context.validate("schemas/service-operation-dtos.schema.json#/$defs/EventDeliveryStatusRequestBody", request);
      const owned = [...context.nativeFixtures.values()].some(fixture => fixture.committed_events.some((full: any) =>
        full.event.event_id === request.event_id && canonical(full.event.actual_signer ?? full.event.executed_by ?? full.event.actor_id) === canonical(context.actor)));
      if (!owned) return fail("not_found", "Event not found");
      // This local-only fixture has no frozen remote fanout targets.
      return respond({ event_id: request.event_id, targets: [] });
    }

    if (operation === "ak.self.read_cursor.read.list.v1") {
      const realmId = url.searchParams.get("realm_id");
      if (realmId && !knownRealm(realmId)) return fail("not_found", "Realm not found");
      return respond({ markers: [...markers.values()].filter(item => !realmId || item.realm_id === realmId) });
    }
    if (operation === "ak.self.read_cursor.command.advance.v1") {
      const request = body(); context.validate("schemas/read-cursor-operations.schema.json#/$defs/read_cursor_advance_request_body", request);
      const event = request.advance_event.event; verify(event); const cursor = event.payload;
      if (canonical(event.actor_id) !== canonical(context.actor) || canonical(cursor.actor_id) !== canonical(context.actor)
          || cursor.device_id !== context.deviceId || event.realm_id !== cursor.realm_id) return fail("param_invalid", "read cursor owner or scope mismatch");
      if (canonical(event.scope_ref) !== canonical({ kind: "realm", realm_id: cursor.realm_id })) return fail("param_invalid", "read cursor envelope scope mismatch");
      const prior = acceptedPrivateEvents.get(event.event_id);
      if (prior) {
        if (prior.bytes !== canonical(event)) return fail("duplicate_conflict", "Event identity has different bytes");
        return respond(prior.outcome);
      }
      const fixture = knownRealm(cursor.realm_id);
      const point = fixture?.committed_events.find((full: any) => full.event.event_id === cursor.position.event_id);
      if (!point) return fail("temporarily_unavailable", "read cursor position is not in the verified fixture history");
      if (cursor.read_scope.kind !== "realm") return fail("temporarily_unavailable", "fixture lacks the scoped causal closure");
      const key = canonical([cursor.actor_id, cursor.realm_id, cursor.read_scope]);
      const current = markers.get(key);
      const currentPoint = current && fixture.committed_events.find((full: any) => full.event.event_id === current.position.event_id);
      if (current && !currentPoint) return fail("temporarily_unavailable", "current cursor coordinate is unavailable");
      let wins = !current;
      if (current) {
        const sameStream = canonical(currentPoint.commit.stream_ref) === canonical(point.commit.stream_ref);
        const oldPosition = BigInt(currentPoint.commit.stream_position);
        const newPosition = BigInt(point.commit.stream_position);
        wins = sameStream && oldPosition !== newPosition ? newPosition > oldPosition
          : cursor.position.hlc > current.position.hlc || (cursor.position.hlc === current.position.hlc && cursor.device_id > current.device_id);
      }
      const winner = wins ? { realm_id: cursor.realm_id, actor_id: cursor.actor_id, device_id: cursor.device_id,
        read_scope: cursor.read_scope, position: cursor.position, updated_at: event.created_at } : current;
      markers.set(key, winner); acceptedPrivateEvents.set(event.event_id, { bytes: canonical(event), outcome: winner });
      return respond(winner);
    }

    const agentMatch = url.pathname.match(/^\/_arkret\/self\/agents\/([^/]+)\/participation$/);
    if (agentMatch && ["GET", "PUT"].includes(method)) {
      const agentId = decodeURIComponent(agentMatch[1]);
      if (!context.agents.has(agentId)) return fail("not_found", "Agent not found");
      const selections = participation.get(agentId) ?? new Map<string, any>();
      if (method === "PUT") {
        const request = body(); context.validate("schemas/principal-operations.schema.json#/$defs/agent_participation_replace_request_body", request);
        const target = request.target_scope;
        const fixture = knownRealm(target.realm_id);
        if (!fixture) return fail("not_found", "Realm not found");
        if (target.kind === "circle" && context.circle(target.circle_id)?.realm_id !== target.realm_id) return fail("not_found", "Circle not found");
        if (target.kind === "strand" && !Object.values(fixture.ids).includes(target.strand_id)) return fail("not_found", "Strand not found");
        const key = canonical(request.target_scope); const current = selections.get(key);
        if (request.expected_version !== (current?.version ?? "0")) return fail("cas_conflict", "Agent participation version changed");
        const version = (BigInt(request.expected_version) + 1n).toString();
        selections.set(key, { target_scope: request.target_scope, selection: request.selection, version,
          ...(version === "9223372036854775807" ? {} : { next_replace_input: { expected_version: version } }) });
        participation.set(agentId, selections);
      }
      return respond({ agent_id: agentId, participation_entries: [...selections.values()] });
    }

    if (["ak.root.identity.document.resource.get.v1", "ak.root.identity.log.read.list.v1", "ak.root.identity.receipts.read.list.v1"].includes(operation)) {
      if (url.searchParams.get("did") !== context.demo.identity.did) return fail("not_found", "DID not found");
      if (operation === "ak.root.identity.document.resource.get.v1") return respond({ did_document: context.demo.identity.document });
      if (operation === "ak.root.identity.log.read.list.v1") return respond({ did: context.demo.identity.did, method: "did:webvh",
        native_history: true, entries: [context.demo.identity.inception_log_entry], has_more: false });
      return respond({ receipts: [] });
    }
    if (operation === "ak.open.realm_authority.read.bundle.v1") {
      const request = body();
      context.validate("schemas/authority-commit-operations.schema.json#/$defs/realm_authority_bundle_request_body", request);
      const fixture = knownRealm(request.realm_id);
      if (!fixture || fixture.committed_events[0]?.event.payload.object.purpose === "principal_control") return fail("not_found", "Realm not found");
      return respond(context.native("mock-realm-authority-bundle-for-request", { fixture, request }));
    }
    return false;
  };
}
