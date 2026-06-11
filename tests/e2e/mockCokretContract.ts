// Parity contract consumed by `cotest/tests/yougen_mock_parity.rs`.
// Each branch here is shadowed by a fixture entry in
// `cotest/tests/fixtures/yougen_mock_parity.json` and gets compared
// against a real soland process. When adding a branch, also add the
// matching fixture case — unmatched branches are silently dead code.
const DEMO_REALM = "ck:realm:0196419b-0000-7000-8000-000000000000";

export function mockCokretContract(req) {
  const method = (req.method ?? "GET").toUpperCase();
  const path = canonicalPath(req.path ?? "/");
  const body = req.body ?? {};

  if (method === "GET" && path === "/_cokret/describe") {
    return json({
      service_did: "did:web:server.local",
      trust_domain: "ck:trust_domain:server.local",
      service_type: "principal_server",
      protocol_version: "1.0",
      supported_profiles: [
        "ck.profile.minimal_client.v1",
        "ck.profile.chat_mvp.v1",
        "ck.profile.kanban_mvp.v1",
        "ck.profile.full_client.v1",
        "ck.profile.principal_server_events_api.v1",
      ],
      supported_features: ["sync.client_sync", "directory.search_realms", "events.submit"],
      supported_operations: [
        "ck.self.events.submit",
        "ck.self.events.query",
        "ck.find.directory.search_realms",
        "ck.self.keys.backups.list",
        "ck.ephemeral.broadcast",
      ],
      limits: {},
    });
  }

  if (method === "POST" && path === "/_cokret/self/events") {
    // Canonical EventsSubmitOutcome wire shape (soland head 37ce729):
    // {status, accepted[], cursor} — no top-level event_id/sync_token.
    const acceptedId = body.event_id ?? firstEventId(body.events) ?? "ck:event:e2e";
    return json({
      status: "accepted",
      accepted: [acceptedId],
      duplicate: [],
      rejected: [],
      actor_frontier: {},
      realm_frontier: {},
      cursor: "sx:e2e:event",
    });
  }

  if (method === "GET" && path === "/_cokret/self/events") {
    return json({ events: [], next_cursor: null });
  }

  if (method === "GET" && path === "/_soland/self/account/me") {
    return json({
      did: "did:web:alice.example",
      handle: "alice.example",
      display_name: "yougen",
      created_at: "2026-04-28T12:00:00Z",
    });
  }

  if (method === "GET" && path === "/_cokret/find/directory/describe") {
    return json({
      service_did: "did:web:server.local",
      resource_types: ["space", "organization", "actor"],
      discovery_profiles: ["ck.profile.directory_service.v1"],
      restricted_query_proof: false,
    });
  }

  if (method === "POST" && path === "/_cokret/find/directory/search-realms") {
    return json({
      results: [realmPreview()],
      next_cursor: null,
    });
  }

  if (method === "GET" && path === "/_cokret/self/keys/backups") {
    return json({ backups: [] });
  }

  if (method === "POST" && path === "/_cokret/self/devices/pairing-challenge") {
    const deviceId = body.device_id ?? "dev_yougen";
    return json({
      challenge_id: `ck:device_challenge:${deviceId}`,
      device_id: deviceId,
      expires_at: "2026-04-28T12:05:00Z",
      server_signature: "mock-signature",
    });
  }

  if (method === "POST" && path === "/_cokret/self/ephemeral") {
    if (!["ck.receipt.read", "ck.typing", "ck.presence", "ck.call.signal"].includes(body.kind)) {
      return json(
        {
          ok: false,
          error: { code: "invalid_param", message: "expected broadcast ephemeral kind" },
        },
        400,
      );
    }
    return json({
      accepted: true,
      kind: body.kind,
      realm_id: body.realm_id,
      server_received_at: "2026-04-28T12:00:00Z",
    });
  }

  return undefined;
}

// Short-form aliases for callers that pass a path without the `/_cokret/`
// prefix. Each alias MUST resolve to a path with a matching branch above;
// `/realm/create` and `/realms/create` were dropped together with the legacy
// realm/space creation surface forbidden by yougen/tests/server_contract.rs.
// `/account/me` (read) and `/account/profile` (update) are distinct
// endpoints — no alias collapses one onto the other.
export function canonicalPath(path) {
  const clean = path.startsWith("/_cokret/") ? path : path.replace(/\/+$/, "");
  const aliases = {
    "/server/describe": "/_cokret/describe",
    "/events/submit": "/_cokret/self/events",
    "/events/list": "/_cokret/self/events",
    "/account/me": "/_soland/self/account/me",
    "/directory/search-realms": "/_cokret/find/directory/search-realms",
    "/keys/backups": "/_cokret/self/keys/backups",
    "/devices/pairing-challenge": "/_cokret/self/devices/pairing-challenge",
    "/ephemeral": "/_cokret/self/ephemeral",
  };
  return aliases[clean] ?? clean;
}

function firstEventId(events) {
  return Array.isArray(events) ? events.find((event) => event?.event_id)?.event_id : undefined;
}

function json(body, status = 200) {
  return { status, body };
}

// Mirrors the shape soland's `/_cokret/find/directory/search-realms` actually emits
// (see `soland/src/routing/spaces/directory.rs::search_realms`). The fields
// here MUST stay aligned with that endpoint — the cotest parity test runs
// this response against a live soland process.
function realmPreview() {
  return {
    realm_id: DEMO_REALM,
    title: "Cokret Demo Realm",
    description: "Shared demo Realm served by mocked server",
    public: true,
    category: null,
    members: ["did:web:alice.example"],
    tags: [],
  };
}
