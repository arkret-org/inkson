// Parity contract consumed by `cotest/tests/yougen_mock_parity.rs`.
// Each branch here is shadowed by a fixture entry in
// `cotest/tests/fixtures/yougen_mock_parity.json` and gets compared
// against a real soland process. When adding a branch, also add the
// matching fixture case — unmatched branches are silently dead code.
const DEMO_SPACE = "ck:space:0196419b-0000-7000-8000-000000000000";

export function mockCokretContract(req) {
  const method = (req.method ?? "GET").toUpperCase();
  const path = canonicalPath(req.path ?? "/");
  const body = req.body ?? {};

  if (method === "GET" && path === "/api/v1/server/describe") {
    return json({
      service_did: "did:web:server.local",
      trust_domain: "ck:trust_domain:server.local",
      service_type: "principal_server",
      protocol_version: "1.0",
      supported_profiles: [
        "cx.profile.minimal_client.v1",
        "cx.profile.chat_mvp.v1",
        "cx.profile.kanban_mvp.v1",
        "cx.profile.full_client.v1",
        "cx.profile.principal_server_events_api.v1",
      ],
      supported_features: ["sync.client_sync", "directory.search_realms", "events.submit"],
      supported_operations: [
        "cx.events.submit",
        "cx.events.query",
        "cx.directory.search_realms",
        "cx.keys.backups.list",
        "cx.ephemeral.broadcast",
      ],
      limits: {},
    });
  }

  if (method === "POST" && path === "/api/v1/events") {
    return json({
      event_id: body.event_id ?? firstEventId(body.events) ?? "ck:event:e2e",
      status: "accepted",
      canonical_digest: "sha256:e2e-event",
      sync_token: "sx:e2e:event",
      received_at: "2026-04-28T12:00:00Z",
      receipt: {
        idempotent: false,
        reducer_profile: "cx.reducer.v1",
        projection_source: body.event_id ?? firstEventId(body.events) ?? "ck:event:e2e",
      },
    });
  }

  if (method === "GET" && path === "/api/v1/events") {
    return json({ events: [], next_cursor: null });
  }

  if (method === "GET" && path === "/api/v1/account/me") {
    return json({
      did: "did:web:alice.example",
      handle: "alice.example",
      display_name: "yougen",
      created_at: "2026-04-28T12:00:00Z",
    });
  }

  if (method === "GET" && path === "/api/v1/directory/describe") {
    return json({
      service_did: "did:web:server.local",
      resource_types: ["space", "organization", "actor"],
      discovery_profiles: ["cx.profile.directory_service.v1"],
      restricted_query_proof: false,
    });
  }

  if (method === "POST" && path === "/api/v1/directory/search-realms") {
    return json({
      results: [spacePreview()],
      next_cursor: null,
    });
  }

  if (method === "GET" && path === "/api/v1/keys/backups") {
    return json({ backups: [] });
  }

  if (method === "POST" && path === "/api/v1/devices/pairing-challenge") {
    const deviceId = body.device_id ?? "dev_yougen";
    return json({
      challenge_id: `ck:device_challenge:${deviceId}`,
      device_id: deviceId,
      expires_at: "2026-04-28T12:05:00Z",
      server_signature: "mock-signature",
    });
  }

  if (method === "POST" && path === "/api/v1/ephemeral") {
    if (!["cx.receipt.read", "cx.typing", "cx.presence", "cx.call.signal"].includes(body.kind)) {
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

// Short-form aliases for callers that pass a path without the `/api/v1/`
// prefix. Each alias MUST resolve to a path with a matching branch above;
// `/realm/create` and `/space/create` were dropped together with the legacy
// realm/space creation surface forbidden by yougen/tests/server_contract.rs.
// `/account/me` (read) and `/account/profile` (update) are distinct
// endpoints — no alias collapses one onto the other.
export function canonicalPath(path) {
  const clean = path.startsWith("/api/v1/") ? path : path.replace(/\/+$/, "");
  const aliases = {
    "/server/describe": "/api/v1/server/describe",
    "/events/submit": "/api/v1/events",
    "/events/list": "/api/v1/events",
    "/account/me": "/api/v1/account/me",
    "/directory/search-realms": "/api/v1/directory/search-realms",
    "/keys/backups": "/api/v1/keys/backups",
    "/devices/pairing-challenge": "/api/v1/devices/pairing-challenge",
    "/ephemeral": "/api/v1/ephemeral",
  };
  return aliases[clean] ?? clean;
}

function firstEventId(events) {
  return Array.isArray(events) ? events.find((event) => event?.event_id)?.event_id : undefined;
}

function json(body, status = 200) {
  return { status, body };
}

// Mirrors the shape soland's `/api/v1/directory/search-realms` actually emits
// (see `soland/src/routing/spaces/directory.rs::search_realms`). The fields
// here MUST stay aligned with that endpoint — the cotest parity test runs
// this response against a live soland process.
function spacePreview() {
  return {
    realm_id: DEMO_SPACE.replace(/^ck:space:/, "ck:realm:"),
    name: "Cokret Demo Space",
    description: "Shared demo Space served by mocked server",
    public: true,
    category: null,
    members: ["did:web:alice.example"],
    tags: [],
  };
}
