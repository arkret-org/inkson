// Parity contract consumed by `cotest/tests/inkson_mock_parity.rs`.
// Each branch here is shadowed by a fixture entry in
// `cotest/tests/fixtures/inkson_mock_parity.json` and gets compared
// against a real soland process. When adding a branch, also add the
// matching fixture case — unmatched branches are silently dead code.
const DEMO_REALM = "ak:realm:0196419b-0000-7000-8000-000000000000";

export function mockArkretContract(req) {
  const method = (req.method ?? "GET").toUpperCase();
  const path = canonicalPath(req.path ?? "/");
  const body = req.body ?? {};
  const query = req.query ?? {};

  if (method === "GET" && path === "/_arkret/describe") {
    return json({
      service_id: "did:web:server.local",
      trust_domain: "ak:trust_domain:server.local",
      service_kind: "principal_server",
      protocol_version: "1.0",
      supported_profiles: [
        "ak.profile.minimal_client.v1",
        "ak.profile.chat_mvp.v1",
        "ak.profile.kanban_mvp.v1",
        "ak.profile.full_client.v1",
        "ak.profile.principal_server_events_api.v1",
      ],
      supported_features: ["sync.client_sync", "directory.search_realms", "events.submit"],
      supported_operations: [
        "ak.server.query.describe",
        "ak.self.events.command.submit",
        "ak.self.events.query.scan",
        "ak.find.directory.query.search_realms",
        "ak.self.keys.backups.query.list",
        "ak.self.ephemeral.command.send",
      ],
      limits: {},
    });
  }

  if (method === "POST" && path === "/_arkret/self/events") {
    // Canonical EventsSubmitOutcome wire shape (soland head 37ce729):
    // {status, accepted[], cursor} — no top-level event_id/sync_token.
    const acceptedId =
      body.event_id ??
      firstEventId(body.events) ??
      "ak:event:0196419b-0000-7000-8000-00000000e2e0";
    // soland's EventsSubmitOutcome skips empty/null fields (duplicate, rejected,
    // actor_frontier, realm_frontier) via serde skip_serializing_if, so a clean
    // accept serializes to exactly {status, accepted, cursor}. Match that shape.
    return json({
      status: "accepted",
      accepted: [acceptedId],
      cursor: "sx:e2e:event",
    });
  }

  if (method === "GET" && path === "/_arkret/self/events") {
    return json({ events: [], next_cursor: null, has_more: false });
  }

  if (method === "GET" && path === "/_arkret/self/account/viewer") {
    const principalId = req.account?.did ?? "did:web:alice.example";
    return json({
      principal_id: principalId,
      state: "active",
      devices: [],
      primary_handle_claim: {
        schema: "ak.schema.handle_claim.v1",
        handle: "alice:local.host",
        subject: principalId,
        binding_state: "verified",
      },
      profile: {
        id: "ak:actor_profile:01964137-0000-7000-8000-0000000000a1",
        schema: "ak.schema.actor_profile.v1",
        principal_id: principalId,
        actor_kind: "user",
        display_name: "inkson",
        created_at: "2026-04-28T12:00:00.000Z",
      },
    });
  }

  if (method === "GET" && path === "/_arkret/find/directory/describe") {
    return json({
      service_id: "did:web:server.local",
      trust_domain: "ak:trust_domain:server.local",
      service_kind: "directory_service",
      protocol_version: "1.0",
      supported_profiles: ["ak.profile.directory_service.v1"],
      supported_operations: ["ak.find.directory.query.describe"],
      supported_bindings: [{ kind: "http_json" }],
      supported_features: [],
      auth_metadata: { mode: "public_no_auth" },
      limits: {},
      plaintext_visibility: {},
      rate_limit_policy: {},
      implemented_features: [],
      claimed_profiles: [],
      verified_profiles: [],
      experimental_features: [],
      compat_surfaces: [],
      development_mode: false,
      resource_kinds: ["realm", "organization", "actor"],
      discovery_profiles: ["ak.profile.directory_service.v1"],
      restricted_query_proof: false,
      ingest_modes: ["push"],
      accept_policy_kind: "open",
      default_ttl_seconds: 86400,
      max_ttl_seconds: 604800,
      revalidation_grace_seconds: 3600,
      accepted_resource_kinds: ["realm", "organization", "actor"],
      accepted_did_methods: ["did:web"],
      rate_limits: {},
    });
  }

  if (method === "POST" && path === "/_arkret/find/directory/search-realms") {
    return json({
      realms: [realmPreview()],
      has_more: false,
    });
  }

  if (method === "GET" && path === "/_arkret/self/keys/backups") {
    const backups = [];
    const backupClass = query.backup_kind;
    return json({
      backups: backupClass
        ? backups.filter((backup) => backup.backup_kind === backupClass)
        : backups,
      has_more: false,
    });
  }

  if (method === "GET" && path === "/_arkret/root/identity/recovery-policy") {
    return json({
      active_policy: null,
      principal_id: body.principal_id ?? req.account?.did ?? "did:web:alice.example",
    });
  }

  if (method === "POST" && path === "/_arkret/gate/account/device-pair") {
    const deviceId = body.new_device_pubkey?.kid ?? "ak:device:01964137-0000-7000-8000-0000000000b2";
    return json({
      device_id: deviceId,
      authorized_event_ref: "ak:event:01964137-0000-7000-8000-00000000d001",
    });
  }

  // Server-mediated device-pairing short-link (open, unauthenticated).
  if (method === "POST" && path === "/_arkret/open/device-pairing/requests") {
    return json({
      device_pairing_request_id: "device_pairing_request:01964137-0000-7000-8000-0000000000c1",
      pairing_code: "7H2K9M4Q",
      gate_audience: "https://local.host",
      server_nonce: "Y290ZXN0LXNlcnZlci1wYWlyaW5nLW5vbmNl",
      expires_at: "2099-01-01T00:00:00.000Z",
    });
  }

  if (method === "POST" && path === "/_arkret/open/device-pairing/resolve") {
    return json({
      arkret_base_url: "https://local.host",
      device_pairing_request_id: "device_pairing_request:01964137-0000-7000-8000-0000000000c1",
      pairing_code: "7H2K9M4Q",
      new_device_pubkey: {
        kty: "OKP",
        kid: "ak:device:01964137-0000-7000-8000-0000000000b2",
        alg: "EdDSA",
        key: "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
      },
      client_nonce: "Y290ZXN0LWRldmljZS1wYWlyaW5nLW5vbmNl",
      gate_audience: "https://local.host",
      server_nonce: "Y290ZXN0LXNlcnZlci1wYWlyaW5nLW5vbmNl",
      display_name: "New device",
      device_metadata: { platform: "browser" },
      expires_at: "2099-01-01T00:00:00.000Z",
    });
  }

  if (method === "POST" && path === "/_arkret/open/device-pairing/requests/status") {
    return json({
      state: "authorized",
      device_id: "ak:device:01964137-0000-7000-8000-0000000000b2",
      authorized_event_ref: "ak:event:01964137-0000-7000-8000-00000000d001",
    });
  }

  if (method === "POST" && path === "/_arkret/self/ephemeral") {
    if (!["ak.receipt.read", "ak.typing", "ak.presence", "ak.call.signal"].includes(body.kind)) {
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
      server_received_at: "2026-04-28T12:00:00.000Z",
    });
  }

  return undefined;
}

// Short-form aliases for callers that pass a path without the `/_arkret/`
// prefix. Each alias MUST resolve to a path with a matching branch above;
// `/realm/create` and `/realms/create` were dropped together with the
// realm/space creation surface forbidden by inkson/tests/server_contract.rs.
// `/account/viewer` is the short alias for the spec account viewer. Profile
// update remains distinct and MUST NOT collapse onto this read path.
export function canonicalPath(path) {
  const clean = path.startsWith("/_arkret/") ? path : path.replace(/\/+$/, "");
  const aliases = {
    "/server/describe": "/_arkret/describe",
    "/events/submit": "/_arkret/self/events",
    "/events/list": "/_arkret/self/events",
    "/account/viewer": "/_arkret/self/account/viewer",
    "/directory/search-realms": "/_arkret/find/directory/search-realms",
    "/keys/backups": "/_arkret/self/keys/backups",
    "/gate/account/device-pair": "/_arkret/gate/account/device-pair",
    "/ephemeral": "/_arkret/self/ephemeral",
  };
  return aliases[clean] ?? clean;
}

function firstEventId(events) {
  return Array.isArray(events) ? events.find((event) => event?.event_id)?.event_id : undefined;
}

function json(body, status = 200) {
  return { status, body };
}

// Mirrors the shape soland's `/_arkret/find/directory/search-realms` actually emits
// (see `soland/src/routing/spaces/directory.rs::search_realms`). The fields
// here MUST stay aligned with that endpoint — the cotest parity test runs
// this response against a live soland process.
function realmPreview() {
  return {
    realm_id: DEMO_REALM,
    title: "Arkret Demo Realm",
    summary: "Shared demo Realm served by mocked server",
    discoverability: "public",
    join_rule: "public",
    member_count_bucket: "1-10",
    as_of: "2026-06-13T00:00:00.000Z",
    source_refs: ["ak:event:0196419b-0000-7000-8000-000000000001"],
    policy_revision: "mock-policy-rev",
  };
}
