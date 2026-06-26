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
  const query = req.query ?? {};

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
        "ck.server.query.describe",
        "ck.self.events.command.submit",
        "ck.self.events.query.scan",
        "ck.find.directory.query.search_realms",
        "ck.self.keys.backups.query.list",
        "ck.self.ephemeral.command.send",
      ],
      limits: {},
    });
  }

  if (method === "POST" && path === "/_cokret/self/events") {
    // Canonical EventsSubmitOutcome wire shape (soland head 37ce729):
    // {status, accepted[], cursor} — no top-level event_id/sync_token.
    const acceptedId = body.event_id ?? firstEventId(body.events) ?? "ck:event:e2e";
    // soland's EventsSubmitOutcome skips empty/null fields (duplicate, rejected,
    // actor_frontier, realm_frontier) via serde skip_serializing_if, so a clean
    // accept serializes to exactly {status, accepted, cursor}. Match that shape.
    return json({
      status: "accepted",
      accepted: [acceptedId],
      cursor: "sx:e2e:event",
    });
  }

  if (method === "GET" && path === "/_cokret/self/events") {
    return json({ events: [], next_cursor: null, has_more: false });
  }

  if (method === "GET" && path === "/_cokret/self/account/viewer") {
    return json({
      principal_id: "did:web:alice.example",
      state: "active",
      devices: [],
      primary_handle_claim: {
        schema: "ck.schema.handle_claim.v1",
        handle: "alice:local.host",
        subject: "did:web:alice.example",
      },
      profile: {
        id: "ck:actor_profile:01964137-0000-7000-8000-0000000000a1",
        schema: "ck.schema.actor_profile.v1",
        principal_id: "did:web:alice.example",
        actor_kind: "user",
        display_name: "yougen",
        created_at: "2026-04-28T12:00:00Z",
      },
    });
  }

  if (method === "GET" && path === "/_cokret/find/directory/describe") {
    return json({
      service_did: "did:web:server.local",
      trust_domain: "ck:trust_domain:server.local",
      service_type: "directory_service",
      protocol_version: "1.0",
      supported_profiles: ["ck.profile.directory_service.v1"],
      supported_operations: ["ck.find.directory.query.describe"],
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
      resource_types: ["realm", "organization", "actor"],
      discovery_profiles: ["ck.profile.directory_service.v1"],
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

  if (method === "POST" && path === "/_cokret/find/directory/search-realms") {
    return json({
      realms: [realmPreview()],
      has_more: false,
    });
  }

  if (method === "GET" && path === "/_cokret/self/keys/backups") {
    const backups = [];
    const backupClass = query.backup_class;
    return json({
      backups: backupClass
        ? backups.filter((backup) => backup.backup_class === backupClass)
        : backups,
      has_more: false,
    });
  }

  if (method === "GET" && path === "/_cokret/root/identity/recovery-policy") {
    return json({
      active_policy: null,
      principal_id: body.principal_id ?? req.account?.did ?? "did:web:alice.example",
    });
  }

  if (method === "POST" && path === "/_cokret/gate/account/device-pair") {
    const deviceId = body.new_device_pubkey?.kid ?? "ck:device:01964137-0000-7000-8000-0000000000b2";
    return json({
      device_id: deviceId,
      authorized_event_ref: "ck:event:01964137-0000-7000-8000-00000000d001",
      device_grant: {
        status: "active",
        authorized_by_device_id: req.account?.device_id,
        authorized_at: "2026-04-28T12:00:00Z",
        display_name: body.display_name ?? null,
      },
      key_backup_hint: {},
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
// `/realm/create` and `/realms/create` were dropped together with the
// realm/space creation surface forbidden by yougen/tests/server_contract.rs.
// `/account/viewer` is the short alias for the spec account viewer. Profile
// update remains distinct and MUST NOT collapse onto this read path.
export function canonicalPath(path) {
  const clean = path.startsWith("/_cokret/") ? path : path.replace(/\/+$/, "");
  const aliases = {
    "/server/describe": "/_cokret/describe",
    "/events/submit": "/_cokret/self/events",
    "/events/list": "/_cokret/self/events",
    "/account/viewer": "/_cokret/self/account/viewer",
    "/directory/search-realms": "/_cokret/find/directory/search-realms",
    "/keys/backups": "/_cokret/self/keys/backups",
    "/gate/account/device-pair": "/_cokret/gate/account/device-pair",
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
    summary: "Shared demo Realm served by mocked server",
    discoverability: "public",
    join_rule: "public",
    member_count_bucket: "1-10",
    as_of: "2026-06-13T00:00:00Z",
    source_refs: ["ck:event:0196419b-0000-7000-8000-000000000001"],
    policy_revision: "mock-policy-rev",
  };
}
