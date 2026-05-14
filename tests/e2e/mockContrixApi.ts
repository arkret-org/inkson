import type { Page, Route } from "@playwright/test";

const DEMO_SPACE = "cx:space:0196419b-0000-7000-8000-000000000000";
const SETUP_SPACE = "cx:space:01js0setupflow000000000000";
const CHILD_SPACE = "cx:space:01launchchild0000000000000";
const GRANDCHILD_SPACE = "cx:space:01launchdeep00000000000000";

export async function mockContrixApi(page: Page) {
  let setupSpaceDeleted = false;
  let setupMembers = ["did:web:alice.example", "did:web:bob.example"];
  let messageCounter = 0;
  let submitCounter = 0;
  const timelineEvents: Array<Record<string, unknown>> = [];

  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/health") {
      return json(route, { ok: true, service: "serverx", storage: "memory" });
    }
    if (url.hostname === "auth.local.host" && url.pathname === "/.well-known/openid-configuration") {
      return json(route, {
        issuer: "https://auth.local.host/",
        authorization_endpoint: "https://auth.local.host/authorize",
        token_endpoint: "https://auth.local.host/oauth2/token",
        userinfo_endpoint: "https://auth.local.host/oauth2/userinfo",
        code_challenge_methods_supported: ["plain", "S256"],
        scopes_supported: ["openid", "profile"],
      });
    }
    if (url.hostname === "auth.local.host" && url.pathname === "/authorize") {
      return route.fulfill({
        status: 200,
        contentType: "text/html",
        body: "<!doctype html><main data-testid=\"coauth-login\"><h1>Sign in</h1><p>coauth</p><a href=\"/register\">Create account</a><a href=\"/recovery\">Lost password or account</a></main>",
      });
    }
    if (!url.pathname.startsWith("/api/v1/")) {
      return route.continue();
    }

    if (url.pathname === "/api/v1/server/describe") {
      if (url.hostname === "auth.local.host") {
        return json(route, {
          service_did: "did:web:auth.local.host",
          service_type: "auth_server",
          protocol_version: "1.0",
          auth_metadata: {
            oauth_issuer: "https://auth.local.host/",
            openid_configuration: "https://auth.local.host/.well-known/openid-configuration",
            issuer_did: "did:web:auth.local.host",
            supported_auth_methods: ["password", "oidc"],
            supported_grant_types: ["authorization_code", "refresh_token"],
            did_binding_methods: ["did_controller_key", "device_key"],
            required_audience: "https://auth.local.host/api/v1",
            session_grant_scope: "urn:contrix:principal-server:session.bind",
            oidc_clients: [
              {
                id: "01GFWR28C4KNE04WG3HKXB7C9R",
                client_id: "01GFWR28C4KNE04WG3HKXB7C9R",
                client_name: "Yougen Dev",
                redirect_uris: ["http://127.0.0.1/auth/callback"],
                grant_types: ["authorization_code", "refresh_token"],
                token_endpoint_auth_method: "none",
              },
            ],
          },
          limits: {},
        });
      }
      return json(route, {
        service_did: "did:web:serverx.local",
        service_type: "principal_server",
        protocol_version: "1.0",
        supported_profiles: [
          "cx.profile.minimal_client.v1",
          "cx.profile.chat_only_client.v1",
          "cx.profile.kanban_only_client.v1",
          "cx.profile.full_client.v1",
          "cx.profile.e2ee_client.v1",
          "cx.profile.push_gateway.v1",
          "cx.profile.mimi_interop.v1",
          "cx.profile.core_event_store.v1",
          "cx.profile.principal_server_events_api.v1",
        ],
        supported_features: [
          "sync.client_sync",
          "sync.backfill",
          "directory.search_spaces",
          "directory.resolve_space",
          "authz.check",
          "space.create",
          "space.manage_members",
          "message.create",
          "message.revise",
          "message.redact",
          "reaction.add",
          "keys.upload",
          "keys.query",
          "keys.claim",
          "device_messages.receive",
          "device_messages.send",
          "push.register_device",
          "mimi_provider_facade",
          "events.submit",
          "moves.submit",
        ],
        supported_operations: [
          "cx.sync.account",
          "cx.events.query",
          "cx.events.subscribe",
          "cx.directory.search_spaces",
          "cx.directory.resolve_space",
          "cx.authz.check",
          "cx.spaces.create",
          "cx.events.submit",
          "cx.message.create",
          "cx.message.revise",
          "cx.message.redact",
          "cx.reaction.add",
          "cx.keys.upload",
          "cx.keys.query",
          "cx.keys.claim",
          "cx.device_messages.receive",
          "cx.device_messages.send",
          "cx.push.register_device",
          "cx.mimi.provider_directory",
          "cx.events.describe",
          "cx.events.submit",
          "cx.moves.submit",
        ],
        supported_schema_profiles: ["cx.schema.core.v1"],
        supported_reducer_profiles: ["cx.reducer.v1"],
        auth_metadata: {
          mode: "development",
          supported_auth_methods: ["oauth2_bearer_introspection"],
          auth_server_url: "https://auth.local.host",
        },
        limits: { storage: "memory" },
      });
    }

    if (url.hostname === "auth.local.host" && url.pathname === "/api/v1/auth/bridge/describe") {
      return json(route, {
        contract: "contrix.rest.auth_bridge.v1",
        version: "2026-05-04-scaffold",
        api_base_path: "/api/v1",
        oauth: {
          discovery_path: "/.well-known/openid-configuration",
          browser_bridge_session_path: "/api/v1/auth/oidc/browser-bridge/session",
          exchange_describe_path: "/api/v1/auth/oidc/exchange/describe",
          exchange_path: "/api/v1/auth/oidc/exchange",
          supported_flows: ["authorization_code_pkce_browser"],
        },
        contrix: {
          login_path: "/api/v1/auth/login",
          logout_path: "/api/v1/auth/logout",
          providers_path: "/api/v1/auth/providers",
          session_grants_path: "/api/v1/session-grants",
          session_grants_introspect_path: "/api/v1/session-grants/introspect",
          session_grant_scope: "urn:contrix:principal-server:session.bind",
        },
        todos: [],
      });
    }

    if (url.hostname === "auth.local.host" && url.pathname === "/api/v1/integration/describe") {
      return json(route, {
        contract: "contrix.rest.integration_manifest.v1",
        version: "2026-05-04-scaffold",
        service: "coauth",
        service_kind: "account_authority",
        api_base_path: "/api/v1",
        describe_path: "/api/v1/integration/describe",
        dependencies: [],
        surfaces: [],
        examples: {},
        todos: [],
      });
    }

    if (url.pathname === "/api/v1/events/describe") {
      return json(route, {
        service_did: "did:web:serverx.local",
        schema_profiles: ["cx.schema.core.v1"],
        reducer_profiles: ["cx.reducer.v1"],
        supported_event_types: [
          "cx.flow.create",
          "cx.flow.move",
          "cx.flow.track.enable",
          "cx.message.create",
        ],
        frontier: ["cx:event:e2e"],
      });
    }

    if (url.pathname === "/api/v1/events" && route.request().method() === "POST") {
      const body = await route.request().postDataJSON();
      if (!route.request().headers()["x-contrix-request-id"]) {
        return json(route, {
          ok: false,
          error: { errcode: "missing_request_id", error: "missing x-contrix-request-id" },
        }, 428);
      }
      let syncToken = "sx:e2e:event";
      if (body.kind === "cx.message.create") {
        messageCounter += 1;
        syncToken = `sx:e2e:message-${messageCounter}`;
        timelineEvents.push({
          ...(body.payload ?? {}),
          event_id: body.event_id,
          kind: body.kind,
          space_id: body.space_id ?? DEMO_SPACE,
          actor_id: body.actor_id ?? "did:web:alice.example",
          actor_seq: body.actor_seq,
          created_at: body.created_at ?? "2026-04-28T12:00:00Z",
          payload: body.payload,
        });
      }
      if (body.kind === "cx.flow.create") {
        messageCounter += 1;
        syncToken = `sx:e2e:flow-${messageCounter}`;
        timelineEvents.push({
          ...(body.payload ?? {}),
          event_id: body.event_id,
          kind: body.kind,
          space_id: body.space_id ?? DEMO_SPACE,
          actor_id: body.actor_id ?? "did:web:alice.example",
          actor_seq: body.actor_seq,
          created_at: body.created_at ?? "2026-04-28T12:00:00Z",
          payload: body.payload,
        });
      }
      return json(route, {
        event_id: body.event_id,
        status: "accepted",
        canonical_digest: "sha256:e2e-event",
        sync_token: syncToken,
        received_at: "2026-04-28T12:00:00Z",
        receipt: {
          idempotent: false,
          reducer_profile: "cx.reducer.v1",
          projection_source: body.event_id,
        },
      });
    }

    if (url.pathname === "/api/v1/moves" && route.request().method() === "POST") {
      const body = await route.request().postDataJSON();
      submitCounter += 1;
      return json(route, {
        move_id: body.id ?? `cx:move:sha256:e2e-${submitCounter}`,
        state: "pending",
        reason: null,
      });
    }

    if (url.pathname === "/api/v1/mimi/provider-directory") {
      return json(route, mimiProviderDirectory());
    }

    if (url.pathname === "/api/v1/mimi/key-material") {
      return json(route, {
        ok: true,
        key_packages: [{ key_package_ref: "mimi:key-package:e2e", target: "mimi://remote.example/alice" }],
        receipt: { kind: "cx.mimi.key_material", profile: "cx.profile.mimi_interop.v1" },
      });
    }

    if (url.pathname.match(/^\/api\/v1\/mimi\/rooms\/[^/]+\/update$/) && route.request().method() === "PUT") {
      const roomId = decodeURIComponent(url.pathname.split("/")[5]);
      return json(route, {
        ok: true,
        room_id: roomId,
        receipt: { kind: "cx.mimi.room_update", operation_id: "cx:operation:mimi-room-update" },
      });
    }

    if (url.pathname.match(/^\/api\/v1\/mimi\/rooms\/[^/]+\/notify$/)) {
      return json(route, {
        ok: true,
        accepted: ["did:web:remote.example"],
        receipt: { kind: "cx.mimi.notify", notification_id: "cx:mimi:notify:e2e" },
      });
    }

    if (url.pathname.match(/^\/api\/v1\/mimi\/rooms\/[^/]+\/messages$/)) {
      return json(route, {
        ok: true,
        mimi_message_id: "mimi-msg-e2e",
        mapped_operation_id: "cx:operation:mimi-submit-e2e",
        contrix_event_id: "cx:event:mimi-submit-e2e",
        receipt: {
          kind: "cx.mimi.mapping_receipt",
          profile: "cx.profile.mimi_interop.v1",
          mimi_room_uri: "mimi://mimi.example.com/rooms/01JSMIMI",
          source_format: "text/markdown;variant=GFM-MIMI",
          target_format: "cx.message.create",
          original_envelope_hash: "sha256:e2e-mimi-envelope",
          mapped_operation_id: "cx:operation:mimi-submit-e2e",
          mimi_message_id: "mimi-msg-e2e",
        },
      });
    }

    if (url.pathname.match(/^\/api\/v1\/mimi\/rooms\/[^/]+\/group-info$/)) {
      const roomId = decodeURIComponent(url.pathname.split("/")[5]);
      return json(route, {
        room_id: roomId,
        mimi_room_uri: "mimi://mimi.example.com/rooms/01JSMIMI",
        group_info: { epoch: 7, mls_group_id: "mls-group-01", policy_root: "sha256:e2e-policy-root" },
        participants: [
          { identifier: "mimi://mimi.example.com/alice", did: "did:web:alice.example", role: "admin" },
          { identifier: "mimi://remote.example/bob", did: "did:web:bob.example", role: "member" },
        ],
        receipt: { kind: "cx.mimi.group_info", profile: "cx.profile.mimi_interop.v1" },
      });
    }

    if (url.pathname === "/api/v1/mimi/consent/request") {
      return json(route, {
        ok: true,
        consent_id: "cx:mimi-consent:e2e",
        state: "requested",
        receipt: { kind: "cx.mimi.request_consent" },
      });
    }

    if (url.pathname === "/api/v1/mimi/consent/update") {
      return json(route, {
        ok: true,
        consent_id: "cx:mimi-consent:e2e",
        state: "accepted",
        receipt: { kind: "cx.mimi.update_consent" },
      });
    }

    if (url.pathname === "/api/v1/mimi/identifiers/query") {
      const body = await route.request().postDataJSON();
      return json(route, {
        query: body.query,
        reachable: true,
        mapped_did: "did:web:alice.example",
        provider_id: "mimi://mimi.example.com",
        proofs: [{ type: "private_identifier_query", expires_at: "2026-04-30T12:00:00Z" }],
        receipt: { kind: "cx.mimi.identifier_query", privacy_mode: body.privacy_mode },
      });
    }

    if (url.pathname === "/api/v1/mimi/report-abuse") {
      return json(route, {
        ok: true,
        report_id: "cx:report:mimi-e2e",
        status: "queued",
        receipt: { kind: "cx.mimi.report_abuse" },
      });
    }

    if (url.pathname === "/api/v1/mimi/proxy-download") {
      return json(route, {
        ok: true,
        blob_ref: "cx:blob:sha256:e2e",
        media_type: "application/octet-stream",
        size: 23,
        proxy_url: "/api/v1/mimi/proxy-download/cx:blob:sha256:e2e",
        receipt: { kind: "cx.mimi.proxy_download", direct_object_store_url: null },
      });
    }

    if (url.pathname === "/api/v1/auth/dev-login") {
      const body = await route.request().postDataJSON();
      return json(route, {
        access_token: "sx_playwright_token",
        token_type: "Bearer",
        actor: body.actor,
        device_id: body.device_id,
        expires_at: "2026-04-28T12:00:00Z",
      });
    }

    if (url.pathname === "/api/v1/auth/passkey/challenge") {
      const body = await route.request().postDataJSON();
      return json(route, {
        challenge: "playwright-passkey-challenge",
        rp_id: "127.0.0.1",
        user_did: body.user_did,
        expires_at: "2026-04-28T12:05:00Z",
      });
    }

    if (url.pathname === "/api/v1/auth/oidc/authorize") {
      return json(route, {
        redirect_url: "https://idp.example/authorize?state=oidc-state-e2e",
        state: "oidc-state-e2e",
      });
    }

    if (url.pathname === "/api/v1/auth/token/refresh") {
      return json(route, {
        access_token: "sx_playwright_refreshed",
        token_type: "Bearer",
        expires_at: "2026-04-28T13:00:00Z",
      });
    }

    if (url.pathname === "/api/v1/account/register") {
      const body = await route.request().postDataJSON();
      return json(route, {
        did: body.did,
        handle: body.handle,
        display_name: body.display_name,
        created_at: "2026-04-28T12:00:00Z",
      }, 201);
    }

    if (url.pathname === "/api/v1/account/me") {
      return json(route, {
        did: "did:web:alice.example",
        handle: "alice.example",
        display_name: "yougen",
        created_at: "2026-04-28T12:00:00Z",
      });
    }

    if (url.pathname === "/api/v1/auth/logout") {
      return json(route, { ok: true });
    }

    if (url.pathname === "/api/v1/spaces" && route.request().method() === "POST") {
      const body = await route.request().postDataJSON();
      setupSpaceDeleted = false;
      setupMembers = ["did:web:alice.example", ...(body.invitees ?? [])];
      return json(route, spaceLifecycle(SETUP_SPACE, setupMembers, setupSpaceDeleted), 201);
    }

    if (url.pathname.match(/^\/api\/v1\/spaces\/[^/]+$/) && route.request().method() === "PATCH") {
      const spaceId = decodeURIComponent(url.pathname.split("/").pop() ?? DEMO_SPACE);
      return json(route, { ok: true, space_id: spaceId });
    }

    if (url.pathname.match(/^\/api\/v1\/spaces\/[^/]+\/policy$/) && route.request().method() === "PUT") {
      const body = await route.request().postDataJSON();
      const spaceId = decodeURIComponent(url.pathname.split("/")[4]);
      return json(route, {
        ok: true,
        space_id: spaceId,
        join_rule: body.join_rule,
        history_visibility: body.history_visibility,
      });
    }

    if (url.pathname.match(/^\/api\/v1\/spaces\/[^/]+\/invite$/) && route.request().method() === "POST") {
      const body = await route.request().postDataJSON();
      const spaceId = decodeURIComponent(url.pathname.split("/")[4]);
      return json(route, {
        ok: true,
        invite_id: "cx:invite:e2e",
        space_id: spaceId,
        target: body.target,
        state: "pending",
      });
    }

    if (url.pathname.match(/^\/api\/v1\/spaces\/[^/]+\/invite\/accept$/) && route.request().method() === "POST") {
      const body = await route.request().postDataJSON();
      const spaceId = decodeURIComponent(url.pathname.split("/")[4]);
      return json(route, {
        ok: true,
        invite_id: body.invite_id,
        space_id: spaceId,
        target: "did:web:carol.example",
        state: "accepted",
      });
    }

    if (url.pathname.match(/^\/api\/v1\/spaces\/[^/]+\/invite\/reject$/) && route.request().method() === "POST") {
      const body = await route.request().postDataJSON();
      const spaceId = decodeURIComponent(url.pathname.split("/")[4]);
      return json(route, {
        ok: true,
        invite_id: body.invite_id,
        space_id: spaceId,
        target: "did:web:carol.example",
        state: "canceled",
      });
    }

    if (url.pathname.match(/^\/api\/v1\/spaces\/[^/]+\/archive$/) && route.request().method() === "POST") {
      const spaceId = decodeURIComponent(url.pathname.split("/")[4]);
      return json(route, { ok: true, space_id: spaceId, archived: true });
    }

    if (url.pathname.match(/^\/api\/v1\/spaces\/[^/]+\/leave$/) && route.request().method() === "POST") {
      const spaceId = decodeURIComponent(url.pathname.split("/")[4]);
      return json(route, { ok: true, space_id: spaceId });
    }

    if (url.pathname.match(/^\/api\/v1\/spaces\/[^/]+\/members\/.+\/ban$/) && route.request().method() === "POST") {
      const parts = url.pathname.split("/");
      return json(route, {
        ok: true,
        space_id: decodeURIComponent(parts[4]),
        member: decodeURIComponent(parts[6]),
        banned: true,
      });
    }

    if (url.pathname === "/api/v1/mls/rotate") {
      const body = await route.request().postDataJSON();
      return json(route, { ok: true, epoch: 2, group_id: body.group_id });
    }

    if (url.pathname === `/api/v1/spaces/${SETUP_SPACE}/members` && route.request().method() === "POST") {
      const body = await route.request().postDataJSON();
      if (!setupMembers.includes(body.member)) {
        setupMembers.push(body.member);
      }
      return json(route, spaceLifecycle(SETUP_SPACE, setupMembers, setupSpaceDeleted));
    }

    if (url.pathname === `/api/v1/spaces/${SETUP_SPACE}/members/did:web:bob.example` && route.request().method() === "DELETE") {
      setupMembers = setupMembers.filter((member) => member !== "did:web:bob.example");
      return json(route, spaceLifecycle(SETUP_SPACE, setupMembers, setupSpaceDeleted));
    }

    if (url.pathname === `/api/v1/spaces/${SETUP_SPACE}` && route.request().method() === "DELETE") {
      setupSpaceDeleted = true;
      return json(route, spaceLifecycle(SETUP_SPACE, setupMembers, setupSpaceDeleted));
    }

    if (url.pathname === "/api/v1/sync") {
      const demoTimelineEvents = timelineEvents.filter((event) => event.space_id === DEMO_SPACE);
      return json(route, {
        next_batch: "sx:e2e:2",
        spaces: {
          [DEMO_SPACE]: {
            summary: {
              title: "Contrix Demo Space",
              summary: "Shared demo Space served by mocked serverx",
              child_space_ids: [CHILD_SPACE],
            },
            timeline: { events: demoTimelineEvents, limited: false },
            state: [],
            ephemeral: [],
            unread: { notification_count: 0, highlight_count: 0 },
          },
          [CHILD_SPACE]: {
            summary: {
              title: "Launch Child Space",
              summary: "Nested board and discussion scope",
              parent_space_id: DEMO_SPACE,
              child_space_ids: [GRANDCHILD_SPACE],
            },
            timeline: { events: [], limited: false },
            state: [],
            ephemeral: [],
            unread: { notification_count: 0, highlight_count: 0 },
          },
          [GRANDCHILD_SPACE]: {
            summary: {
              title: "Launch Deep Space",
              summary: "Grandchild scope fixture",
              parent_space_id: CHILD_SPACE,
            },
            timeline: { events: [], limited: false },
            state: [],
            ephemeral: [],
            unread: { notification_count: 0, highlight_count: 0 },
          },
        },
        to_device: [{ type: "cx.mls.welcome", content: { ciphertext: "opaque" } }],
        account_data: [
          {
            kind: "cx.notification",
            notification_id: "notif-msg-1",
            title: "New message",
            body: "Alice sent a message in Demo Space",
            space_id: DEMO_SPACE,
            notification_kind: "message",
            type: "message",
            timestamp: "2026-04-28T12:01:00Z",
            read: false,
          },
          {
            kind: "cx.notification",
            notification_id: "notif-invite-1",
            title: "New invite",
            body: "You were invited to review Demo Space",
            space_id: DEMO_SPACE,
            notification_kind: "invite",
            type: "invite",
            timestamp: "2026-04-28T12:02:00Z",
            read: false,
          },
        ],
        device_lists: { changed: [], left: [] },
      });
    }

    if (url.pathname === "/api/v1/directory/search-spaces") {
      return json(route, {
        results: [spacePreview()],
        next_cursor: null,
      });
    }

    if (url.pathname === "/api/v1/directory/search-organizations") {
      return json(route, {
        results: [
          {
            id: "did:web:org.contrix.example",
            did: "did:web:org.contrix.example",
            handle: "contrix.example",
            name: "Contrix Labs",
            description: "Protocol and client engineering for Contrix deployments.",
            discoverability: "listed",
            profile_visibility: "public",
            directory_services: ["did:web:serverx.local"],
            proofs: [{ type: "org_membership" }],
          },
        ],
        next_cursor: null,
      });
    }

    if (url.pathname === "/api/v1/directory/search-actors") {
      return json(route, {
        results: [
          {
            did: "did:web:bob.example",
            handle: "bob.example",
            display_name: "Bob Example",
          },
        ],
        next_cursor: null,
      });
    }

    if (url.pathname === "/api/v1/directory/resolve-handle") {
      const body = await route.request().postDataJSON();
      return json(route, {
        did: "did:web:alice.example",
        handle: body.handle,
        did_document: {
          id: "did:web:alice.example",
          alsoKnownAs: [`acct:${body.handle}`],
        },
      });
    }

    if (url.pathname === "/api/v1/directory/resolve-space") {
      return json(route, {
        space_preview: spacePreview(),
        stripped_state: [],
        join_rule: "public",
        via_services: ["did:web:serverx.local"],
      });
    }

    if (url.pathname === "/api/v1/directory/describe") {
      return json(route, {
        service_did: "did:web:serverx.local",
        resource_types: ["space", "organization", "actor"],
        discovery_profiles: ["cx.profile.directory_service.v1"],
        restricted_query_proof: false,
      });
    }

    if (url.pathname === "/api/v1/events") {
      const requestedSpaces = (url.searchParams.get("spaces") ?? "")
        .split(",")
        .map((space) => space.trim())
        .filter(Boolean);
      const events = requestedSpaces.length
        ? timelineEvents.filter((event) => requestedSpaces.includes(String(event.space_id)))
        : timelineEvents;
      return json(route, { events, next_cursor: null, frontier: {} });
    }

    if (url.pathname === "/api/v1/sync/snapshot-head") {
      return json(route, {
        snapshot_ref: `cx:snapshot:${DEMO_SPACE}:head`,
        state_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        frontier: { space_id: DEMO_SPACE },
        signature: { alg: "none" },
      });
    }

    if (url.pathname === "/api/v1/identity/describe") {
      return json(route, {
        service_did: "did:web:serverx.local",
        registry_mode: "development_local",
        supported_receipts: ["local"],
        protocol_version: "1.0",
        profiles: ["cx.identity.local-dev.v1"],
      });
    }

    if (url.pathname === "/api/v1/identity/resolve") {
      const body = await route.request().postDataJSON();
      return json(route, {
        did_document: { id: body.did },
        key_log_head: null,
        seq: 0,
        receipts: [],
        method_evidence: { mode: "development_local" },
      });
    }

    if (url.pathname === "/api/v1/identity/submit-did-operation") {
      return json(route, {
        ok: true,
        operation_id: "cx:didop:e2e",
        status: "accepted",
      }, 202);
    }

    if (url.pathname === "/api/v1/sync/describe") {
      return json(route, {
        service_did: "did:web:serverx.local",
        supported_sync_profiles: ["initial", "incremental"],
        limits: {},
        frontier: {},
      });
    }

    if (url.pathname === "/api/v1/authz/check") {
      return json(route, {
        allowed: true,
        reason_code: "frontier_current",
        grants: ["cx:grant:e2e"],
        obligations: [{ type: "audit", reason_required: false }],
      });
    }

    if (url.pathname === "/api/v1/authz/effective-grants") {
      return json(route, {
        grants: [
          {
            grant_id: "cx:grant:e2e",
            issuer: "did:web:admin.example",
            subject: url.searchParams.get("subject"),
            actions: ["space.read", "message.create"],
            resource_selectors: ["space:cx:space:0196419b-0000-7000-8000-000000000000/**"],
            constraints: [
              { type: "temporal", not_after: "2026-12-31T00:00:00Z" },
              {
                type: "type_restriction",
                params: { object_type_allow: ["space"], facet_allow: ["renderable", "stateful"] },
              },
            ],
            delegation_chain: ["cx:grant:root", "cx:grant:e2e"],
          },
        ],
        state_hash: "cx:statehash:e2e",
        evaluated_at: "2026-04-28T12:00:00Z",
      });
    }

    if (url.pathname === "/api/v1/authz/invites") {
      return json(route, { invites: [], next_cursor: null });
    }

    if (url.pathname === "/api/v1/profile/presence") {
      return json(route, { actor: url.searchParams.get("did"), presence: "online" });
    }

    if (url.pathname === "/api/v1/keys/upload") {
      return json(route, { one_time_key_counts: { signed_curve25519: 1 }, fallback_keys: {} });
    }

    if (url.pathname === "/api/v1/keys/query") {
      return json(route, { device_keys: {}, failures: {} });
    }

    if (url.pathname === "/api/v1/keys/claim") {
      return json(route, { one_time_keys: {}, failures: {} });
    }

    if (url.pathname === "/api/v1/device_messages" && route.request().method() === "GET") {
      return json(route, { events: [], next_batch: "sx:devmsg:1", limited: false });
    }

    if (url.pathname === "/api/v1/device_messages" && route.request().method() === "POST") {
      return json(route, { ok: true, delivered: { "did:web:alice.example": ["dev_yougen"] }, unknown_devices: {} });
    }

    if (url.pathname === "/api/v1/receipts") {
      const body = await route.request().postDataJSON();
      if (body.receipt_type !== "cx.receipt.read") {
        return json(route, {
          ok: false,
          error: { errcode: "invalid_receipt_type", error: "expected cx.receipt.read" },
        }, 400);
      }
      return json(route, { ok: true });
    }

    if (url.pathname === "/api/v1/push/register-device") {
      return json(route, { ok: true, registration_id: "cx:push:e2e", expires_at: null });
    }

    if (url.pathname === "/api/v1/push/unregister-device") {
      return json(route, { ok: true });
    }

    if (url.pathname === "/api/v1/blob/upload") {
      return json(route, {
        blob_ref: "cx:blob:sha256:e2e",
        size: 22,
        media_type: "application/octet-stream",
        sha256: "01015dc8af66d01f557ea63f13538f1964848840a350c5311d1efc8ad138bb91",
        thumbnail_ref: "cx:blob:sha256:e2e-thumb",
        upload_receipt: { service_did: "did:web:serverx.local", content_hash_verified: true },
      });
    }

    if (url.pathname === "/api/v1/media/ice-config") {
      return json(route, {
        ice_servers: [
          { urls: ["stun:stun.serverx.local:3478"] },
          {
            urls: ["turn:turn.serverx.local:3478?transport=udp"],
            username: "turn-user",
            credential: "turn-secret",
          },
        ],
        ttl_seconds: 600,
      });
    }

    if (url.pathname === "/api/v1/blob/get") {
      return route.fulfill({ status: 200, contentType: "application/octet-stream", body: "yougen encrypted bytes" });
    }

    if (url.pathname === "/api/v1/moderation/report") {
      return json(route, { report_id: "cx:report:e2e", status: "queued", routed_to: ["did:web:serverx.local#moderation"] });
    }

    return json(route, { ok: false, error: { errcode: "not_found", error: `No e2e mock for ${url.pathname}` } }, 404);
  });
}

function spacePreview() {
  return {
    space_id: DEMO_SPACE,
    name: "Contrix Demo Space",
    description: "Shared demo Space served by mocked serverx",
    tags: ["demo"],
    public: true,
    category: "collaboration",
  };
}

function spaceLifecycle(spaceId: string, members: string[], deleted: boolean) {
  return {
    ok: true,
    space_id: spaceId,
    owner: "did:web:alice.example",
    members,
    deleted,
  };
}

function mimiProviderDirectory() {
  return {
    schema: "cx.schema.mimi_interop.v1",
    service_did: "did:web:mimi.example.com",
    service_type: "mimi_provider_facade",
    supported_profiles: ["cx.profile.mimi_interop.v1"],
    mimi: {
      protocol_draft: "draft-ietf-mimi-protocol-06",
      content_draft: "draft-ietf-mimi-content-08",
      room_policy_draft: "draft-ietf-mimi-room-policy-03",
      identifier_draft: "draft-kohbrok-mimi-identifiers-01",
      base_url: "https://mimi.example.com/api/v1/mimi",
      provider_id: "mimi://mimi.example.com",
      features: [
        "key_material",
        "room_update",
        "notify",
        "submit_message",
        "group_info",
        "consent",
        "identifier_query",
        "report_abuse",
        "proxy_download",
      ],
      mls_cipher_suites: ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
      content_profiles: [
        "application/mimi-content",
        "text/plain;charset=utf-8",
        "text/markdown;variant=GFM-MIMI",
        "application/vnd.contrix.content+json",
      ],
      room_policy_components: ["roles", "join_rules", "history_visibility"],
    },
    proof: { type: "mock-http-message-signature" },
  };
}

function json(route: Route, body: unknown, status = 200) {
  return route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}
