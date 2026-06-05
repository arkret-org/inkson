import type { Page, Route } from "@playwright/test";
import { mockCokretContract } from "./mockCokretContract";

const DEMO_REALM = "ck:realm:0196419b-0000-7000-8000-000000000000";
const SETUP_REALM = "ck:realm:01js0setupflow000000000000";
const CHILD_REALM = "ck:realm:01launchchild0000000000000";
const GRANDCHILD_REALM = "ck:realm:01launchdeep00000000000000";
const DEMO_BOARD_SPACE = "ck:space:0196419b-0000-7000-8000-00000000b0a0";
const DEMO_SECOND_BOARD_SPACE = "ck:space:0196419b-0000-7000-8000-00000000b0b0";
const DEMO_TODO_LIST = "ck:space:01list-todo000000000000000000";
const DEMO_PROGRESS_LIST = "ck:space:01list-progress00000000000000";
const DEMO_DONE_LIST = "ck:space:01list-done00000000000000000";
const DEMO_SECOND_LIST = "ck:space:01list-secondary000000000000";
const DEMO_FLOW_LEGAL_REVIEW = "ck:flow:0196419b-0000-7000-8000-000000000101";
const DEMO_FLOW_ONBOARDING_COPY = "ck:flow:0196419b-0000-7000-8000-000000000102";
const DEMO_FLOW_SECURITY_SIGNOFF = "ck:flow:0196419b-0000-7000-8000-000000000103";
const DEMO_FLOW_SECONDARY_CARD = "ck:flow:0196419b-0000-7000-8000-000000000104";

type SpaceContainerProjection = {
  container_space_id: string;
  realm_id: string;
  kind: string;
  title: string;
  state: string;
  rank?: string;
  parent_space_id?: string;
};

type FlowProjection = {
  flow_id: string;
  realm_id: string;
  title: string;
  summary?: string;
  state: string;
  board_space_id?: string;
  list_space_id?: string;
  rank?: string;
  fields?: Record<string, unknown>;
};

export async function mockCokretApi(page: Page) {
  let messageCounter = 0;
  const createdRealms: Array<{ id: string; title: string; summary: string; encryption_profile: string }> = [];
  const timelineEvents: Array<Record<string, unknown>> = [];
  const eventRealmId = (event: Record<string, unknown>) =>
    String(event.realm_id ?? "");
  const boardSpaceContainers: SpaceContainerProjection[] = [
    {
      container_space_id: DEMO_BOARD_SPACE,
      realm_id: DEMO_REALM,
      kind: "board",
      title: "Persisted demo board",
      state: "active",
    },
    {
      container_space_id: DEMO_SECOND_BOARD_SPACE,
      realm_id: DEMO_REALM,
      kind: "board",
      title: "Secondary planning board",
      state: "active",
    },
    {
      container_space_id: DEMO_TODO_LIST,
      realm_id: DEMO_REALM,
      kind: "list",
      title: "To Do",
      state: "active",
      rank: "U",
      parent_space_id: DEMO_BOARD_SPACE,
    },
    {
      container_space_id: DEMO_PROGRESS_LIST,
      realm_id: DEMO_REALM,
      kind: "list",
      title: "In Progress",
      state: "active",
      rank: "f",
      parent_space_id: DEMO_BOARD_SPACE,
    },
    {
      container_space_id: DEMO_DONE_LIST,
      realm_id: DEMO_REALM,
      kind: "list",
      title: "Done",
      state: "active",
      rank: "p",
      parent_space_id: DEMO_BOARD_SPACE,
    },
    {
      container_space_id: DEMO_SECOND_LIST,
      realm_id: DEMO_REALM,
      kind: "list",
      title: "Selected Backlog",
      state: "active",
      rank: "U",
      parent_space_id: DEMO_SECOND_BOARD_SPACE,
    },
  ];
  const boardFlowProjections: FlowProjection[] = [
    {
      flow_id: DEMO_FLOW_LEGAL_REVIEW,
      realm_id: DEMO_REALM,
      title: "Legal review for public beta",
      summary: "Finalize external processor wording before launch checklist can move.",
      state: "active",
      board_space_id: DEMO_BOARD_SPACE,
      list_space_id: DEMO_TODO_LIST,
      rank: "U",
      fields: {
        labels: ["legal", "beta"],
        assignee: "Alice",
        due_at: "May 08",
        discussion_visibility: "locked",
        discussion_ref_hash: "sha256:locked-private-decision",
        locked_reason: "You can see that a restricted discussion is linked, but not its name or members.",
      },
    },
    {
      flow_id: DEMO_FLOW_ONBOARDING_COPY,
      realm_id: DEMO_REALM,
      title: "Onboarding copy",
      summary: "Waiting on discussion-scoped feedback from support and docs reviewers.",
      state: "active",
      board_space_id: DEMO_BOARD_SPACE,
      list_space_id: DEMO_PROGRESS_LIST,
      rank: "U",
      fields: { labels: ["copy", "support"], assignee: "Bob", due_at: "May 10" },
    },
    {
      flow_id: DEMO_FLOW_SECURITY_SIGNOFF,
      realm_id: DEMO_REALM,
      title: "Security sign-off",
      summary: "Projection detected a stale column head after an offline move.",
      state: "active",
      board_space_id: DEMO_BOARD_SPACE,
      list_space_id: DEMO_DONE_LIST,
      rank: "U",
      fields: { labels: ["security", "reviewed"], assignee: "Carol", due_at: "May 01" },
    },
    {
      flow_id: DEMO_FLOW_SECONDARY_CARD,
      realm_id: DEMO_REALM,
      title: "Secondary board card",
      summary: "Only visible after the Board selector switches projection scope.",
      state: "active",
      board_space_id: DEMO_SECOND_BOARD_SPACE,
      list_space_id: DEMO_SECOND_LIST,
      rank: "U",
      fields: { labels: ["planning"], assignee: "Dana", due_at: "May 12" },
    },
  ];

  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/health") {
      return json(route, { ok: true, service: "server", storage: "memory" });
    }
    if (url.hostname === "auth.local.host" && url.pathname === "/.well-known/openid-configuration") {
      return json(route, {
        issuer: "https://auth.local.host/",
        authorization_endpoint: "https://auth.local.host/authorize",
        token_endpoint: "https://auth.local.host/oauth/token",
        userinfo_endpoint: "https://auth.local.host/oauth/userinfo",
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
    if (!url.pathname.startsWith("/_cokret/")) {
      return route.continue();
    }

    if (url.pathname === "/_cokret/describe") {
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
            required_audience: "https://auth.local.host/_cokret/gate",
            session_grant_scope: "urn:cokret:principal-server:session.bind",
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
        service_did: "did:web:server.local",
        trust_domain: "ck:trust_domain:server.local",
        service_type: "principal_server",
        protocol_version: "1.0",
        supported_profiles: [
          "ck.profile.minimal_client.v1",
          "ck.profile.chat_mvp.v1",
          "ck.profile.kanban_mvp.v1",
          "ck.profile.full_client.v1",
          "ck.profile.e2ee_client.v1",
          "ck.profile.push_gateway.v1",
          "ck.profile.mimi_interop.v1",
          "ck.profile.core_event_store.v1",
          "ck.profile.principal_server_events_api.v1",
        ],
        supported_features: [
          "sync.client_sync",
          "sync.backfill",
          "directory.search_realms",
          "directory.resolve_realm",
          "authz.check",
          "realm.create",
          "space.create",
          "space.manage_members",
          "message.create",
          "message.revise",
          "message.redact",
          "reaction.add",
          "keys.upload",
          "keys.query",
          "keys.claim",
          "device_messages.get",
          "device_messages.put",
          "push.register_device",
          "mimi_provider_facade",
          "events.submit",
        ],
        supported_operations: [
          "ck.self.account.subscribe",
          "ck.self.events.query",
          "ck.self.events.subscribe",
          "ck.find.directory.search_realms",
          "ck.find.directory.resolve_realm",
          "ck.self.authz.check",
          "ck.realm.create",
          "ck.space.create",
          "ck.member.state",
          "ck.invite.create",
          "ck.invite.accept",
          "ck.invite.cancel",
          "ck.self.events.submit",
          "ck.message.create",
          "ck.message.revise",
          "ck.message.redact",
          "ck.reaction.add",
          "ck.self.keys.upload",
          "ck.self.keys.query",
          "ck.self.keys.claim",
          "ck.self.device_messages.get",
          "ck.self.device_messages.put",
          "ck.edge.push.register_device",
          "ck.open.mimi.provider_directory",
          "ck.self.events.describe",
          "ck.self.events.submit",
        ],
        supported_schema_profiles: ["ck.schema.core.v1"],
        supported_reducer_profiles: ["ck.reducer.v1"],
        supported_bindings: [{ kind: "http_json" }],
        auth_metadata: {
          mode: "development",
          supported_auth_methods: ["oauth2_bearer_introspection"],
          auth_server_url: "https://auth.local.host",
        },
        limits: { storage: "memory" },
        rate_limit_policy: { writes_per_minute: 120 },
        plaintext_visibility: {
          default: "e2ee",
          allowed_services: ["did:web:server.local"],
        },
        implemented_features: [],
        claimed_profiles: [],
        verified_profiles: [],
        experimental_features: [],
        compat_surfaces: [],
        development_mode: true,
      });
    }

    if (url.hostname === "auth.local.host" && url.pathname === "/_cokret/gate/auth/bridge/describe") {
      return json(route, {
        contract: "cokret.rest.auth_bridge.v1",
        version: "2026-05-04-scaffold",
        api_base_path: "/_cokret/gate",
        oauth: {
          discovery_path: "/.well-known/openid-configuration",
          browser_bridge_session_path: "/_cokret/gate/auth/oidc/browser-bridge/session",
          exchange_describe_path: "/_cokret/gate/auth/oidc/exchange/describe",
          exchange_path: "/_cokret/gate/auth/oidc/exchange",
          supported_flows: ["authorization_code_pkce_browser"],
        },
        cokret: {
          login_path: "/_cokret/gate/auth/login",
          logout_path: "/_soland/gate/auth/logout",
          providers_path: "/_cokret/gate/auth/providers",
          session_grants_path: "/_cokret/gate/session-grants",
          session_grants_introspect_path: "/_cokret/gate/session-grants/introspect",
          session_grant_scope: "urn:cokret:principal-server:session.bind",
        },
        todos: [],
      });
    }

    if (url.hostname === "auth.local.host" && url.pathname === "/_cokret/gate/auth/oidc/browser-bridge/session") {
      const body = await route.request().postDataJSON();
      const redirectUri = body.redirect_uri ?? "http://127.0.0.1:4527/auth/callback";
      const principalAudience = body.principal_audience ?? "did:web:server.local";
      const authorizeUrl = new URL("https://auth.local.host/authorize");
      authorizeUrl.searchParams.set("response_type", "code");
      authorizeUrl.searchParams.set("client_id", "01GFWR28C4KNE04WG3HKXB7C9R");
      authorizeUrl.searchParams.set("redirect_uri", redirectUri);
      authorizeUrl.searchParams.set("scope", "openid");
      authorizeUrl.searchParams.set("state", "oidc-state-e2e");
      authorizeUrl.searchParams.set("nonce", "oidc-nonce-e2e");
      authorizeUrl.searchParams.set("resource", principalAudience);
      authorizeUrl.searchParams.set("code_challenge_method", "S256");
      authorizeUrl.searchParams.set("code_challenge", "oidc-code-challenge-e2e");
      return json(route, {
        contract: "cokret.rest.auth_bridge.oidc_browser_session.v1",
        version: "2026-05-04-scaffold",
        authorize_url: authorizeUrl.toString(),
        callback_uri: redirectUri,
        issuer: "https://auth.local.host/",
        authorization_endpoint: "https://auth.local.host/authorize",
        token_endpoint: "https://auth.local.host/oauth/token",
        userinfo_endpoint: "https://auth.local.host/oauth/userinfo",
        client_id: "01GFWR28C4KNE04WG3HKXB7C9R",
        state: "oidc-state-e2e",
        nonce: "oidc-nonce-e2e",
        code_verifier: "oidc-code-verifier-e2e",
        code_challenge: "oidc-code-challenge-e2e",
        code_challenge_method: "S256",
        principal_audience: principalAudience,
        todo: "mock browser bridge session",
      });
    }

    if (url.hostname === "auth.local.host" && url.pathname === "/_cokret/gate/integration/describe") {
      return json(route, {
        contract: "cokret.rest.integration_manifest.v1",
        version: "2026-05-04-scaffold",
        service: "coauth",
        service_kind: "account_authority",
        api_base_path: "/_cokret/gate",
        describe_path: "/_cokret/gate/integration/describe",
        dependencies: [],
        surfaces: [],
        examples: {},
        todos: [],
      });
    }

    if (url.pathname === "/_cokret/self/projection/spaces") {
      const realmId = url.searchParams.get("realm_id") ?? DEMO_REALM;
      return json(route, {
        realm_id: realmId,
        total: boardSpaceContainers.length,
        spaces: boardSpaceContainers,
      });
    }

    if (url.pathname === "/_cokret/self/projection/flows") {
      const realmId = url.searchParams.get("realm_id") ?? DEMO_REALM;
      return json(route, {
        realm_id: realmId,
        total: boardFlowProjections.length,
        flows: boardFlowProjections,
      });
    }

    if (url.pathname === "/_cokret/self/events/describe") {
      return json(route, {
        service_did: "did:web:server.local",
        schema_profiles: ["ck.schema.core.v1"],
        reducer_profiles: ["ck.reducer.v1"],
        supported_event_types: [
          "ck.flow.create",
          "ck.flow.move",
          "ck.flow.tracks.update",
          "ck.message.create",
        ],
        frontier: ["ck:event:e2e"],
      });
    }

    if (url.pathname === "/_cokret/self/events" && route.request().method() === "POST") {
      const body = await route.request().postDataJSON();
      if (!route.request().headers()["x-cokret-request-id"]) {
        return json(route, {
          ok: false,
          error: { code: "missing_request_id", message: "missing x-cokret-request-id" },
        }, 428);
      }
      let syncToken = "sx:e2e:event";
      const submittedEvents = Array.isArray(body.events) ? body.events : [body];
      for (const event of submittedEvents) {
        if (event.kind !== "ck.realm.create") {
          continue;
        }
        const raw = JSON.stringify(event);
        const id =
          event.realm_id ??
          event.payload?.realm_id ??
          event.payload?.object?.realm_id ??
          raw.match(/ck:realm:[0-9a-f-]+/)?.[0] ??
          SETUP_REALM;
        const title =
          event.payload?.object?.title ??
          event.payload?.title ??
          event.payload?.fields?.title ??
          "Setup Flow Space";
        const summary =
          event.payload?.object?.summary ??
          event.payload?.summary ??
          event.payload?.fields?.summary ??
          "Created from yougen workspace setup";
        const encryptionProfile =
          event.payload?.object?.encryption_profile ??
          event.payload?.encryption_profile ??
          "mls_rfc9420";
        if (!createdRealms.some((realm) => realm.id === id)) {
          createdRealms.push({ id, title, summary, encryption_profile: encryptionProfile });
        }
      }
      if (body.kind === "ck.space.create") {
        const object = body.payload?.object ?? {};
        const containerId =
          object.id ?? body.payload?.space_id ?? body.payload?.container_space_id ?? body.target_ref;
        if (typeof containerId === "string" && !boardSpaceContainers.some((row) => row.container_space_id === containerId)) {
          boardSpaceContainers.push({
            container_space_id: containerId,
            realm_id: object.realm_id ?? body.realm_id ?? DEMO_REALM,
            kind: object.kind ?? "list",
            title: object.title ?? containerId,
            state: "active",
            rank: object.rank,
            parent_space_id: object.parent_space_id,
          });
        }
      }
      if (body.kind === "ck.message.create") {
        messageCounter += 1;
        syncToken = `sx:e2e:message-${messageCounter}`;
        const realmId = body.realm_id ?? DEMO_REALM;
        timelineEvents.push({
          ...(body.payload ?? {}),
          event_id: body.event_id,
          kind: body.kind,
          realm_id: realmId,
          actor_id: body.actor_id ?? "did:web:alice.example",
          actor_seq: body.actor_seq,
          created_at: body.created_at ?? "2026-04-28T12:00:00Z",
          payload: body.payload,
        });
      }
      if (body.kind === "ck.flow.create") {
        messageCounter += 1;
        syncToken = `sx:e2e:flow-${messageCounter}`;
        const object = body.payload?.object ?? {};
        const component = Array.isArray(body.payload?.components)
          ? body.payload.components.find(
              (candidate: { family?: string }) => candidate.family === "ck.component.flow.position.v1",
            )
          : undefined;
        const flowId = body.payload?.flow_id ?? object.id;
        if (typeof flowId === "string") {
          const fields = object.fields ?? {};
          const nextProjection: FlowProjection = {
            flow_id: flowId,
            realm_id: object.realm_id ?? body.realm_id ?? DEMO_REALM,
            title: object.title ?? body.payload?.title ?? flowId,
            summary: object.summary,
            state: "active",
            board_space_id: component?.board_space_id ?? fields.board_space_id,
            list_space_id: component?.list_space_id ?? fields.list_space_id,
            rank: component?.rank ?? fields.rank ?? body.payload?.rank,
            fields,
          };
          const existing = boardFlowProjections.findIndex((row) => row.flow_id === flowId);
          if (existing >= 0) {
            boardFlowProjections[existing] = nextProjection;
          } else {
            boardFlowProjections.push(nextProjection);
          }
        }
        timelineEvents.push({
          ...(body.payload ?? {}),
          event_id: body.event_id,
          kind: body.kind,
          realm_id: body.realm_id ?? DEMO_REALM,
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
          reducer_profile: "ck.reducer.v1",
          projection_source: body.event_id,
        },
      });
    }

    if (url.pathname === "/_cokret/open/mimi/provider-directory") {
      return json(route, mimiProviderDirectory());
    }

    if (url.pathname === "/_cokret/open/mimi/key-material") {
      return json(route, {
        ok: true,
        key_packages: [{ key_package_ref: "mimi:key-package:e2e", target: "mimi://remote.example/alice" }],
        receipt: { kind: "ck.open.mimi.key_material", profile: "ck.profile.mimi_interop.v1" },
      });
    }

    if (url.pathname.match(/^\/_cokret\/open\/mimi\/rooms\/[^/]+\/update$/) && route.request().method() === "PUT") {
      const roomId = decodeURIComponent(url.pathname.split("/")[5]);
      return json(route, {
        ok: true,
        room_id: roomId,
        receipt: { kind: "ck.open.mimi.room_update", operation_id: "ck:operation:mimi-room-update" },
      });
    }

    if (url.pathname.match(/^\/_cokret\/open\/mimi\/rooms\/[^/]+\/notify$/)) {
      return json(route, {
        ok: true,
        accepted: ["did:web:remote.example"],
        receipt: { kind: "ck.open.mimi.notify", notification_id: "ck:mimi:notify:e2e" },
      });
    }

    if (url.pathname.match(/^\/_cokret\/open\/mimi\/rooms\/[^/]+\/messages$/)) {
      return json(route, {
        ok: true,
        mimi_message_id: "mimi-msg-e2e",
        mapped_operation_id: "ck:operation:mimi-submit-e2e",
        cokret_event_id: "ck:event:mimi-submit-e2e",
        receipt: {
          kind: "ck.mimi.mapping_receipt",
          profile: "ck.profile.mimi_interop.v1",
          mimi_room_uri: "mimi://mimi.example.com/rooms/01JSMIMI",
          source_format: "text/markdown;variant=GFM-MIMI",
          target_format: "ck.message.create",
          original_envelope_hash: "sha256:e2e-mimi-envelope",
          mapped_operation_id: "ck:operation:mimi-submit-e2e",
          mimi_message_id: "mimi-msg-e2e",
        },
      });
    }

    if (url.pathname.match(/^\/_cokret\/open\/mimi\/rooms\/[^/]+\/group-info$/)) {
      const roomId = decodeURIComponent(url.pathname.split("/")[5]);
      return json(route, {
        room_id: roomId,
        mimi_room_uri: "mimi://mimi.example.com/rooms/01JSMIMI",
        group_info: { epoch: 7, mls_group_id: "mls-group-01", policy_root: "sha256:e2e-policy-root" },
        participants: [
          { identifier: "mimi://mimi.example.com/alice", did: "did:web:alice.example", role: "admin" },
          { identifier: "mimi://remote.example/bob", did: "did:web:bob.example", role: "member" },
        ],
        receipt: { kind: "ck.open.mimi.group_info", profile: "ck.profile.mimi_interop.v1" },
      });
    }

    if (url.pathname === "/_cokret/open/mimi/consent/request") {
      return json(route, {
        ok: true,
        consent_id: "ck:mimi-consent:e2e",
        state: "requested",
        receipt: { kind: "ck.open.mimi.request_consent" },
      });
    }

    if (url.pathname === "/_cokret/open/mimi/consent/update") {
      return json(route, {
        ok: true,
        consent_id: "ck:mimi-consent:e2e",
        state: "accepted",
        receipt: { kind: "ck.open.mimi.update_consent" },
      });
    }

    if (url.pathname === "/_cokret/open/mimi/identifiers/query") {
      const body = await route.request().postDataJSON();
      return json(route, {
        query: body.query,
        reachable: true,
        mapped_did: "did:web:alice.example",
        provider_id: "mimi://mimi.example.com",
        proofs: [{ type: "private_identifier_query", expires_at: "2026-04-30T12:00:00Z" }],
        receipt: { kind: "ck.open.mimi.identifier_query", privacy_mode: body.privacy_mode },
      });
    }

    if (url.pathname === "/_cokret/open/mimi/report-abuse") {
      return json(route, {
        ok: true,
        report_id: "ck:report:mimi-e2e",
        status: "queued",
        receipt: { kind: "ck.open.mimi.report_abuse" },
      });
    }

    if (url.pathname === "/_cokret/open/mimi/proxy-download") {
      return json(route, {
        ok: true,
        blob_ref: "ck:blob:sha256:e2e",
        media_type: "application/octet-stream",
        size: 23,
        proxy_url: "/_cokret/open/mimi/proxy-download/ck:blob:sha256:e2e",
        receipt: { kind: "ck.open.mimi.proxy_download", direct_object_store_url: null },
      });
    }

    if (url.pathname === "/_soland/gate/auth/dev-login") {
      const body = await route.request().postDataJSON();
      return json(route, {
        access_token: "sx_playwright_token",
        token_type: "Bearer",
        actor: body.actor,
        device_id: body.device_id,
        expires_at: "2026-04-28T12:00:00Z",
      });
    }

    if (url.pathname === "/_cokret/gate/auth/passkey/challenge") {
      const body = await route.request().postDataJSON();
      return json(route, {
        challenge: "playwright-passkey-challenge",
        rp_id: "127.0.0.1",
        user_did: body.user_did,
        expires_at: "2026-04-28T12:05:00Z",
      });
    }

    if (url.pathname === "/_cokret/gate/auth/oidc/authorize") {
      return json(route, {
        redirect_url: "https://idp.example/authorize?state=oidc-state-e2e",
        state: "oidc-state-e2e",
      });
    }

    if (url.pathname === "/_cokret/gate/auth/token/refresh") {
      return json(route, {
        access_token: "sx_playwright_refreshed",
        token_type: "Bearer",
        expires_at: "2026-04-28T13:00:00Z",
      });
    }

    if (url.pathname === "/_soland/self/account/register") {
      const body = await route.request().postDataJSON();
      return json(route, {
        did: body.did,
        handle: body.handle,
        display_name: body.display_name,
        created_at: "2026-04-28T12:00:00Z",
      }, 201);
    }

    if (url.pathname === "/_soland/self/account/me") {
      return json(route, {
        did: "did:web:alice.example",
        handle: "alice.example",
        display_name: "yougen",
        created_at: "2026-04-28T12:00:00Z",
      });
    }

    if (url.pathname === "/_soland/self/account/profile") {
      const body = await route.request().postDataJSON();
      return json(route, {
        did: "did:web:alice.example",
        handle: "alice.example",
        display_name: body.display_name ?? "yougen",
        bio: body.bio ?? null,
        avatar_url: body.avatar_url ?? null,
      });
    }

    if (url.pathname === "/_soland/gate/auth/logout") {
      return json(route, { ok: true });
    }

    if (url.pathname === "/_cokret/self/mls/rotate") {
      const body = await route.request().postDataJSON();
      return json(route, { ok: true, epoch: 2, group_id: body.group_id });
    }

    if (url.pathname === "/_cokret/self/account/subscribe") {
      const demoTimelineEvents = timelineEvents.filter((event) => eventRealmId(event) === DEMO_REALM);
      const frame = {
        kind: "delta",
        cursor: "ck:cursor:e2e-2",
        realms: {
          join: {
            ...Object.fromEntries(
              createdRealms.map((realm) => [
                realm.id,
                {
                  summary: {
                    title: realm.title,
                    summary: realm.summary,
                    encryption_profile: realm.encryption_profile,
                    child_realm_ids: [],
                  },
                  timeline: {
                    events: timelineEvents.filter((event) => eventRealmId(event) === realm.id),
                    limited: false,
                  },
                  state: { events: [] },
                  ephemeral: { events: [] },
                  unread: { notification_count: 0, highlight_count: 0 },
                },
              ]),
            ),
            [DEMO_REALM]: {
              summary: {
                title: "Cokret Demo Space",
                summary: "Shared demo Space served by mocked server",
                encryption_profile: "mls_rfc9420",
                child_realm_ids: [CHILD_REALM],
              },
              timeline: { events: demoTimelineEvents, limited: false },
              state: { events: [] },
              ephemeral: { events: [] },
              unread: { notification_count: 0, highlight_count: 0 },
            },
            [CHILD_REALM]: {
              summary: {
                title: "Launch Child Space",
                summary: "Nested board and discussion scope",
                parent_realm_id: DEMO_REALM,
                child_realm_ids: [GRANDCHILD_REALM],
              },
              timeline: { events: [], limited: false },
              state: { events: [] },
              ephemeral: { events: [] },
              unread: { notification_count: 0, highlight_count: 0 },
            },
            [GRANDCHILD_REALM]: {
              summary: {
                title: "Launch Deep Space",
                summary: "Grandchild scope fixture",
                parent_realm_id: CHILD_REALM,
              },
              timeline: { events: [], limited: false },
              state: { events: [] },
              ephemeral: { events: [] },
              unread: { notification_count: 0, highlight_count: 0 },
            },
          },
          invite: {},
          knock: {},
          leave: {},
        },
        to_device: { messages: [{ type: "ck.mls.welcome", content: { ciphertext: "opaque" } }] },
        account_data: { events: [
          {
            kind: "ck.notification",
            notification_id: "notif-msg-1",
            title: "New message",
            body: "Alice sent a message in Demo Space",
            realm_id: DEMO_REALM,
            notification_kind: "message",
            type: "message",
            timestamp: "2026-04-28T12:01:00Z",
            read: false,
          },
          {
            kind: "ck.notification",
            notification_id: "notif-invite-1",
            invite_id: "ck:invite:01904100-0000-7000-8000-000000000099",
            title: "New invite",
            body: "You were invited to review Demo Space",
            realm_id: DEMO_REALM,
            notification_kind: "invite",
            type: "invite",
            timestamp: "2026-04-28T12:02:00Z",
            read: false,
          },
        ] },
        device_lists: { changed: [], left: [] },
        presence: { events: [] },
        notifications: { events: [] },
      };
      return route.fulfill({
        status: 200,
        contentType: "application/x-ndjson",
        body: `${JSON.stringify(frame)}\n${JSON.stringify({ kind: "catchup_complete", cursor: "ck:cursor:e2e-2" })}\n`,
      });
    }

    if (url.pathname === "/_cokret/find/directory/search-realms") {
      return json(route, {
        results: [realmPreview()],
        next_cursor: null,
      });
    }

    if (url.pathname === "/_cokret/find/directory/search-organizations") {
      return json(route, {
        results: [
          {
            id: "did:web:org.cokret.example",
            did: "did:web:org.cokret.example",
            handle: "cokret.example",
            name: "Cokret Labs",
            description: "Protocol and client engineering for Cokret deployments.",
            discoverability: "listed",
            profile_visibility: "public",
            directory_services: ["did:web:server.local"],
            proofs: [{ type: "org_membership" }],
          },
        ],
        next_cursor: null,
      });
    }

    if (url.pathname === "/_cokret/find/directory/search-actors") {
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

    if (url.pathname === "/_cokret/find/directory/resolve-handle") {
      const body = await route.request().postDataJSON();
      const audience =
        body.audience ?? body.realm_id ?? body.requester ?? "did:web:server.local";
      const memberDeliveryBinding = {
        recipient_service_did: "did:web:server.local",
        recipient_service_type: "principal_server",
        binding_source: "explicit",
        delivery_modes: ["events", "sync", "to_device", "push", "key_packages"],
      };
      return json(route, {
        did: "did:web:alice.example",
        subject: "did:web:alice.example",
        handle: body.handle,
        audience,
        member_delivery_binding: memberDeliveryBinding,
        handle_claim: {
          subject: "did:web:alice.example",
          handle: body.handle,
          issuer: "did:web:server.local",
          audience,
          member_delivery_binding: memberDeliveryBinding,
        },
        did_document: {
          id: "did:web:alice.example",
          alsoKnownAs: [`acct:${body.handle}`],
        },
      });
    }

    if (url.pathname === "/_cokret/find/directory/resolve-realm") {
      return json(route, {
        realm_preview: realmPreview(),
        stripped_state: [],
        join_rule: "public",
        join_candidates: [joinCandidate()],
      });
    }

    if (url.pathname === "/_cokret/find/directory/describe") {
      return json(route, {
        service_did: "did:web:server.local",
        resource_types: ["space", "organization", "actor"],
        discovery_profiles: ["ck.profile.directory_service.v1"],
        restricted_query_proof: false,
      });
    }

    if (url.pathname === "/_cokret/self/events/query") {
      const requestedRealms = (url.searchParams.get("realms") ?? "")
        .split(",")
        .map((realm) => realm.trim())
        .filter(Boolean);
      const events = requestedRealms.length
        ? timelineEvents.filter((event) => requestedRealms.includes(eventRealmId(event)))
        : timelineEvents;
      return json(route, { events, next_cursor: null, frontier: {} });
    }

    if (url.pathname === "/_cokret/self/snapshot/head") {
      return json(route, {
        snapshot_ref: `ck:snapshot:${DEMO_REALM}:head`,
        state_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        frontier: { realm_id: DEMO_REALM },
        signature: { alg: "none" },
      });
    }

    if (url.pathname === "/_cokret/root/identity/describe") {
      return json(route, {
        service_did: "did:web:server.local",
        registry_mode: "development_local",
        supported_receipts: ["local"],
        protocol_version: "1.0",
        profiles: ["ck.identity.local-dev.v1"],
      });
    }

    if (url.pathname === "/_cokret/root/identity/resolve") {
      const body = await route.request().postDataJSON();
      return json(route, {
        did_document: { id: body.did },
        key_log_head: null,
        seq: 0,
        receipts: [],
        method_evidence: { mode: "development_local" },
      });
    }

    if (url.pathname === "/_cokret/root/identity/submit-did-operation") {
      return json(route, {
        ok: true,
        operation_id: "ck:didop:e2e",
        status: "accepted",
      }, 202);
    }

    if (url.pathname === "/_cokret/self/account/describe") {
      return json(route, {
        service_did: "did:web:server.local",
        supported_sync_profiles: ["initial", "incremental"],
        limits: {},
        frontier: {},
      });
    }

    if (url.pathname === "/_cokret/self/authz/check") {
      return json(route, {
        allowed: true,
        reason_code: "frontier_current",
        grants: ["ck:grant:e2e"],
        obligations: [{ type: "audit", reason_required: false }],
      });
    }

    if (url.pathname === "/_cokret/self/authz/effective-grants") {
      return json(route, {
        grants: [
          {
            grant_id: "ck:grant:e2e",
            issuer: "did:web:admin.example",
            subject: url.searchParams.get("subject"),
            actions: ["space.read", "message.create"],
            resource_selectors: [`realm:${DEMO_REALM}`],
            constraints: [
              { type: "temporal", not_after: "2026-12-31T00:00:00Z" },
              {
                type: "type_restriction",
                params: { object_type_allow: ["space"], facet_allow: ["renderable", "stateful"] },
              },
            ],
            delegation_chain: ["ck:grant:root", "ck:grant:e2e"],
          },
        ],
        state_digest: "ck:statehash:e2e",
        evaluated_at: "2026-04-28T12:00:00Z",
      });
    }

    if (url.pathname === "/_cokret/self/authz/invites") {
      return json(route, { invites: [], next_cursor: null });
    }

    if (url.pathname === "/_cokret/self/keys/upload") {
      return json(route, { one_time_key_counts: { signed_curve25519: 1 }, fallback_keys: {} });
    }

    if (url.pathname === "/_cokret/self/keys/query") {
      return json(route, { device_keys: {}, failures: {} });
    }

    if (url.pathname === "/_cokret/self/keys/claim") {
      return json(route, { one_time_keys: {}, failures: {} });
    }

    if (url.pathname === "/_cokret/self/device_messages" && route.request().method() === "GET") {
      return json(route, { events: [], next_cursor: "ck:cursor:devmsg-1", limited: false });
    }

    if (url.pathname === "/_cokret/self/device_messages" && route.request().method() === "POST") {
      return json(route, { ok: true, delivered: { "did:web:alice.example": ["dev_yougen"] }, unknown_devices: {} });
    }

    if (url.pathname === "/_cokret/self/ephemeral") {
      const body = await route.request().postDataJSON();
      if (!["ck.receipt.read", "ck.typing", "ck.presence", "ck.call.signal"].includes(body.kind)) {
        return json(route, {
          ok: false,
          error: { code: "invalid_param", message: "expected broadcast ephemeral kind" },
        }, 400);
      }
      return json(route, {
        accepted: true,
        kind: body.kind,
        realm_id: body.realm_id,
        server_received_at: new Date().toISOString(),
      });
    }

    if (url.pathname === "/_cokret/edge/push/register-device") {
      return json(route, { ok: true, registration_id: "ck:push:e2e", expires_at: null });
    }

    if (url.pathname === "/_cokret/edge/push/unregister-device") {
      return json(route, { ok: true });
    }

    if (url.pathname === "/_cokret/self/blob/upload") {
      return json(route, {
        blob_ref: "ck:blob:sha256:e2e",
        size_bytes: 22,
        media_type: "application/octet-stream",
        content_digest: "sha256:01015dc8af66d01f557ea63f13538f1964848840a350c5311d1efc8ad138bb91",
        thumbnail_ref: "ck:blob:sha256:e2e-thumb",
        upload_receipt: { service_did: "did:web:server.local", content_digest_verified: true },
      });
    }

    if (url.pathname === "/_cokret/self/rtc/ice-config") {
      const body = await route.request().postDataJSON();
      return json(route, {
        realm_id: body.realm_id ?? DEMO_REALM,
        call_id: body.call_id ?? "ck:call:01964137-0000-7000-8000-000000000001",
        actor_id: body.actor_id ?? "did:web:alice.example",
        device_id: body.device_id ?? "ck:device:01904100-0000-7000-8000-a11ce0000001",
        ice_servers: [
          { urls: ["stun:stun.server.local:3478"] },
          {
            urls: ["turn:turn.server.local:3478?transport=udp"],
            username: "turn-user",
            credential: "turn-secret",
          },
        ],
        ttl_seconds: 600,
        refresh_lead_seconds: 150,
        issued_at: "2026-05-19T00:00:00Z",
        signature: {
          alg: "EdDSA",
          kid: "did:web:server.local#media-ice",
          sig: "placeholder",
        },
      });
    }

    if (url.pathname === "/_cokret/self/blob/get") {
      return route.fulfill({ status: 200, contentType: "application/octet-stream", body: "yougen encrypted bytes" });
    }

    if (url.pathname === "/_cokret/self/moderation/report") {
      return json(route, { report_id: "ck:report:e2e", status: "queued", routed_to: ["did:web:server.local#moderation"] });
    }

    // Encrypted Cloud Vault — the recovery view uploads a backup body whose
    // ciphertext was sealed client-side with Argon2id + XChaCha20-Poly1305.
    // The server only ever sees the opaque ciphertext blob + metadata; this
    // mock echoes that contract so the recovery rekey e2e (D1) can assert
    // the server never witnessed a plaintext recovery key.
    const keyBackupMatch = url.pathname.match(/^\/_cokret\/self\/keys\/backups\/([^/]+)$/);
    if (keyBackupMatch) {
      if (route.request().method() === "PUT") {
        return json(route, {
          backup_id: keyBackupMatch[1],
          status: "stored",
        });
      }
      if (route.request().method() === "GET") {
        return json(route, {
          backup_id: keyBackupMatch[1],
          status: "stored",
          ciphertext: "BASE64URL_OPAQUE_BLOB",
        });
      }
    }
    if (url.pathname === "/_cokret/self/keys/backups") {
      return json(route, { backups: [] });
    }

    const contractResponse = mockCokretContract({
      method: route.request().method(),
      path: url.pathname,
      query: Object.fromEntries(url.searchParams.entries()),
      headers: route.request().headers(),
      body: await contractRequestBody(route),
    });
    if (contractResponse) {
      return json(route, contractResponse.body, contractResponse.status);
    }

    return json(route, { ok: false, error: { code: "not_found", message: `No e2e mock for ${url.pathname}` } }, 404);
  });
}

async function contractRequestBody(route: Route) {
  const method = route.request().method().toUpperCase();
  if (method === "GET" || method === "HEAD") {
    return undefined;
  }
  const raw = route.request().postData();
  if (!raw) {
    return undefined;
  }
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

function realmPreview() {
  return {
    realm_id: DEMO_REALM,
    title: "Cokret Demo Realm",
    description: "Shared demo Realm served by mocked server",
    tags: ["demo"],
    public: true,
    category: "collaboration",
  };
}

function joinCandidate() {
  return {
    realm_id: DEMO_REALM,
    service_did: "did:web:server.local",
    service_type: "principal_server",
    role: "primary",
    endpoint: null,
    operations: ["ck.self.events.submit"],
    join_methods: ["invite_accept", "member_join"],
    priority: 0,
    source: "directory_ingest",
    as_of: "2026-05-30T00:00:00Z",
    expires_at: "2099-01-01T00:00:00Z",
  };
}

function mimiProviderDirectory() {
  return {
    schema: "ck.schema.mimi_interop.v1",
    service_did: "did:web:mimi.example.com",
    service_type: "mimi_provider_facade",
    supported_profiles: ["ck.profile.mimi_interop.v1"],
    mimi: {
      protocol_draft: "draft-ietf-mimi-protocol-06",
      content_draft: "draft-ietf-mimi-content-08",
      room_policy_draft: "draft-ietf-mimi-room-policy-03",
      identifier_draft: "draft-kohbrok-mimi-identifiers-01",
      base_url: "https://mimi.example.com/_cokret/open/mimi",
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
        "application/vnd.cokret.content+json",
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
