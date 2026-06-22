import { expect, type Page, type Route } from "@playwright/test";
import { mockCokretContract } from "./mockCokretContract";

const DEMO_REALM = "ck:realm:0196419b-0000-7000-8000-000000000000";
const SETUP_REALM = "ck:realm:01js0setupflow000000000000";
const CHILD_REALM = "ck:realm:01launchchild0000000000000";
const GRANDCHILD_REALM = "ck:realm:01launchdeep00000000000000";
const DIRECT_BOB_REALM = "ck:realm:01directbob000000000000000";
const DIRECT_BOB_STRAND = "ck:strand:01directbob0000000000000000";
const DEMO_BOARD_SPACE = "ck:space:0196419b-0000-7000-8000-00000000b0a0";
const DEMO_SECOND_BOARD_SPACE = "ck:space:0196419b-0000-7000-8000-00000000b0b0";
const DEMO_TODO_LIST = "ck:space:01list-todo000000000000000000";
const DEMO_PROGRESS_LIST = "ck:space:01list-progress00000000000000";
const DEMO_DONE_LIST = "ck:space:01list-done00000000000000000";
const DEMO_SECOND_LIST = "ck:space:01list-secondary000000000000";
const DEMO_STRAND_LEGAL_REVIEW = "ck:strand:0196419b-0000-7000-8000-000000000101";
const DEMO_STRAND_ONBOARDING_COPY = "ck:strand:0196419b-0000-7000-8000-000000000102";
const DEMO_STRAND_SECURITY_SIGNOFF = "ck:strand:0196419b-0000-7000-8000-000000000103";
const DEMO_STRAND_SECONDARY_CARD = "ck:strand:0196419b-0000-7000-8000-000000000104";
const DEMO_BLOB_REF =
  "ck:blob:sha256:01015dc8af66d01f557ea63f13538f1964848840a350c5311d1efc8ad138bb91";

type SpaceContainerProjection = {
  container_space_id: string;
  realm_id: string;
  kind: string;
  title: string;
  state: string;
  rank?: string;
  parent_space_id?: string;
};

type StrandProjection = {
  strand_id: string;
  realm_id: string;
  title: string;
  summary?: string;
  state: string;
  board_space_id?: string;
  list_space_id?: string;
  rank?: string;
  assigned_actor_ids?: string[];
  fields?: Record<string, unknown>;
};

type MockCokretApiOptions = {
  advertiseListHandlesForSubject?: boolean;
};

export async function mockCokretApi(page: Page, options: MockCokretApiOptions = {}) {
  const advertiseListHandlesForSubject = options.advertiseListHandlesForSubject ?? true;
  let messageCounter = 0;
  const createdRealms: Array<{ id: string; title: string; summary: string; encryption_profile: string }> = [];
  const projectionEvents: Array<Record<string, unknown>> = [];
  let recoveryPolicy: Record<string, unknown> | null = null;
  const keyBackups = new Map<string, Record<string, unknown>>();
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
  const boardStrandProjections: StrandProjection[] = [
    {
      strand_id: DEMO_STRAND_LEGAL_REVIEW,
      realm_id: DEMO_REALM,
      title: "Legal review for public beta",
      summary: "Finalize external processor wording before launch checklist can move.",
      state: "active",
      board_space_id: DEMO_BOARD_SPACE,
      list_space_id: DEMO_TODO_LIST,
      rank: "U",
      assigned_actor_ids: ["did:web:alice.example"],
      fields: {
        labels: ["legal", "beta"],
        due_at: "May 08",
        discussion_visibility: "locked",
        discussion_ref_hash: "sha256:locked-private-decision",
        locked_reason: "You can see that a restricted discussion is linked, but not its name or members.",
      },
    },
    {
      strand_id: DEMO_STRAND_ONBOARDING_COPY,
      realm_id: DEMO_REALM,
      title: "Onboarding copy",
      summary: "Waiting on discussion-scoped feedback from support and docs reviewers.",
      state: "active",
      board_space_id: DEMO_BOARD_SPACE,
      list_space_id: DEMO_PROGRESS_LIST,
      rank: "U",
      assigned_actor_ids: ["did:web:bob.example"],
      fields: { labels: ["copy", "support"], due_at: "May 10" },
    },
    {
      strand_id: DEMO_STRAND_SECURITY_SIGNOFF,
      realm_id: DEMO_REALM,
      title: "Security sign-off",
      summary: "Projection detected a stale column head after an offline move.",
      state: "active",
      board_space_id: DEMO_BOARD_SPACE,
      list_space_id: DEMO_DONE_LIST,
      rank: "U",
      assigned_actor_ids: ["did:web:carol.example"],
      fields: { labels: ["security", "reviewed"], due_at: "May 01" },
    },
    {
      strand_id: DEMO_STRAND_SECONDARY_CARD,
      realm_id: DEMO_REALM,
      title: "Secondary board card",
      summary: "Only visible after the Board selector switches projection scope.",
      state: "active",
      board_space_id: DEMO_SECOND_BOARD_SPACE,
      list_space_id: DEMO_SECOND_LIST,
      rank: "U",
      assigned_actor_ids: ["did:web:dana.example"],
      fields: { labels: ["planning"], due_at: "May 12" },
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
        scopes_supported: ["openid", "profile", "urn:cokret:principal-server:session.bind"],
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

    if (url.pathname === "/_cokret/describe" && route.request().method() === "GET") {
      if (url.hostname === "auth.local.host") {
        return json(route, {
          service_did: "did:web:auth.local.host",
          service_type: "auth_server",
          protocol_version: "1.0",
          auth_metadata: {
            did_binding_methods: ["did_controller_key", "device_key"],
            mode: "development",
            account_authority: {
              origin: "https://auth.local.host",
              gate_account_base: "https://auth.local.host/_cokret/gate/account",
            },
            methods: [
              {
                method: "oidc",
                issuer: "https://auth.local.host/",
                openid_configuration: "https://auth.local.host/.well-known/openid-configuration",
                client_id: "01GFWR28C4KNE04WG3HKXB7C9R",
                scopes: ["openid", "profile", "urn:cokret:principal-server:session.bind"],
                grant_exchange: { proof_kind: "oidc_code_exchange" },
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
          "device_messages.ack",
          "push.register_device",
          "mimi_provider_facade",
          "events.submit",
        ],
        supported_operations: [
          "ck.server.query.describe",
          "ck.self.account.stream.subscribe",
          "ck.self.account.query.describe",
          "ck.self.account.query.viewer",
          "ck.self.account.command.update_profile",
          "ck.self.events.query.scan",
          "ck.self.events.stream.subscribe",
          "ck.self.events.query.describe",
          "ck.self.events.command.submit",
          "ck.self.projection.spaces.query.list",
          "ck.self.projection.strands.query.list",
          "ck.find.directory.query.search_realms",
          "ck.find.directory.query.resolve_realm",
          "ck.find.directory.query.describe",
          "ck.find.directory.query.search_organizations",
          "ck.find.directory.query.search_actors",
          "ck.find.directory.query.resolve_handle",
          ...(advertiseListHandlesForSubject
            ? ["ck.find.directory.query.list_handles_for_subject"]
            : []),
          "ck.self.authz.query.check",
          "ck.self.authz.grants.query.effective",
          "ck.self.authz.invites.query.list",
          "ck.root.identity.registry.query.describe",
          "ck.root.identity.query.resolve",
          "ck.root.identity.recovery_policy.resource.get",
          "ck.root.identity.recovery_policy.command.publish",
          "ck.gate.account.command.register",
          "ck.gate.account.command.pair_device",
          "ck.gate.account.command.revoke_session",
          "ck.self.contact.query.list",
          "ck.self.contact.command.request",
          "ck.self.contact.command.respond",
          "ck.self.contact.command.tombstone",
          "ck.self.invite_receive_policy.resource.get",
          "ck.self.invite_receive_policy.resource.replace",
          "ck.self.direct_conversation.command.resolve",
          "ck.self.keys.upload.create",
          "ck.self.keys.query.lookup",
          "ck.self.keys.command.claim",
          "ck.self.keys.backups.query.list",
          "ck.self.keys.backups.resource.replace",
          "ck.self.device_messages.query.list",
          "ck.self.device_messages.command.send",
          "ck.self.device_messages.command.ack",
          "ck.edge.push.command.register_device",
          "ck.edge.push.command.unregister_device",
          "ck.self.blob.upload.create",
          "ck.self.blob.resource.get",
          "ck.self.media.query.ice_config",
          "ck.self.moderation.command.report",
          "ck.open.mimi.query.provider_directory",
          "ck.open.mimi.exchange.request_key_material",
          "ck.open.mimi.query.group_info",
          "ck.open.mimi.command.update_room",
          "ck.open.mimi.command.notify",
          "ck.open.mimi.command.submit_message",
          "ck.open.mimi.command.request_consent",
          "ck.open.mimi.command.update_consent",
          "ck.open.mimi.query.identifiers",
          "ck.open.mimi.command.report_abuse",
          "ck.open.mimi.command.proxy_download",
          "ck.open.invite_locator.query.resolve",
          "ck.self.ephemeral.command.send",
        ],
        supported_schema_profiles: ["ck.schema.core.v1"],
        supported_reducer_profiles: ["ck.reducer.v1"],
        supported_bindings: [{ kind: "http_json" }],
        auth_metadata: {
          mode: "development",
          account_authority: {
            origin: "https://auth.local.host",
            gate_account_base: "https://auth.local.host/_cokret/gate/account",
          },
          methods: [
            {
              method: "oidc",
              issuer: "https://auth.local.host/",
              openid_configuration: "https://auth.local.host/.well-known/openid-configuration",
              client_id: "01GFWR28C4KNE04WG3HKXB7C9R",
              scopes: ["openid", "profile", "urn:cokret:principal-server:session.bind"],
              grant_exchange: { proof_kind: "oidc_code_exchange" },
            },
          ],
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

    if (url.pathname === "/_cokret/self/projection/spaces" && route.request().method() === "GET") {
      const realmId = url.searchParams.get("realm_id") ?? DEMO_REALM;
      return json(route, {
        realm_id: realmId,
        total: boardSpaceContainers.length,
        spaces: boardSpaceContainers,
      });
    }

    if (url.pathname === "/_cokret/self/projection/strands" && route.request().method() === "GET") {
      const realmId = url.searchParams.get("realm_id") ?? DEMO_REALM;
      return json(route, {
        realm_id: realmId,
        total: boardStrandProjections.length,
        strands: boardStrandProjections,
      });
    }

    if (url.pathname === "/_cokret/self/events/describe" && route.request().method() === "GET") {
      // Spec ck.self.events.query.describe -> canonical ServiceDescribe shape
      // (17 required fields; yougen decodes the SDK ServerDescription).
      return json(route, {
        service_did: "did:web:server.local",
        trust_domain: "ck:trust_domain:server.local",
        service_type: "principal_server",
        protocol_version: "1.0",
        supported_profiles: ["ck.profile.core_event_store.v1"],
        supported_operations: ["ck.self.events.command.submit", "ck.self.events.query.describe"],
        supported_bindings: [{ kind: "http_json" }],
        supported_features: [],
        auth_metadata: {
          mode: "development",
          account_authority: {
            origin: "https://auth.local.host",
            gate_account_base: "https://auth.local.host/_cokret/gate/account",
          },
          methods: [
            {
              method: "oidc",
              issuer: "https://auth.local.host/",
              openid_configuration: "https://auth.local.host/.well-known/openid-configuration",
              client_id: "01GFWR28C4KNE04WG3HKXB7C9R",
              scopes: ["openid", "profile", "urn:cokret:principal-server:session.bind"],
              grant_exchange: { proof_kind: "oidc_code_exchange" },
            },
          ],
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
        // Strict typed EventId — must be a canonical ck:event:<uuidv7>.
        frontier: ["ck:event:0196419b-0000-7000-8000-00000000e2e0"],
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
        const raw = JSON.stringify(event);
        if (event.kind !== "ck.realm.create" && !raw.includes("ck.realm.create")) {
          continue;
        }
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
          "Setup Strand Space";
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
        projectionEvents.push({
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
      if (body.kind === "ck.strand.create") {
        messageCounter += 1;
        syncToken = `sx:e2e:strand-${messageCounter}`;
        const object = body.payload?.object ?? {};
        const component = Array.isArray(body.payload?.components)
          ? body.payload.components.find(
              (candidate: { family?: string }) => candidate.family === "ck.component.strand.position.v1",
            )
          : undefined;
        const strandId = body.payload?.strand_id ?? object.id;
        if (typeof strandId === "string") {
          const fields = object.fields ?? {};
          const nextProjection: StrandProjection = {
            strand_id: strandId,
            realm_id: object.realm_id ?? body.realm_id ?? DEMO_REALM,
            title: object.title ?? body.payload?.title ?? strandId,
            summary: object.summary,
            state: "active",
            board_space_id: component?.board_space_id ?? fields.board_space_id,
            list_space_id: component?.list_space_id ?? fields.list_space_id,
            rank: component?.rank ?? fields.rank ?? body.payload?.rank,
            fields,
          };
          const existing = boardStrandProjections.findIndex((row) => row.strand_id === strandId);
          if (existing >= 0) {
            boardStrandProjections[existing] = nextProjection;
          } else {
            boardStrandProjections.push(nextProjection);
          }
        }
        projectionEvents.push({
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
      // soland (head 37ce729) returns the canonical EventsSubmitOutcome wire
      // shape: {status, accepted[], cursor} — no top-level event_id/sync_token.
      // yougen folds accepted[0] -> event_id and keeps cursor as-is.
      return json(route, {
        status: "accepted",
        accepted: body.event_id ? [body.event_id] : [],
        duplicate: [],
        rejected: [],
        actor_frontier: {},
        realm_frontier: {},
        cursor: syncToken,
      });
    }

    if (url.pathname === "/_cokret/open/mimi/provider-directory" && route.request().method() === "GET") {
      return json(route, mimiProviderDirectory());
    }

    if (url.pathname === "/_cokret/open/mimi/key-material" && route.request().method() === "POST") {
      return json(route, {
        ok: true,
        key_packages: [{ key_package_ref: "mimi:key-package:e2e", target: "mimi://remote.example/alice" }],
        receipt: { kind: "ck.open.mimi.exchange.request_key_material", profile: "ck.profile.mimi_interop.v1" },
      });
    }

    if (url.pathname.match(/^\/_cokret\/open\/mimi\/strands\/[^/]+\/update$/) && route.request().method() === "POST") {
      const roomId = decodeURIComponent(url.pathname.split("/")[5]);
      return json(route, {
        ok: true,
        room_id: roomId,
        receipt: { kind: "ck.open.mimi.command.update_room", operation_id: "ck:operation:mimi-room-update" },
      });
    }

    if (url.pathname.match(/^\/_cokret\/open\/mimi\/strands\/[^/]+\/notify$/) && route.request().method() === "POST") {
      return json(route, {
        ok: true,
        accepted: ["did:web:remote.example"],
        receipt: { kind: "ck.open.mimi.command.notify", notification_id: "ck:mimi:notify:e2e" },
      });
    }

    if (url.pathname.match(/^\/_cokret\/open\/mimi\/strands\/[^/]+\/messages$/) && route.request().method() === "POST") {
      return json(route, {
        event_ref: "ck:event:01964137-0000-7000-8000-00000000d0aa",
        delivery: {
          kind: "ck.mimi.mapping_receipt",
          profile: "ck.profile.mimi_interop.v1",
          mimi_room_uri: "mimi://mimi.example.com/rooms/01JSMIMI",
          source_format: "text/markdown;variant=GFM-MIMI",
          target_format: "ck.message.create",
          original_envelope_hash: "sha256:e2e-mimi-envelope",
          mapped_operation_id: "ck:operation:mimi-submit-e2e",
          mimi_message_id: "mimi-msg-e2e",
        },
        rejected: [],
      });
    }

    if (url.pathname.match(/^\/_cokret\/open\/mimi\/strands\/[^/]+\/group-info$/) && route.request().method() === "GET") {
      return json(route, {
        group_info: { epoch: 7, mls_group_id: "mls-group-01", policy_root: "sha256:e2e-policy-root" },
        room_binding_ref: "ck:event:01964137-0000-7000-8000-00000000d0ab",
        proofs: [{ kind: "ck.open.mimi.query.group_info", profile: "ck.profile.mimi_interop.v1" }],
      });
    }

    if (url.pathname === "/_cokret/open/mimi/consent/request" && route.request().method() === "POST") {
      return json(route, {
        ok: true,
        consent_id: "ck:mimi-consent:e2e",
        state: "requested",
        receipt: { kind: "ck.open.mimi.command.request_consent" },
      });
    }

    if (url.pathname === "/_cokret/open/mimi/consent/update" && route.request().method() === "POST") {
      return json(route, {
        ok: true,
        consent_id: "ck:mimi-consent:e2e",
        state: "accepted",
        receipt: { kind: "ck.open.mimi.command.update_consent" },
      });
    }

    if (url.pathname === "/_cokret/open/mimi/identifiers/query" && route.request().method() === "POST") {
      const body = await route.request().postDataJSON();
      return json(route, {
        matches: [
          {
            identifier_commitment: `sha256:${"2".repeat(64)}`,
            matched: true,
            mimi_uri: body.identifiers?.[0]?.mimi_uri ?? "mimi://remote.example/alice",
            subject: "did:web:alice.example",
          },
        ],
        proofs: [{ type: "private_identifier_query", expires_at: "2026-04-30T12:00:00Z" }],
        has_more: false,
      });
    }

    if (url.pathname === "/_cokret/open/mimi/report-abuse" && route.request().method() === "POST") {
      return json(route, {
        ok: true,
        report_id: "ck:report:mimi-e2e",
        status: "queued",
        receipt: { kind: "ck.open.mimi.command.report_abuse" },
      });
    }

    if (url.pathname === "/_cokret/open/mimi/proxy-download" && route.request().method() === "POST") {
      return json(route, {
        download_ref: `https://mimi.example.com/proxy/${DEMO_BLOB_REF}`,
        headers: { "content-type": "application/octet-stream" },
        expires_at: "2026-04-30T12:00:00Z",
      });
    }

    if (url.pathname === "/_cokret/gate/account/register" && route.request().method() === "POST") {
      const body = await route.request().postDataJSON();
      return json(route, {
        principal_id: body.principal_id,
        state: "active",
        devices: body.device_id
          ? [
              {
                device_id: body.device_id,
                status: "active",
                display_name: "Current device",
                authorized_at: "2026-04-28T12:00:00Z",
              },
            ]
          : [],
        profile: {
          id: "ck:actor_profile:01964137-0000-7000-8000-0000000000a1",
          schema: "ck.schema.actor_profile.v1",
          principal_id: body.principal_id,
          actor_kind: "user",
          display_name: body.display_name ?? "yougen",
          profile_fields: {},
          accountable_principal_ids: [],
          created_at: "2026-04-28T12:00:00Z",
        },
      }, 201);
    }

    if (url.pathname === "/_cokret/self/account/profile" && route.request().method() === "POST") {
      const body = await route.request().postDataJSON();
      const patch = body.patch ?? {};
      const displayName = typeof patch.display_name === "string" ? patch.display_name : "yougen";
      const avatarBlobRef = typeof patch.avatar_blob_ref === "string" ? patch.avatar_blob_ref : undefined;
      const bio = typeof patch["profile_fields.bio"] === "string" ? patch["profile_fields.bio"] : undefined;
      return json(route, {
        profile: {
          id: "ck:actor_profile:01964137-0000-7000-8000-0000000000a1",
          schema: "ck.schema.actor_profile.v1",
          principal_id: "did:web:alice.example",
          actor_kind: "user",
          display_name: displayName,
          handle: "alice.example",
          avatar_blob_ref: avatarBlobRef,
          profile_fields: bio ? { bio } : {},
          accountable_principal_ids: [],
          created_at: "2026-04-28T12:00:00Z",
          updated_at: "2026-04-28T12:10:00Z",
        },
      });
    }

    if (url.pathname === "/_cokret/gate/account/session-grants/revoke" && route.request().method() === "POST") {
      return json(route, { revoked_count: 1, revoked_grant_ids: [] });
    }

    if (url.pathname === "/_cokret/self/account/subscribe" && route.request().method() === "GET") {
      const demoProjectionEvents = projectionEvents.filter((event) => eventRealmId(event) === DEMO_REALM);
      const notificationEvents = [
        {
          kind: "ck.notification",
          notification_id: "notif-msg-1",
          title: "New message",
          body: "Alice sent a message in Demo Realm",
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
          body: "You were invited to review Demo Realm",
          realm_id: DEMO_REALM,
          notification_kind: "invite",
          type: "invite",
          timestamp: "2026-04-28T12:02:00Z",
          read: false,
        },
      ];
      const frame = {
        kind: "delta",
        cursor: "ck:cursor:e2e-2",
        realms: {
          ...Object.fromEntries(
            createdRealms.map((realm) => [
              realm.id,
              {
                summary: {
                  title: realm.title,
                  summary: realm.summary,
                  encryption_profile: realm.encryption_profile,
                },
                timeline: {
                  events: projectionEvents.filter((event) => eventRealmId(event) === realm.id),
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
              title: "Cokret Demo Realm",
              summary: "Shared demo Realm served by mocked server",
              encryption_profile: "mls_rfc9420",
            },
            timeline: { events: demoProjectionEvents, limited: false },
            state: { events: [] },
            ephemeral: { events: [] },
            unread: { notification_count: 0, highlight_count: 0 },
          },
          [CHILD_REALM]: {
            summary: {
              title: "Launch Realm",
              summary: "Board and discussion scope",
            },
            timeline: { events: [], limited: false },
            state: { events: [] },
            ephemeral: { events: [] },
            unread: { notification_count: 0, highlight_count: 0 },
          },
          [GRANDCHILD_REALM]: {
            summary: {
              title: "Launch Deep Realm",
              summary: "Related scope fixture",
            },
            timeline: { events: [], limited: false },
            state: { events: [] },
            ephemeral: { events: [] },
            unread: { notification_count: 0, highlight_count: 0 },
          },
        },
        left_realms: [],
        to_device: {
          messages: [{ kind: "ck.mls.welcome", content: { ciphertext: "opaque" } }],
          ack_token: "mock-to-device-ack",
        },
        account_data: { events: notificationEvents },
        device_lists: { changed: [], left: [] },
        presence: { events: [] },
        notifications: { events: notificationEvents, unread_count: 2 },
      };
      return route.fulfill({
        status: 200,
        contentType: "application/x-ndjson",
        body: `${JSON.stringify(frame)}\n${JSON.stringify({ kind: "catchup_complete", cursor: "ck:cursor:e2e-2" })}\n`,
      });
    }

    if (url.pathname === "/_cokret/find/directory/search-realms" && route.request().method() === "POST") {
      return json(route, {
        realms: [realmPreview()],
        next_cursor: null,
        has_more: false,
      });
    }

    if (url.pathname === "/_cokret/find/directory/search-organizations" && route.request().method() === "POST") {
      return json(route, {
        organizations: [
          {
            organization_did: "did:web:org.cokret.example",
            handle: "cokret.example",
            preview: {
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
          },
        ],
        next_cursor: null,
        has_more: false,
      });
    }

    if (url.pathname === "/_cokret/find/directory/search-actors" && route.request().method() === "POST") {
      return json(route, {
        actors: [
          {
            actor_id: "did:web:bob.example",
            display_name: "Bob Example",
            preview: {
              did: "did:web:bob.example",
              handle: "bob.example",
              display_name: "Bob Example",
            },
          },
        ],
        next_cursor: null,
        has_more: false,
      });
    }

    if (url.pathname === "/_cokret/open/invite-locators/resolve" && route.request().method() === "POST") {
      expect(url.search).toBe("");
      const body = await route.request().postDataJSON();
      expect(body.locator_token).toBeTruthy();
      return json(route, {
        schema: "ck.schema.principal_locator.v1",
        subject_id: "did:web:carol.example",
        recipient_service_did: "did:web:server.local",
        issued_at: "2026-06-07T00:00:00Z",
        expires_at: "2026-06-07T00:15:00Z",
        locator_ref_digest: `sha256:${"1".repeat(64)}`,
        proofs: [
          {
            proof_purpose: "recipient_service_acceptance",
            proof: {
              kind: "detached_jws",
              verification_method: "did:web:server.local#server-key-1",
              alg: "EdDSA",
              payload_digest: `sha256:${"2".repeat(64)}`,
              created_at: "2026-06-07T00:00:00Z",
              jws: "header..sig",
            },
          },
        ],
      });
    }

    if (url.pathname === "/_cokret/find/directory/resolve-handle" && route.request().method() === "POST") {
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

    if (url.pathname === "/_cokret/find/directory/list-handles-for-subject" && route.request().method() === "POST") {
      const body = await route.request().postDataJSON();
      const subject = body.subject ?? "did:web:alice.example";
      return json(route, {
        subject,
        primary_handle: "alice:local.host",
        as_of: "2026-04-28T12:00:00Z",
        has_more: false,
        claims: [
          {
            subject,
            handle: "alice:local.host",
            issuer: "did:web:server.local",
            issuer_service_did: "did:web:server.local",
            binding_state: "verified",
            claim_kind: "handle_binding",
            visibility: "public",
            audience: "did:web:server.local",
            created_at: "2026-04-28T12:00:00Z",
            verified_at: "2026-04-28T12:00:00Z",
            expires_at: "2027-04-28T12:00:00Z",
          },
        ],
      });
    }

    if (url.pathname === "/_cokret/find/directory/resolve-realm" && route.request().method() === "POST") {
      return json(route, {
        realm_preview: realmPreview(),
        stripped_state: [],
        join_rule: "public",
        join_candidates: [joinCandidate()],
      });
    }

    if (url.pathname === "/_cokret/find/directory/describe" && route.request().method() === "GET") {
      return json(route, {
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

    if (url.pathname === "/_cokret/self/events" && route.request().method() === "GET") {
      const requestedRealms = (url.searchParams.get("realms") ?? "")
        .split(",")
        .map((realm) => realm.trim())
        .filter(Boolean);
      const events = requestedRealms.length
        ? projectionEvents.filter((event) => requestedRealms.includes(eventRealmId(event)))
        : projectionEvents;
      return json(route, { events, next_cursor: null, has_more: false });
    }

    // NB: no `/_cokret/self/snapshot/head` route. The mock's describe does
    // not advertise `ck.self.snapshot.query.manifest_head`, so the client falls back to
    // event replay before issuing the request. The current wire shape is the
    // full signed `ck.schema.snapshot.v1` manifest (self-id field `id`); the
    // removed `snapshot_ref` pointer DTO is hard-rejected and MUST NOT be
    // reintroduced here.
    if (url.pathname === "/_cokret/root/identity/describe" && route.request().method() === "GET") {
      return json(route, {
        service_did: "did:web:server.local",
        registry_mode: "development_local",
        supported_receipts: ["local"],
        protocol_version: "1.0",
        profiles: ["ck.identity.local-dev.v1"],
      });
    }

    if (url.pathname === "/_cokret/root/identity/resolve" && route.request().method() === "POST") {
      const body = await route.request().postDataJSON();
      return json(route, {
        did_document: { id: body.did },
        key_log_head: null,
        seq: 0,
        receipts: [],
        method_evidence: { mode: "development_local" },
      });
    }

    if (url.pathname === "/_cokret/self/account/describe" && route.request().method() === "GET") {
      return json(route, {
        service_did: "did:web:server.local",
        supported_sync_profiles: ["initial", "incremental"],
        limits: {},
        frontier: {},
      });
    }

    if (url.pathname === "/_cokret/self/authz/check" && route.request().method() === "POST") {
      return json(route, {
        allowed: true,
        reason_code: "frontier_current",
        grants: ["ck:grant:e2e"],
        obligations: [{ type: "audit", reason_required: false }],
      });
    }

    if (url.pathname === "/_cokret/self/authz/effective-grants" && route.request().method() === "GET") {
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
                params: { allowed_object_types: ["space"], allowed_facets: ["renderable", "stateful"] },
              },
            ],
            delegation_chain: ["ck:grant:root", "ck:grant:e2e"],
          },
        ],
        state_digest: "ck:statehash:e2e",
        evaluated_at: "2026-04-28T12:00:00Z",
      });
    }

    if (url.pathname === "/_cokret/self/authz/invites" && route.request().method() === "GET") {
      return json(route, { invites: [], next_cursor: null });
    }

    if (url.pathname === "/_cokret/self/contacts" && route.request().method() === "GET") {
      return json(route, {
        contacts: [
          {
            peer: "did:web:bob.example",
            state: "accepted",
            request_event_ref: "ck:event:0196419b-0000-7000-8000-000000000101",
            response_event_ref: "ck:event:0196419b-0000-7000-8000-000000000102",
            granted_by_me: ["direct_message", "invite"],
            granted_to_me: ["direct_message", "invite"],
            bidirectional_scopes: ["direct_message", "invite"],
            effective_scopes: ["direct_message", "invite"],
            // U3 — consent grant the peer gave me for the invite scope.
            invite_consent_grant_ref: "ck:event:0196419b-0000-7000-8000-000000000102",
            direct_conversation: {
              realm_id: DIRECT_BOB_REALM,
              main_strand_id: DIRECT_BOB_STRAND,
              binding_event_ref: "ck:event:0196419b-0000-7000-8000-000000000103",
              state: "active",
            },
          },
          {
            peer: "did:web:carol.example",
            state: "pending_outgoing",
            request_event_ref: "ck:event:0196419b-0000-7000-8000-000000000104",
            granted_by_me: ["invite"],
            granted_to_me: [],
            bidirectional_scopes: [],
            effective_scopes: ["invite"],
          },
          {
            peer: "did:web:dave.example",
            state: "pending_incoming",
            request_event_ref: "ck:event:0196419b-0000-7000-8000-000000000105",
            granted_by_me: [],
            granted_to_me: ["direct_message"],
            bidirectional_scopes: [],
            effective_scopes: ["direct_message"],
            // Cross-PS incoming request: respond must reverse-deliver to this PS.
            peer_service_did: "did:web:ps.dave.example",
          },
          {
            // Accepted contact who granted me `invite` scope but with NO real
            // consent grant ref — exercises the "对方未授权邀请" disabled row in
            // the realm-invite-from-contacts picker (no fallback ref).
            peer: "did:web:erin.example",
            state: "accepted",
            request_event_ref: "ck:event:0196419b-0000-7000-8000-000000000106",
            response_event_ref: "ck:event:0196419b-0000-7000-8000-000000000107",
            granted_by_me: ["direct_message", "invite"],
            granted_to_me: ["direct_message", "invite"],
            bidirectional_scopes: ["direct_message", "invite"],
            effective_scopes: ["direct_message", "invite"],
          },
        ],
        has_more: false,
        next_cursor: null,
      });
    }

    // U2 — contact request (now accepts an optional `message`).
    if (url.pathname === "/_cokret/self/contacts/request" && route.request().method() === "POST") {
      return json(route, {
        request_event_ref: "ck:event:0196419b-0000-7000-8000-000000000108",
        requester_consent_refs: [],
        state: "pending_outgoing",
      });
    }

    // U1 — accept / reject an incoming contact request.
    if (url.pathname === "/_cokret/self/contacts/respond" && route.request().method() === "POST") {
      const body = await route.request().postDataJSON();
      return json(route, {
        response_event_ref: "ck:event:0196419b-0000-7000-8000-000000000109",
        consent_grant_refs: body.action === "accept" ? ["ck:event:0196419b-0000-7000-8000-000000000110"] : [],
        state: body.action === "accept" ? "accepted" : "rejected",
      });
    }

    // U5 — tombstone / block a contact.
    if (url.pathname === "/_cokret/self/contacts/tombstone" && route.request().method() === "POST") {
      return json(route, {
        tombstone_event_ref: "ck:event:0196419b-0000-7000-8000-000000000111",
        consent_revoke_refs: [],
        state: "tombstoned",
        partial_revoke: false,
      });
    }

    // U4 — invite_receive_policy ("谁可以邀请我"). Spec invite-addressing.md
    // §5: GET/SET carry the bare `cokret_sdk::InviteReceivePolicy` (required
    // `schema` + `subject_id`, typed enums, trust lists) — no `ok` wrapper.
    if (url.pathname === "/_cokret/self/invite-receive-policy" && route.request().method() === "PUT") {
      // The real soland handler echoes the stored policy back verbatim;
      // mirror that so the client's `trusted_*` lists round-trip intact.
      const body = await route.request().postDataJSON();
      return json(route, body);
    }
    if (url.pathname === "/_cokret/self/invite-receive-policy" && route.request().method() === "GET") {
      return json(route, {
        schema: "ck.schema.invite_receive_policy.v1",
        subject_id: "did:web:alice.example",
        allowed_introduction_kinds: ["consent_grant", "locator_ref", "shared_realm"],
        explicit_address_behavior: "quarantine",
        unknown_invites: "quarantine",
        blocked_subjects: ["did:web:spammer.example"],
        disclosure: { high_trust: "outcome", low_trust: "opaque" },
      });
    }

    if (url.pathname === "/_cokret/self/direct-conversations/resolve" && route.request().method() === "POST") {
      return json(route, {
        state: "found",
        realm_id: DIRECT_BOB_REALM,
        main_strand_id: DIRECT_BOB_STRAND,
        binding_event_ref: "ck:event:0196419b-0000-7000-8000-000000000103",
        created: false,
      });
    }

    if (url.pathname === "/_cokret/self/keys/upload" && route.request().method() === "POST") {
      return json(route, { one_time_key_counts: { signed_curve25519: 1 }, fallback_keys: {} });
    }

    if (url.pathname === "/_cokret/self/keys/query" && route.request().method() === "POST") {
      return json(route, { device_keys: {}, failures: {} });
    }

    if (url.pathname === "/_cokret/self/keys/claim" && route.request().method() === "POST") {
      return json(route, { one_time_keys: {}, failures: {} });
    }

    if (url.pathname === "/_cokret/self/account/viewer" && route.request().method() === "GET") {
      return json(route, {
        principal_id: "did:web:alice.example",
        state: "active",
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
        devices: [
          {
            device_id: "ck:device:01964137-0000-7000-8000-0000000000a1",
            status: "active",
            display_name: "Current device",
            authorized_at: "2026-04-28T12:00:00Z",
          },
        ],
      });
    }

    if (url.pathname === "/_cokret/gate/account/device-pair" && route.request().method() === "POST") {
      const body = await route.request().postDataJSON();
      const deviceId = body.new_device_pubkey?.kid ?? "ck:device:01964137-0000-7000-8000-0000000000b2";
      return json(route, {
        device_id: deviceId,
        authorized_event_ref: "ck:event:01964137-0000-7000-8000-00000000d001",
        device_grant: { status: "active" },
        key_backup_hint: {},
      });
    }

    if (url.pathname === "/_cokret/self/device_messages" && route.request().method() === "GET") {
      return json(route, { messages: [], ack_token: "mock-device-messages-ack", next_cursor: "ck:cursor:devmsg-1", has_more: false, limited: false });
    }

    if (url.pathname === "/_cokret/self/device_messages" && route.request().method() === "POST") {
      return json(route, { ok: true, delivered: { "did:web:alice.example": ["dev_yougen"] }, unknown_devices: {} });
    }

    if (url.pathname === "/_cokret/self/device_messages/ack" && route.request().method() === "POST") {
      return json(route, { ok: true, pruned_count: 0 });
    }

    if (url.pathname === "/_cokret/self/ephemeral" && route.request().method() === "POST") {
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

    if (url.pathname === "/_cokret/edge/push/register-device" && route.request().method() === "POST") {
      return json(route, { ok: true, registration_id: "ck:push:e2e", expires_at: null });
    }

    if (url.pathname === "/_cokret/edge/push/unregister-device" && route.request().method() === "POST") {
      return json(route, { ok: true });
    }

    if (url.pathname === "/_cokret/self/blob/upload" && route.request().method() === "POST") {
      return json(route, {
        blob_ref: DEMO_BLOB_REF,
        size_bytes: 22,
        media_type: "application/octet-stream",
        content_digest: "sha256:01015dc8af66d01f557ea63f13538f1964848840a350c5311d1efc8ad138bb91",
        upload_receipt: { service_did: "did:web:server.local", content_digest_verified: true },
      });
    }

    if (url.pathname === "/_cokret/self/rtc/ice-config" && route.request().method() === "POST") {
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

    if (url.pathname === "/_cokret/self/blob/get" && route.request().method() === "GET") {
      return route.fulfill({ status: 200, contentType: "application/octet-stream", body: "yougen encrypted bytes" });
    }

    if (url.pathname === "/_cokret/self/moderation/report" && route.request().method() === "POST") {
      return json(route, { report_id: "ck:report:e2e", status: "queued", routed_to: ["did:web:server.local#moderation"] });
    }

    // Recovery bootstrap publishes a signed policy and then uploads an
    // encrypted did_recovery backup. The server mock stores only the public
    // policy summary plus opaque backup bodies.
    if (url.pathname === "/_cokret/root/identity/recovery-policy") {
      const method = route.request().method().toUpperCase();
      if (method === "GET") {
        return json(route, { active_policy: recoveryPolicy });
      }
      if (method === "POST") {
        const body = ((await contractRequestBody(route)) ?? {}) as Record<string, unknown>;
        recoveryPolicy = {
          policy_id: body.policy_id,
          principal_id: body.principal_id,
          version: body.version,
          trust_domain: body.trust_domain,
          allowed_proof_kinds: Array.isArray(body.allowed_proof_kinds)
            ? body.allowed_proof_kinds
            : [],
        };
        return json(route, {
          ok: true,
          policy_id: body.policy_id,
          principal_id: body.principal_id,
          version: body.version,
          accepted_at: new Date().toISOString(),
        });
      }
    }

    const keyBackupMatch = url.pathname.match(/^\/_cokret\/self\/keys\/backups\/([^/]+)$/);
    if (keyBackupMatch) {
      if (route.request().method() === "PUT") {
        const body = ((await contractRequestBody(route)) ?? {}) as Record<string, unknown>;
        const backup = {
          ...body,
          backup_id: body.backup_id ?? keyBackupMatch[1],
        };
        keyBackups.set(keyBackupMatch[1], backup);
        return json(route, {
          backup_id: keyBackupMatch[1],
          status: "accepted",
          ciphertext_digest: typeof body.ciphertext_digest === "string"
            ? body.ciphertext_digest
            : "sha256:e2e",
        });
      }
    }
    if (url.pathname === "/_cokret/self/keys/backups" && route.request().method() === "GET") {
      const backupClass = url.searchParams.get("backup_class");
      const backups = Array.from(keyBackups.values()).filter((backup) =>
        backupClass ? backup.backup_class === backupClass : true,
      );
      return json(route, { backups, has_more: false });
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
    summary: "Shared demo Realm served by mocked server",
    discoverability: "public",
    join_rule: "public",
    member_count_bucket: "1-10",
    as_of: "2026-06-13T00:00:00Z",
    source_refs: ["ck:event:0196419b-0000-7000-8000-000000000001"],
    policy_revision: "mock-policy-rev",
  };
}

function joinCandidate() {
  return {
    realm_id: DEMO_REALM,
    service_did: "did:web:server.local",
    service_type: "principal_server",
    role: "primary",
    endpoint: null,
    operations: ["ck.self.events.command.submit"],
    join_methods: ["invite_accept", "member_join"],
    priority: 0,
    source: "directory_ingest",
    seal_basis: {
      leaves: ["ck:seal:sha256:1111111111111111111111111111111111111111111111111111111111111111"],
      control_event_set_root: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      state_root: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
    },
    as_of: "2026-05-30T00:00:00Z",
    expires_at: "2099-01-01T00:00:00Z",
  };
}

function mimiProviderDirectory() {
  return {
    providers: [
      {
        service_did: "did:web:mimi.example.com",
        service_type: "mimi_provider_facade",
        provider_id: "mimi://mimi.example.com",
        base_url: "https://mimi.example.com/_cokret/open/mimi",
        supported_profiles: ["ck.profile.mimi_interop.v1"],
      },
    ],
    features: {
      protocol_draft: "draft-ietf-mimi-protocol-06",
      content_draft: "draft-ietf-mimi-content-08",
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
    expires_at: "2026-04-30T12:00:00Z",
  };
}

function json(route: Route, body: unknown, status = 200) {
  return route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}
