import { expect, type Page, type Route } from "@playwright/test";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { mockCokretContract } from "./mockCokretContract";

const DEMO_REALM = "ak:realm:0196419b-0000-7000-8000-000000000000";
const SETUP_REALM = "ak:realm:01js0setupflow000000000000";
const LOW_FLOOR_REALM = "ak:realm:01lowfloor0000000000000000";
const CHILD_REALM = "ak:realm:01launchchild0000000000000";
const GRANDCHILD_REALM = "ak:realm:01launchdeep00000000000000";
const DIRECT_BOB_REALM = "ak:realm:01directbob000000000000000";
const DIRECT_BOB_STRAND = "ak:strand:01directbob0000000000000000";
const DEMO_CIRCLE = "ak:circle:0196419b-0000-7000-8000-00000000c1c1";
const DEMO_BOARD_SPACE = "ak:space:0196419b-0000-7000-8000-00000000b0a0";
const DEMO_SECOND_BOARD_SPACE = "ak:space:0196419b-0000-7000-8000-00000000b0b0";
const DEMO_TODO_LIST = "ak:space:01list-todo000000000000000000";
const DEMO_PROGRESS_LIST = "ak:space:01list-progress00000000000000";
const DEMO_DONE_LIST = "ak:space:01list-done00000000000000000";
const DEMO_SECOND_LIST = "ak:space:01list-secondary000000000000";
const DEMO_STRAND_LEGAL_REVIEW =
  "ak:strand:0196419b-0000-7000-8000-000000000101";
const DEMO_STRAND_ONBOARDING_COPY =
  "ak:strand:0196419b-0000-7000-8000-000000000102";
const DEMO_STRAND_SECURITY_SIGNOFF =
  "ak:strand:0196419b-0000-7000-8000-000000000103";
const DEMO_STRAND_SECONDARY_CARD =
  "ak:strand:0196419b-0000-7000-8000-000000000104";
const DEMO_BLOB_REF =
  "ak:blob:sha256:01015dc8af66d01f557ea63f13538f1964848840a350c5311d1efc8ad138bb91";
const ENROLLMENT_AUTHORITY_DID =
  "did:key:z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw";
const ENROLLMENT_AUTHORITY_VM = `${ENROLLMENT_AUTHORITY_DID}#z6MknBuwKMPAzbhp6EwCnaxsEDk4G2KFeWRu273gYVuTY5jw`;

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
  accountPrincipalId?: string;
  primaryHandle?: string | null;
  directoryPrimaryHandle?: string | null;
  currentDeviceId?: string;
  accountDevices?: MockAccountDevice[];
  enableDeviceEnrollment?: boolean;
  includeDemoRealms?: boolean;
  includeLowFloorRealm?: boolean;
  personalAgentPairingExpiresAt?: string;
};

type MockAccountDevice = {
  device_id: string;
  status?: string;
  display_name?: string | null;
  authorized_at?: string | null;
  revoked_at?: string | null;
  verification_state?: string;
};

type MockCircleState = "active" | "archived" | "tombstoned";
type InksonWireCommand = "canonical-json" | "sha256-canonical-json";
type InksonWireCanonicalJson = { canonical: string };
type InksonWireDigest = { digest: string };

const inksonRepoRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
);

function canonicalJson(value: unknown): string {
  assertJsonTransportable(value, "$");
  return inksonWire<InksonWireCanonicalJson>("canonical-json", { value })
    .canonical;
}

function canonicalSha256(value: unknown) {
  assertJsonTransportable(value, "$");
  return inksonWire<InksonWireDigest>("sha256-canonical-json", { value })
    .digest;
}

function inksonWire<T>(command: InksonWireCommand, input: unknown): T {
  const binary = process.env.INKSON_WIRE_BIN;
  const result = spawnSync(
    binary ?? "cargo",
    binary
      ? [command]
      : ["run", "--quiet", "--bin", "inkson-wire", "--", command],
    {
      cwd: inksonRepoRoot,
      encoding: "utf8",
      input: JSON.stringify(input),
      maxBuffer: 10 * 1024 * 1024,
    },
  );
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(
      `inkson-wire ${command} failed with exit ${result.status}:\n${result.stderr}`,
    );
  }
  return JSON.parse(result.stdout.trim()) as T;
}

function assertJsonTransportable(value: unknown, path: string): void {
  if (value === null) {
    return;
  }

  switch (typeof value) {
    case "string":
    case "boolean":
      return;
    case "number":
      if (!Number.isFinite(value) || Object.is(value, -0)) {
        throw new TypeError(`non-JSON number at ${path}: ${value}`);
      }
      return;
    case "object":
      break;
    default:
      throw new TypeError(`non-JSON value at ${path}: ${typeof value}`);
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      if (item === undefined) {
        throw new TypeError(`non-JSON undefined item at ${path}[${index}]`);
      }
      assertJsonTransportable(item, `${path}[${index}]`);
    });
    return;
  }

  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw new TypeError(`non-JSON object at ${path}`);
  }

  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (item === undefined) {
      throw new TypeError(`non-JSON undefined member at ${path}.${key}`);
    }
    assertJsonTransportable(item, `${path}.${key}`);
  }
}

function isDid(value: unknown): value is string {
  return typeof value === "string" && /^did:[a-z0-9]+:[^\s#?]+$/.test(value);
}

function isDeviceId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^ak:device:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      value,
    )
  );
}

function isDeviceOrDid(value: unknown): value is string {
  return isDeviceId(value) || isDid(value);
}

function signedEventDigest(event: Record<string, unknown>) {
  const digestPayload = { ...event };
  delete digestPayload.proofs;
  delete digestPayload.unsigned;
  return canonicalSha256(digestPayload);
}

export async function mockCokretApi(
  page: Page,
  options: MockCokretApiOptions = {},
) {
  const advertiseListHandlesForSubject =
    options.advertiseListHandlesForSubject ?? true;
  const accountPrincipalId =
    options.accountPrincipalId ?? "did:web:alice.example";
  const primaryHandle =
    options.primaryHandle === undefined
      ? "alice:local.host"
      : options.primaryHandle;
  const directoryPrimaryHandle =
    options.directoryPrimaryHandle === undefined
      ? primaryHandle
      : options.directoryPrimaryHandle;
  const directoryHandleForSubject = (subject: string) => {
    if (!directoryPrimaryHandle) {
      return null;
    }
    if (subject === accountPrincipalId) {
      return directoryPrimaryHandle;
    }
    const materialized = subject.match(/^did:web:([^:]+):users:([^:]+)$/);
    if (materialized) {
      return `${materialized[2]}:${materialized[1]}`;
    }
    const simpleExample = subject.match(/^did:web:([a-z0-9._-]+)\.example$/i);
    if (simpleExample) {
      return `${simpleExample[1].toLowerCase()}:example.com`;
    }
    return null;
  };
  const currentDeviceId =
    options.currentDeviceId ?? "ak:device:01964137-0000-7000-8000-0000000000a1";
  const includeDemoRealms = options.includeDemoRealms ?? true;
  const includeLowFloorRealm = options.includeLowFloorRealm ?? false;
  const personalAgentPairingExpiresAt =
    options.personalAgentPairingExpiresAt ?? "2099-07-06T00:10:00Z";
  const accountDevices = new Map<string, MockAccountDevice>();
  for (const device of options.accountDevices ?? [
    {
      device_id: "ak:device:01964137-0000-7000-8000-0000000000a1",
      status: "active",
      display_name: "Current device",
      authorized_at: "2026-04-28T12:00:00Z",
    },
  ]) {
    accountDevices.set(device.device_id, { ...device });
  }
  let messageCounter = 0;
  const createdRealms: Array<{
    id: string;
    title: string;
    summary: string;
    encryption_profile: string;
  }> = [];
  const projectionEvents: Array<Record<string, unknown>> = [];
  const circleStates = new Map<string, MockCircleState>([
    [DEMO_CIRCLE, "active"],
  ]);
  const circleView = (circleId = DEMO_CIRCLE) => ({
    circle_id: circleId,
    realm_id: DEMO_REALM,
    title: "Demo Circle",
    summary: "Mock Circle for lifecycle operations",
    directory_visibility: "realm_members",
    join_rule: "invite",
    history_visibility: "joined",
    content_encryption_floor: "mls_rfc9420",
    metadata_encryption_floor: "mls_rfc9420",
    encryption_profile: "mls_rfc9420",
    mls_group_ref: "mls:demo-circle",
    pending_mls_removals: [],
    state: circleStates.get(circleId) ?? "active",
    members: [accountPrincipalId],
    created_by: accountPrincipalId,
    created_at: "2026-06-23T00:00:00Z",
    updated_by: accountPrincipalId,
    updated_at: "2026-06-23T00:00:00Z",
  });
  let recoveryPolicy: Record<string, unknown> | null = null;
  const keyBackups = new Map<string, Record<string, unknown>>();
  const personalAgents = new Map<string, Record<string, unknown>>();
  const personalAgentKeyStates = new Map<string, Record<string, unknown>>();
  const personalAgentGrants = new Map<string, Array<Record<string, unknown>>>();
  let personalAgentCounter = 0;
  const eventRealmId = (event: Record<string, unknown>) =>
    String(event.realm_id ?? "");
  const accountDeviceSummaries = () =>
    Array.from(accountDevices.values()).map((device) => {
      const summary: Record<string, unknown> = {
        device_id: device.device_id,
        status: device.status ?? (device.authorized_at ? "active" : "unknown"),
      };
      if (device.display_name !== undefined) {
        summary.display_name = device.display_name;
      }
      if (device.authorized_at) {
        summary.authorized_at = device.authorized_at;
      }
      if (device.revoked_at) {
        summary.revoked_at = device.revoked_at;
      }
      if (device.verification_state) {
        summary.verification_state = device.verification_state;
      }
      if (device.device_id === currentDeviceId) {
        summary.is_current_session_device = true;
      }
      return summary;
    });
  const markDeviceAuthorized = (deviceId: string) => {
    accountDevices.set(deviceId, {
      ...(accountDevices.get(deviceId) ?? {
        device_id: deviceId,
        display_name: "Current device",
      }),
      status: "active",
      verification_state: "verified",
      authorized_at: new Date().toISOString(),
      revoked_at: null,
    });
  };
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
      summary:
        "Finalize external processor wording before launch checklist can move.",
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
        locked_reason:
          "You can see that a restricted discussion is linked, but not its name or members.",
      },
    },
    {
      strand_id: DEMO_STRAND_ONBOARDING_COPY,
      realm_id: DEMO_REALM,
      title: "Onboarding copy",
      summary:
        "Waiting on discussion-scoped feedback from support and docs reviewers.",
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
      summary:
        "Only visible after the Board selector switches projection scope.",
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
    if (
      url.hostname === "auth.local.host" &&
      url.pathname === "/.well-known/openid-configuration"
    ) {
      return json(route, {
        issuer: "https://auth.local.host/",
        authorization_endpoint: "https://auth.local.host/authorize",
        token_endpoint: "https://auth.local.host/oauth/token",
        userinfo_endpoint: "https://auth.local.host/oauth/userinfo",
        code_challenge_methods_supported: ["plain", "S256"],
        scopes_supported: [
          "openid",
          "profile",
          "urn:arkret:principal-server:session.bind",
        ],
      });
    }
    if (url.hostname === "auth.local.host" && url.pathname === "/authorize") {
      return route.fulfill({
        status: 200,
        contentType: "text/html",
        body: '<!doctype html><main data-testid="coauth-login"><h1>Sign in</h1><p>coauth</p><a href="/register">Create account</a><a href="/recovery">Lost password or account</a></main>',
      });
    }
    if (!url.pathname.startsWith("/_arkret/")) {
      return route.continue();
    }
    if (
      options.enableDeviceEnrollment &&
      url.hostname === "auth.local.host" &&
      url.pathname === "/_arkret/gate/account/device-enroll" &&
      route.request().method() === "POST"
    ) {
      const body = await route.request().postDataJSON();
      const deviceId =
        typeof body.device_id === "string" ? body.device_id : currentDeviceId;
      const authorizedEvent: Record<string, unknown> = {
        event_id: "ak:event:01964137-0000-7000-8000-00000000d0e1",
        kind: "ak.device.authorize",
        realm_id: "ak:realm:01964137-0000-7000-8000-00000000c0de",
        actor_id: accountPrincipalId,
        executed_by: ENROLLMENT_AUTHORITY_DID,
        authorization_ref: `${accountPrincipalId}#enrollment-authority`,
        actor_seq: typeof body.actor_seq === "number" ? body.actor_seq : 1,
        created_at: "2026-06-22T00:00:00Z",
        hlc: "019641370000-0000-12345678",
        prev_refs: [],
        refs: [],
        payload: {
          principal_id: accountPrincipalId,
          device_id: deviceId,
          device_public_key:
            typeof body.device_public_key === "string"
              ? body.device_public_key
              : "z6MkExamplePublicKey",
          authorized_by: ENROLLMENT_AUTHORITY_DID,
          not_before: "2026-06-22T00:00:00Z",
          enrollment_authority_binding: {
            kind: "service_attested",
            authority_did: ENROLLMENT_AUTHORITY_DID,
            authorization_ref: `${accountPrincipalId}#enrollment-authority`,
          },
        },
      };
      const eventDigest = signedEventDigest(authorizedEvent);
      authorizedEvent.proofs = [
        {
          kind: "detached_jws",
          alg: "EdDSA",
          verification_method: ENROLLMENT_AUTHORITY_VM,
          event_digest: eventDigest,
          created_at: "2026-06-22T00:00:00Z",
          domain: ENROLLMENT_AUTHORITY_DID,
          audience: "did:web:server.local",
          jws: "ey.ey.sig",
        },
      ];
      return json(route, {
        principal_id: accountPrincipalId,
        device_id: deviceId,
        authority_did: ENROLLMENT_AUTHORITY_DID,
        authorized_event: authorizedEvent,
      });
    }

    if (
      url.pathname === "/_arkret/describe" &&
      route.request().method() === "GET"
    ) {
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
              gate_account_base: "https://auth.local.host/_arkret/gate/account",
            },
            methods: [
              {
                method: "oidc",
                issuer: "https://auth.local.host/",
                openid_configuration:
                  "https://auth.local.host/.well-known/openid-configuration",
                client_id: "01GFWR28C4KNE04WG3HKXB7C9R",
                scopes: [
                  "openid",
                  "profile",
                  "urn:arkret:principal-server:session.bind",
                ],
                grant_exchange: { proof_kind: "oidc_code_exchange" },
              },
            ],
          },
          limits: {},
        });
      }
      return json(route, {
        service_did: "did:web:server.local",
        trust_domain: "ak:trust_domain:server.local",
        service_type: "principal_server",
        protocol_version: "1.0",
        supported_profiles: [
          "ak.profile.minimal_client.v1",
          "ak.profile.chat_mvp.v1",
          "ak.profile.kanban_mvp.v1",
          "ak.profile.full_client.v1",
          "ak.profile.e2ee_client.v1",
          "ak.profile.push_gateway.v1",
          "ak.profile.mimi_interop.v1",
          "ak.profile.core_event_store.v1",
          "ak.profile.principal_server_events_api.v1",
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
          "ak.server.query.describe",
          "ak.self.account.stream.subscribe",
          "ak.self.account.query.describe",
          "ak.self.account.query.viewer",
          "ak.self.account.command.update_profile",
          "ak.self.events.query.scan",
          "ak.self.events.stream.subscribe",
          "ak.self.events.query.describe",
          "ak.self.events.command.submit",
          "ak.self.space.query.list",
          "ak.self.strand.query.list",
          "ak.find.directory.query.search_realms",
          "ak.find.directory.query.resolve_realm",
          "ak.find.directory.query.describe",
          "ak.find.directory.query.search_organizations",
          "ak.find.directory.query.search_actors",
          "ak.find.directory.query.resolve_handle",
          ...(advertiseListHandlesForSubject
            ? ["ak.find.directory.query.list_handles_for_subject"]
            : []),
          "ak.self.authz.query.check",
          "ak.self.authz.grants.query.effective",
          "ak.self.authz.invites.query.list",
          "ak.root.identity.registry.query.describe",
          "ak.root.identity.query.resolve",
          "ak.root.identity.recovery_policy.resource.get",
          "ak.root.identity.recovery_policy.command.publish",
          "ak.gate.account.command.register",
          "ak.gate.account.command.pair_device",
          "ak.gate.account.command.revoke_session",
          "ak.self.contact.query.list",
          "ak.self.contact.command.request",
          "ak.self.contact.command.respond",
          "ak.self.contact.command.tombstone",
          "ak.self.invite_receive_policy.resource.get",
          "ak.self.invite_receive_policy.resource.replace",
          "ak.self.direct_conversation.command.resolve",
          "ak.self.circle.command.create",
          "ak.self.circle.query.list",
          "ak.self.circle.resource.get",
          "ak.self.circle.member.command.add",
          "ak.self.circle.member.resource.delete",
          "ak.self.circle.command.rotate_scope",
          "ak.self.circle.command.archive",
          "ak.self.circle.command.restore",
          "ak.self.circle.command.tombstone",
          "ak.self.keys.upload.create",
          "ak.self.keys.query.lookup",
          "ak.self.keys.command.claim",
          "ak.self.keys.backups.query.list",
          "ak.self.keys.backups.resource.replace",
          "ak.self.device_messages.query.list",
          "ak.self.device_messages.command.send",
          "ak.self.device_messages.command.ack",
          "ak.edge.push.command.register_device",
          "ak.edge.push.command.unregister_device",
          "ak.self.blob.upload.create",
          "ak.self.blob.resource.get",
          "ak.self.media.query.ice_config",
          "ak.self.moderation.command.report",
          "ak.open.mimi.query.provider_directory",
          "ak.open.mimi.exchange.request_key_material",
          "ak.open.mimi.query.group_info",
          "ak.open.mimi.command.update_room",
          "ak.open.mimi.command.notify",
          "ak.open.mimi.command.submit_message",
          "ak.open.mimi.command.request_consent",
          "ak.open.mimi.command.update_consent",
          "ak.open.mimi.query.identifiers",
          "ak.open.mimi.command.report_abuse",
          "ak.open.mimi.command.proxy_download",
          "ak.open.invite_locator.query.resolve",
          "ak.self.ephemeral.command.send",
        ],
        supported_schema_profiles: ["ak.schema.core.v1"],
        supported_reducer_profiles: ["ak.reducer.v1"],
        supported_bindings: [{ kind: "http_json" }],
        auth_metadata: {
          mode: "development",
          account_authority: {
            origin: "https://auth.local.host",
            gate_account_base: "https://auth.local.host/_arkret/gate/account",
          },
          methods: [
            {
              method: "oidc",
              issuer: "https://auth.local.host/",
              openid_configuration:
                "https://auth.local.host/.well-known/openid-configuration",
              client_id: "01GFWR28C4KNE04WG3HKXB7C9R",
              scopes: [
                "openid",
                "profile",
                "urn:arkret:principal-server:session.bind",
              ],
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

    if (
      url.pathname.startsWith("/_arkret/self/realms/") &&
      url.pathname.endsWith("/spaces") &&
      route.request().method() === "GET"
    ) {
      const realmId = url.pathname.split("/")[4] ?? DEMO_REALM;
      return json(route, {
        realm_id: realmId,
        total: boardSpaceContainers.length,
        spaces: boardSpaceContainers,
      });
    }

    if (
      url.pathname.startsWith("/_arkret/self/realms/") &&
      url.pathname.endsWith("/strands") &&
      route.request().method() === "GET"
    ) {
      const realmId = url.pathname.split("/")[4] ?? DEMO_REALM;
      return json(route, {
        realm_id: realmId,
        total: boardStrandProjections.length,
        strands: boardStrandProjections,
      });
    }

    if (
      url.pathname === "/_arkret/self/circles" &&
      route.request().method() === "GET"
    ) {
      const realmId = url.searchParams.get("realm_id") ?? DEMO_REALM;
      return json(route, {
        realm_id: realmId,
        circles: realmId === DEMO_REALM ? [circleView()] : [],
      });
    }

    const circleLifecycle = url.pathname.match(
      /^\/_arkret\/self\/circles\/([^/]+)\/(archive|restore|tombstone)$/,
    );
    if (circleLifecycle && route.request().method() === "POST") {
      const [, circleId, action] = circleLifecycle;
      const state = circleStates.get(circleId);
      if (!state) {
        return json(route, { error: { code: "not_found" } }, 404);
      }
      if (action === "archive" && state !== "active") {
        return json(route, { error: { code: "circle_not_active" } }, 412);
      }
      if (action === "restore" && state !== "archived") {
        return json(route, { error: { code: "circle_not_archived" } }, 412);
      }
      if (action === "tombstone" && state === "tombstoned") {
        return json(route, { error: { code: "circle_already_terminal" } }, 412);
      }
      const next =
        action === "archive"
          ? "archived"
          : action === "restore"
            ? "active"
            : "tombstoned";
      circleStates.set(circleId, next);
      return json(route, circleView(circleId));
    }

    if (
      url.pathname === "/_arkret/self/events/describe" &&
      route.request().method() === "GET"
    ) {
      // Spec ak.self.events.query.describe -> canonical ServiceDescribe shape
      // (17 required fields; inkson decodes the SDK ServerDescription).
      return json(route, {
        service_did: "did:web:server.local",
        trust_domain: "ak:trust_domain:server.local",
        service_type: "principal_server",
        protocol_version: "1.0",
        supported_profiles: ["ak.profile.core_event_store.v1"],
        supported_operations: [
          "ak.self.events.command.submit",
          "ak.self.events.query.describe",
        ],
        supported_bindings: [{ kind: "http_json" }],
        supported_features: [],
        auth_metadata: {
          mode: "development",
          account_authority: {
            origin: "https://auth.local.host",
            gate_account_base: "https://auth.local.host/_arkret/gate/account",
          },
          methods: [
            {
              method: "oidc",
              issuer: "https://auth.local.host/",
              openid_configuration:
                "https://auth.local.host/.well-known/openid-configuration",
              client_id: "01GFWR28C4KNE04WG3HKXB7C9R",
              scopes: [
                "openid",
                "profile",
                "urn:arkret:principal-server:session.bind",
              ],
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
        // Strict typed EventId — must be a canonical ak:event:<uuidv7>.
        frontier: ["ak:event:0196419b-0000-7000-8000-00000000e2e0"],
      });
    }

    if (
      url.pathname === "/_arkret/self/events" &&
      route.request().method() === "POST"
    ) {
      const body = await route.request().postDataJSON();
      if (!route.request().headers()["x-arkret-request-id"]) {
        return json(
          route,
          {
            ok: false,
            error: {
              code: "missing_request_id",
              message: "missing x-arkret-request-id",
            },
          },
          428,
        );
      }
      let syncToken = "sx:e2e:event";
      const submittedEvents = Array.isArray(body.events) ? body.events : [body];
      for (const event of submittedEvents) {
        if (event.kind === "ak.device.authorize") {
          const payload = event.payload ?? event.content ?? {};
          const binding = payload.enrollment_authority_binding ?? {};
          if (
            !isDid(payload.principal_id) ||
            !isDeviceId(payload.device_id) ||
            typeof payload.device_public_key !== "string" ||
            payload.device_public_key.trim() === "" ||
            !isDeviceOrDid(payload.authorized_by) ||
            binding.kind !== "service_attested" ||
            !isDid(binding.authority_did) ||
            typeof binding.authorization_ref !== "string" ||
            binding.authorization_ref.trim() === ""
          ) {
            return json(
              route,
              {
                ok: false,
                error: {
                  code: "schema_violation",
                  message:
                    "ak.device.authorize payload violates mock SDK artifact schema",
                },
              },
              400,
            );
          }
          const authorizedDeviceId = payload.device_id ?? event.device_id;
          if (typeof authorizedDeviceId === "string") {
            markDeviceAuthorized(authorizedDeviceId);
          }
          continue;
        }
        const raw = JSON.stringify(event);
        if (
          event.kind !== "ak.realm.create" &&
          !raw.includes("ak.realm.create")
        ) {
          continue;
        }
        const id =
          event.realm_id ??
          event.payload?.realm_id ??
          event.payload?.object?.realm_id ??
          raw.match(/ak:realm:[0-9a-f-]+/)?.[0] ??
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
          "Created from inkson workspace setup";
        const encryptionProfile =
          event.payload?.object?.encryption_profile ??
          event.payload?.encryption_profile ??
          "mls_rfc9420";
        if (!createdRealms.some((realm) => realm.id === id)) {
          createdRealms.push({
            id,
            title,
            summary,
            encryption_profile: encryptionProfile,
          });
        }
      }
      if (body.kind === "ak.space.create") {
        const object = body.payload?.object ?? {};
        const containerId =
          object.id ??
          body.payload?.space_id ??
          body.payload?.container_space_id ??
          body.target_ref;
        if (
          typeof containerId === "string" &&
          !boardSpaceContainers.some(
            (row) => row.container_space_id === containerId,
          )
        ) {
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
      if (body.kind === "ak.message.create") {
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
      if (body.kind === "ak.strand.create") {
        messageCounter += 1;
        syncToken = `sx:e2e:strand-${messageCounter}`;
        const object = body.payload?.object ?? {};
        const component = Array.isArray(body.payload?.components)
          ? body.payload.components.find(
              (candidate: { family?: string }) =>
                candidate.family === "ak.component.strand.position.v1",
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
          const existing = boardStrandProjections.findIndex(
            (row) => row.strand_id === strandId,
          );
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
      // inkson folds accepted[0] -> event_id and keeps cursor as-is.
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

    if (
      url.pathname === "/_arkret/open/mimi/provider-directory" &&
      route.request().method() === "GET"
    ) {
      return json(route, mimiProviderDirectory());
    }

    if (
      url.pathname === "/_arkret/open/mimi/key-material" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        ok: true,
        key_packages: [
          {
            key_package_ref: "mimi:key-package:e2e",
            target: "mimi://remote.example/alice",
          },
        ],
        receipt: {
          kind: "ak.open.mimi.exchange.request_key_material",
          profile: "ak.profile.mimi_interop.v1",
        },
      });
    }

    if (
      url.pathname.match(/^\/_arkret\/open\/mimi\/strands\/[^/]+\/update$/) &&
      route.request().method() === "POST"
    ) {
      const roomId = decodeURIComponent(url.pathname.split("/")[5]);
      return json(route, {
        ok: true,
        room_id: roomId,
        receipt: {
          kind: "ak.open.mimi.command.update_room",
          operation_id: "ak:operation:mimi-room-update",
        },
      });
    }

    if (
      url.pathname.match(/^\/_arkret\/open\/mimi\/strands\/[^/]+\/notify$/) &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        ok: true,
        accepted: ["did:web:remote.example"],
        receipt: {
          kind: "ak.open.mimi.command.notify",
          notification_id: "ak:mimi:notify:e2e",
        },
      });
    }

    if (
      url.pathname.match(/^\/_arkret\/open\/mimi\/strands\/[^/]+\/messages$/) &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        event_ref: "ak:event:01964137-0000-7000-8000-00000000d0aa",
        delivery: {
          kind: "ak.mimi.mapping_receipt",
          profile: "ak.profile.mimi_interop.v1",
          mimi_room_uri: "mimi://mimi.example.com/rooms/01JSMIMI",
          source_format: "text/markdown;variant=GFM-MIMI",
          target_format: "ak.message.create",
          original_envelope_hash: "sha256:e2e-mimi-envelope",
          mapped_operation_id: "ak:operation:mimi-submit-e2e",
          mimi_message_id: "mimi-msg-e2e",
        },
        rejected: [],
      });
    }

    if (
      url.pathname.match(
        /^\/_arkret\/open\/mimi\/strands\/[^/]+\/group-info$/,
      ) &&
      route.request().method() === "GET"
    ) {
      return json(route, {
        group_info: {
          epoch: 7,
          mls_group_id: "mls-group-01",
          policy_root: "sha256:e2e-policy-root",
        },
        room_binding_ref: "ak:event:01964137-0000-7000-8000-00000000d0ab",
        proofs: [
          {
            kind: "ak.open.mimi.query.group_info",
            profile: "ak.profile.mimi_interop.v1",
          },
        ],
      });
    }

    if (
      url.pathname === "/_arkret/open/mimi/consent/request" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        ok: true,
        consent_id: "ak:mimi-consent:e2e",
        state: "requested",
        receipt: { kind: "ak.open.mimi.command.request_consent" },
      });
    }

    if (
      url.pathname === "/_arkret/open/mimi/consent/update" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        ok: true,
        consent_id: "ak:mimi-consent:e2e",
        state: "accepted",
        receipt: { kind: "ak.open.mimi.command.update_consent" },
      });
    }

    if (
      url.pathname === "/_arkret/open/mimi/identifiers/query" &&
      route.request().method() === "POST"
    ) {
      const body = await route.request().postDataJSON();
      return json(route, {
        matches: [
          {
            identifier_commitment: `sha256:${"2".repeat(64)}`,
            matched: true,
            mimi_uri:
              body.identifiers?.[0]?.mimi_uri ?? "mimi://remote.example/alice",
            subject: "did:web:alice.example",
          },
        ],
        proofs: [
          {
            type: "private_identifier_query",
            expires_at: "2026-04-30T12:00:00Z",
          },
        ],
        has_more: false,
      });
    }

    if (
      url.pathname === "/_arkret/open/mimi/report-abuse" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        ok: true,
        report_id: "ak:report:mimi-e2e",
        status: "queued",
        receipt: { kind: "ak.open.mimi.command.report_abuse" },
      });
    }

    if (
      url.pathname === "/_arkret/open/mimi/proxy-download" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        download_ref: `https://mimi.example.com/proxy/${DEMO_BLOB_REF}`,
        headers: { "content-type": "application/octet-stream" },
        expires_at: "2026-04-30T12:00:00Z",
      });
    }

    if (
      url.pathname === "/_arkret/gate/account/register" &&
      route.request().method() === "POST"
    ) {
      const body = await route.request().postDataJSON();
      if (body.device_id && !accountDevices.has(body.device_id)) {
        accountDevices.set(body.device_id, {
          device_id: body.device_id,
          status: "unknown",
          display_name: "Current device",
          verification_state: "unverified",
        });
      }
      return json(
        route,
        {
          principal_id: body.principal_id,
          state: "active",
          devices: accountDeviceSummaries(),
          profile: {
            id: "ak:actor_profile:01964137-0000-7000-8000-0000000000a1",
            schema: "ak.schema.actor_profile.v1",
            principal_id: body.principal_id,
            actor_kind: "user",
            display_name: body.display_name ?? "inkson",
            profile_fields: {},
            accountable_principal_ids: [],
            created_at: "2026-04-28T12:00:00Z",
          },
        },
        201,
      );
    }

    if (
      url.pathname === "/_arkret/self/account/profile" &&
      route.request().method() === "POST"
    ) {
      const body = await route.request().postDataJSON();
      const patch = body.patch ?? {};
      const displayName =
        typeof patch.display_name === "string" ? patch.display_name : "inkson";
      const avatarBlobRef =
        typeof patch.avatar_blob_ref === "string"
          ? patch.avatar_blob_ref
          : undefined;
      const bio =
        typeof patch["profile_fields.bio"] === "string"
          ? patch["profile_fields.bio"]
          : undefined;
      return json(route, {
        profile: {
          id: "ak:actor_profile:01964137-0000-7000-8000-0000000000a1",
          schema: "ak.schema.actor_profile.v1",
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

    if (
      url.pathname === "/_arkret/gate/account/session-grants/revoke" &&
      route.request().method() === "POST"
    ) {
      return json(route, { revoked_count: 1, revoked_grant_ids: [] });
    }

    if (
      url.pathname === "/_arkret/self/account/subscribe" &&
      route.request().method() === "GET"
    ) {
      const demoProjectionEvents = projectionEvents.filter(
        (event) => eventRealmId(event) === DEMO_REALM,
      );
      const notificationEvents = includeDemoRealms
        ? [
            {
              kind: "ak.notification",
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
              kind: "ak.notification",
              notification_id: "notif-invite-1",
              invite_id: "ak:invite:01904100-0000-7000-8000-000000000099",
              title: "New invite",
              body: "You were invited to review Demo Realm",
              realm_id: DEMO_REALM,
              notification_kind: "invite",
              type: "invite",
              timestamp: "2026-04-28T12:02:00Z",
              read: false,
            },
          ]
        : [];
      const frame = {
        kind: "delta",
        cursor: "ak:cursor:e2e-2",
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
                  events: projectionEvents.filter(
                    (event) => eventRealmId(event) === realm.id,
                  ),
                  limited: false,
                },
                state: { events: [] },
                ephemeral: { events: [] },
                unread: { notification_count: 0, highlight_count: 0 },
              },
            ]),
          ),
          ...(includeDemoRealms
            ? {
                [DEMO_REALM]: {
                  summary: {
                    title: "Arkret Demo Realm",
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
              }
            : {}),
          ...(includeLowFloorRealm
            ? {
                [LOW_FLOOR_REALM]: {
                  summary: {
                    title: "Low floor fixture Realm",
                    summary:
                      "Mocks the live first-account PCR floor advisory condition",
                    encryption_profile: "none",
                  },
                  timeline: { events: [], limited: false },
                  state: { events: [] },
                  ephemeral: { events: [] },
                  unread: { notification_count: 0, highlight_count: 0 },
                },
              }
            : {}),
        },
        left_realms: [],
        to_device: {
          messages: includeDemoRealms
            ? [{ kind: "ak.mls.welcome", content: { ciphertext: "opaque" } }]
            : [],
          ack_token: "mock-to-device-ack",
        },
        account_data: { events: notificationEvents },
        device_lists: { changed: [], left: [] },
        presence: { events: [] },
        notifications: {
          events: notificationEvents,
          unread_count: notificationEvents.length,
        },
      };
      return route.fulfill({
        status: 200,
        contentType: "application/x-ndjson",
        body: `${JSON.stringify(frame)}\n${JSON.stringify({ kind: "catchup_complete", cursor: "ak:cursor:e2e-2" })}\n`,
      });
    }

    if (
      url.pathname === "/_arkret/find/directory/search-realms" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        realms: [realmPreview()],
        next_cursor: null,
        has_more: false,
      });
    }

    if (
      url.pathname === "/_arkret/find/directory/search-organizations" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        organizations: [
          {
            organization_did: "did:web:org.arkret.example",
            handle: "arkret.example",
            display_name: "Arkret Labs",
            as_of: "2026-06-19T00:00:00Z",
            source_refs: ["ak:event:0196419b-0000-7000-8000-0000000000d1"],
            policy_revision: "local",
          },
        ],
        next_cursor: null,
        has_more: false,
      });
    }

    if (
      url.pathname === "/_arkret/find/directory/search-actors" &&
      route.request().method() === "POST"
    ) {
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

    if (
      url.pathname === "/_arkret/open/invite-locators/resolve" &&
      route.request().method() === "POST"
    ) {
      expect(url.search).toBe("");
      const body = await route.request().postDataJSON();
      expect(body.locator_token).toBeTruthy();
      return json(route, {
        schema: "ak.schema.principal_locator.v1",
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

    if (
      url.pathname === "/_arkret/find/directory/resolve-handle" &&
      route.request().method() === "POST"
    ) {
      const body = await route.request().postDataJSON();
      const audience =
        body.audience ??
        body.realm_id ??
        body.requester ??
        "did:web:server.local";
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

    if (
      url.pathname === "/_arkret/find/directory/list-handles-for-subject" &&
      route.request().method() === "POST"
    ) {
      const body = await route.request().postDataJSON();
      const subject = body.subject ?? accountPrincipalId;
      const subjectPrimaryHandle = directoryHandleForSubject(subject);
      if (!subjectPrimaryHandle) {
        return json(route, {
          subject,
          primary_handle: null,
          as_of: "2026-04-28T12:00:00Z",
          has_more: false,
          claims: [],
        });
      }
      return json(route, {
        subject,
        primary_handle: subjectPrimaryHandle,
        as_of: "2026-04-28T12:00:00Z",
        has_more: false,
        claims: [
          {
            subject,
            handle: subjectPrimaryHandle,
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

    if (
      url.pathname === "/_arkret/find/directory/resolve-realm" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        realm_preview: realmPreview(),
        stripped_state: [],
        join_rule: "public",
        join_candidates: [joinCandidate()],
      });
    }

    if (
      url.pathname === "/_arkret/find/directory/describe" &&
      route.request().method() === "GET"
    ) {
      return json(route, {
        service_did: "did:web:server.local",
        trust_domain: "ak:trust_domain:server.local",
        service_type: "directory_service",
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
        resource_types: ["realm", "organization", "actor"],
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

    if (
      url.pathname === "/_arkret/self/events" &&
      route.request().method() === "GET"
    ) {
      const requestedRealms = (url.searchParams.get("realms") ?? "")
        .split(",")
        .map((realm) => realm.trim())
        .filter(Boolean);
      const events = requestedRealms.length
        ? projectionEvents.filter((event) =>
            requestedRealms.includes(eventRealmId(event)),
          )
        : projectionEvents;
      return json(route, { events, next_cursor: null, has_more: false });
    }

    // NB: no `/_arkret/self/snapshot/head` route. The mock's describe does
    // not advertise `ak.self.snapshot.query.manifest_head`, so the client falls back to
    // event replay before issuing the request. The current wire shape is the
    // full signed `ak.schema.snapshot.v1` manifest (self-id field `id`); the
    // removed `snapshot_ref` pointer DTO is hard-rejected and MUST NOT be
    // reintroduced here.
    if (
      url.pathname === "/_arkret/root/identity/describe" &&
      route.request().method() === "GET"
    ) {
      return json(route, {
        service_did: "did:web:server.local",
        registry_mode: "development_local",
        supported_receipts: ["local"],
        protocol_version: "1.0",
        profiles: ["ak.identity.local-dev.v1"],
      });
    }

    if (
      url.pathname === "/_arkret/root/identity/resolve" &&
      route.request().method() === "POST"
    ) {
      const body = await route.request().postDataJSON();
      return json(route, {
        did_document: { id: body.did },
        key_log_head: null,
        seq: 0,
        receipts: [],
        method_evidence: { mode: "development_local" },
      });
    }

    if (
      url.pathname === "/_arkret/self/account/describe" &&
      route.request().method() === "GET"
    ) {
      return json(route, {
        service_did: "did:web:server.local",
        supported_sync_profiles: ["initial", "incremental"],
        limits: {},
        frontier: {},
      });
    }

    if (
      url.pathname === "/_arkret/self/authz/check" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        allowed: true,
        reason_code: "frontier_current",
        grants: ["ak:grant:0196419b-0000-7000-8000-00000000e2e1"],
        obligations: [{ type: "audit", reason_required: false }],
      });
    }

    if (
      url.pathname === "/_arkret/self/authz/effective-grants" &&
      route.request().method() === "GET"
    ) {
      return json(route, {
        grants: [
          {
            grant_id: "ak:grant:0196419b-0000-7000-8000-00000000e2e1",
            issuer: "did:web:admin.example",
            subject: url.searchParams.get("subject"),
            actions: ["space.read", "message.create"],
            resource_selectors: [`realm:${DEMO_REALM}`],
            constraints: [
              { type: "temporal", not_after: "2026-12-31T00:00:00Z" },
              {
                type: "type_restriction",
                params: {
                  allowed_object_types: ["space"],
                  allowed_facets: ["renderable", "stateful"],
                },
              },
            ],
            delegation_chain: [
              "ak:grant:0196419b-0000-7000-8000-00000000e2e0",
              "ak:grant:0196419b-0000-7000-8000-00000000e2e1",
            ],
          },
        ],
        state_digest:
          "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        evaluated_at: "2026-04-28T12:00:00Z",
      });
    }

    if (
      url.pathname === "/_arkret/self/authz/invites" &&
      route.request().method() === "GET"
    ) {
      return json(route, { invites: [], next_cursor: null });
    }

    if (
      url.pathname === "/_arkret/self/contacts" &&
      route.request().method() === "GET"
    ) {
      return json(route, {
        contacts: [
          {
            peer: "did:web:bob.example",
            state: "accepted",
            request_event_ref: "ak:event:0196419b-0000-7000-8000-000000000101",
            response_event_ref: "ak:event:0196419b-0000-7000-8000-000000000102",
            granted_by_me: ["direct_message", "invite"],
            granted_to_me: ["direct_message", "invite"],
            bidirectional_scopes: ["direct_message", "invite"],
            effective_scopes: ["direct_message", "invite"],
            // U3 — consent grant the peer gave me for the invite scope.
            invite_consent_grant_ref:
              "ak:event:0196419b-0000-7000-8000-000000000102",
            direct_conversation: {
              realm_id: DIRECT_BOB_REALM,
              main_strand_id: DIRECT_BOB_STRAND,
              binding_event_ref:
                "ak:event:0196419b-0000-7000-8000-000000000103",
              state: "active",
            },
          },
          {
            peer: "did:web:carol.example",
            state: "pending_outgoing",
            request_event_ref: "ak:event:0196419b-0000-7000-8000-000000000104",
            granted_by_me: ["invite"],
            granted_to_me: [],
            bidirectional_scopes: [],
            effective_scopes: ["invite"],
          },
          {
            peer: "did:web:dave.example",
            state: "pending_incoming",
            request_event_ref: "ak:event:0196419b-0000-7000-8000-000000000105",
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
            request_event_ref: "ak:event:0196419b-0000-7000-8000-000000000106",
            response_event_ref: "ak:event:0196419b-0000-7000-8000-000000000107",
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
    if (
      url.pathname === "/_arkret/self/contacts/request" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        request_event_ref: "ak:event:0196419b-0000-7000-8000-000000000108",
        requester_consent_refs: [],
        state: "pending_outgoing",
      });
    }

    // U1 — accept / reject an incoming contact request.
    if (
      url.pathname === "/_arkret/self/contacts/respond" &&
      route.request().method() === "POST"
    ) {
      const body = await route.request().postDataJSON();
      return json(route, {
        response_event_ref: "ak:event:0196419b-0000-7000-8000-000000000109",
        consent_grant_refs:
          body.action === "accept"
            ? ["ak:event:0196419b-0000-7000-8000-000000000110"]
            : [],
        state: body.action === "accept" ? "accepted" : "rejected",
      });
    }

    // U5 — tombstone / block a contact.
    if (
      url.pathname === "/_arkret/self/contacts/tombstone" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        tombstone_event_ref: "ak:event:0196419b-0000-7000-8000-000000000111",
        consent_revoke_refs: [],
        state: "tombstoned",
        partial_revoke: false,
      });
    }

    // U4 — invite_receive_policy ("谁可以邀请我"). Spec invite-addressing.md
    // §5: GET/SET carry the bare `arkret_sdk::InviteReceivePolicy` (required
    // `schema` + `subject_id`, typed enums, trust lists) — no `ok` wrapper.
    if (
      url.pathname === "/_arkret/self/invite-receive-policy" &&
      route.request().method() === "PUT"
    ) {
      // The real soland handler echoes the stored policy back verbatim;
      // mirror that so the client's `trusted_*` lists round-trip intact.
      const body = await route.request().postDataJSON();
      return json(route, body);
    }
    if (
      url.pathname === "/_arkret/self/invite-receive-policy" &&
      route.request().method() === "GET"
    ) {
      return json(route, {
        schema: "ak.schema.invite_receive_policy.v1",
        subject_id: "did:web:alice.example",
        allowed_introduction_kinds: [
          "consent_grant",
          "locator_ref",
          "shared_realm",
        ],
        explicit_address_behavior: "quarantine",
        unknown_invites: "quarantine",
        blocked_subjects: ["did:web:spammer.example"],
        disclosure: { high_trust: "outcome", low_trust: "opaque" },
      });
    }

    if (
      url.pathname === "/_arkret/self/direct-conversations/resolve" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        state: "found",
        realm_id: DIRECT_BOB_REALM,
        main_strand_id: DIRECT_BOB_STRAND,
        binding_event_ref: "ak:event:0196419b-0000-7000-8000-000000000103",
        created: false,
      });
    }

    if (
      url.pathname === "/_arkret/self/keys/upload" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        one_time_key_counts: { signed_curve25519: 1 },
        fallback_keys: {},
      });
    }

    if (
      url.pathname === "/_arkret/self/keys/query" &&
      route.request().method() === "POST"
    ) {
      return json(route, { device_keys: {}, failures: {} });
    }

    if (
      url.pathname === "/_arkret/self/keys/claim" &&
      route.request().method() === "POST"
    ) {
      return json(route, { one_time_keys: {}, failures: {} });
    }

    if (
      url.pathname === "/_arkret/self/account/viewer" &&
      route.request().method() === "GET"
    ) {
      const viewer: Record<string, unknown> = {
        principal_id: accountPrincipalId,
        state: "active",
        profile: {
          id: "ak:actor_profile:01964137-0000-7000-8000-0000000000a1",
          schema: "ak.schema.actor_profile.v1",
          principal_id: accountPrincipalId,
          actor_kind: "user",
          display_name: "inkson",
          created_at: "2026-04-28T12:00:00Z",
        },
        current_device_id: currentDeviceId,
        devices: accountDeviceSummaries(),
      };
      if (primaryHandle) {
        viewer.primary_handle_claim = {
          schema: "ak.schema.handle_claim.v1",
          handle: primaryHandle,
          subject: accountPrincipalId,
        };
      }
      return json(route, viewer);
    }

    if (
      url.pathname === "/_arkret/self/agents" &&
      route.request().method() === "GET"
    ) {
      return json(route, {
        agents: Array.from(personalAgents.values()),
        has_more: false,
      });
    }

    if (
      url.pathname === "/_arkret/self/agents" &&
      route.request().method() === "POST"
    ) {
      const body = ((await contractRequestBody(route)) ?? {}) as Record<
        string,
        unknown
      >;
      personalAgentCounter += 1;
      const slug =
        typeof body.agent_slug === "string" && body.agent_slug.trim()
          ? body.agent_slug.trim()
          : `agent-${personalAgentCounter}`;
      const agentPrincipalId = `did:web:agents.example:${slug}`;
      const agent = {
        agent_principal_id: agentPrincipalId,
        display_name:
          typeof body.display_name === "string" ? body.display_name : slug,
        agent_slug: slug,
        status: "pending_runtime_key",
        created_at: "2026-07-06T00:00:00Z",
        updated_at: "2026-07-06T00:00:00Z",
        requested_scope: body.requested_scope ?? null,
        controller_principal_id: accountPrincipalId,
      };
      const keyState = {
        status: "pending_runtime_key",
        pairing_request_id: `pair-${personalAgentCounter}`,
        pairing_code: "246810",
        pairing_expires_at: personalAgentPairingExpiresAt,
        requested_scope: body.requested_scope ?? null,
      };
      personalAgents.set(agentPrincipalId, agent);
      personalAgentKeyStates.set(agentPrincipalId, keyState);
      personalAgentGrants.set(agentPrincipalId, []);
      return json(route, {
        agent_principal_id: agentPrincipalId,
        pairing_request_id: keyState.pairing_request_id,
        pairing_code: keyState.pairing_code,
        expires_at: keyState.pairing_expires_at,
      });
    }

    const agentGrantsMatch = url.pathname.match(
      /^\/_arkret\/self\/agents\/([^/]+)\/grants$/,
    );
    if (agentGrantsMatch && route.request().method() === "POST") {
      const agentPrincipalId = decodeURIComponent(agentGrantsMatch[1]);
      const body = ((await contractRequestBody(route)) ?? {}) as Record<
        string,
        unknown
      >;
      const grants = personalAgentGrants.get(agentPrincipalId) ?? [];
      const grant = {
        grant_id: `ak:grant:01964137-0000-7000-8000-${String(grants.length + 1).padStart(12, "0")}`,
        ...(typeof body.grant === "object" && body.grant !== null
          ? (body.grant as Record<string, unknown>)
          : {}),
      };
      grants.push(grant);
      personalAgentGrants.set(agentPrincipalId, grants);
      return json(route, {
        ok: true,
        grant_id: grant.grant_id,
      });
    }

    const agentGetMatch = url.pathname.match(/^\/_arkret\/self\/agents\/([^/]+)$/);
    if (agentGetMatch && route.request().method() === "GET") {
      const agentPrincipalId = decodeURIComponent(agentGetMatch[1]);
      const agent = personalAgents.get(agentPrincipalId);
      if (!agent) {
        return json(
          route,
          {
            ok: false,
            error: { code: "not_found", message: "agent not found" },
          },
          404,
        );
      }
      return json(route, {
        agent,
        status: agent.status ?? "pending_runtime_key",
        grants: personalAgentGrants.get(agentPrincipalId) ?? [],
        key_state: personalAgentKeyStates.get(agentPrincipalId) ?? null,
      });
    }

    if (
      url.pathname === "/_arkret/gate/account/agent-key-pair" &&
      route.request().method() === "POST"
    ) {
      const body = ((await contractRequestBody(route)) ?? {}) as Record<
        string,
        unknown
      >;
      const agentPrincipalId = String(body.agent_principal_id ?? "");
      const agent = personalAgents.get(agentPrincipalId);
      if (!agent) {
        return json(
          route,
          {
            ok: false,
            error: { code: "not_found", message: "agent not found" },
          },
          404,
        );
      }
      const authorizedEventRef =
        "ak:event:01964137-0000-7000-8000-00000000a601";
      agent.status = "active";
      agent.updated_at = "2026-07-06T00:05:00Z";
      const previousKeyState = personalAgentKeyStates.get(agentPrincipalId) ?? {};
      personalAgentKeyStates.set(agentPrincipalId, {
        ...previousKeyState,
        status: "active",
        verification_method: body.verification_method,
        public_key: body.public_key,
        authorized_event_ref: authorizedEventRef,
      });
      return json(route, {
        ok: true,
        agent_principal_id: agentPrincipalId,
        status: "active",
        authorized_event_ref: authorizedEventRef,
        verification_method: body.verification_method,
      });
    }

    if (
      url.pathname === "/_arkret/gate/account/device-pair" &&
      route.request().method() === "POST"
    ) {
      const body = await route.request().postDataJSON();
      const deviceId =
        body.new_device_pubkey?.kid ??
        "ak:device:01964137-0000-7000-8000-0000000000b2";
      return json(route, {
        device_id: deviceId,
        authorized_event_ref: "ak:event:01964137-0000-7000-8000-00000000d001",
        device_grant: { status: "active" },
        key_backup_hint: {},
      });
    }

    if (
      url.pathname === "/_arkret/self/device_messages" &&
      route.request().method() === "GET"
    ) {
      return json(route, {
        messages: [],
        ack_token: "mock-device-messages-ack",
        next_cursor: "ak:cursor:devmsg-1",
        has_more: false,
        limited: false,
      });
    }

    if (
      url.pathname === "/_arkret/self/device_messages" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        ok: true,
        delivered: { "did:web:alice.example": ["dev_inkson"] },
        unknown_devices: {},
      });
    }

    if (
      url.pathname === "/_arkret/self/device_messages/ack" &&
      route.request().method() === "POST"
    ) {
      return json(route, { ok: true, pruned_count: 0 });
    }

    if (
      url.pathname === "/_arkret/self/ephemeral" &&
      route.request().method() === "POST"
    ) {
      const body = await route.request().postDataJSON();
      if (
        ![
          "ak.receipt.read",
          "ak.typing",
          "ak.presence",
          "ak.call.signal",
        ].includes(body.kind)
      ) {
        return json(
          route,
          {
            ok: false,
            error: {
              code: "invalid_param",
              message: "expected broadcast ephemeral kind",
            },
          },
          400,
        );
      }
      return json(route, {
        accepted: true,
        kind: body.kind,
        realm_id: body.realm_id,
        server_received_at: new Date().toISOString(),
      });
    }

    if (
      url.pathname === "/_arkret/edge/push/register-device" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        ok: true,
        registration_id: "ak:push:e2e",
        expires_at: null,
      });
    }

    if (
      url.pathname === "/_arkret/edge/push/unregister-device" &&
      route.request().method() === "POST"
    ) {
      return json(route, { ok: true });
    }

    if (
      url.pathname === "/_arkret/self/blob/upload" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        blob_ref: DEMO_BLOB_REF,
        size_bytes: 22,
        media_type: "application/octet-stream",
        content_digest:
          "sha256:01015dc8af66d01f557ea63f13538f1964848840a350c5311d1efc8ad138bb91",
        upload_receipt: {
          service_did: "did:web:server.local",
          content_digest_verified: true,
        },
      });
    }

    if (
      url.pathname === "/_arkret/self/rtc/ice-config" &&
      route.request().method() === "POST"
    ) {
      const body = await route.request().postDataJSON();
      return json(route, {
        realm_id: body.realm_id ?? DEMO_REALM,
        call_id: body.call_id ?? "ak:call:01964137-0000-7000-8000-000000000001",
        actor_id: body.actor_id ?? "did:web:alice.example",
        device_id:
          body.device_id ?? "ak:device:01904100-0000-7000-8000-a11ce0000001",
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

    if (
      url.pathname === "/_arkret/self/blob/get" &&
      route.request().method() === "GET"
    ) {
      return route.fulfill({
        status: 200,
        contentType: "application/octet-stream",
        body: "inkson encrypted bytes",
      });
    }

    if (
      url.pathname === "/_arkret/self/moderation/report" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        report_id: "ak:report:e2e",
        status: "queued",
        routed_to: ["did:web:server.local#moderation"],
      });
    }

    // Recovery bootstrap publishes a signed policy and then uploads an
    // encrypted did_recovery backup. The server mock stores only the public
    // policy summary plus opaque backup bodies.
    if (url.pathname === "/_arkret/root/identity/recovery-policy") {
      const method = route.request().method().toUpperCase();
      if (method === "GET") {
        return json(route, { active_policy: recoveryPolicy });
      }
      if (method === "POST") {
        const body = ((await contractRequestBody(route)) ?? {}) as Record<
          string,
          unknown
        >;
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

    const keyBackupMatch = url.pathname.match(
      /^\/_arkret\/self\/keys\/backups\/([^/]+)$/,
    );
    if (keyBackupMatch) {
      if (route.request().method() === "PUT") {
        const body = ((await contractRequestBody(route)) ?? {}) as Record<
          string,
          unknown
        >;
        const backup = {
          ...body,
          backup_id: body.backup_id ?? keyBackupMatch[1],
        };
        keyBackups.set(keyBackupMatch[1], backup);
        return json(route, {
          backup_id: keyBackupMatch[1],
          status: "accepted",
          ciphertext_digest:
            typeof body.ciphertext_digest === "string"
              ? body.ciphertext_digest
              : "sha256:e2e",
        });
      }
    }
    if (
      url.pathname === "/_arkret/self/keys/backups" &&
      route.request().method() === "GET"
    ) {
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

    return json(
      route,
      {
        ok: false,
        error: {
          code: "not_found",
          message: `No e2e mock for ${url.pathname}`,
        },
      },
      404,
    );
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
    title: "Arkret Demo Realm",
    summary: "Shared demo Realm served by mocked server",
    discoverability: "public",
    join_rule: "public",
    member_count_bucket: "1-10",
    as_of: "2026-06-13T00:00:00Z",
    source_refs: ["ak:event:0196419b-0000-7000-8000-000000000001"],
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
    operations: ["ak.self.events.command.submit"],
    join_methods: ["invite_accept", "member_join"],
    priority: 0,
    source: "directory_ingest",
    seal_basis: {
      leaves: [
        "ak:seal:sha256:1111111111111111111111111111111111111111111111111111111111111111",
      ],
      control_event_set_root:
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      state_root:
        "sha256:3333333333333333333333333333333333333333333333333333333333333333",
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
        base_url: "https://mimi.example.com/_arkret/open/mimi",
        supported_profiles: ["ak.profile.mimi_interop.v1"],
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
        "application/vnd.arkret.content+json",
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
