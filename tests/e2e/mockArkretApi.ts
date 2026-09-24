import { expect, type Page, type Route } from "@playwright/test";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  currentHttpDescribeCapabilities,
  DIRECTORY_DESCRIBE_BUNDLE,
  DIRECTORY_PUBLIC_READ_BUNDLE,
  PRINCIPAL_DESCRIBE_BUNDLE,
  PRINCIPAL_HTTP_CORE_BUNDLE,
} from "./currentDescribeCapabilities";

// Derived from the `demo-realm-genesis` wire fixture: it is the digest of
// the authored Realm create Event, so any change to that Event's canonical
// bytes moves it. The guard below refuses to run on a stale value rather
// than serving a Realm the client cannot address.
export const DEMO_REALM =
  "ak:realm:AZi4qfYh-BjEbd_wdqq1Z8srSeqAzJwsU4wDNH-XJD3D";
export const PRINCIPAL_CONTROL_REALM =
  "ak:realm:Ac9iLS6pVSDjqFeDeJjvUhbtREpxQ8IWem2mi64wrqDq";
const STRAND_POSITION_CELL_FAMILY = "ak.component.strand.position.v1";
const DEMO_FRONTIER_EVENT =
  "ak:event:Ad0EZUHcfLJv92Of4w-RJec6fkNlWP11fsQAQ4dqUOHS";
const LOW_FLOOR_REALM = "ak:realm:Ad-rGYKVGY9i32DG2R9ZwMezGzT5g2rmdYjrifmGO6Fe";
const CHILD_REALM = "ak:realm:AajANEG2ah2GJghhdat8rziaz1qjK25iQAYUUR6kcIeW";
const GRANDCHILD_REALM =
  "ak:realm:AY4xhb3ZNeBXAhtM2T1YS3-9sqDdRdVeL3cVRBQ9LTAt";
const DIRECT_BOB_REALM =
  "ak:realm:AUEAoXMJeJWBETvkqm7gk4imduk7g-l8bim19OPFQDaO";
const DIRECT_BOB_STRAND =
  "ak:strand:Ae9PN2rTd0Dojs9yS8iLnfheJtjSEZ3mgDDyONpztHUd";
const DIRECT_OWN_AGENT_REALM =
  "ak:realm:AbhO_nhWEZ7jojF3JULUGyzIUTiHNshUWblbkJCr7NbP";
const DIRECT_OWN_AGENT_STRAND =
  "ak:strand:ASy992JMe_xzh5pluAqo5YuyCnAfDdFni4lmeHQldlUM";
const DEMO_CIRCLE = "ak:circle:AVhDoodj6EFMf5ZQ1JXfSmM5ZNZrK3ekqYa4-EOvqSiE";
const DEMO_BOARD_SPACE =
  "ak:space:AY61QviMxoJ0ALEn5U39bA7Qbi1BxHCrOq4950m2JRjM";
const DEMO_SECOND_BOARD_SPACE =
  "ak:space:AUqXxLkoB6IUAy7p6DSMGyoUVhO0KevW5ZzWGTP_4xIh";
const DEMO_TODO_LIST = "ak:space:AZLgY4qsY8KB47PSg9tg4oYHPmyQf7A7JlzMa0JMmmVi";
const DEMO_PROGRESS_LIST =
  "ak:space:ARC32_kqx5-YFlPdEX0StqbYHhqEo2Inh25kKZPcW3u-";
const DEMO_DONE_LIST = "ak:space:AeFSLuUZ7jW2w3xVl0s9ZTzojGeaOIrzzn4yQeweskV0";
const DEMO_SECOND_LIST =
  "ak:space:AXIKcuc3xUnThWU2npxUFVgxgvnRP1_U_ZC8EvSFAWy5";
const DEMO_STRAND_LEGAL_REVIEW =
  "ak:strand:AUftf_3k2fRKMG0NFlHe5iEMBOUpxMwYMRu-yhMJl-yz";
const DEMO_STRAND_ONBOARDING_COPY =
  "ak:strand:ASZZoDGudNfXFZynKh4xcEpb5d8kLZQXRpycxlg1qyW-";
const DEMO_STRAND_SECURITY_SIGNOFF =
  "ak:strand:AQmnyvvBmKOWOEOSD2rAYsVBQn6vJ_wdbdUY8CKUGB5c";
const DEMO_STRAND_SECONDARY_CARD =
  "ak:strand:AeuYGIMbDLHP-zzs9g6vzWrgtPNhcol9h_doKgtHxKqd";
const MOCK_CREATED_CIRCLE_IDS = [
  "ak:circle:AQUeFABQK9MQb8JmkZyP7wD2QfYOSDaCH1LDepfyMD-G",
  "ak:circle:AX-AFSYZHl0U2MQP-Ng7mU-aOm_Flhf0pVBoHYUK6Shg",
] as const;
const eventIdForDerivedId = (id: string, prefix: string): string => {
  if (!id.startsWith(prefix)) {
    throw new Error(`expected ${prefix} Event-derived id, got ${id}`);
  }
  return `ak:event:${id.slice(prefix.length)}`;
};
const mockCommitId = (value: unknown): string => {
  const digest = createHash("sha256").update(JSON.stringify(value)).digest();
  return `ak:realm_commit:A${digest.toString("base64url")}`;
};
const mockMlsGroupId = (scope: string): string =>
  createHash("sha256").update(`ak.mls.group_id.v1\0${scope}`).digest("base64url");
const DEMO_BLOB_REF =
  "ak:blob:sha256:431ced6916a2a21a156e38701afe55bbd7f88969fbbfc56d7fe099d47f265460";
const DEMO_AVATAR_PNG_BASE64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";
type SpaceContainerProjection = {
  space_id: string;
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
  is_default: boolean;
  board_space_id?: string;
  list_space_id?: string;
  rank?: string;
  assigned_actor_ids?: string[];
  fields?: Record<string, unknown>;
};

type MockArkretApiOptions = {
  accountPrincipalId?: string;
  primaryHandle?: string | null;
  directoryPrimaryHandle?: string | null;
  currentDeviceId?: string;
  currentDeviceSigningSeedB64url?: string;
  accountDevices?: MockAccountDevice[];
  includeDemoRealms?: boolean;
  includeLowFloorRealm?: boolean;
  includePrincipalControlRealm?: boolean;
  personalAgentPairingExpiresAt?: string;
  includeSidecarInCircleList?: boolean;
  preseedRecoveryMaterial?: boolean;
  seedDefaultActiveAgent?: boolean;
  emptyBoard?: boolean;
};

type MockAccountDevice = {
  device_id: string;
  status?:
    | "active"
    | "revocation_pending"
    | "revoked"
    | "expired"
    | "generation_fenced"
    | "conflicted";
  display_name?: string | null;
  authorized_at?: string | null;
  revoked_at?: string | null;
  verification_state?: "verified" | "unresolved" | "stale";
};

type MockCircleState = "active" | "archived" | "tombstoned";
type InksonWireCommand =
  | "canonical-json"
  | "did-key-from-seed"
  | "sha256-canonical-json"
  | "service-resolution"
  | "principal-locator"
  | "validate-mock-response";
type InksonWireCanonicalJson = { canonical: string };
type InksonWireDigest = { digest: string };

type MockOperationInventoryRow = {
  method: string;
  path_template: string;
  operation_id: string;
  responses: Record<string, { schema_ref: string | null }>;
};

type StaticMockResponseFixture = {
  operation_id: string;
  status: number;
  value: unknown;
};

type RealmGenesisFixture = {
  realm_id: string;
  accepted_events: Array<Record<string, unknown>>;
};

const inksonRepoRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
);
const mockOperationInventory = (
  JSON.parse(
    readFileSync(
      resolve(
        dirname(fileURLToPath(import.meta.url)),
        "mock-operation-inventory.json",
      ),
      "utf8",
    ),
  ) as { operations: MockOperationInventoryRow[] }
).operations.map((operation) => ({
  ...operation,
  pathPattern: new RegExp(
    `^${operation.path_template
      .split(/(\{[^}]+\})/)
      .map((part) =>
        part.startsWith("{")
          ? "[^/]+"
          : part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
      )
      .join("")}$`,
  ),
}));
const validatedMockResponses = new Set<string>();
const currentPrincipalServiceResolution = inksonWire<Record<string, any>>(
  "service-resolution",
  {},
);
export const CURRENT_STATION_ID = String(currentPrincipalServiceResolution.service_id);
export const CURRENT_STATION_DID = String(currentPrincipalServiceResolution.normalized_did_document.did);

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
      : [
          "run",
          "--quiet",
          "--features",
          "spec-conformance",
          "--bin",
          "inkson-wire",
          "--",
          command,
        ],
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

function validateMockResponse(route: Route, status: number, value?: unknown) {
  const request = route.request();
  const method = request.method().toUpperCase();
  const pathname = new URL(request.url()).pathname;
  if (!pathname.startsWith("/_arkret/")) {
    return;
  }
  const matches = mockOperationInventory.filter(
    (operation) =>
      operation.method === method && operation.pathPattern.test(pathname),
  );
  if (matches.length !== 1) {
    throw new Error(
      `mock route ${method} ${pathname} resolves to ${matches.length} embedded OpenAPI operations`,
    );
  }
  validateMockResponseForOperation(matches[0], status, value);
}

function validateMockResponseForOperation(
  operation: (typeof mockOperationInventory)[number],
  status: number,
  value?: unknown,
) {
  const response =
    operation.responses[String(status)] ?? operation.responses.default;
  if (!response) {
    throw new Error(
      `mock route ${operation.operation_id} has no OpenAPI response for status ${status}`,
    );
  }
  if (!response.schema_ref) {
    if (value === undefined) {
      return;
    }
    throw new Error(
      `mock route ${operation.operation_id} status ${status} forbids a JSON body`,
    );
  }
  if (value === undefined) {
    throw new Error(
      `mock route ${operation.operation_id} status ${status} requires a JSON body`,
    );
  }
  assertNoRetiredMockFields(value);
  validateMockSchema(response.schema_ref, value);
}

function preflightStaticMockResponses(fixtures: StaticMockResponseFixture[]) {
  for (const fixture of fixtures) {
    const matches = mockOperationInventory.filter(
      (operation) => operation.operation_id === fixture.operation_id,
    );
    if (matches.length !== 1) {
      throw new Error(
        `static mock fixture ${fixture.operation_id} resolves to ${matches.length} embedded OpenAPI operations`,
      );
    }
    validateMockResponseForOperation(matches[0], fixture.status, fixture.value);
  }
}

export function assertNoRetiredMockFields(value: unknown, path = "$"): void {
  if (value === null || typeof value !== "object") {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) =>
      assertNoRetiredMockFields(item, `${path}[${index}]`),
    );
    return;
  }

  const object = value as Record<string, unknown>;
  for (const key of ["registry_mode", "supported_receipts"]) {
    if (Object.hasOwn(object, key)) {
      throw new Error(`retired mock response field ${path}.${key}`);
    }
  }
  for (const key of ["auth_metadata", "method_evidence"]) {
    const nested = object[key];
    if (
      nested !== null &&
      typeof nested === "object" &&
      !Array.isArray(nested) &&
      Object.hasOwn(nested, "mode")
    ) {
      throw new Error(`retired mock response field ${path}.${key}.mode`);
    }
  }
  for (const [key, nested] of Object.entries(object)) {
    assertNoRetiredMockFields(nested, `${path}.${key}`);
  }
}

function validateMockSchema(schemaRef: string, value: unknown) {
  const validationKey = `${schemaRef}\n${JSON.stringify(value)}`;
  if (validatedMockResponses.has(validationKey)) {
    return;
  }
  inksonWire("validate-mock-response", {
    schema_ref: schemaRef,
    value,
  });
  validatedMockResponses.add(validationKey);
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

function didCoreId(value: string): string {
  return value.startsWith("ak:did_core:")
    ? value
    : `ak:did_core:${value.replace(/^did:/, "")}`;
}

function didFromCoreId(value: string): string {
  return value.replace(/^ak:did_core:/, "did:");
}

function signedEventDigest(event: Record<string, unknown>) {
  const digestPayload = { ...event };
  delete digestPayload.proofs;
  delete digestPayload.unsigned;
  delete digestPayload.event_id;
  return canonicalSha256(digestPayload);
}

export async function mockArkretApi(
  page: Page,
  options: MockArkretApiOptions = {},
) {
  const accountPrincipalId =
    options.accountPrincipalId ?? "did:web:alice.example";
  const accountPrincipalCoreId = didCoreId(accountPrincipalId);
  const accountId = {
    principal_id: accountPrincipalCoreId,
    station_id: CURRENT_STATION_ID,
  };
  // `event-envelope.schema.json` closes the envelope (`additionalProperties:
  // false`) and types `actor_id` as the composite `common-ids#/$defs/actor_id`:
  // the account variant carries the complete AccountId and there is no
  // top-level `station_id` beside it. Every synthesized Event below authors
  // through this one value rather than spelling the shape again.
  const accountActorId = { kind: "account", account_id: accountId };
  const accountActorIdFor = (principalCoreId: string) => ({
    kind: "account",
    account_id: { principal_id: principalCoreId, station_id: CURRENT_STATION_ID },
  });
  const primaryHandle =
    options.primaryHandle === undefined
      ? "alice:local.host"
      : options.primaryHandle;
  const directoryPrimaryHandle =
    options.directoryPrimaryHandle === undefined
      ? primaryHandle
      : options.directoryPrimaryHandle;
  // `handle_claim_status_view` (`schemas/handle-claim.schema.json`): the signed
  // core sits under `claim`, and the status half — who verified it, when, until
  // when — wraps it. The client reads it that way
  // (`transport::account::primary_handle_from_viewer` filters on
  // `claim.claim.subject_account_id`, `status`, `revocation` and
  // `fresh_until`), so a flat claim is a handle the panel silently drops.
  // Both the account viewer and the directory's handle list serve this shape,
  // so it is built once.
  const handleClaimStatusView = (handle: string, subjectPrincipalId: string) => ({
    schema: "ak.schema.handle_claim.v1",
    claim: {
      schema: "ak.schema.handle_claim_core.v1",
      handle,
      handle_aliases: [],
      subject_account_id: {
        principal_id: subjectPrincipalId,
        station_id: CURRENT_STATION_ID,
      },
      issuer_id: CURRENT_STATION_ID,
      claim: { kind: "handle_binding" },
      visibility: "public",
      audience: null,
      issued_at: "2026-04-28T12:00:00.000Z",
      expires_at: "2099-04-28T12:00:00.000Z",
      source_refs: [],
      proofs: [
        {
          kind: "detached_jws",
          verification_method: `${CURRENT_STATION_DID}#handle-claim-key`,
          payload_digest: `sha256:${"0".repeat(64)}`,
          created_at: "2026-04-28T12:00:00.000Z",
          domain: "ak.handle_claim_proof.v1",
          proof_purpose: "issuer_attestation",
          jws: "e30..c2ln",
        },
        {
          kind: "detached_jws",
          verification_method: `${CURRENT_STATION_DID}#handle-claim-key`,
          payload_digest: `sha256:${"0".repeat(64)}`,
          created_at: "2026-04-28T12:00:00.000Z",
          domain: "ak.handle_claim_proof.v1",
          proof_purpose: "holder_acceptance",
          jws: "e30..c2ln",
        },
      ],
    },
    status: "verified",
    as_of: "2026-04-28T12:00:00.000Z",
    verifier_id: CURRENT_STATION_ID,
    verified_at: "2026-04-28T12:00:00.000Z",
    revocation: null,
    fresh_until: "2099-04-28T12:00:00.000Z",
    status_proof: {
      kind: "detached_jws",
      verification_method: `${CURRENT_STATION_DID}#handle-claim-key`,
      payload_digest: `sha256:${"0".repeat(64)}`,
      created_at: "2026-04-28T12:00:00.000Z",
      domain: "ak.handle_claim_status.v1",
      proof_purpose: "status_attestation",
      jws: "e30..c2ln",
    },
  });

  // `contact_operation_outcome` is a prepare/commit union, not the single-shot
  // `{event_ref, state}` object this mock used to serve — the client drives it
  // through `ContactOperationOutcome` and could not even deserialize the old
  // shape.
  //
  // The prepare half is a stand-in draft the caller signs, which the mock can
  // author honestly. The commit half is a *signed acceptance receipt* the
  // client verifies (`transport::account::verify_contact_request_receipt`), so
  // a hand-written one would be rejected by the very check it exists to
  // exercise; the mock answers with the schema's own failure branch instead of
  // pretending. Minting real receipts belongs in `inkson-wire` beside
  // `demo-realm-genesis` — see arkret-work `2026-09-06-0700`.
  const contactOutcome = (
    resultKind: "request" | "response" | "reject" | "scope_update" | "tombstone",
    body: Record<string, unknown>,
  ) => {
    const operationId =
      typeof body.operation_id === "string"
        ? body.operation_id
        : "ak:operation:01964137-0000-7000-8000-0000000000f2";
    if (body.phase === "commit") {
      return {
        status: "failed",
        result_kind: resultKind,
        operation_id: operationId,
        reason: "contact_round_conflict",
      };
    }
    return {
      status: "prepared",
      result_kind: resultKind,
      operation_id: operationId,
      reservation_handle: "e2e-contact-reservation",
      expires_at: "2099-01-01T00:00:00.000Z",
      event_draft: {
        unsigned_event_bytes: "ZTJlLWNvbnRhY3QtZHJhZnQ",
        event_digest: `sha256:${"c".repeat(64)}`,
      },
    };
  };

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
  const includeSidecarInCircleList =
    options.includeSidecarInCircleList ?? false;
  const includeLowFloorRealm = options.includeLowFloorRealm ?? false;
  const personalAgentPairingExpiresAt =
    options.personalAgentPairingExpiresAt ?? "2099-07-06T00:10:00.000Z";
  const accountDevices = new Map<string, MockAccountDevice>();
  const deviceSigningKeys = new Map<string, string>();
  if (options.currentDeviceSigningSeedB64url) {
    const fixtureKey = inksonWire<{ did_key: string }>("did-key-from-seed", {
      seed_b64url: options.currentDeviceSigningSeedB64url,
    }).did_key;
    deviceSigningKeys.set(currentDeviceId, fixtureKey);
  }
  for (const device of options.accountDevices ?? [
    {
      device_id: "ak:device:01964137-0000-7000-8000-0000000000a1",
      status: "active",
      display_name: "Current device",
      authorized_at: "2026-04-28T12:00:00.000Z",
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
  if (includeDemoRealms) {
    const fixture = inksonWire<RealmGenesisFixture>(
      "demo-realm-genesis",
      {},
    );
    if (fixture.realm_id !== DEMO_REALM) {
      throw new Error(
        `Demo Realm constant ${DEMO_REALM} differs from SDK fixture ${fixture.realm_id}`,
      );
    }
    projectionEvents.push(...fixture.accepted_events.map((event) => ({
      ...event,
      producer_proof: {
        kind: "detached_jws",
        verification_method: `${CURRENT_STATION_DID}#mock-producer`,
        event_digest: canonicalSha256(event),
        created_at: event.created_at,
        jws: "e30..c2ln",
      },
    })));
  }
  let serverDidDocument: Record<string, unknown> =
    currentPrincipalServiceResolution.normalized_did_document;
  preflightStaticMockResponses(
    staticMockResponseFixtures(serverDidDocument),
  );
  let sidecarAgentIds = ["ak:did_core:web:agents.example:assistant"];
  const circleStates = new Map<string, MockCircleState>([
    [DEMO_CIRCLE, "active"],
  ]);
  const circleMetadata = new Map<
    string,
    {
      title: string;
      summary?: string;
      encryption_profile: string;
      join_rule: string;
    }
  >([
    [
      DEMO_CIRCLE,
      {
        title: "Demo Circle",
        summary: "Mock Circle for lifecycle operations",
        encryption_profile: "mls_rfc9420",
        join_rule: "invite",
      },
    ],
  ]);
  const circleMembers = new Map<string, string[]>([
    [DEMO_CIRCLE, [accountPrincipalCoreId]],
  ]);
  let circleCounter = 0;
  const circleView = (circleId = DEMO_CIRCLE) => ({
    circle_id: circleId,
    realm_id: DEMO_REALM,
    title: circleMetadata.get(circleId)?.title ?? "Demo Circle",
    summary: circleMetadata.get(circleId)?.summary,
    display: {
      short_name: "Demo",
      color_token: "slate",
      symbol: { glyph: "ring" },
    },
    directory_visibility: "realm_members",
    join_rule: circleMetadata.get(circleId)?.join_rule ?? "invite",
    history_access: "since_join",
    mls_group_id: mockMlsGroupId(circleId),
    state: circleStates.get(circleId) ?? "active",
    viewer_membership: circleMembers
      .get(circleId)
      ?.includes(accountPrincipalCoreId)
      ? "join"
      : undefined,
    member_ids: (circleMembers.get(circleId) ?? []).map(accountActorIdFor),
    created_by: accountActorId,
    created_at: "2026-06-23T00:00:00.000Z",
    updated_by: accountActorId,
    updated_at: "2026-06-23T00:00:00.000Z",
  });
  const sidecarCircleView = () => ({
    ...circleView("ak:circle:ASIRcVOtSZ-VzuyAm1rolDcftU2vWjs2t6iTH21vQmP5"),
    profile_ref: "ak.profile.internal_scope.v1",
    title: "Internal scope",
    display: {
      short_name: "AI-ALICE",
      color_token: "slate",
      symbol: { glyph: "spark" },
    },
  });
  const seededRecoveryPolicyId =
    "ak:policy:019a6aa0-0000-7000-8000-0000000000bb";
  const seededBackupHpkeKey =
    "z6LSbsw3xDCtsMcRWf8HqYViCDXmadAiioEcZCiefbnKxNjt";
  let recoveryPolicy: Record<string, unknown> | null =
    options.preseedRecoveryMaterial === true
      ? {
          policy_id: seededRecoveryPolicyId,
          account_id: accountId,
          version: 1,
           acceptance_basis_ref: mockCommitId(seededRecoveryPolicyId),
          trust_domain: "ak:trust_domain:soland.local",
          methods: [{ kind: "did_root" }],
          supersedes_id: null,
          expires_at: null,
          issued_at: "2026-07-29T00:00:00.000Z",
          accepted_at: "2026-07-29T00:00:01.000Z",
        }
      : null;
  const keyBackups = new Map<string, Record<string, unknown>>();
  if (options.preseedRecoveryMaterial === true) {
    const backupId = "ak:backup:019a6aa0-0000-7000-8000-000000000002";
    keyBackups.set(backupId, {
      backup_id: backupId,
      actor_id: accountActorId,
      device_id: currentDeviceId,
      backup_kind: "secret_storage",
      backup_version: "v1",
      created_at: "2026-07-29T00:00:02.000Z",
      ciphertext_digest: `sha256:${"b".repeat(64)}`,
      encryption: {
        recipient_method: "recovery_public_key",
        recipient_key_ref: "recovery-key-e2e",
      },
      series_id: "ak:backup_series:019a6aa0-0000-7000-8000-000000000003",
      series_seq: 0,
      recovery_policy_ref: {
        policy_id: seededRecoveryPolicyId,
        policy_version: 1,
      },
    });
  }
  const personalAgents = new Map<string, Record<string, unknown>>();
  const personalAgentKeyStates = new Map<string, Record<string, unknown>>();
  const personalAgentGrants = new Map<string, Array<Record<string, unknown>>>();
  const managedPcrRealmIds = new Set<string>();
  let personalAgentCounter = 0;
  // Two orthogonal axes (key-management.md §3.6.1). Store lifecycle intent on
  // the Agent projection and derive runtime readiness only from key/pairing
  // facts, matching the public SDK model.
  const projectAgentAxes = (
    agentId: string,
  ): { lifecycle: string; runtime_state: string } => {
    const stored = String(personalAgents.get(agentId)?.lifecycle ?? "active");
    if (stored === "deactivated") {
      return { lifecycle: "deactivated", runtime_state: "pairing_expired" };
    }
    if (stored === "pending_runtime_key" || stored === "pairing_expired") {
      return { lifecycle: "active", runtime_state: stored };
    }
    const lifecycle = stored === "paused" ? "paused" : "active";
    const ks = personalAgentKeyStates.get(agentId);
    const keyed = Boolean(
      ks &&
      (ks.authorized_event_ref ||
        (Array.isArray(ks.active_authorizations) &&
          ks.active_authorizations.length > 0)),
    );
    const pairingExpiresAt = String(ks?.pairing_expires_at ?? "");
    const pairingOpen =
      Boolean(ks?.pairing_request_id) &&
      pairingExpiresAt > "2026-08-03T00:00:00.000Z";
    if (keyed) {
      return {
        lifecycle,
        runtime_state: pairingOpen ? "replacing" : "ready",
      };
    }
    return {
      lifecycle,
      runtime_state: pairingOpen ? "pending_runtime_key" : "pairing_expired",
    };
  };
  const projectAgent = (agentId: string): Record<string, unknown> => {
    const axes = projectAgentAxes(agentId);
    const readiness =
      axes.lifecycle === "active" && axes.runtime_state === "ready"
        ? { state: "ready", blockers: [] }
        : {
            state: "not_ready",
            blockers: [
              axes.runtime_state === "replacing"
                ? "pairing_open"
                : "runtime_key_missing",
            ],
          };
    return {
      ...personalAgents.get(agentId),
      lifecycle: axes.lifecycle,
      readiness,
      presence: {
        state: "unknown",
        expires_at: "2099-01-01T00:00:30.000Z",
        refresh_after: "2099-01-01T00:00:00.000Z",
      },
    };
  };
  // A consumed bootstrap handle is absent from the public key-state DTO.
  const activeAssistantId = "ak:did_core:web:agents.example:assistant";
  const activeAssistantDid = didFromCoreId(activeAssistantId);
  const activeAssistantScope = {
    actions: ["ak.event.read"],
    resources: [
      { kind: "operation", operation: "ak.self.committed_event.read.scan.v1" },
    ],
  };
  const activeAssistantKeyState = {
    agent_id: activeAssistantId,
    controller_account_id: accountId,
    principal_control_realm_id:
      "ak:realm:AS7wchHFRbXWnMQPln42BrokXsPCf18uboKMm-yhYquI",
    controller_authorization_ref: `${activeAssistantDid}#managed-controller`,
    requested_scope: activeAssistantScope,
    authorized_event_ref:
      "ak:event:AfoRpfP-sl-s9gK_9-GfLiYW9eincnIfCJF8xRcVowkj",
    active_authorizations: [
      {
        key_id: "runtime-key-1",
        verification_method: `${activeAssistantDid}#runtime-key-1`,
        authorized_event_ref:
          "ak:event:AfoRpfP-sl-s9gK_9-GfLiYW9eincnIfCJF8xRcVowkj",
      },
    ],
  };
  if (options.seedDefaultActiveAgent !== false) {
    personalAgents.set(activeAssistantId, {
      agent_id: activeAssistantId,
      display_name: "Alice Assistant",
      slug: "assistant",
      avatar_blob_ref: DEMO_BLOB_REF,
      lifecycle: "active",
      created_at: "2026-07-06T00:00:00.000Z",
      updated_at: "2026-07-06T00:05:00.000Z",
    });
    personalAgentKeyStates.set(activeAssistantId, activeAssistantKeyState);
  }
  personalAgents.set("ak:did_core:web:agents.example:deactivated", {
    agent_id: "ak:did_core:web:agents.example:deactivated",
    display_name: "Deactivated Agent",
    slug: "deactivated",
    lifecycle: "deactivated",
    created_at: "2026-07-05T00:00:00.000Z",
    updated_at: "2026-07-06T00:10:00.000Z",
  });
  if (personalAgentPairingExpiresAt.startsWith("2000-")) {
    const expiredAgentId = "ak:did_core:web:agents.example:summary";
    const expiredRealmId =
      "ak:realm:AQ4lJ43jR05ytJIf7AGNbPU_MuY1FqT_ny_e8MhCCnwc";
    const expiredScope = {
      actions: [
        "ak.event.read",
        "ak.message.create",
        "ak.reaction.add",
        "ak.self.committed_event.stream.subscribe.v1",
        "ak.self.committed_event.read.scan.v1",
        "ak.self.events.command.submit.v1",
      ],
      resources: [
        {
          kind: "operation",
          operation: "ak.self.committed_event.stream.subscribe.v1",
        },
      ],
    };
    personalAgents.set(expiredAgentId, {
      agent_id: expiredAgentId,
      slug: "summary",
      lifecycle: "active",
      created_at: "2026-07-06T00:00:00.000Z",
      updated_at: "2026-07-06T00:10:00.000Z",
    });
    personalAgentKeyStates.set(expiredAgentId, {
      agent_id: expiredAgentId,
      controller_account_id: accountId,
      principal_control_realm_id: expiredRealmId,
      controller_authorization_ref: `${didFromCoreId(expiredAgentId)}#managed-controller`,
      requested_scope: expiredScope,
    });
    personalAgentGrants.set(expiredAgentId, []);
  }
  const eventRealmId = (event: Record<string, unknown>) =>
    String(event.realm_id ?? (event.scope_ref as Record<string, unknown> | undefined)?.realm_id ?? DEMO_REALM);
  const committedEventView = (
    event: Record<string, unknown>,
    streamPosition: number,
  ) => {
    try {
      validateMockSchema("schemas/event-envelope.schema.json#/$defs/shared_event_envelope", event);
    } catch (error) {
      throw new Error(`invalid projected Event ${String(event.kind)} ${String(event.event_id)}: ${String(error)}`);
    }
    const realmId = eventRealmId(event);
    const eventId = String(event.event_id ?? "");
    const commitId = mockCommitId({ event_id: eventId });
    return {
      commit: {
        commit_id: commitId,
        realm_id: realmId,
        stream_ref: { kind: "realm", realm_id: realmId },
        stream_position: streamPosition,
        previous_commit_ref:
          streamPosition === 0
            ? null
             : mockCommitId({ event_id: eventId, stream_position: streamPosition - 1 }),
        event_ref: eventId,
        governance_generation: 0,
        authority_ref: eventId,
        committed_at: "2026-09-20T00:00:00.000Z",
        signature: {
          context: "ak.realm_commit_signature.v1",
          signature_algorithm: "Ed25519",
           verification_method: `${CURRENT_STATION_DID}#realm-commit`,
          signed_digest: canonicalSha256({ event_id: eventId, stream_position: streamPosition }),
          created_at: "2026-09-20T00:00:00.000Z",
           sig: "A".repeat(86),
        },
      },
      event,
    };
  };
  const accountDeviceSummaries = () =>
    Array.from(accountDevices.values()).map((device) => {
      const summary: Record<string, unknown> = {
        device_id: device.device_id,
        status: device.status ?? "active",
         verification_state: device.verification_state ?? "unresolved",
      };
      if (summary.verification_state === "verified") {
        summary.verification_source = "genesis";
        summary.authorized_event_ref = DEMO_FRONTIER_EVENT;
      }
      if (device.display_name !== undefined) {
        summary.display_name = device.display_name;
      }
      if (device.authorized_at) {
        summary.authorized_at = device.authorized_at;
      }
      if (device.revoked_at) {
        summary.revoked_at = device.revoked_at;
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
  const producerSigningKeys = (events: Array<Record<string, any>>) =>
    Object.fromEntries(
      events.map((event) => {
        const method = event.proofs?.[0]?.verification_method;
        if (typeof method !== "string") {
          throw new Error(
            "accepted Event mock requires a producer verification method",
          );
        }
        const [controller, fragment] = method.split("#", 2);
        const key = controller.startsWith("did:key:")
          ? controller
          : deviceSigningKeys.get(fragment);
        if (typeof key !== "string" || !key.startsWith("did:key:")) {
          throw new Error(
            `accepted Event mock has no signing key for ${method}`,
          );
        }
        return [method, key];
      }),
    );
  const boardSpaceContainers: SpaceContainerProjection[] = options.emptyBoard
    ? []
    : [
        {
          space_id: DEMO_BOARD_SPACE,
          realm_id: DEMO_REALM,
          kind: "board",
          title: "Persisted demo board",
          state: "active",
        },
        {
          space_id: DEMO_SECOND_BOARD_SPACE,
          realm_id: DEMO_REALM,
          kind: "board",
          title: "Secondary planning board",
          state: "active",
        },
        {
          space_id: DEMO_TODO_LIST,
          realm_id: DEMO_REALM,
          kind: "list",
          title: "To Do",
          state: "active",
          rank: "U",
          parent_space_id: DEMO_BOARD_SPACE,
        },
        {
          space_id: DEMO_PROGRESS_LIST,
          realm_id: DEMO_REALM,
          kind: "list",
          title: "In Progress",
          state: "active",
          rank: "f",
          parent_space_id: DEMO_BOARD_SPACE,
        },
        {
          space_id: DEMO_DONE_LIST,
          realm_id: DEMO_REALM,
          kind: "list",
          title: "Done",
          state: "active",
          rank: "p",
          parent_space_id: DEMO_BOARD_SPACE,
        },
        {
          space_id: DEMO_SECOND_LIST,
          realm_id: DEMO_REALM,
          kind: "list",
          title: "Selected Backlog",
          state: "active",
          rank: "U",
          parent_space_id: DEMO_SECOND_BOARD_SPACE,
        },
      ];
  const boardStrandProjections: StrandProjection[] = options.emptyBoard
    ? []
    : [
        {
          strand_id: DEMO_STRAND_LEGAL_REVIEW,
          realm_id: DEMO_REALM,
          title: "Legal review for public beta",
          summary:
            "Finalize external processor wording before launch checklist can move.",
          state: "active",
          is_default: false,
          board_space_id: DEMO_BOARD_SPACE,
          list_space_id: DEMO_TODO_LIST,
          rank: "U",
          assigned_actor_ids: [accountActorIdFor(accountPrincipalCoreId)],
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
          is_default: false,
          board_space_id: DEMO_BOARD_SPACE,
          list_space_id: DEMO_PROGRESS_LIST,
          rank: "U",
          assigned_actor_ids: [accountActorIdFor("ak:did_core:web:bob.example")],
          fields: { labels: ["copy", "support"], due_at: "May 10" },
        },
        {
          strand_id: DEMO_STRAND_SECURITY_SIGNOFF,
          realm_id: DEMO_REALM,
          title: "Security sign-off",
          summary:
            "Projection detected a stale column head after an offline move.",
          state: "active",
          is_default: false,
          board_space_id: DEMO_BOARD_SPACE,
          list_space_id: DEMO_DONE_LIST,
          rank: "U",
          assigned_actor_ids: [accountActorIdFor("ak:did_core:web:carol.example")],
          fields: { labels: ["security", "reviewed"], due_at: "May 01" },
        },
        {
          strand_id: DEMO_STRAND_SECONDARY_CARD,
          realm_id: DEMO_REALM,
          title: "Secondary board card",
          summary:
            "Only visible after the Board selector switches projection scope.",
          state: "active",
          is_default: false,
          board_space_id: DEMO_SECOND_BOARD_SPACE,
          list_space_id: DEMO_SECOND_LIST,
          rank: "U",
          assigned_actor_ids: [accountActorIdFor("ak:did_core:web:dana.example")],
          fields: { labels: ["planning"], due_at: "May 12" },
        },
      ];
  const canonicalProjectionEvent = (
    eventId: string,
    kind: string,
    actorSeq: number,
    payload: Record<string, unknown>,
  ) => {
    const createdAt = `2026-04-28T12:${String(actorSeq - 200).padStart(2, "0")}:00.000Z`;
    return {
      event_id: eventId,
      kind,
      realm_id: DEMO_REALM,
      scope_ref: { kind: "realm", realm_id: DEMO_REALM },
      actor_id: accountActorId,
      created_at: createdAt,
      payload,
      producer_proof: {
        kind: "detached_jws",
        verification_method: `${didFromCoreId(accountPrincipalCoreId)}#${currentDeviceId}`,
        event_digest: `sha256:${"0".repeat(64)}`,
        created_at: createdAt,
        jws: "e30..c2ln",
      },
    };
  };
  projectionEvents.push(
    ...boardSpaceContainers.map((space, index) =>
      canonicalProjectionEvent(
        eventIdForDerivedId(space.space_id, "ak:space:"),
        "ak.space.create",
        200 + index,
        {
          object: {
            schema: "ak.schema.space.v1",
            realm_id: space.realm_id,
            kind: space.kind,
            title: space.title,
            created_by: accountActorId,
            created_at: `2026-04-28T12:${String(index).padStart(2, "0")}:00.000Z`,
            ...(space.rank ? { rank: space.rank } : {}),
            ...(space.parent_space_id
              ? { parent_space_id: space.parent_space_id }
              : {}),
          },
        },
      ),
    ),
    // `strand.schema.json` forbids `board_space_id` / `list_space_id` / `rank`
    // inside `metadata.fields`, so a conforming create carries the card and
    // nothing about where it sits — exactly what
    // `views::kanban::model::board_projection` documents and folds.
    //
    // Placement therefore needs a following `ak.strand.move`, and this fixture
    // does not have one yet: a synthesized move in the subscribe timeline makes
    // the client drop the whole Realm, not just that Event — the sidebar goes
    // to "No Realms loaded yet". Adding `preconditions` on the position cell
    // did not change it, and the client's own tracing does not reach the
    // browser console, so the cause is still open. Until it is found, the
    // cards stay UNPLACED, which is the legal state between an accepted create
    // and its first Move; the Board tests fail on their own assertions rather
    // than on a Realm that never appears. See arkret-work
    // `2026-09-06-0700`.
    ...boardStrandProjections.map((strand, index) =>
      canonicalProjectionEvent(
        eventIdForDerivedId(strand.strand_id, "ak:strand:"),
        "ak.strand.create",
        210 + index,
        {
          object: {
            schema: "ak.schema.strand.v1",
            realm_id: strand.realm_id,
            tracks: { discussion: {} },
            created_by: accountActorId,
            created_at: `2026-04-28T12:${10 + index}:00.000Z`,
            metadata: {
              title: strand.title,
              summary: strand.summary,
              fields: { ...strand.fields, strand_kind: "card" },
            },
          },
        },
      ),
    ),
  );
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
        scopes_supported: ["openid", "profile"],
      });
    }
    if (url.hostname === "auth.local.host" && url.pathname === "/authorize") {
      return route.fulfill({
        status: 200,
        contentType: "text/html",
        body: '<!doctype html><main data-testid="coauth-login"><h1>Sign in</h1><p>coauth</p><a href="/register">Create account</a><a href="/recovery">Lost password or account</a></main>',
      });
    }
    if (url.hostname === "server.local" && url.pathname === "/webvh/service/did.json") {
      const entries = currentPrincipalServiceResolution.method_history_evidence.log_entries;
      return route.fulfill({ status: 200, contentType: "application/did+json", body: JSON.stringify(entries[entries.length - 1].state) });
    }
    if (url.hostname === "server.local" && url.pathname === "/webvh/service/did.jsonl") {
      return route.fulfill({ status: 200, contentType: "application/jsonl", body: currentPrincipalServiceResolution.method_history_evidence.log_entries.map((entry: unknown) => JSON.stringify(entry)).join("\n") + "\n" });
    }
    if (url.hostname === "server.local" && url.pathname === "/webvh/service/did-witness.json") {
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(currentPrincipalServiceResolution.method_history_evidence.witness_records) });
    }
    if (!url.pathname.startsWith("/_arkret/")) {
      return route.continue();
    }
    if (
      url.pathname === "/_arkret/describe" &&
      route.request().method() === "GET"
    ) {
      if (url.hostname === "auth.local.host") {
        return route.fulfill({
          status: 404,
          contentType: "application/json",
          body: JSON.stringify({
            errcode: "route_not_found",
            error: "authentication providers do not expose a public Arkret service role",
          }),
        });
      }
      return json(route, principalServiceDescribe());
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
        has_more: false,
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
        strands: boardStrandProjections.map(
          ({ fields: _fields, ...strand }) => strand,
        ),
        has_more: false,
      });
    }

    if (
      url.pathname === "/_arkret/self/circles" &&
      route.request().method() === "GET"
    ) {
      const realmId = url.searchParams.get("realm_id") ?? DEMO_REALM;
      return json(route, {
        realm_id: realmId,
        circles:
          realmId === DEMO_REALM
            ? [
                ...[...circleStates.keys()]
                  .filter(
                    (circleId) => circleStates.get(circleId) !== "tombstoned",
                  )
                  .map((circleId) => circleView(circleId)),
                ...(includeSidecarInCircleList ? [sidecarCircleView()] : []),
              ]
            : [],
      });
    }

    if (
      url.pathname === "/_arkret/self/circles" &&
      route.request().method() === "POST"
    ) {
      const request = route.request().postDataJSON() as {
        title: string;
        summary?: string;
        encryption_profile?: string;
        join_rule?: string;
      };
      const circleId = MOCK_CREATED_CIRCLE_IDS[circleCounter];
      if (!circleId) {
        throw new Error(
          `mock Circle fixture exhausted at index ${circleCounter}`,
        );
      }
      circleCounter += 1;
      circleStates.set(circleId, "active");
      circleMetadata.set(circleId, {
        title: request.title,
        summary: request.summary,
        encryption_profile: request.encryption_profile ?? "mls_rfc9420",
        join_rule: request.join_rule ?? "invite",
      });
      circleMembers.set(circleId, []);
      return json(route, circleView(circleId));
    }

    const circleMemberCollection = url.pathname.match(
      /^\/_arkret\/self\/circles\/([^/]+)\/members$/,
    );
    if (circleMemberCollection && route.request().method() === "POST") {
      const circleId = circleMemberCollection[1];
      const request = route.request().postDataJSON() as {
        actor_id: string;
        membership?: string;
      };
      const membership = request.membership ?? "join";
      const members = new Set(circleMembers.get(circleId) ?? []);
      if (membership === "join") {
        members.add(request.actor_id);
      } else if (membership === "leave" || membership === "ban") {
        members.delete(request.actor_id);
      }
      circleMembers.set(circleId, [...members]);
      return json(route, {
        circle_id: circleId,
        member_id: accountActorIdFor(request.actor_id),
        membership,
      });
    }

    const circleMemberResource = url.pathname.match(
      /^\/_arkret\/self\/circles\/([^/]+)\/members\/(.+)$/,
    );
    if (circleMemberResource && route.request().method() === "DELETE") {
      const [, circleId, actorId] = circleMemberResource;
      const members = new Set(circleMembers.get(circleId) ?? []);
      members.delete(decodeURIComponent(actorId));
      circleMembers.set(circleId, [...members]);
      return json(route, {
        circle_id: circleId,
        member_id: accountActorIdFor(decodeURIComponent(actorId)),
        membership: "leave",
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
      const submittedEntries = Array.isArray(body.events)
        ? body.events
        : [body];
      const submittedEvents = submittedEntries.map(
        (entry: Record<string, any>) => entry.event ?? entry,
      );
      for (const event of submittedEvents) {
        if (
          event.kind === "ak.circle.archive" ||
          event.kind === "ak.circle.restore" ||
          event.kind === "ak.circle.tombstone"
        ) {
          const circleId = event.payload?.target_ref;
          const state =
            typeof circleId === "string" ? circleStates.get(circleId) : undefined;
          if (!state) {
            return json(route, { error: { code: "not_found" } }, 404);
          }
          if (event.kind === "ak.circle.archive" && state !== "active") {
            return json(route, { error: { code: "circle_not_active" } }, 412);
          }
          if (event.kind === "ak.circle.restore" && state !== "archived") {
            return json(route, { error: { code: "circle_not_archived" } }, 412);
          }
          if (event.kind === "ak.circle.tombstone" && state === "tombstoned") {
            return json(
              route,
              { error: { code: "circle_already_terminal" } },
              412,
            );
          }
          circleStates.set(
            circleId,
            event.kind === "ak.circle.archive"
              ? "archived"
              : event.kind === "ak.circle.restore"
                ? "active"
                : "tombstoned",
          );
          continue;
        }
        if (event.kind === "ak.device.authorize") {
          const payload = event.payload ?? event.content ?? {};
          if (
            !isDid(payload.principal_id) ||
            !isDeviceId(payload.device_id) ||
            typeof payload.device_public_key !== "string" ||
            payload.device_public_key.trim() === "" ||
            !isDeviceOrDid(payload.authorized_by) ||
            !["root_anchored", "accepted_device"].includes(
              payload.authorization_binding_kind,
            ) ||
            typeof payload.device_signature !== "string" ||
            payload.device_signature.trim() === ""
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
            deviceSigningKeys.set(
              authorizedDeviceId,
              payload.device_public_key,
            );
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
          (event.kind === "ak.realm.create" &&
          typeof event.event_id === "string" &&
          event.event_id.startsWith("ak:event:")
            ? `ak:realm:${event.event_id.slice("ak:event:".length)}`
            : undefined) ??
          event.realm_id ??
          event.payload?.realm_id ??
          event.payload?.object?.realm_id ??
          // `common-ids.schema.json`: a Realm id is `ak:realm:` plus a 44-char
          // base64url token, so a lowercase-hex/dash class never matches one.
          raw.match(/ak:realm:[A-Za-z0-9_-]{44}/)?.[0];
        if (typeof id !== "string") {
          throw new Error(
            "Realm create mock could not derive the canonical Realm id",
          );
        }
        const title =
          event.payload?.object?.title ??
          event.payload?.title ??
          event.payload?.fields?.title ??
          "Setup Strand Space";
        const summary =
          event.payload?.object?.summary ??
          event.payload?.summary ??
          event.payload?.fields?.summary ??
          "Created from inkson realm setup";
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
        if (event.kind === "ak.realm.create") {
          for (const accepted of submittedEvents) {
            if (
              typeof accepted.event_id === "string" &&
              !projectionEvents.some((projected) => projected.event_id === accepted.event_id)
            ) {
              projectionEvents.push(accepted);
            }
          }
        }
        if (
          typeof event.event_id === "string" &&
          !projectionEvents.some(
            (projected) => projected.event_id === event.event_id,
          )
        ) {
          projectionEvents.push(event);
        }
      }
      if (body.kind === "ak.space.create") {
        const object = body.payload?.object ?? {};
        const spaceId = object.id ?? body.payload?.space_id ?? body.target_ref;
        if (
          typeof spaceId === "string" &&
          !boardSpaceContainers.some((row) => row.space_id === spaceId)
        ) {
          boardSpaceContainers.push({
            space_id: spaceId,
            realm_id: object.realm_id ?? body.realm_id ?? DEMO_REALM,
            kind: object.kind ?? "list",
            title: object.title ?? spaceId,
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
      }
      if (body.kind === "ak.strand.create") {
        messageCounter += 1;
        syncToken = `sx:e2e:strand-${messageCounter}`;
        const object = body.payload?.object ?? {};
        const component = Array.isArray(body.payload?.components)
          ? body.payload.components.find(
              (candidate: { family?: string }) =>
                candidate.family === STRAND_POSITION_CELL_FAMILY,
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
            is_default: false,
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
      }
      // soland (head 37ce729) returns the canonical EventsSubmitOutcome wire
      // shape: {status, accepted[], cursor} — no top-level event_id/sync_token.
      // inkson folds accepted[0] -> event_id and keeps cursor as-is.
      return json(route, {
        status: "accepted",
        accepted: submittedEvents
          .map((event: Record<string, any>) => event.event_id)
          .filter(
            (eventId: unknown): eventId is string =>
              typeof eventId === "string",
          ),
        pending_delivery_count: 0,
        duplicate: [],
        rejected: [],
        quarantine: [],
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
        keypackages: [
          {
            device_id: "ak:device:01964137-0000-7000-8000-0000000000b2",
            mls_keypackage: "bWltaS1rZXktcGFja2FnZS1lMmU",
          },
        ],
        failures: [],
      });
    }

    if (
      url.pathname.match(/^\/_arkret\/open\/mimi\/strands\/[^/]+\/update$/) &&
      route.request().method() === "POST"
    ) {
      const roomId = decodeURIComponent(url.pathname.split("/")[5]);
      // `roomId` is the addressed Strand; the outcome answers whether the
      // update was accepted, not which room it was.
      void roomId;
      return json(route, {
        accepted: true,
        rejections: [],
      });
    }

    if (
      url.pathname.match(/^\/_arkret\/open\/mimi\/strands\/[^/]+\/notify$/) &&
      route.request().method() === "POST"
    ) {
      return json(route, { accepted: true });
    }

    if (
      url.pathname.match(/^\/_arkret\/open\/mimi\/strands\/[^/]+\/messages$/) &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        event_ref: "ak:event:AX-AFSYZHl0U2MQP-Ng7mU-aOm_Flhf0pVBoHYUK6Shg",
        delivery: {
          status: "accepted",
          delivered_to_ids: ["ak:did_core:web:remote.example"],
        },
        rejections: [],
      });
    }

    if (
      url.pathname === "/_arkret/open/mimi/consent/request" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        consent_id: "ak:consent:01964137-0000-7000-8000-0000000000f1",
        challenge: "e2e-consent-challenge",
      });
    }

    if (
      url.pathname === "/_arkret/open/mimi/consent/update" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        consent_id: "ak:consent:01964137-0000-7000-8000-0000000000f1",
        decision: "accept",
        updated_at: "2026-04-28T12:00:00.000Z",
        event_ref: "ak:event:AX-AFSYZHl0U2MQP-Ng7mU-aOm_Flhf0pVBoHYUK6Shg",
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
            subject_id: accountPrincipalCoreId,
          },
        ],
        proofs: [
          {
            kind: "detached_jws",
            verification_method: `${CURRENT_STATION_DID}#mimi-identifier-query`,
            payload_digest: `sha256:${"0".repeat(64)}`,
            created_at: "2026-04-28T12:00:00.000Z",
            jws: "e30..c2ln",
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
        report_id: "ak:report:AX-AFSYZHl0U2MQP-Ng7mU-aOm_Flhf0pVBoHYUK6Shg",
        routed_to_ids: [],
      });
    }

    if (
      url.pathname === "/_arkret/open/mimi/proxy-download" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        download_ref: `https://mimi.example.com/proxy/${DEMO_BLOB_REF}`,
        headers: { "content-type": "application/octet-stream" },
        expires_at: "2026-04-30T12:00:00.000Z",
      });
    }

    if (
      url.pathname === "/_arkret/gate/account/register" &&
      route.request().method() === "POST"
    ) {
      const body = await route.request().postDataJSON();
      const identityCreation = body.identity_creation as
        Record<string, any> | undefined;
      const genesisEvents = identityCreation?.pcr_genesis_unit?.events;
      const createEvent = Array.isArray(genesisEvents)
        ? genesisEvents[0]
        : undefined;
      const authorizeEvent = Array.isArray(genesisEvents)
        ? genesisEvents[1]
        : undefined;
      const authorizePayload = authorizeEvent?.payload ?? {};
      const descriptor =
        createEvent?.payload?.object?.founding_device_descriptor;
      const registrationDeviceId =
        identityCreation?.initial_session?.device_id ?? body.device_id;
      if (identityCreation) {
        const rootAnchored =
          createEvent?.kind === "ak.realm.create" &&
          authorizeEvent?.kind === "ak.device.authorize" &&
          authorizePayload.authorization_binding_kind === "root_anchored" &&
          authorizePayload.authorized_by === body.principal_id &&
          descriptor?.device_id === registrationDeviceId &&
          descriptor?.device_id === authorizePayload.device_id &&
          typeof authorizePayload.device_signature === "string" &&
          authorizePayload.device_signature.length > 0;
        if (!rootAnchored) {
          return json(
            route,
            {
              ok: false,
              error: {
                code: "schema_violation",
                message:
                  "identity creation requires a root_anchored founding device PCR genesis unit",
              },
            },
            400,
          );
        }
      }
      if (registrationDeviceId && !accountDevices.has(registrationDeviceId)) {
        accountDevices.set(registrationDeviceId, {
          device_id: registrationDeviceId,
          status: "active",
          display_name: "Current device",
          verification_state: identityCreation ? "verified" : "unresolved",
        });
      }
      if (
        typeof registrationDeviceId === "string" &&
        typeof descriptor?.device_public_key === "string"
      ) {
        deviceSigningKeys.set(
          registrationDeviceId,
          descriptor.device_public_key,
        );
      }
      const creationOutcome = (() => {
        if (
          !identityCreation ||
          !createEvent ||
          !authorizeEvent ||
          !descriptor
        ) {
          return {};
        }
        const createdAt = "2026-08-09T00:00:00.000Z";
        const createCommitId =
          "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4";
        const commitSignature = {
          context: "ak.realm_commit_signature.v1",
          signature_algorithm: "Ed25519",
          verification_method: `${CURRENT_STATION_ID}#realm-commit`,
          signed_digest: `sha256:${"5".repeat(64)}`,
          created_at: createdAt,
          sig: "e2e-realm-commit-signature",
        };
        return {
          binding_receipt: {
            binding_state: "bound",
            identity_creation_lease_id:
              identityCreation.identity_creation_lease_id,
            lease_fence: identityCreation.lease_fence,
            operation_status: "accepted",
            operation_digest: identityCreation.control_proof.operation_digest,
          },
          pcr_genesis_commits: [
            {
              commit_id: createCommitId,
              realm_id: createEvent.realm_id,
              stream_ref: { kind: "realm", realm_id: createEvent.realm_id },
              stream_position: 0,
              previous_commit_ref: null,
              event_ref: createEvent.event_id,
              governance_generation: 0,
              authority_ref: createEvent.event_id,
              committed_at: createdAt,
              signature: commitSignature,
            },
            {
              commit_id:
                "ak:realm_commit:AdA0TA9zF1BPiudM7qe4WqKZLjMn0r7--gKAHqstAWDZ",
              realm_id: createEvent.realm_id,
              stream_ref: { kind: "realm", realm_id: createEvent.realm_id },
              stream_position: 1,
              previous_commit_ref: createCommitId,
              event_ref: authorizeEvent.event_id,
              governance_generation: 0,
              authority_ref: createEvent.event_id,
              committed_at: createdAt,
              signature: commitSignature,
            },
          ],
          session_grant_outcome: {
            principal_id: body.principal_id,
            device_id: registrationDeviceId,
            session_grant: "e2e-standard-session-grant",
            expires_at: "2027-08-09T00:00:00.000Z",
            grant_id:
              "ak:session_grant:ATLC-gY-xpE0kN3QXVYxo0Kh32EoNCTBQTSFuu_P57e6",
            session_public_key:
              identityCreation.initial_session.session_public_key,
            audience: identityCreation.initial_session.audience,
            granted_scope: [
              "ak.self.account.read.describe.v1",
              "ak.self.committed_event.read.scan.v1",
            ],
          },
        };
      })();
      return json(
        route,
        {
          principal_id: body.principal_id,
          state: "active",
          devices: accountDeviceSummaries(),
          profile: {
            id: "ak:actor_profile:AbhO_nhWEZ7jojF3JULUGyzIUTiHNshUWblbkJCr7NbP",
            schema: "ak.schema.actor_profile.v1",
            principal_id: body.principal_id,
            actor_kind: "user",
            display_name: body.display_name ?? "inkson",
            profile_fields: {},
            accountable_principal_ids: [],
            created_at: "2026-04-28T12:00:00.000Z",
          },
          ...creationOutcome,
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
          id: "ak:actor_profile:AbhO_nhWEZ7jojF3JULUGyzIUTiHNshUWblbkJCr7NbP",
          schema: "ak.schema.actor_profile.v1",
          principal_id: "ak:did_core:web:alice.example",
          realm_id: PRINCIPAL_CONTROL_REALM,
          actor_kind: "user",
          display_name: displayName,
          handle: primaryHandle ?? "alice:local.host",
          avatar_blob_ref: avatarBlobRef,
          profile_fields: bio ? { bio } : {},
          accountable_principal_ids: [],
          created_at: "2026-04-28T12:00:00.000Z",
          updated_at: "2026-04-28T12:10:00.000Z",
        },
        commit: committedEventView(
          (body.profile_event?.event ?? body.profile_event ?? projectionEvents[0]) as Record<string, unknown>,
          0,
        ).commit,
      });
    }

    if (
      url.pathname === "/_arkret/gate/account/session-grants/revoke" &&
      route.request().method() === "POST"
    ) {
      return json(route, { revoked_count: 1, revoked_session_grant_ids: [] });
    }

    if (
      url.pathname === "/_arkret/self/account/subscribe" &&
      route.request().method() === "GET"
    ) {
      if (url.searchParams.has("after")) {
        await new Promise((resolve) => setTimeout(resolve, 5_000));
        const frames = [
          { kind: "frontier", cursor: "ak:cursor:e2e-2" },
          { kind: "catchup_complete", cursor: "ak:cursor:e2e-2" },
        ];
        frames.forEach((frame) =>
          validateMockSchema(
            "schemas/account-subscribe-frame.schema.json",
            frame,
          ),
        );
        return route.fulfill({
          status: 200,
          contentType: "application/x-ndjson",
          body: `${frames.map(canonicalJson).join("\n")}\n`,
        });
      }
      const demoProjectionEvents = projectionEvents.filter(
        (event) => eventRealmId(event) === DEMO_REALM,
      );
      const notificationEvents = includeDemoRealms
        ? [
            {
              event_id: "ak:event:AYMlm81t-z3S1gmmf9y7mEjg4EoUVLa9JapMVEiyY2p7",
              kind: "ak.account_data.set",
              realm_id: DEMO_REALM,
              scope_ref: { kind: "realm", realm_id: DEMO_REALM },
              actor_id: accountActorId,
              actor_seq: 101,
              created_at: "2026-04-28T12:01:00.000Z",
              hlc: "019641370001-0000-12345678",
              prev_refs: [],
              payload: {
                key: "ak.notifications.projection.v1",
                 expected_server_revision: 0,
                body: {
                  id: "ak:notification:01964137-0000-7000-8000-000000000001",
                  schema: "ak.schema.notification.v1",
                  actor_id: accountPrincipalCoreId,
                  source_event_id:
                    "ak:event:AYMlm81t-z3S1gmmf9y7mEjg4EoUVLa9JapMVEiyY2p7",
                  realm_id: DEMO_REALM,
                  notification_kind: "message",
                  priority: "normal",
                  state: "unread",
                  preview: {
                    title: "New message",
                    body: "Alice sent a message in Demo Realm",
                    event_kind: "ak.message.create",
                  },
                  created_at: "2026-04-28T12:01:00.000Z",
                },
              },
              refs: [],
              proofs: [
                {
                  kind: "detached_jws",
                  verification_method: `${accountPrincipalId}#${currentDeviceId}`,
                  event_digest: `sha256:${"0".repeat(64)}`,
                  created_at: "2026-04-28T12:01:00.000Z",
                  jws: "e30..c2ln",
                },
              ],
            },
            {
              event_id: "ak:event:Aaa8behhWSeKSNCcHiTuAoq1xiTXvuVAQxja-XifnQv2",
              kind: "ak.account_data.set",
              realm_id: DEMO_REALM,
              scope_ref: { kind: "realm", realm_id: DEMO_REALM },
              actor_id: accountActorId,
              actor_seq: 102,
              created_at: "2026-04-28T12:02:00.000Z",
              hlc: "019641370002-0000-12345678",
              prev_refs: [],
              payload: {
                key: "ak.notifications.projection.v1",
                 expected_server_revision: 0,
                body: {
                  id: "ak:notification:01964137-0000-7000-8000-000000000002",
                  schema: "ak.schema.notification.v1",
                  actor_id: accountPrincipalCoreId,
                  source_event_id:
                    "ak:event:Aaa8behhWSeKSNCcHiTuAoq1xiTXvuVAQxja-XifnQv2",
                  realm_id: DEMO_REALM,
                  notification_kind: "invite",
                  priority: "normal",
                  state: "unread",
                  preview: {
                    title: "New invite",
                    body: "You were invited to review Demo Realm",
                    event_kind: "ak.invite.create",
                  },
                  created_at: "2026-04-28T12:02:00.000Z",
                },
              },
              refs: [],
              proofs: [
                {
                  kind: "detached_jws",
                  verification_method: `${accountPrincipalId}#${currentDeviceId}`,
                  event_digest: `sha256:${"0".repeat(64)}`,
                  created_at: "2026-04-28T12:02:00.000Z",
                  jws: "e30..c2ln",
                },
              ],
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
                state_at_window_start: {
                  actor_profiles: [],
                  realm_metadata: {
                    title: realm.title,
                    summary: realm.summary,
                  },
                },
                summary: { joined_member_count: 1 },
                committed_events: projectionEvents
                  .filter((event) => eventRealmId(event) === realm.id)
                  .map(committedEventView),
                unread_notifications: {
                  notification_count: 0,
                  highlight_count: 0,
                },
              },
            ]),
          ),
          ...(options.includePrincipalControlRealm
            ? {
                [PRINCIPAL_CONTROL_REALM]: {
                  state_at_window_start: {
                    actor_profiles: [],
                    realm_metadata: {},
                  },
                  summary: { joined_member_count: 1 },
                  committed_events: [],
                  unread_notifications: {
                    notification_count: 0,
                    highlight_count: 0,
                  },
                },
              }
            : {}),
          ...(includeDemoRealms
            ? {
                [DEMO_REALM]: {
                  state_at_window_start: {
                    actor_profiles: [],
                    realm_metadata: {
                      title: "Arkret Demo Realm",
                      summary: "Shared demo Realm served by mocked server",
                    },
                  },
                  summary: { joined_member_count: 2 },
                  // `realm_sync_entry` carries a `member_roster`, not a bare
                  // `members` array: the roster is the closed shape the client
                  // reads (`sync_engine` folds `member_roster.entries`), and
                  // each entry names a complete ActorId.
                  member_roster: {
                    entries: [
                      {
                        actor_id: accountActorId,
                        membership: "join",
                      },
                      {
                        actor_id: {
                          kind: "service",
                          service_id: activeAssistantId,
                        },
                        membership: "join",
                      },
                    ],
                    limited: false,
                  },
                  committed_events: demoProjectionEvents.map(committedEventView),
                  unread_notifications: {
                    notification_count: 0,
                    highlight_count: 0,
                  },
                },
                [CHILD_REALM]: {
                  state_at_window_start: {
                    actor_profiles: [],
                    realm_metadata: {
                      title: "Launch Realm",
                      summary: "Board and discussion scope",
                    },
                  },
                  summary: { joined_member_count: 1 },
                  committed_events: [],
                  unread_notifications: {
                    notification_count: 0,
                    highlight_count: 0,
                  },
                },
                [GRANDCHILD_REALM]: {
                  state_at_window_start: {
                    actor_profiles: [],
                    realm_metadata: {
                      title: "Launch Deep Realm",
                      summary: "Related scope fixture",
                    },
                  },
                  summary: { joined_member_count: 1 },
                  committed_events: [],
                  unread_notifications: {
                    notification_count: 0,
                    highlight_count: 0,
                  },
                },
              }
            : {}),
          ...(includeLowFloorRealm
            ? {
                [LOW_FLOOR_REALM]: {
                  state_at_window_start: {
                    actor_profiles: [],
                    realm_metadata: {
                      title: "Low floor fixture Realm",
                      summary:
                        "Mocks the live first-account PCR floor advisory condition",
                    },
                  },
                  summary: { joined_member_count: 1 },
                  committed_events: [],
                  unread_notifications: {
                    notification_count: 0,
                    highlight_count: 0,
                  },
                },
              }
            : {}),
        },
        to_device: {
          messages: [],
        },
        account_data: {
          events: notificationEvents.map((event) => ({
            event_id: event.event_id,
            kind: event.kind,
            realm_id: event.realm_id,
            scope_ref: event.scope_ref,
            actor_id: event.actor_id,
            created_at: event.created_at,
            payload: event.payload,
            producer_proof: (event.proofs as Array<Record<string, unknown>>)[0],
          })),
        },
        device_lists: { changed_ids: [], left_ids: [] },
        notifications: { items: [] },
      };
      validateMockSchema("schemas/account-subscribe-frame.schema.json", frame);
      validateMockSchema("schemas/account-subscribe-frame.schema.json", {
        kind: "catchup_complete",
        cursor: "ak:cursor:e2e-2",
      });
      return route.fulfill({
        status: 200,
        contentType: "application/x-ndjson",
        body: `${canonicalJson(frame)}\n${canonicalJson({ kind: "catchup_complete", cursor: "ak:cursor:e2e-2" })}\n`,
      });
    }

    if (
      url.pathname === "/_arkret/find/directory/search-realms" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        // Realm creation does not opt the resource into a Directory. This mock
        // has no signed discovery Event plus announce/pull ingest setup, so the
        // spec-correct directory result is empty.
        realms: [],
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
      return json(
        route,
        inksonWire("principal-locator", {
          subject_id: "ak:did_core:web:carol.example",
        }),
      );
    }

    if (
      url.pathname === "/_arkret/find/directory/resolve-realm" &&
      route.request().method() === "POST"
    ) {
      return json(route, directoryRealmResolution());
    }

    if (
      url.pathname === "/_arkret/find/directory/describe" &&
      route.request().method() === "GET"
    ) {
      return json(route, directoryServiceDescribe());
    }

    if (
      url.pathname === "/_arkret/self/committed-events/subscribe" &&
      route.request().method() === "GET"
    ) {
      const cursor = "ak:cursor:e2e-events-2";
      if (url.searchParams.has("after")) {
        await new Promise((resolve) => setTimeout(resolve, 5_000));
        const controlFrames = [
          { kind: "checkpoint", cursor },
          { kind: "catchup_complete", cursor },
        ];
        controlFrames.forEach((frame) =>
          validateMockSchema(
            "schemas/committed-event-subscribe-frame.schema.json",
            frame,
          ),
        );
        return route.fulfill({
          status: 200,
          contentType: "application/x-ndjson",
          body: `${controlFrames.map(canonicalJson).join("\n")}\n`,
        });
      }
      const requestedRealms = url.searchParams
        .getAll("realm_ids")
        .map((realm) => realm.trim())
        .filter(Boolean);
      const frames: Array<Record<string, unknown>> = projectionEvents
        .filter(
          (event) =>
            requestedRealms.length === 0 ||
            requestedRealms.includes(eventRealmId(event)),
        )
        .map((payload, index) => ({
          kind: "committed_event",
          realm_id: eventRealmId(payload),
          cursor,
          payload: committedEventView(payload, index),
        }));
      frames.push({ kind: "catchup_complete", cursor });
      frames.forEach((frame, index) => {
        try {
          validateMockSchema("schemas/committed-event-subscribe-frame.schema.json", frame);
        } catch (error) {
          throw new Error(`committed event frame ${index} (${String((frame.payload as Record<string, unknown> | undefined)?.event && ((frame.payload as Record<string, unknown>).event as Record<string, unknown>).kind)}): ${String(error)}`);
        }
      });
      return route.fulfill({
        status: 200,
        contentType: "application/x-ndjson",
        body: `${frames.map(canonicalJson).join("\n")}\n`,
      });
    }

    if (
      url.pathname === "/_arkret/self/streams/scan" &&
      route.request().method() === "POST"
    ) {
      const requestBody = (await route.request().postDataJSON()) as Record<
        string,
        unknown
      >;
      const requestedRealm =
        typeof requestBody.realm_id === "string" ? requestBody.realm_id : "";
      return json(route, {
        committed_events: projectionEvents
          .filter((event) => eventRealmId(event) === requestedRealm)
          .map(committedEventView),
        truncated: false,
      });
    }

    // invite-addressing.md §7 — before dispatching private invite delivery the
    // client MUST read the accepted Event back through
    // `ak.self.committed_event.read.scan.v1` (`POST /_arkret/self/streams/scan`)
    // rather than re-authoring an equivalent one, because only the server's own
    // view is guaranteed byte-identical to the persisted canonical bytes. The
    // mock therefore serves back exactly what it accepted on POST
    // /_arkret/self/events.
    const committedEventMatch = url.pathname.match(
      /^\/_arkret\/self\/committed-events\/(ak:event:[A-Za-z0-9_-]+)$/,
    );
    if (committedEventMatch && route.request().method() === "GET") {
      const requestedEventId = decodeURIComponent(committedEventMatch[1]);
      const index = projectionEvents.findIndex(
        (event) => event.event_id === requestedEventId,
      );
      if (index < 0) {
        return json(route, { error: { code: "not_found" } }, 404);
      }
      return json(route, committedEventView(projectionEvents[index], index));
    }

    // invite-addressing.md §7 — `ak.self.invites.command.dispatch.v1`. The client
    // hands raw `introduction_evidence` plus the accepted Event to its OWN
    // Station; it never signs federation material and never calls the
    // peer surface. The response is the closed `invite_delivery_outcome`: §5.1
    // keeps the low-trust tier opaque (`deferred`, no `disclosed_outcome`) and
    // only lets the high-trust tier disclose `delivered | blocked`.
    if (
      url.pathname === "/_arkret/self/invites/dispatch" &&
      route.request().method() === "POST"
    ) {
      const requestBody = ((await contractRequestBody(route)) ?? {}) as Record<
        string,
        unknown
      >;
      const evidence = (requestBody.introduction_evidence ?? {}) as {
        kind?: string;
      };
      const highTrust = [
        "locator_ref",
        "consent_grant",
        "shared_realm",
      ].includes(evidence.kind ?? "");
      return json(route, {
        status: highTrust ? "accepted" : "deferred",
        ...(highTrust ? { disclosed_outcome: "delivered" } : {}),
        received_at: "2026-06-13T00:00:00.000Z",
      });
    }

    // NB: no `/_arkret/self/realm-state-snapshot/head` route. The mock's describe does
    // not advertise `ak.self.realm_state_snapshot.read.manifest_head.v1`, so the client falls back to
    // event replay before issuing the request. The current wire shape is the
    // full signed `ak.schema.realm_state_snapshot.v1` manifest (self-id field `id`); the
    // removed `realm_state_snapshot_ref` pointer DTO is hard-rejected and MUST NOT be
    // reintroduced here.
    if (
      url.pathname === "/_arkret/root/identity/describe" &&
      route.request().method() === "GET"
    ) {
      return json(route, identityRegistryServiceDescribe());
    }

    if (
      url.pathname === "/_arkret/root/identity/resolve" &&
      route.request().method() === "POST"
    ) {
      const body = await route.request().postDataJSON();
      return json(
        route,
        identityResolveOutcome(String(body.did), serverDidDocument),
      );
    }

    if (
      url.pathname === "/_arkret/self/account/describe" &&
      route.request().method() === "GET"
    ) {
      return json(route, principalServiceDescribe());
    }

    if (
      url.pathname === "/_arkret/self/authz/check" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        decision: "allow",
        reason_code: "frontier_current",
        matched_grants: [],
        applied_constraints: [],
        policy_results: [],
        missing_proofs: [],
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
            id: "ak:grant:Aa1lsSUPO6wXCITbk8eNFN84GlTcykTUKRcvz1PQJsau",
            issuer: "did:web:admin.example",
            subject: url.searchParams.get("subject"),
            actions: ["space.read", "message.create"],
            resource_selectors: [`realm:${DEMO_REALM}`],
            constraints: [
              { type: "temporal", not_after: "2026-12-31T00:00:00.000Z" },
              {
                type: "kind_restriction",
                params: {
                  allowed_object_kinds: ["space"],
                  allowed_facets: ["renderable", "stateful"],
                },
              },
            ],
            delegation_chain: [
              "ak:grant:Ab1Y2gdaHKIySvl3lY954bFCuMV-rh6sV2f8wmRJLaIF",
              "ak:grant:Aa1lsSUPO6wXCITbk8eNFN84GlTcykTUKRcvz1PQJsau",
            ],
          },
        ],
        state_digest:
          "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        evaluated_at: "2026-04-28T12:00:00.000Z",
      });
    }

    if (
      url.pathname === "/_arkret/self/authz/invites" &&
      route.request().method() === "GET"
    ) {
      return json(route, { invites: [], has_more: false });
    }

    if (
      url.pathname === "/_arkret/self/contacts" &&
      route.request().method() === "GET"
    ) {
      return json(route, {
        contacts: [
          {
            peer: {
              kind: "human",
              account_id: {
                principal_id: "ak:did_core:web:bob.example",
                station_id: CURRENT_STATION_ID,
              },
            },
            state: "accepted",
            request_event_ref:
              "ak:event:AUftf_3k2fRKMG0NFlHe5iEMBOUpxMwYMRu-yhMJl-yz",
            response_event_ref:
              "ak:event:ASZZoDGudNfXFZynKh4xcEpb5d8kLZQXRpycxlg1qyW-",
            granted_to_peer_scopes: ["direct_message", "invite"],
            granted_by_peer_scopes: ["direct_message", "invite"],
            bidirectional_scopes: ["direct_message", "invite"],
            next_prepare_input: {
              contact_round_id:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
              version: 2,
              predecessor_event_ref:
                "ak:event:ASZZoDGudNfXFZynKh4xcEpb5d8kLZQXRpycxlg1qyW-",
            },
            direct_conversation: {
              realm_id: DIRECT_BOB_REALM,
              main_strand_id: DIRECT_BOB_STRAND,
              binding_event_ref:
                "ak:event:AQmnyvvBmKOWOEOSD2rAYsVBQn6vJ_wdbdUY8CKUGB5c",
              state: "found",
            },
            contact_agents: [
              {
                actor_id: {
                  kind: "service",
                  service_id: "ak:did_core:web:agents.example:bob-helper",
                },
                controller_account_id: {
                  principal_id: "ak:did_core:web:bob.example",
                  station_id: CURRENT_STATION_ID,
                },
                display_name: "Bob Helper",
                agent_slug: "helper",
                avatar_blob_ref: DEMO_BLOB_REF,
                direct_conversation: {
                  realm_id:
                    "ak:realm:Ab8b2glgQEo48OSA-g8P4SfHSFLwgN1jG8Jv-AlcdVnI",
                  main_strand_id:
                    "ak:strand:AQAG6N7vDa1nxssksTCIdqNm-FTDJoKuBrHIclJ7FBy0",
                  binding_event_ref:
                    "ak:event:ARhOgV4T1qZleEVITbO4iNd_ggoy771-VwFQBRHzRm4x",
                  state: "found",
                },
              },
            ],
          },
          {
            peer: {
              kind: "human",
              account_id: {
                principal_id: "ak:did_core:web:carol.example",
                station_id: CURRENT_STATION_ID,
              },
            },
            state: "pending_outgoing",
            request_event_ref:
              "ak:event:AeuYGIMbDLHP-zzs9g6vzWrgtPNhcol9h_doKgtHxKqd",
            granted_to_peer_scopes: ["invite"],
            granted_by_peer_scopes: [],
            bidirectional_scopes: [],
          },
        ],
        has_more: false,
      });
    }

    // U2 — contact request (now accepts an optional `message`).
    if (
      url.pathname === "/_arkret/self/contacts/request" &&
      route.request().method() === "POST"
    ) {
      const requestBody = ((await contractRequestBody(route)) ?? {}) as Record<
        string,
        unknown
      >;
      return json(route, contactOutcome("request", requestBody));
    }

    // U1 — accept / reject an incoming contact request.
    if (
      url.pathname === "/_arkret/self/contacts/respond" &&
      route.request().method() === "POST"
    ) {
      const body = ((await contractRequestBody(route)) ?? {}) as Record<
        string,
        unknown
      >;
      return json(
        route,
        contactOutcome(body.action === "reject" ? "reject" : "response", body),
      );
    }

    // U5 — tombstone / block a contact.
    if (
      url.pathname === "/_arkret/self/contacts/tombstone" &&
      route.request().method() === "POST"
    ) {
      const tombstoneBody = ((await contractRequestBody(route)) ?? {}) as Record<
        string,
        unknown
      >;
      return json(route, contactOutcome("tombstone", tombstoneBody));
    }

    // U4 — invite_receive_policy ("who may invite me"). Spec invite-addressing.md
    // §5: GET/SET carry the bare `arkret_sdk::InviteReceivePolicy` (required
    // `schema` + `account_id`, typed enums, trust lists) — no `ok` wrapper.
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
        account_id: { principal_id: accountPrincipalCoreId, station_id: CURRENT_STATION_ID },
        holder_allowed_introduction_kinds: [
          "consent_grant",
          "locator_ref",
          "shared_realm",
        ],
        explicit_address_behavior: "quarantine",
        unknown_invites: "quarantine",
        denied_actor_ids: [
          {
            kind: "account",
            account_id: {
              principal_id: "ak:did_core:web:spammer.example",
              station_id: CURRENT_STATION_ID,
            },
          },
        ],
        disclosure: { high_trust: "outcome", low_trust: "opaque" },
      });
    }

    if (
      url.pathname === "/_arkret/self/direct-conversations/resolve" &&
      route.request().method() === "POST"
    ) {
      const body = ((await contractRequestBody(route)) ?? {}) as Record<
        string,
        unknown
      >;
      const peer = body.peer as
        string | { agent_id?: string; principal_id?: string } | undefined;
      const peerId =
        typeof peer === "string"
          ? peer
          : (peer?.agent_id ?? peer?.principal_id ?? "");
      const ownedAgent = peerId === "ak:did_core:web:agents.example:assistant";
      return json(route, {
        state: "found",
        coordinates: {
          pair_key:
            "sha256:e8c24c1badc48eefa472a1700e87a6597a95aedfab8cbe3173f1622b9ad427b5",
          realm_id: ownedAgent ? DIRECT_OWN_AGENT_REALM : DIRECT_BOB_REALM,
          main_strand_id: ownedAgent
            ? DIRECT_OWN_AGENT_STRAND
            : DIRECT_BOB_STRAND,
          binding_event_ref: ownedAgent
            ? "ak:event:AUsIM7jMWF-QEkZ3Fd8dVqgxiIcM5iASgTtudL5PCcGL"
            : "ak:event:AQmnyvvBmKOWOEOSD2rAYsVBQn6vJ_wdbdUY8CKUGB5c",
        },
        group_state_ref: ownedAgent
          ? "ak:event:ASxjW4aTY3IHG1S2ppEjlCLLjAWhegQuSyKadYw7T3oh"
          : "ak:event:AfR_M7E56E86OkxTne77vQ9fmdFkzpnxO_TBqB4ymjKV",
        send_blockers: [],
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
      url.pathname === "/_arkret/self/keys/keypackages/upload" &&
      route.request().method() === "POST"
    ) {
      const body = (await route.request().postDataJSON()) as Record<
        string,
        unknown
      >;
      const keyPackages = Array.isArray(body.key_packages)
        ? (body.key_packages as Array<Record<string, unknown>>)
        : [];
      return json(route, {
        accepted: keyPackages.length,
        rejections: [],
        // `keypackage_ref_array` is non-empty by definition, so the member is
        // absent rather than `[]` when nothing was accepted.
        ...(() => {
          const refs = keyPackages
            .map((entry) => entry.keypackage_ref)
            .filter((value): value is string => typeof value === "string");
          return refs.length > 0 ? { keypackage_refs: refs } : {};
        })(),
      });
    }

    if (
      url.pathname === "/_arkret/self/keys/query" &&
      route.request().method() === "POST"
    ) {
      const body = ((await contractRequestBody(route)) ?? {}) as Record<
        string,
        unknown
      >;
      expect(Array.isArray(body.device_keys)).toBe(true);
      const requestedDeviceKeys = body.device_keys as Array<{
        account_id: { principal_id: string; station_id: string };
        device_ids: string[];
      }>;
      const generationRef = 1;
      const attestedAt = new Date(Date.now() - 1000).toISOString();
      return json(route, {
        device_keys: requestedDeviceKeys.map(({ account_id, device_ids }) => ({
          account_id,
          device_keys: Object.fromEntries(device_ids.map((device_id) => [device_id, {
              // The self face carries the Station-verified projection and the
              // reference later Events use. The origin attestation and its
              // proof stay on the peer face and never reach a client.
              signer_evidence_ref:
                "ak:signer_evidence:sha256:3f3c1d4dd0b7f0f0b8f2f1f0a9c8b7a6958473625140f0e1d2c3b4a596877869",
              algorithms: {},
              trust_algorithms: [],
              device_projection: {
                  device_signing_key_did:
                    "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX",
                  hpke_key: "fixture-hpke-key",
                  device_authorize_event_id:
                    "ak:event:Ad-rGYKVGY9i32DG2R9ZwMezGzT5g2rmdYjrifmGO6Fe",
                  authorized_generation_ref: generationRef,
                  device_status: "active",
                  authorization_window: {
                    not_before: attestedAt,
                    expires_at: null,
                  },
                  attested_at: attestedAt,
                  expires_at: new Date(Date.now() + 600000).toISOString(),
              },
          }])),
        })),
        failures: [],
        device_generations: requestedDeviceKeys.map(({ account_id }) => ({
          account_id,
          generation_state: {
            current_device_generation_ref: generationRef,
            device_generation_status: "active",
          },
        })),
      });
    }

    if (
      url.pathname === "/_arkret/self/keys/claim" &&
      route.request().method() === "POST"
    ) {
      return json(route, { one_time_keys: [], failures: [] });
    }

    if (
      url.pathname === "/_arkret/self/account/viewer" &&
      route.request().method() === "GET"
    ) {
      const viewer: Record<string, unknown> = {
        principal_id: accountPrincipalCoreId,
        state: "active",
        profile: {
          id: "ak:actor_profile:AbhO_nhWEZ7jojF3JULUGyzIUTiHNshUWblbkJCr7NbP",
          schema: "ak.schema.actor_profile.v1",
          principal_id: accountPrincipalCoreId,
          realm_id: PRINCIPAL_CONTROL_REALM,
          actor_kind: "user",
          display_name: "inkson",
          created_at: "2026-04-28T12:00:00.000Z",
        },
        devices: accountDeviceSummaries(),
      };
      if (primaryHandle) {
        // `handle_claim_status_view` (`schemas/handle-claim.schema.json`): the
        // signed core sits under `claim`, and the status half — who verified
        // it, when, until when — wraps it. The client reads it that way
        // (`transport::account::primary_handle_from_viewer` filters on
        // `claim.claim.subject_account_id`, `status`, `revocation` and
        // `fresh_until`), so a flat claim here is a Realm the panel silently
        // shows as handle-less.
        viewer.primary_handle_claim = handleClaimStatusView(
          primaryHandle,
          accountPrincipalCoreId,
        );
      }
      return json(route, viewer);
    }

    if (
      (url.pathname === "/_arkret/self/invite-locators" ||
        url.pathname === "/_arkret/self/invite-locators/rotate") &&
      route.request().method() === "POST"
    ) {
      const body = await route.request().postDataJSON();
      expect(body.ttl_seconds).toBe(900);
      expect(body.one_time_use).toBe(false);
      return json(route, {
        locator_id: "ak:invite_locator:01964137-0000-7000-8000-0000000000a1",
        locator_token: "e2e_invite_locator_token_00000001",
        expires_at: "2026-07-27T00:15:00.000Z",
        one_time_use: false,
      });
    }

    if (
      url.pathname === "/_arkret/self/agents" &&
      route.request().method() === "GET"
    ) {
      return json(route, {
        agents: Array.from(personalAgents.keys()).map(projectAgent),
        has_more: false,
      });
    }

    if (
      url.pathname === "/_arkret/self/agent-sidecars:ensure" &&
      route.request().method() === "POST"
    ) {
      const body = await route.request().postDataJSON();
      if (
        Array.isArray(body?.addressed_agent_ids) &&
        body.addressed_agent_ids.every(
          (value: unknown) => typeof value === "string",
        )
      ) {
        sidecarAgentIds = [...body.addressed_agent_ids];
      }
      const contextRef = body?.context_ref ?? {};
      const contextExists = boardStrandProjections.some(
        (strand) =>
          strand.realm_id === contextRef.realm_id &&
          strand.strand_id === contextRef.strand_id &&
          strand.state === "active",
      );
      if (!contextExists) {
        return json(
          route,
          {
            ok: false,
            error: {
              code: "not_found",
              message: "context_ref.strand_id not found",
            },
          },
          404,
        );
      }
      return json(route, {
        ok: true,
        sidecar_id: "ak:sidecar:ARtoYyyaAqwT8z7xX2YLO-x_zdkPXEy8ygoDx-tu-5fm",
        access_readiness: "ready",
        pending_access_reconciliations: [],
      });
    }

    if (
      url.pathname === "/_arkret/self/agent-sidecars" &&
      route.request().method() === "GET"
    ) {
      const sidecarId =
        "ak:sidecar:ARtoYyyaAqwT8z7xX2YLO-x_zdkPXEy8ygoDx-tu-5fm";
      const desiredAgentIds = [...sidecarAgentIds].sort();
      return json(route, {
        sidecars: [
          {
            sidecar: {
              id: sidecarId,
              schema: "ak.schema.agent_sidecar.v1",
              realm_id: DEMO_REALM,
              controller_account_id: accountId,
              state: "active",
              created_at: "2026-07-20T00:00:00.000Z",
            },
            desired_agent_ids: desiredAgentIds,
            effective_agent_ids: desiredAgentIds,
            mls_context: {
              participant_authority_digest: canonicalSha256({
                domain: "ak.sidecar.participant_authority.v1",
                sidecar_id: sidecarId,
                realm_id: DEMO_REALM,
                controller_account_id: accountId,
                desired_agent_ids: desiredAgentIds,
              }),
              authority_stream_head: [
                "ak:event:ASxjW4aTY3IHG1S2ppEjlCLLjAWhegQuSyKadYw7T3oh",
              ],
              mls_group_id: mockMlsGroupId(sidecarId),
              epoch: 1,
              genesis_event_ref:
                "ak:event:ASxjW4aTY3IHG1S2ppEjlCLLjAWhegQuSyKadYw7T3oh",
              current_controller_device_ready: true,
            },
            access_readiness: "ready",
            pending_access_reconciliations: [],
          },
        ],
      });
    }

    if (
      url.pathname.startsWith("/_arkret/self/agent-sidecars/") &&
      route.request().method() === "GET"
    ) {
      const sidecarId =
        "ak:sidecar:ARtoYyyaAqwT8z7xX2YLO-x_zdkPXEy8ygoDx-tu-5fm";
      const desiredAgentIds = [...sidecarAgentIds].sort();
      return json(route, {
        sidecar: {
          id: sidecarId,
          schema: "ak.schema.agent_sidecar.v1",
          realm_id: DEMO_REALM,
          controller_account_id: accountId,
          state: "active",
          created_at: "2026-07-20T00:00:00.000Z",
        },
        desired_agent_ids: desiredAgentIds,
        effective_agent_ids: desiredAgentIds,
        mls_context: {
          participant_authority_digest: canonicalSha256({
            domain: "ak.sidecar.participant_authority.v1",
            sidecar_id: sidecarId,
            realm_id: DEMO_REALM,
            controller_account_id: accountId,
            desired_agent_ids: desiredAgentIds,
          }),
          authority_stream_head: [
            "ak:event:ASxjW4aTY3IHG1S2ppEjlCLLjAWhegQuSyKadYw7T3oh",
          ],
          mls_group_id: mockMlsGroupId(sidecarId),
          epoch: 1,
          genesis_event_ref:
            "ak:event:ASxjW4aTY3IHG1S2ppEjlCLLjAWhegQuSyKadYw7T3oh",
          current_controller_device_ready: true,
        },
        access_readiness: "ready",
        pending_access_reconciliations: [],
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
      const slug =
        typeof body.slug === "string" && body.slug.trim()
          ? body.slug.trim()
          : "";
      if (!slug) {
        return json(
          route,
          {
            ok: false,
            error: { code: "param_invalid", message: "slug is required" },
          },
          400,
        );
      }
      const phase = typeof body.phase === "string" ? body.phase : "";
      const agentId = didCoreId(
        phase === "commit" && typeof body.agent_id === "string"
          ? body.agent_id
          : `did:web:agents.example:${slug}`,
      );
      const agentDid = didFromCoreId(agentId);
      const principalControlRealmId =
        "ak:realm:AQ4lJ43jR05ytJIf7AGNbPU_MuY1FqT_ny_e8MhCCnwc";
      const controllerRealmId = DEMO_REALM;
      const controllerAuthorizationRef = `${agentDid}#managed-controller`;
      const requestedScopeDigest = canonicalSha256({
        agent_id: agentId,
        controller_principal_id: accountPrincipalCoreId,
        kind: "ak.agent.requested_scope_commitment.v1",
        requested_scope: body.requested_scope,
      });
      if (phase === "prepare") {
        personalAgentCounter += 1;
        managedPcrRealmIds.add(principalControlRealmId);
        return json(route, {
          status: "awaiting_controller_event",
          agent_id: agentId,
          principal_control_realm_id: principalControlRealmId,
          controller_realm_id: controllerRealmId,
          allocation_handle: `agent-provision-allocation-${personalAgentCounter}.e2e.signature`,
          controller_authorization_ref: controllerAuthorizationRef,
          requested_scope_digest: requestedScopeDigest,
        });
      }
      if (phase !== "commit") {
        return json(
          route,
          {
            ok: false,
            error: {
              code: "param_invalid",
              message: "phase must be prepare or commit",
            },
          },
          400,
        );
      }
      const provisionEvent =
        typeof body.provision_event === "object" &&
        body.provision_event !== null
          ? (body.provision_event as Record<string, unknown>)
          : {};
      const event =
        typeof provisionEvent.event === "object" &&
        provisionEvent.event !== null
          ? (provisionEvent.event as Record<string, unknown>)
          : {};
      const payload =
        typeof event.payload === "object" && event.payload !== null
          ? (event.payload as Record<string, unknown>)
          : {};
      const agent = {
        agent_id: agentId,
        ...(typeof payload.display_name === "string"
          ? { display_name: payload.display_name }
          : {}),
        slug,
        ...(typeof payload.avatar_blob_ref === "string"
          ? { avatar_blob_ref: payload.avatar_blob_ref }
          : {}),
        lifecycle: "active",
        created_at: "2026-07-06T00:00:00.000Z",
        updated_at: "2026-07-06T00:00:00.000Z",
      };
      const keyState = {
        agent_id: agentId,
        controller_account_id: accountId,
        principal_control_realm_id: principalControlRealmId,
        controller_authorization_ref: controllerAuthorizationRef,
        pairing_request_id: `pair-${personalAgentCounter}`,
        pairing_code: "pairing-secret-246810-e2e",
        pairing_expires_at: personalAgentPairingExpiresAt,
        requested_scope: body.requested_scope,
      };
      personalAgents.set(agentId, agent);
      personalAgentKeyStates.set(agentId, keyState);
      personalAgentGrants.set(agentId, []);
      return json(route, {
        status: "complete",
        agent_id: agentId,
        principal_control_realm_id: principalControlRealmId,
        controller_authorization_ref: controllerAuthorizationRef,
        requested_scope_digest: requestedScopeDigest,
        pairing_request_id: keyState.pairing_request_id,
        pairing_code: keyState.pairing_code,
        expires_at: keyState.pairing_expires_at,
      });
    }

    const agentLifecycleMatch = url.pathname.match(
      /^\/_arkret\/self\/agents\/([^/]+)\/(pause|resume)$/,
    );
    if (agentLifecycleMatch && route.request().method() === "POST") {
      const agentId = decodeURIComponent(agentLifecycleMatch[1]);
      const action = agentLifecycleMatch[2];
      const agent = personalAgents.get(agentId);
      const keyState = personalAgentKeyStates.get(agentId);
      if (!agent || !keyState) {
        return json(
          route,
          {
            ok: false,
            error: { code: "not_found", message: "agent not found" },
          },
          404,
        );
      }
      const body = ((await contractRequestBody(route)) ?? {}) as Record<
        string,
        unknown
      >;
      const lifecycleSubmission = body.lifecycle_event as
        Record<string, any> | undefined;
      const event = lifecycleSubmission?.event as
        Record<string, any> | undefined;
      const expectedKind = `ak.self.agent.${action}`;
      const expectedFrom = action === "pause" ? "active" : "paused";
      const expectedTo = action === "pause" ? "paused" : "active";
      const expectedReason = action === "pause" ? body.reason : undefined;
      const payload = event?.payload;
      const valid =
        event?.kind === expectedKind &&
        event?.realm_id === keyState.principal_control_realm_id &&
        event?.actor_id === agentId &&
        event?.executed_by === accountPrincipalId &&
        event?.authorization_ref === keyState.controller_authorization_ref &&
        Array.isArray(event?.proofs) &&
        event.proofs.length > 0 &&
        lifecycleSubmission?.authorization_lease &&
        lifecycleSubmission?.control_proposal_ack &&
        payload?.transition === action &&
        payload?.previous_status === expectedFrom &&
        payload?.reason === expectedReason;
      if (!valid) {
        return json(
          route,
          {
            ok: false,
            error: {
              code: "param_invalid",
              message:
                "lifecycle_event does not match the delegated Agent transition",
            },
          },
          400,
        );
      }
      agent.lifecycle = expectedTo;
      agent.updated_at = "2026-07-19T08:00:00.000Z";
      return json(route, { ok: true, status: expectedTo });
    }

    const agentDeactivateMatch = url.pathname.match(
      /^\/_arkret\/self\/agents\/([^/]+)\/deactivate$/,
    );
    if (agentDeactivateMatch && route.request().method() === "POST") {
      const agentId = decodeURIComponent(agentDeactivateMatch[1]);
      const agent = personalAgents.get(agentId);
      const keyState = personalAgentKeyStates.get(agentId);
      if (!agent || !keyState) {
        return json(
          route,
          {
            ok: false,
            error: { code: "not_found", message: "agent not found" },
          },
          404,
        );
      }
      const body = ((await contractRequestBody(route)) ?? {}) as Record<
        string,
        any
      >;
      const lifecycleSubmission = body.lifecycle_event as
        Record<string, any> | undefined;
      const event = lifecycleSubmission?.event as
        Record<string, any> | undefined;
      const keyEvents = Array.isArray(body.key_revocation_events)
        ? body.key_revocation_events
        : [];
      const capabilityEvents = Array.isArray(body.capability_revocation_events)
        ? body.capability_revocation_events
        : [];
      const activeAuthorizations = Array.isArray(keyState.active_authorizations)
        ? keyState.active_authorizations
        : [];
      const activeGrants = personalAgentGrants.get(agentId) ?? [];
      const previousStatus = String(agent.lifecycle ?? "active");
      const suppliedKeyIds = new Set(
        keyEvents.map((candidate: Record<string, any>) =>
          String(candidate?.event?.payload?.key_id ?? ""),
        ),
      );
      const suppliedGrantIds = new Set(
        capabilityEvents.map((candidate: Record<string, any>) =>
          String(candidate?.event?.payload?.grant_id ?? ""),
        ),
      );
      const validLifecycle =
        event?.kind === "ak.self.agent.deactivate" &&
        event?.realm_id === keyState.principal_control_realm_id &&
        event?.actor_id === agentId &&
        event?.executed_by === accountPrincipalId &&
        event?.authorization_ref === keyState.controller_authorization_ref &&
        Array.isArray(event?.proofs) &&
        event.proofs.length > 0 &&
        lifecycleSubmission?.authorization_lease &&
        lifecycleSubmission?.control_proposal_ack &&
        event?.payload?.transition === "deactivate" &&
        event?.payload?.previous_status === previousStatus &&
        event?.payload?.reason === body.reason;
      const keysCovered = activeAuthorizations.every(
        (authorization: Record<string, any>) =>
          suppliedKeyIds.has(String(authorization.key_id ?? "")),
      );
      const grantsCovered = activeGrants.every((grant) =>
        suppliedGrantIds.has(String(grant.grant_id ?? "")),
      );
      if (!validLifecycle || !keysCovered || !grantsCovered) {
        return json(
          route,
          {
            ok: false,
            error: {
              code: "failed_precondition",
              message: "deactivation revocation bundle is incomplete",
            },
          },
          412,
        );
      }
      agent.lifecycle = "deactivated";
      agent.updated_at = "2026-07-19T08:00:00.000Z";
      keyState.active_authorizations = [];
      personalAgentGrants.set(agentId, []);
      return json(route, { ok: true, status: "deactivated" });
    }

    const agentRenewPairingMatch = url.pathname.match(
      /^\/_arkret\/self\/agents\/([^/]+)\/renew-pairing$/,
    );
    if (agentRenewPairingMatch && route.request().method() === "POST") {
      const agentId = decodeURIComponent(agentRenewPairingMatch[1]);
      const agent = personalAgents.get(agentId);
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
      const renewAxes = projectAgentAxes(agentId);
      if (renewAxes.lifecycle === "deactivated") {
        return json(
          route,
          {
            ok: false,
            error: {
              code: "failed_precondition",
              message: "agent is deactivated; deactivation is terminal",
            },
          },
          412,
        );
      }
      personalAgentCounter += 1;
      const renewedExpiresAt = "2099-07-06T00:20:00.000Z";
      // Both active and paused agents may replace without a forced pause; the
      // branch is bootstrap for a never-keyed agent, replacement otherwise
      // (key-management.md §3.6.1).
      const keyState = {
        ...(personalAgentKeyStates.get(agentId) ?? {}),
        pairing_request_id: `pair-renew-${personalAgentCounter}`,
        pairing_code: "pairing-secret-135791-e2e",
        pairing_expires_at: renewedExpiresAt,
      };
      personalAgents.set(agentId, {
        ...agent,
        updated_at: "2026-07-06T00:30:00.000Z",
      });
      personalAgentKeyStates.set(agentId, keyState);
      return json(route, {
        agent_id: agentId,
        principal_control_realm_id: keyState.principal_control_realm_id,
        controller_authorization_ref: keyState.controller_authorization_ref,
        requested_scope_digest: canonicalSha256({
          agent_id: keyState.agent_id,
          controller_principal_id: keyState.controller_account_id.principal_id,
          kind: "ak.agent.requested_scope_commitment.v1",
          requested_scope: keyState.requested_scope,
        }),
        pairing_request_id: keyState.pairing_request_id,
        pairing_code: keyState.pairing_code,
        expires_at: keyState.pairing_expires_at,
      });
    }

    const agentParticipationMatch = url.pathname.match(
      /^\/_arkret\/self\/agents\/([^/]+)\/participation$/,
    );
    if (agentParticipationMatch && route.request().method() === "GET") {
      return json(route, {
        agent_id: decodeURIComponent(agentParticipationMatch[1]),
        participation_entries: [],
      });
    }

    const agentGetMatch = url.pathname.match(
      /^\/_arkret\/self\/agents\/([^/]+)$/,
    );
    if (agentGetMatch && route.request().method() === "GET") {
      const agentId = decodeURIComponent(agentGetMatch[1]);
      const agent = personalAgents.get(agentId);
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
      const storedKeyState = personalAgentKeyStates.get(agentId);
      return json(route, {
        agent: projectAgent(agentId),
        grants: personalAgentGrants.get(agentId) ?? [],
        ...(storedKeyState ? { key_state: storedKeyState } : {}),
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
      const submission = body.authorize_event as { event?: Record<string, unknown> };
      const event = submission?.event ?? {};
      const payload = (event.payload ?? {}) as Record<string, unknown>;
      const agentId = String(payload.agent_id ?? "");
      const agent = personalAgents.get(agentId);
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
      const authorizedEventRef = String(event.event_id ?? "");
      agent.lifecycle = "active";
      agent.updated_at = "2026-07-06T00:05:00.000Z";
      const previousKeyState = personalAgentKeyStates.get(agentId) ?? {};
      const nextKeyState: Record<string, unknown> = {
        ...previousKeyState,
        authorized_event_ref: authorizedEventRef,
        active_authorizations: [
          {
            key_id: payload.key_id,
            verification_method: payload.verification_method,
            authorized_event_ref: authorizedEventRef,
          },
        ],
      };
      delete nextKeyState.pairing_request_id;
      delete nextKeyState.pairing_code;
      delete nextKeyState.pairing_expires_at;
      personalAgentKeyStates.set(agentId, nextKeyState);
      return json(route, {
        activation_state: "active",
        authorize_event_ref: authorizedEventRef,
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
        authorized_event_ref:
          "ak:event:AQUeFABQK9MQb8JmkZyP7wD2QfYOSDaCH1LDepfyMD-G",
      });
    }

    // Server-mediated device-pairing short-link (open, unauthenticated).
    if (
      url.pathname === "/_arkret/open/device-pairing/requests" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        device_pairing_request_id:
          "device_pairing_request:01964137-0000-7000-8000-0000000000c1",
        pairing_code: "7H2K9M4Q",
        gate_audience_uri: url.origin,
        server_nonce: "Y290ZXN0LXNlcnZlci1wYWlyaW5nLW5vbmNl",
        expires_at: "2099-01-01T00:00:00.000Z",
      });
    }

    if (
      url.pathname === "/_arkret/open/device-pairing/resolve" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        arkret_base_url: url.origin,
        device_pairing_request_id:
          "device_pairing_request:01964137-0000-7000-8000-0000000000c1",
        pairing_code: "7H2K9M4Q",
        new_device_pubkey: {
          kty: "OKP",
          kid: "ak:device:01964137-0000-7000-8000-0000000000b2",
          algorithm: "Ed25519",
          key: "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
        },
        client_nonce: "Y290ZXN0LWRldmljZS1wYWlyaW5nLW5vbmNl",
        gate_audience_uri: url.origin,
        server_nonce: "Y290ZXN0LXNlcnZlci1wYWlyaW5nLW5vbmNl",
        display_name: "New device",
        device_metadata: { platform: "browser" },
        expires_at: "2099-01-01T00:00:00.000Z",
      });
    }

    if (
      url.pathname === "/_arkret/open/device-pairing/requests/status" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        state: "authorized",
        device_id: "ak:device:01964137-0000-7000-8000-0000000000b2",
        authorized_event_ref:
          "ak:event:AQUeFABQK9MQb8JmkZyP7wD2QfYOSDaCH1LDepfyMD-G",
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
        delivered: {
          [accountPrincipalCoreId]: {
            [currentDeviceId]: {
              device_message_id:
                "ak:device_message:01964137-0000-7000-8000-0000000000d9",
              status: "delivered",
            },
          },
        },
        unknown_devices: {},
      });
    }

    if (
      url.pathname === "/_arkret/self/device_messages/ack" &&
      route.request().method() === "POST"
    ) {
      return json(route, { pruned_count: 0 });
    }

    if (
      url.pathname === "/_arkret/self/signal" &&
      route.request().method() === "POST"
    ) {
      const body = await route.request().postDataJSON();
      return json(route, {
        accepted: true,
        realm_id: body.realm_id,
        envelope_digest:
          body.proof?.envelope_digest ?? `sha256:${"0".repeat(64)}`,
        dispatched_recipient_count: 0,
        server_received_at: new Date().toISOString(),
      });
    }

    if (
      url.pathname === "/_arkret/self/signal/subscribe" &&
      route.request().method() === "GET"
    ) {
      validateMockResponse(route, 403);
      return route.fulfill({ status: 403 });
    }

    if (
      url.pathname === "/_arkret/edge/push/register-device" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        push_target_id: "ak:pseudonym:push:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        registration_id: "push_e2e_registration_0001",
        expires_at: "2099-01-01T00:00:00.000Z",
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
        size_bytes: 68,
        media_type: "image/jpeg",
      });
    }

    if (
      url.pathname === "/_arkret/self/rtc/ice-config" &&
      route.request().method() === "POST"
    ) {
      const body = await route.request().postDataJSON();
      return json(route, {
        realm_id: body.realm_id ?? DEMO_REALM,
        call_id:
          body.call_id ??
          "ak:call:AbhvODyrIRCskAIoS9IXLjMfD-Zsr8lwDpiCU_zLR4it",
        actor_id: body.actor_id
          ? accountActorIdFor(String(body.actor_id))
          : accountActorId,
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
        issued_at: "2026-05-19T00:00:00.000Z",
        signature: {
          alg: "Ed25519",
          kid: `${CURRENT_STATION_DID}#media-ice`,
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
        contentType: "image/png",
        body: Buffer.from(DEMO_AVATAR_PNG_BASE64, "base64"),
      });
    }

    if (
      url.pathname === "/_arkret/self/moderation/report" &&
      route.request().method() === "POST"
    ) {
      return json(route, {
        report_id: "ak:report:AX-AFSYZHl0U2MQP-Ng7mU-aOm_Flhf0pVBoHYUK6Shg",
        routed_to_ids: [CURRENT_STATION_ID],
      });
    }

    // Recovery bootstrap publishes a signed policy and then uploads an
    // encrypted secret_storage backup. The server mock stores only the public
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
        const event =
          typeof body.event === "object" && body.event !== null
            ? (body.event as Record<string, any>)
            : {};
        const policy =
          typeof event.payload?.value === "object" &&
          event.payload.value !== null
            ? (event.payload.value as Record<string, any>)
            : {};
        const acceptedAt = new Date().toISOString();
        const policyId = policy.policy_id ?? seededRecoveryPolicyId;
        const acceptanceBasisRef = mockCommitId({ policy_id: policyId, version: policy.version ?? 1 });
        recoveryPolicy = {
          policy_id: policyId,
          account_id: accountId,
          version: policy.version ?? 1,
          acceptance_basis_ref: acceptanceBasisRef,
          trust_domain: policy.trust_domain ?? "ak:trust_domain:soland.local",
          methods: Array.isArray(policy.methods)
            ? policy.methods
            : [],
          policy,
          supersedes_id: policy.supersedes_id ?? null,
          expires_at: policy.expires_at ?? null,
          issued_at: policy.issued_at ?? acceptedAt,
          accepted_at: acceptedAt,
        };
        return json(route, {
          policy_id: policyId,
          account_id: accountId,
          version: policy.version ?? 1,
          acceptance_basis_ref: acceptanceBasisRef,
          accepted_at: acceptedAt,
        });
      }
    }

    const accountDataMatch = url.pathname.match(
      /^\/_arkret\/self\/account_data\/([^/]+)$/,
    );
    if (accountDataMatch && route.request().method() === "GET") {
      return json(route, {
        account_data_key: decodeURIComponent(accountDataMatch[1]),
        revision: 0,
        content: null,
        updated_at: "2026-04-28T12:00:00.000Z",
      });
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
              : `sha256:${"e".repeat(64)}`,
        });
      }
    }
    if (
      url.pathname === "/_arkret/self/keys/backups" &&
      route.request().method() === "GET"
    ) {
      const backupClass = url.searchParams.get("backup_kind");
      const backups = Array.from(keyBackups.values()).filter((backup) =>
        backupClass ? backup.backup_kind === backupClass : true,
      );
      return json(route, {
        backups,
        active_series: {
          account_id: accountId,
          control_realm_id: PRINCIPAL_CONTROL_REALM,
          authority_commit_id: mockCommitId({ account_id: accountId, backup_kind: "secret_storage" }),
          // This fixture's accepted pointer is independent of object uploads,
          // deletions and the list filter; only preseeded recovery activates it.
          secret_storage: options.preseedRecoveryMaterial === true
            ? {
                state: "active",
                active_series_id: "ak:backup_series:019a6aa0-0000-7000-8000-000000000003",
                series_pointer_version: 1,
              }
            : { state: "absent" },
        },
        has_more: false,
      });
    }

    if (
      /^\/_arkret\/open\/services\/[^/]+\/resolution$/.test(url.pathname) &&
      route.request().method() === "GET"
    ) {
      return json(route, inksonWire("service-resolution", {}));
    }

    return route.fulfill({ status: 404 });
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

function directoryRealmResolution() {
  return {
    realm_id: DEMO_REALM,
    public_metadata: {
      display_name: "Arkret Demo Realm",
      summary: "Shared demo Realm served by mocked server",
    },
    indexed_at: "2026-06-13T00:00:00.000Z",
    expires_at: "2099-01-01T00:00:00.000Z",
  };
}

function directoryServiceDescribe() {
  return {
    service_id: CURRENT_STATION_ID,
    service_resolution: {
      did: CURRENT_STATION_DID,
      method_history_head: "development-unverified",
      version_id: "development-unverified",
    },
    trust_domain: "ak:trust_domain:server.local",
    service_kind: "directory_service",
    protocol_version: "1.0",
    supported_profiles: [],
    ...currentHttpDescribeCapabilities(
      [DIRECTORY_DESCRIBE_BUNDLE, DIRECTORY_PUBLIC_READ_BUNDLE],
      "https://server.local/_arkret/find/directory",
    ),
    supported_features: [],
    auth_metadata: {},
    limits: {},
    plaintext_visibility: {},
    rate_limit_policy: {},
    verified_profiles: [],
    interop_surfaces: [],
    development_mode: false,
    resource_kinds: ["realm"],
  };
}

function principalServiceDescribe() {
  return {
    service_id: CURRENT_STATION_ID,
    service_resolution: {
      did: CURRENT_STATION_DID,
      method_history_head: currentPrincipalServiceResolution.method_history_evidence.boundary.to_method_history_head,
      version_id: currentPrincipalServiceResolution.method_history_evidence.boundary.to_version_id,
    },
    trust_domain: "ak:trust_domain:server.local",
    service_kind: "station",
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
      "ak.profile.station_events_api.v1",
    ],
    supported_features: [],
    ...currentHttpDescribeCapabilities([
      PRINCIPAL_DESCRIBE_BUNDLE,
      PRINCIPAL_HTTP_CORE_BUNDLE,
    ]),
    auth_metadata: {
      account_authority: {
        origin: "https://auth.local.host",
        gate_account_base_url: "https://auth.local.host/_arkret/gate/account",
      },
      methods: [
        {
          method: "oidc",
          issuer_uri: "https://auth.local.host/",
          openid_configuration_url:
            "https://auth.local.host/.well-known/openid-configuration",
          client_id: "01GFWR28C4KNE04WG3HKXB7C9R",
          scopes: ["openid", "profile"],
          grant_exchange: { kind: "account_handoff" },
        },
      ],
    },
    limits: {
      x_storage: "memory",
    },
    rate_limit_policy: {
      policy_version: "1",
      entries: [
        {
          endpoint: "/_arkret",
          rate_limit_scope: "service",
          window_seconds: 60,
          max_requests: 120,
        },
      ],
    },
    plaintext_visibility: {
      max_visibility: "none",
      notes: "E2EE-only mock: no plaintext-visible service surface.",
    },
    verified_profiles: [],
    interop_surfaces: [],
    development_mode: true,
  };
}

function eventsServiceDescribe() {
  return {
    ...principalServiceDescribe(),
    supported_profiles: ["ak.profile.core_event_store.v1"],
    supported_features: [],
  };
}

function identityRegistryServiceDescribe() {
  return {
    ...principalServiceDescribe(),
    service_kind: "identity_registry",
    supported_profiles: ["ak.profile.identity_registry.v1"],
    supported_operation_bundles: [
      "ak.operation_bundle.identity_registry.describe.v1",
      "ak.operation_bundle.identity_registry.http_core.v1",
    ],
    transport_bindings: [
      {
        kind: "http_json",
        base_url: "https://server.local/",
        extension_profile_required: null,
      },
    ],
    supported_features: [],
    verified_profiles: [],
    interop_surfaces: [],
  };
}

function identityResolveOutcome(
  did: string,
  serverDidDocument: Record<string, unknown>,
) {
  return {
    did_document:
      did === CURRENT_STATION_DID ? serverDidDocument : { id: did },
    seq: 0,
    receipts: [],
  };
}

function staticMockResponseFixtures(
  serverDidDocument: Record<string, unknown>,
): StaticMockResponseFixture[] {
  return [
    {
      operation_id: "ak.server.read.describe.v1",
      status: 200,
      value: principalServiceDescribe(),
    },
    {
      operation_id: "ak.server.read.describe.v1",
      status: 200,
      value: eventsServiceDescribe(),
    },
    {
      operation_id: "ak.open.mimi.read.provider_directory.v1",
      status: 200,
      value: mimiProviderDirectory(),
    },
    {
      operation_id: "ak.find.directory.read.resolve_realm.v1",
      status: 200,
      value: directoryRealmResolution(),
    },
    {
      operation_id: "ak.find.directory.read.describe.v1",
      status: 200,
      value: directoryServiceDescribe(),
    },
    {
      operation_id: "ak.root.identity.registry.read.describe.v1",
      status: 200,
      value: identityRegistryServiceDescribe(),
    },
    {
      operation_id: "ak.root.identity.read.resolve.v1",
      status: 200,
      value: identityResolveOutcome(CURRENT_STATION_DID, serverDidDocument),
    },
    {
      operation_id: "ak.self.account.read.describe.v1",
      status: 200,
      value: principalServiceDescribe(),
    },
  ];
}

function mimiProviderDirectory() {
  const features = [
    "key_material",
    "room_update",
    "notify",
    "submit_message",
    "consent",
    "identifier_query",
    "report_abuse",
    "proxy_download",
  ];
  return {
    schema: "ak.schema.mimi_interop.v1",
    service_id: CURRENT_STATION_ID,
    service_kind: "mimi_provider_facade",
    supported_profiles: ["ak.profile.mimi_interop.v1"],
    mimi: {
      protocol_draft: "draft-ietf-mimi-protocol-06",
      content_draft: "draft-ietf-mimi-content-08",
      room_policy_draft: "draft-ietf-mimi-room-policy-03",
      identifier_draft: "draft-kohbrok-mimi-identifiers-01",
      base_url: "https://mimi.example.com/_arkret/open/mimi",
      provider_id: "mimi://mimi.example.com",
      endpoints: features.map((endpointId) => ({
        endpoint_id: endpointId,
        relative_path: `/${endpointId.replaceAll("_", "-")}`,
      })),
      features,
      mls_cipher_suites: ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
      content_profiles: ["application/mimi-content"],
      room_policy_components: ["membership"],
    },
    proof: {
      kind: "detached_jws",
      verification_method: `${CURRENT_STATION_DID}#mimi-provider`,
      payload_digest: `sha256:${"0".repeat(64)}`,
      created_at: "2026-04-28T12:00:00.000Z",
      jws: "e30..c2ln",
    },
  };
}

function json(route: Route, body: unknown, status = 200) {
  validateMockResponse(route, status, body);
  return route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}
