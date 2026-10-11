import { expect, type Page, type Route } from "@playwright/test";
import { spawnSync } from "node:child_process";
import { Buffer } from "node:buffer";
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

const STRAND_POSITION_CELL_FAMILY = "ak.component.strand.position.v1";
const DEMO_FRONTIER_EVENT = "ak:event:Ad0EZUHcfLJv92Of4w-RJec6fkNlWP11fsQAQ4dqUOHS";
const DIRECT_BOB_REALM =
  "ak:realm:AUEAoXMJeJWBETvkqm7gk4imduk7g-l8bim19OPFQDaO";
const DIRECT_BOB_STRAND =
  "ak:strand:Ae9PN2rTd0Dojs9yS8iLnfheJtjSEZ3mgDDyONpztHUd";
export const DIRECT_BOB_HELPER_REALM =
  "ak:realm:Ab8b2glgQEo48OSA-g8P4SfHSFLwgN1jG8Jv-AlcdVnI";
export const DIRECT_BOB_HELPER_STRAND =
  "ak:strand:AQAG6N7vDa1nxssksTCIdqNm-FTDJoKuBrHIclJ7FBy0";
const DIRECT_OWN_AGENT_REALM =
  "ak:realm:AbhO_nhWEZ7jojF3JULUGyzIUTiHNshUWblbkJCr7NbP";
const DIRECT_OWN_AGENT_STRAND =
  "ak:strand:ASy992JMe_xzh5pluAqo5YuyCnAfDdFni4lmeHQldlUM";
const DEMO_CIRCLE = "ak:circle:AVhDoodj6EFMf5ZQ1JXfSmM5ZNZrK3ekqYa4-EOvqSiE";
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
  // The suite byte and all digest octets form one canonical identifier token.
  const token = Buffer.concat([Buffer.from([0x01]), digest]);
  return `ak:realm_commit:${token.toString("base64url")}`;
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
  assigned_actor_ids?: Array<{
    kind: "account";
    account_id: { principal_id: string; station_id: string };
  }>;
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
  assistantKeyBinding?: "missing" | "mismatched";
  emptyBoard?: boolean;
  encryptedDemoRealm?: boolean;
  demoNotification?: boolean;
  invitePreview?: "disclosed" | "restricted" | "retry_once";
  invitePreviewDelayMs?: number;
  contactRequestOutcome?: "failed" | "tampered";
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
  | "service-document"
  | "direct-conversation-pair-key"
  | "principal-locator"
  | "validate-mock-response"
  | "contact-request-prepare"
  | "contact-request-commit"
  | "contact-request-sign"
  | "contact-request-verify"
  | "mock-realm-fixture"
  | "mock-realm-verify"
  | "mock-realm-authority-bundle"
  | "mock-current-principal"
  | "mock-realm-scan"
  | "mock-exact-current"
  | "mock-realm-signer-keys"
  | "mock-realm-submit";
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
const snapshotReadOperations = new Set([
  "ak.self.realm_state_snapshot.read.manifest_head.v1",
  "ak.self.realm_state_snapshot.read.by_ref.v1",
]);
type MockErrorDescriptor = {
  code: string;
  http_status: number;
  type_uri: string;
  title: string;
  status: string;
};
// The SDK exposes these descriptors in Rust, but the existing wire CLI only
// exposes schema validation. Read the normative metadata once, without copying
// its status/type/title table or adding another Rust command.
const mockErrorRegistryRoot = resolve(inksonRepoRoot, "..", "arkret-spec", "spec", "v1", "artifacts", "registry");
const mockErrorRegistry = JSON.parse(readFileSync(resolve(mockErrorRegistryRoot, "error-code-registry.json"), "utf8")) as {
  codes: MockErrorDescriptor[];
};
const mockOperationErrorMapping = JSON.parse(readFileSync(resolve(mockErrorRegistryRoot, "operations-error-mapping.json"), "utf8")) as {
  rules: { universal_codes: string };
  operations: Array<{ operation_id: string; operation_specific: string[] }>;
};
function activeMockErrorDescriptor(code: string): MockErrorDescriptor {
  const matches = mockErrorRegistry.codes.filter((entry) => entry.code === code && entry.status === "active");
  if (matches.length !== 1) throw new Error(`${code} must resolve to one active error registry descriptor`);
  return matches[0];
}
const snapshotUnavailableDescriptor = (() => {
  const descriptor = activeMockErrorDescriptor("realm_state_snapshot_unavailable");
  for (const operationId of snapshotReadOperations) {
    const operations = mockOperationErrorMapping.operations.filter((operation) => operation.operation_id === operationId);
    if (operations.length !== 1 || !operations[0].operation_specific.includes(descriptor.code)) {
      throw new Error(`snapshot unavailable is not registered for ${operationId}`);
    }
  }
  return descriptor;
})();
const streamScanOperationId = "ak.self.committed_event.read.scan.v1";
const streamScanCapabilityDeniedDescriptor = (() => {
  const descriptor = activeMockErrorDescriptor("capability_denied");
  const operations = mockOperationErrorMapping.operations.filter((operation) => operation.operation_id === streamScanOperationId);
  const universalCodes: string[] = mockOperationErrorMapping.rules.universal_codes.match(/[a-z][a-z0-9_]+/g) ?? [];
  if (operations.length !== 1 || !universalCodes.includes(descriptor.code)) {
    throw new Error(`stream scan capability denial is not registered for ${streamScanOperationId}`);
  }
  return descriptor;
})();
const currentPrincipalServiceResolution = inksonWire<Record<string, any>>(
  "service-resolution",
  {},
);
export const CURRENT_STATION_ID = String(currentPrincipalServiceResolution.service_id);
export const CURRENT_STATION_DID = String(currentPrincipalServiceResolution.normalized_did_document.did);
const currentDirectoryServiceResolution = inksonWire<Record<string, any>>(
  "service-resolution",
  { service_kind: "directory_service" },
);
const currentDirectoryDid = String(currentDirectoryServiceResolution.normalized_did_document.did);
const currentDirectoryDocument = inksonWire<Record<string, unknown>>(
  "service-document",
  { service_kind: "directory_service" },
);
type NativeRealmFixture = {
  snapshot: Record<string, any>;
  committed_events: Array<{ commit: Record<string, any>; event: Record<string, any> }>;
  signer_facts: Array<Record<string, any>>;
  source_create: Record<string, any>;
  source_authorization: Record<string, any>;
  identity: { did: string; account_id: { principal_id: string; station_id: string }; principal_control_realm_id: string; document: Record<string, any>; inception_log_entry: Record<string, any>; resolution: Record<string, any> };
  invite_recipient?: { identity: NativeRealmFixture["identity"]; source_create: Record<string, any>; source_authorization: Record<string, any> };
  account_entry: Record<string, any>;
  ids: Record<string, string>;
  public_blobs?: Record<string, string>;
  notification_deltas?: Array<Record<string, unknown>>;
  managed_agent: {
    did: string;
    account_id: { principal_id: string; station_id: string };
    principal_control_realm_id: string;
    controller_authorization_ref: string;
    requested_scope: Record<string, any>;
    inception_log_entry: Record<string, any>;
    binding_log_entry: Record<string, any>;
    genesis: { event: Record<string, any>; commit: Record<string, any> };
    runtime_authorization: { event: Record<string, any>; commit: Record<string, any> };
    provision: { event: Record<string, any>; commit: Record<string, any> };
  };
};
const nativeRealm = (
  salt: number, title: string, board = false, empty_board = false,
  encrypted = false, demo_notification = false,
) => inksonWire<NativeRealmFixture>("mock-realm-fixture", {
  salt, title, board, empty_board, encrypted, demo_notification,
});
const DEMO_REALM_FIXTURE = nativeRealm(9, "Arkret Demo Realm", true);
const INVITED_NATIVE_FIXTURE = inksonWire<NativeRealmFixture>("mock-realm-fixture", {
  salt: 10, title: "Invited Realm", directed_invite: true,
});
export const DEMO_INVITE_ID = INVITED_NATIVE_FIXTURE.ids.invite;
export const BOB_ACCOUNT_ID = INVITED_NATIVE_FIXTURE.identity.account_id;
export const BOB_HELPER_ACCOUNT_ID = INVITED_NATIVE_FIXTURE.managed_agent.account_id;
if (!DEMO_INVITE_ID) throw new Error("directed Invite fixture omits its accepted InviteCreate ID");
const CHILD_REALM_FIXTURE = nativeRealm(11, "Launch Realm");
const GRANDCHILD_REALM_FIXTURE = nativeRealm(12, "Launch Deep Realm");
const LOW_FLOOR_REALM_FIXTURE = nativeRealm(13, "Low floor fixture Realm");
export const CURRENT_PRINCIPAL_DID = DEMO_REALM_FIXTURE.identity.did;
export const CURRENT_PRINCIPAL_CORE_ID = DEMO_REALM_FIXTURE.identity.account_id.principal_id;
export const CURRENT_ACCOUNT_ID = DEMO_REALM_FIXTURE.identity.account_id;
export const CURRENT_ACCOUNT_ACTOR_ID = { kind: "account", account_id: CURRENT_ACCOUNT_ID };
export const CURRENT_ACCOUNT_RESOLUTION = DEMO_REALM_FIXTURE.identity.resolution;
export const CURRENT_ASSISTANT_DID = DEMO_REALM_FIXTURE.managed_agent.did;
export const CURRENT_ASSISTANT_CORE_ID = DEMO_REALM_FIXTURE.managed_agent.account_id.principal_id;
export const CURRENT_ASSISTANT_ACCOUNT_ID = DEMO_REALM_FIXTURE.managed_agent.account_id;
export const CURRENT_ASSISTANT_PCR = DEMO_REALM_FIXTURE.managed_agent.principal_control_realm_id;
export const PRINCIPAL_CONTROL_REALM = DEMO_REALM_FIXTURE.identity.principal_control_realm_id;
export const DEMO_REALM = String(DEMO_REALM_FIXTURE.snapshot.realm_id);
export const INVITED_REALM = String(INVITED_NATIVE_FIXTURE.snapshot.realm_id);
export const DEMO_PARENT_MEMBERSHIP_REVISION = DEMO_REALM_FIXTURE.snapshot.current_state_entries.find(
  (row: any) => row.selector.kind === "member_state" &&
    canonicalJson(row.selector.actor_id) === canonicalJson(CURRENT_ACCOUNT_ACTOR_ID),
)!.revision;
const CHILD_REALM = String(CHILD_REALM_FIXTURE.snapshot.realm_id);
const GRANDCHILD_REALM = String(GRANDCHILD_REALM_FIXTURE.snapshot.realm_id);
const LOW_FLOOR_REALM = String(LOW_FLOOR_REALM_FIXTURE.snapshot.realm_id);
export const DEMO_BOARD_SPACE = DEMO_REALM_FIXTURE.ids.board;
const DEMO_SECOND_BOARD_SPACE = DEMO_REALM_FIXTURE.ids.second_board;
const DEMO_TODO_LIST = DEMO_REALM_FIXTURE.ids.todo;
const DEMO_PROGRESS_LIST = DEMO_REALM_FIXTURE.ids.progress;
const DEMO_DONE_LIST = DEMO_REALM_FIXTURE.ids.done;
const DEMO_SECOND_LIST = DEMO_REALM_FIXTURE.ids.second_list;
const DEMO_STRAND_LEGAL_REVIEW = DEMO_REALM_FIXTURE.ids.review;
const DEMO_STRAND_ONBOARDING_COPY = DEMO_REALM_FIXTURE.ids.scope;
const DEMO_STRAND_SECURITY_SIGNOFF = DEMO_REALM_FIXTURE.ids.security;
const DEMO_STRAND_SECONDARY_CARD = DEMO_REALM_FIXTURE.ids.secondary;
const INVITED_REALM_FIXTURE: RealmGenesisFixture = { realm_id: String(INVITED_NATIVE_FIXTURE.snapshot.realm_id), accepted_events: INVITED_NATIVE_FIXTURE.committed_events.map(full => full.event) };


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

export function inksonWire<T>(command: InksonWireCommand, input: unknown): T {
  const binary = process.env.INKSON_WIRE_BIN;
  const result = spawnSync(
    binary ?? "cargo",
    binary
      ? [command]
      : [
          "run",
          "--quiet",
          "--profile",
          "joint-e2e",
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

function validateMockResponse(route: Route, status: number, value?: unknown, contentType = "application/json") {
  const request = route.request();
  const method = request.method().toUpperCase();
  const pathname = new URL(request.url()).pathname;
  if (!pathname.startsWith("/_arkret/")) {
    return;
  }
  const pathMatches = mockOperationInventory.filter(
    (operation) =>
      operation.method === method && operation.pathPattern.test(pathname),
  );
  // OpenAPI literal paths take precedence over a parameterized sibling path.
  const literalMatches = pathMatches.filter(
    (operation) => operation.path_template === pathname,
  );
  const matches = literalMatches.length > 0 ? literalMatches : pathMatches;
  if (matches.length !== 1) {
    throw new Error(
      `mock route ${method} ${pathname} resolves to ${matches.length} embedded OpenAPI operations`,
    );
  }
  validateMockResponseForOperation(matches[0], status, value, contentType);
}

export function validateMockResponseForOperation(
  operation: MockOperationInventoryRow,
  status: number,
  value?: unknown,
  contentType = "application/json",
) {
  // OpenAPI lists the success shapes. These exact registered failures
  // come from the global HTTP Problem contract and its operation error map.
  // No other operation or undeclared status receives an error-response bypass.
  if (snapshotReadOperations.has(operation.operation_id) && status === snapshotUnavailableDescriptor.http_status) {
    validateClosedMockProblem(snapshotUnavailableDescriptor, status, value, contentType);
    return;
  }
  if (operation.operation_id === streamScanOperationId && status === streamScanCapabilityDeniedDescriptor.http_status) {
    validateClosedMockProblem(streamScanCapabilityDeniedDescriptor, status, value, contentType);
    return;
  }
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

function validateClosedMockProblem(descriptor: MockErrorDescriptor, status: number, value: unknown, contentType: string) {
  if (contentType !== "application/problem+json") {
    throw new Error(`${descriptor.code} requires application/problem+json`);
  }
  validateMockSchema("schemas/http-problem-details.schema.json", value);
  const problem = value as Record<string, unknown>;
  if (status !== descriptor.http_status || problem.status !== status || problem.type !== descriptor.type_uri || problem.title !== descriptor.title) {
    throw new Error(`${descriptor.code} status/type/title do not match the error registry`);
  }
  // RFC consumers tolerate unknown extensions. These producers emit only the
  // standard members of their minimal responses.
  const members = new Set(["type", "title", "status", "detail", "instance"]);
  if (Object.keys(problem).some((member) => !members.has(member))) {
    throw new Error(`${descriptor.code} producer forbids extension members`);
  }
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

export function validateMockSchema(schemaRef: string, value: unknown) {
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
  if (value.startsWith("did:webvh:")) return `ak:did_core:webvh:${value.split(":")[2]}`;
  return value.startsWith("ak:did_core:")
    ? value
    : `ak:did_core:${value.replace(/^did:/, "")}`;
}

function didFromCoreId(value: string): string {
  if (value === CURRENT_ASSISTANT_CORE_ID) return CURRENT_ASSISTANT_DID;
  if (value === CURRENT_PRINCIPAL_CORE_ID) return CURRENT_PRINCIPAL_DID;
  if (value === CURRENT_STATION_ID) return CURRENT_STATION_DID;
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
    options.accountPrincipalId ?? CURRENT_PRINCIPAL_DID;
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
    kind: "account" as const,
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

  // Request fixtures use the SDK's exact unsigned Event and source receipt.
  // Other ceremonies need bilateral round material and remain terminal failures.
  const contactReservations = new Map<string, {
    prepareBytes: string;
    idempotencyKey: unknown;
    prepared: Record<string, any>;
    commitBytes?: string;
    terminal?: Record<string, any>;
  }>();
  const outgoingContactRows: Record<string, any>[] = [];
  const contactOutcome = (
    resultKind: "request" | "response" | "reject" | "scope_update" | "tombstone",
    body: Record<string, unknown>,
  ) => {
    const operationId =
      typeof body.operation_id === "string"
        ? body.operation_id
        : "ak:operation:01964137-0000-7000-8000-0000000000f2";
    const failed = (reason = "contact_round_conflict") => ({
        status: "failed",
        result_kind: resultKind,
        operation_id: operationId,
        reason,
    });
    if (resultKind !== "request") return failed();
    const existing = contactReservations.get(operationId);
    if (body.phase === "prepare") {
      const prepareBytes = canonicalJson(body);
      if (existing) {
        return existing.prepareBytes === prepareBytes
          ? existing.prepared : failed("contact_idempotency_conflict");
      }
      if (outgoingContactRows.some(row => canonicalJson(row.peer) === canonicalJson(body.peer))) {
        return failed();
      }
      const prepared = inksonWire<Record<string, any>>("contact-request-prepare", {
        holder: accountId,
        realm_id: PRINCIPAL_CONTROL_REALM,
        body,
      });
      contactReservations.set(operationId, {
        prepareBytes, idempotencyKey: body.idempotency_key, prepared,
      });
      return prepared;
    }
    if (!existing || existing.idempotencyKey !== body.idempotency_key) {
      return failed("contact_idempotency_conflict");
    }
    const commitBytes = canonicalJson(body);
    if (existing.commitBytes) {
      return existing.commitBytes === commitBytes
        ? existing.terminal : failed("contact_idempotency_conflict");
    }
    if (options.contactRequestOutcome === "failed") {
      existing.commitBytes = commitBytes;
      existing.terminal = failed();
      return existing.terminal;
    }
    const key = inksonWire<{ public_key_b64url: string }>("did-key-from-seed", {
      seed_b64url: options.currentDeviceSigningSeedB64url ?? "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
    });
    const committed = inksonWire<{ outcome: Record<string, any>; list_row: Record<string, any> }>("contact-request-commit", {
      prepared: existing.prepared,
      body,
      producer_verification_method: `${didFromCoreId(accountPrincipalCoreId)}#${currentDeviceId}`,
      producer_public_key_b64url: key.public_key_b64url,
    });
    existing.commitBytes = commitBytes;
    existing.terminal = committed.outcome;
    outgoingContactRows.push(committed.list_row);
    if (options.contactRequestOutcome === "tampered") {
      const response = structuredClone(committed.outcome);
      response.request_acceptance_receipt.core.request_event_ref = DEMO_FRONTIER_EVENT;
      existing.terminal = response;
      return response;
    }
    return committed.outcome;
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
  const demoNative = options.encryptedDemoRealm || options.emptyBoard || options.demoNotification
    ? nativeRealm(
        9, "Arkret Demo Realm", true, options.emptyBoard ?? false,
        options.encryptedDemoRealm ?? false, options.demoNotification ?? false,
      )
    : DEMO_REALM_FIXTURE;
  const DEMO_REALM = String(demoNative.snapshot.realm_id);
  const DEMO_BOARD_SPACE = demoNative.ids.board;
  const DEMO_SECOND_BOARD_SPACE = demoNative.ids.second_board;
  const DEMO_TODO_LIST = demoNative.ids.todo;
  const DEMO_PROGRESS_LIST = demoNative.ids.progress;
  const DEMO_DONE_LIST = demoNative.ids.done;
  const DEMO_SECOND_LIST = demoNative.ids.second_list;
  const DEMO_STRAND_LEGAL_REVIEW = demoNative.ids.review;
  const DEMO_STRAND_ONBOARDING_COPY = demoNative.ids.scope;
  const DEMO_STRAND_SECURITY_SIGNOFF = demoNative.ids.security;
  const DEMO_STRAND_SECONDARY_CARD = demoNative.ids.secondary;
  let invitedRealmId = DEMO_REALM;
  const nativeFixtures = new Map<string, NativeRealmFixture>();
  const registerNative = (fixture: NativeRealmFixture) => {
    nativeFixtures.set(String(fixture.snapshot.realm_id), structuredClone(fixture));
    projectionEvents.push(...fixture.committed_events.map(full => structuredClone(full.event)));
  };
  if (includeDemoRealms) {
    for (const fixture of [demoNative, CHILD_REALM_FIXTURE, GRANDCHILD_REALM_FIXTURE]) registerNative(fixture);
  }
  if (includeLowFloorRealm) registerNative(LOW_FLOOR_REALM_FIXTURE);
  if (options.invitePreview !== undefined) {
    registerNative(INVITED_NATIVE_FIXTURE);
    invitedRealmId = String(INVITED_NATIVE_FIXTURE.snapshot.realm_id);
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
  const circleMembers = new Map<string, Record<string, unknown>[]>([
    [DEMO_CIRCLE, [accountActorId]],
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
      ?.some(member => canonicalJson(member) === canonicalJson(accountActorId))
      ? "join"
      : undefined,
    member_ids: circleMembers.get(circleId) ?? [],
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
          trust_domain: "ak:trust_domain:coland.local",
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
  const activeAssistantId = demoNative.managed_agent.account_id.principal_id;
  const activeAssistantKeyState = {
    agent_id: activeAssistantId,
    controller_account_id: accountId,
    principal_control_realm_id: demoNative.managed_agent.principal_control_realm_id,
    controller_authorization_ref: demoNative.managed_agent.controller_authorization_ref,
    requested_scope: demoNative.managed_agent.requested_scope,
    authorized_event_ref: demoNative.managed_agent.runtime_authorization.event.event_id,
    active_authorizations: [
      {
        key_id: demoNative.managed_agent.runtime_authorization.event.payload.key_id,
        verification_method: demoNative.managed_agent.runtime_authorization.event.payload.verification_method,
        authorized_event_ref: demoNative.managed_agent.runtime_authorization.event.event_id,
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
      created_at: demoNative.managed_agent.genesis.event.created_at,
      updated_at: demoNative.managed_agent.runtime_authorization.event.created_at,
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
  const eventRealmId = (event: Record<string, unknown>) => {
    const explicitRealm = event.realm_id ??
      (event.scope_ref as Record<string, unknown> | undefined)?.realm_id;
    if (explicitRealm !== undefined) {
      return String(explicitRealm);
    }
    // Root-scoped RealmCreate obtains its Realm from the exact native Commit.
    for (const fixture of nativeFixtures.values()) {
      const full = fixture.committed_events.find(
        (full) => full.event.event_id === event.event_id,
      );
      if (full) {
        return String(full.commit.realm_id);
      }
    }
    throw new Error(`no exact SDK fixture Realm for ${String(event.event_id)}`);
  };
  const committedEventView = (
    event: Record<string, unknown>,
    streamPosition: number,
  ) => {
    const fixture = nativeFixtures.get(eventRealmId(event));
    const full = fixture?.committed_events.find(full => full.event.event_id === event.event_id);
    if (!full || canonicalJson(full.event) !== canonicalJson(event)) {
      throw new Error(`no exact SDK fixture Commit for ${String(event.event_id)} at ${streamPosition}`);
    }
    return full;
  };
  const inviteDeliveryContent = options.invitePreview === undefined
    ? null
    : {
        schema: "ak.schema.invite_delivery.v1",
        updated_at: "2026-09-27T00:00:00.000Z",
        delivery_entries: [
          {
            invite_id: DEMO_INVITE_ID,
            realm_id: invitedRealmId,
            inviter_account_id: INVITED_NATIVE_FIXTURE.identity.account_id,
            authority_locator_hints: [
              {
                service_kind: "station",
                service_id: CURRENT_STATION_ID,
                source: "invite",
              },
            ],
            received_at: "2026-09-27T00:00:00.000Z",
            expires_at: "2099-09-27T00:00:00.000Z",
          },
        ],
      };
  const inviteAuthorityBundle = () => {
    const fixture = nativeFixtures.get(invitedRealmId);
    if (!fixture) throw new Error("invite preview has no accepted native authority source");
    return inksonWire<Record<string, any>>("mock-realm-authority-bundle", fixture);
  };
  const nativeReadable = (fixture: NativeRealmFixture) =>
    !fixture.invite_recipient || fixture.snapshot.current_state_entries.some(
      (row: Record<string, any>) => row.selector?.kind === "member_state"
        && canonicalJson(row.selector.actor_id) === canonicalJson(CURRENT_ACCOUNT_ACTOR_ID)
        && row.value?.membership === "join",
    );
  let invitePreviewAttempts = 0;
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
    if (url.hostname === "directory.example" && url.pathname === "/.well-known/did.json") {
      return route.fulfill({ status: 200, contentType: "application/did+json", body: canonicalJson(currentDirectoryDocument) });
    }
    if (url.hostname === "alice.example" && url.pathname === "/webvh/alice/did.json") {
      return route.fulfill({ status: 200, contentType: "application/did+json", body: canonicalJson(DEMO_REALM_FIXTURE.identity.document) });
    }
    if (url.hostname === "alice.example" && url.pathname === "/webvh/alice/did.jsonl") {
      return route.fulfill({ status: 200, contentType: "application/jsonl", body: canonicalJson(DEMO_REALM_FIXTURE.identity.inception_log_entry) + "\n" });
    }
    if (url.hostname === "bob.example" && url.pathname === "/webvh/bob/did.json") {
      return route.fulfill({ status: 200, contentType: "application/did+json", body: canonicalJson(INVITED_NATIVE_FIXTURE.identity.document) });
    }
    if (url.hostname === "bob.example" && url.pathname === "/webvh/bob/did.jsonl") {
      return route.fulfill({ status: 200, contentType: "application/jsonl", body: canonicalJson(INVITED_NATIVE_FIXTURE.identity.inception_log_entry) + "\n" });
    }
    if (url.hostname === "agents.example" && url.pathname === "/webvh/helper/did.json") {
      return route.fulfill({ status: 200, contentType: "application/did+json", body: canonicalJson(INVITED_NATIVE_FIXTURE.managed_agent.binding_log_entry.state) });
    }
    if (url.hostname === "agents.example" && url.pathname === "/webvh/helper/did.jsonl") {
      const entries = [INVITED_NATIVE_FIXTURE.managed_agent.inception_log_entry, INVITED_NATIVE_FIXTURE.managed_agent.binding_log_entry];
      return route.fulfill({ status: 200, contentType: "application/jsonl", body: entries.map(canonicalJson).join("\n") + "\n" });
    }
    if (url.hostname === "agents.example" && url.pathname === "/webvh/assistant/did.json") {
      return route.fulfill({ status: 200, contentType: "application/did+json", body: canonicalJson(demoNative.managed_agent.binding_log_entry.state) });
    }
    if (url.hostname === "agents.example" && url.pathname === "/webvh/assistant/did.jsonl") {
      const entries = [demoNative.managed_agent.inception_log_entry, demoNative.managed_agent.binding_log_entry];
      return route.fulfill({ status: 200, contentType: "application/jsonl", body: entries.map(canonicalJson).join("\n") + "\n" });
    }
    if (!url.pathname.startsWith("/_arkret/")) {
      return route.continue();
    }
    if (
      url.pathname === "/_arkret/describe" &&
      route.request().method() === "GET"
    ) {
      if (url.searchParams.get("service_kind") === "directory_service") {
        return json(route, directoryServiceDescribe());
      }
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
      return json(route, principalServiceDescribe(`${url.origin}/`));
    }

    if (
      url.pathname.startsWith("/_arkret/self/realms/") &&
      url.pathname.endsWith("/spaces") &&
      route.request().method() === "GET"
    ) {
      const realmId = decodeURIComponent(url.pathname.split("/")[4] ?? DEMO_REALM);
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
      const realmId = decodeURIComponent(url.pathname.split("/")[4] ?? DEMO_REALM);
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
      const request = route.request().postDataJSON();
      validateMockSchema("schemas/circle-operations.schema.json#/$defs/circle_member_request_body", request);
      const event = request.member_event.event;
      const { member_id: memberId, membership } = event.payload;
      expect(event.kind).toBe("ak.circle.member.state");
      expect(event.scope_ref).toEqual({ kind: "circle", realm_id: DEMO_REALM, circle_id: circleId });
      expect(event.payload.circle_id).toBe(circleId);
      const members = new Map((circleMembers.get(circleId) ?? []).map(member => [canonicalJson(member), member]));
      if (membership === "join") {
        members.set(canonicalJson(memberId), memberId);
      } else if (membership === "leave" || membership === "ban") {
        members.delete(canonicalJson(memberId));
      }
      circleMembers.set(circleId, [...members.values()]);
      return json(route, { circle_id: circleId, member_id: memberId, membership });
    }

    const circleMemberResource = url.pathname.match(
      /^\/_arkret\/self\/circles\/([^/]+)\/members\/(.+)$/,
    );
    if (circleMemberResource && route.request().method() === "DELETE") {
      const [, circleId] = circleMemberResource;
      const request = route.request().postDataJSON();
      validateMockSchema("schemas/circle-operations.schema.json#/$defs/circle_member_delete_request_body", request);
      const event = request.member_event.event;
      const memberId = event.payload.member_id;
      expect(event.kind).toBe("ak.circle.member.state");
      expect(event.payload.circle_id).toBe(circleId);
      expect(event.payload.membership).toBe("leave");
      const members = new Map((circleMembers.get(circleId) ?? []).map(member => [canonicalJson(member), member]));
      members.delete(canonicalJson(memberId));
      circleMembers.set(circleId, [...members.values()]);
      return json(route, { circle_id: circleId, member_id: memberId, membership: "leave" });
    }

    if (
      url.pathname === "/_arkret/self/events" &&
      route.request().method() === "POST"
    ) {
      const body = await route.request().postDataJSON();
      let syncToken = "sx:e2e:event";
      const submittedEntries = Array.isArray(body.events)
        ? body.events
        : [body];
      const submittedEvents = submittedEntries.map(
        (entry: Record<string, any>) => entry.event ?? entry,
      );
      const explicitRealm = submittedEvents.map((event: Record<string, any>) => event.realm_id)
        .find((realm: unknown) => typeof realm === "string");
      const existingCommit = Array.from(nativeFixtures.values()).flatMap(fixture => fixture.committed_events)
        .find(full => full.event.event_id === submittedEvents[0]?.event_id);
      const requestedRealm = explicitRealm ?? existingCommit?.commit.realm_id;
      const accepted = inksonWire<{ fixture: NativeRealmFixture; outcome: Record<string, any> }>("mock-realm-submit", {
        fixture: requestedRealm ? nativeFixtures.get(String(requestedRealm)) ?? null : null,
        request: body,
        seed_b64url: options.currentDeviceSigningSeedB64url ?? "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        device_id: currentDeviceId,
      });
      const realmId = String(accepted.fixture.snapshot.realm_id);
      if ((requestedRealm !== undefined && String(requestedRealm) !== realmId)
        || accepted.fixture.committed_events.some(full => full.commit.realm_id !== realmId
          || full.commit.stream_ref.realm_id !== realmId)) {
        throw new Error("native accepted fixture has inconsistent Realm/stream bindings");
      }
      nativeFixtures.set(realmId, accepted.fixture);
      for (const full of accepted.fixture.committed_events) {
        if (!projectionEvents.some(event => event.event_id === full.event.event_id)) projectionEvents.push(full.event);
      }
      for (const event of submittedEvents) {
        if (event.kind === "ak.invite.accept") {
          expect(event.payload.invite_id).toBe(DEMO_INVITE_ID);
          expect(event.actor_id).toEqual(CURRENT_ACCOUNT_ACTOR_ID);
          expect(nativeReadable(accepted.fixture)).toBe(true);
          const profile = accepted.fixture.snapshot.current_state_entries.find(
            (row: Record<string, any>) => row.selector.kind === "realm_profile",
          )?.value;
          if (!createdRealms.some(realm => realm.id === realmId)) {
            createdRealms.push({ id: realmId, title: profile?.title ?? "Invited Realm",
              summary: profile?.summary ?? "", encryption_profile: "none" });
          }
          continue;
        }
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
      return json(route, accepted.outcome);
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
          principal_id: CURRENT_PRINCIPAL_CORE_ID,
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
      const catchup = url.searchParams.get("catchup") === "true";
      if (url.searchParams.has("after")) {
        await new Promise((resolve) => setTimeout(resolve, 5_000));
        const frames = [
          { kind: "delta", cursor: "ak:cursor:e2e-2" },
          ...(catchup ? [{ kind: "catchup_complete", cursor: "ak:cursor:e2e-2" }] : []),
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
                        actor_id: { kind: "account", account_id: demoNative.managed_agent.account_id },
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
          deliveries: [],
        },
        account_data: {
          events: [],
          ...(inviteDeliveryContent ? { station_cas: { upserts: [{
            account_data_key: "ak.account.invite_delivery", revision: 1,
            content: inviteDeliveryContent, updated_at: inviteDeliveryContent.updated_at,
          }], removals: [] } } : {}),
        },
        device_lists: { changed_ids: [], left_ids: [] },
        notifications: {
          // The SDK fixture supplies closed deltas and their actual accepted
          // source binding; do not reconstruct protocol fields in this mock.
          items: includeDemoRealms && options.demoNotification
            ? structuredClone(demoNative.notification_deltas ?? [])
            : [],
        },
      };
      for (const [realmId, entry] of Object.entries(frame.realms)) {
        const fixture = nativeFixtures.get(realmId);
        if (fixture) Object.assign(entry, structuredClone(fixture.account_entry));
      }
      const frames = [
        frame,
        ...(catchup ? [{ kind: "catchup_complete", cursor: "ak:cursor:e2e-2" }] : []),
      ];
      frames.forEach((value) =>
        validateMockSchema("schemas/account-subscribe-frame.schema.json", value),
      );
      return route.fulfill({
        status: 200,
        contentType: "application/x-ndjson",
        body: `${frames.map(canonicalJson).join("\n")}\n`,
      });
    }

    if (
      url.pathname === "/_arkret/self/realm-joins/preview" &&
      route.request().method() === "POST" &&
      options.invitePreview !== undefined
    ) {
      const body = await route.request().postDataJSON();
      expect(body.target.realm_id).toBe(invitedRealmId);
      expect(body.target.invite_id).toBe(DEMO_INVITE_ID);
      invitePreviewAttempts += 1;
      if ((options.invitePreviewDelayMs ?? 0) > 0) {
        await new Promise((resolve) =>
          setTimeout(resolve, options.invitePreviewDelayMs),
        );
      }
      if (options.invitePreview === "restricted") {
        return route.fulfill({ status: 404 });
      }
      if (options.invitePreview === "retry_once" && invitePreviewAttempts === 1) {
        return route.fulfill({ status: 503 });
      }
      return json(route, {
        request_id: body.request_id,
        authority_bundle: inviteAuthorityBundle(),
        preview: {
          realm_id: invitedRealmId,
          join_rule: "invite",
          history_access: "all_history_for_current_members",
          governance_generation: 0,
          display_name: "Preview-only Realm",
        },
      });
    }

    if (
      url.pathname === "/_arkret/self/realm-joins/prepare" &&
      route.request().method() === "POST" &&
      options.invitePreview !== undefined
    ) {
      const body = await route.request().postDataJSON();
      expect(body.target.realm_id).toBe(invitedRealmId);
      expect(body.target.invite_id).toBe(DEMO_INVITE_ID);
      const authorityBundle = inviteAuthorityBundle();
      return json(route, {
        request_id: body.request_id,
        authority_bundle: authorityBundle,
        realm_stream_head: authorityBundle.realm_stream_head,
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
        .filter((event) => {
          const realmId = eventRealmId(event);
          const fixture = nativeFixtures.get(realmId);
          if (!fixture) throw new Error(`committed subscription has no registered native source for ${realmId}`);
          return nativeReadable(fixture) &&
            (requestedRealms.length === 0 || requestedRealms.includes(realmId));
        })
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
      const fixture = nativeFixtures.get(requestedRealm);
      if (!fixture || !nativeReadable(fixture)) return json(route, {
        type: streamScanCapabilityDeniedDescriptor.type_uri,
        title: streamScanCapabilityDeniedDescriptor.title,
        status: streamScanCapabilityDeniedDescriptor.http_status,
        detail: "The requested stream is not readable by this fixture caller.",
      }, streamScanCapabilityDeniedDescriptor.http_status, "application/problem+json");
      return json(route, inksonWire("mock-realm-scan", { fixture, request: requestBody }));
    }

    // invite-addressing.md §7 — before dispatching private invite delivery the
    // client MUST read the accepted Event back through
    // `ak.self.committed_event.read.scan.v1` (`POST /_arkret/self/streams/scan`)
    // rather than re-authoring an equivalent one, because only the server's own
    // view is guaranteed byte-identical to the persisted canonical bytes. The
    // mock therefore serves back exactly what it accepted on POST
    // /_arkret/self/events.
    const committedEventMatch = url.pathname.match(
      /^\/_arkret\/self\/committed-events\/([^/]+)$/,
    );
    if (committedEventMatch && route.request().method() === "GET") {
      const requestedEventId = decodeURIComponent(committedEventMatch[1]);
      // Recovery authority reads the exact founding PCR unit, separately from
      // the collaboration Realm's committed stream and Account baseline.
      for (const fixture of [demoNative, INVITED_NATIVE_FIXTURE, ...nativeFixtures.values()]) {
        const source = [fixture.source_create, fixture.source_authorization,
          fixture.invite_recipient?.source_create, fixture.invite_recipient?.source_authorization,
          fixture.managed_agent.genesis, fixture.managed_agent.runtime_authorization,
          fixture.managed_agent.provision,
        ].filter((full): full is Record<string, any> => full !== undefined).find(
          full => full.event.event_id === requestedEventId,
        );
        if (source) return json(route, source);
      }
      const index = projectionEvents.findIndex(
        (event) => event.event_id === requestedEventId,
      );
      if (index < 0) {
        throw new Error(`native committed Event resource has no exact accepted source for ${requestedEventId}`);
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

    if (url.pathname === "/_arkret/self/current-results/exact" && route.request().method() === "POST") {
      const request = route.request().postDataJSON();
      const fixture = nativeFixtures.get(String(request.realm_id));
      if (!fixture || !nativeReadable(fixture)) throw new Error("exact current request has no readable native Realm");
      return json(route, inksonWire("mock-exact-current", { fixture, request }));
    }

    if (url.pathname === "/_arkret/self/realm-state-snapshot/head" && route.request().method() === "GET") {
      const fixture = nativeFixtures.get(url.searchParams.get("realm_id") ?? "");
      return fixture && nativeReadable(fixture) ? json(route, fixture.snapshot) : snapshotUnavailable(route);
    }
    if (/^\/_arkret\/self\/realm-state-snapshot\/[^/]+$/.test(url.pathname) && route.request().method() === "GET") {
      const fixture = nativeFixtures.get(url.searchParams.get("realm_id") ?? "");
      return fixture && nativeReadable(fixture) && fixture.snapshot.snapshot_id === decodeURIComponent(url.pathname.split("/").at(-1) ?? "") ? json(route, fixture.snapshot) : snapshotUnavailable(route);
    }
    if (url.pathname === "/_arkret/self/signer-keys/query" && route.request().method() === "POST") {
      const request = await route.request().postDataJSON();
      const fixture = nativeFixtures.get(request.realm_id);
      return fixture && nativeReadable(fixture) ? json(route, inksonWire("mock-realm-signer-keys", { fixture, request })) : json(route, { error: { code: "not_found" } }, 404);
    }
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

    if (url.pathname === "/_arkret/self/account/current-principal" && route.request().method() === "POST") {
      const request = await route.request().postDataJSON();
      return json(route, inksonWire("mock-current-principal", { fixture: DEMO_REALM_FIXTURE, request }));
    }
    if (
      url.pathname === "/_arkret/self/account/describe" &&
      route.request().method() === "GET"
    ) {
      return json(route, principalServiceDescribe(`${url.origin}/`));
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
          ...outgoingContactRows,
          {
            peer: {
              kind: "human",
              account_id: BOB_ACCOUNT_ID,
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
                actor_id: { kind: "account", account_id: BOB_HELPER_ACCOUNT_ID },
                controller_account_id: BOB_ACCOUNT_ID,
                display_name: "Bob Helper",
                agent_slug: "helper",
                avatar_blob_ref: DEMO_BLOB_REF,
                direct_conversation: {
                  realm_id: DIRECT_BOB_HELPER_REALM,
                  main_strand_id: DIRECT_BOB_HELPER_STRAND,
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

    // Request prepare/sign/commit retains the original reservation and receipt.
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

    if ((url.pathname === "/_arkret/self/contacts/reject" ||
         url.pathname === "/_arkret/self/contacts/scope-update") &&
        route.request().method() === "POST") {
      const body = ((await contractRequestBody(route)) ?? {}) as Record<string, unknown>;
      return json(route, contactOutcome(
        url.pathname.endsWith("/reject") ? "reject" : "scope_update", body));
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
      // The real coland handler echoes the stored policy back verbatim;
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
        // Invite-preview cases start with an already delivered holder-private
        // entry under an explicit notify policy; dispatch admission is separate.
        explicit_address_behavior: options.invitePreview !== undefined ? "notify" : "quarantine",
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
      const peer = body.peer as {
        kind: "human" | "agent";
        account_id?: Record<string, string>;
        actor_id?: Record<string, unknown>;
        controller_account_id?: Record<string, string>;
      };
      const ownedAgent = peer.kind === "agent" &&
        canonicalJson(peer.actor_id) === canonicalJson({
          kind: "account", account_id: CURRENT_ASSISTANT_ACCOUNT_ID,
        });
      const foreignAgent = peer.kind === "agent" &&
        canonicalJson(peer.actor_id) === canonicalJson({
          kind: "account", account_id: BOB_HELPER_ACCOUNT_ID,
        });
      if (ownedAgent) expect(peer).toEqual({
        kind: "agent", actor_id: { kind: "account", account_id: CURRENT_ASSISTANT_ACCOUNT_ID },
        controller_account_id: CURRENT_ACCOUNT_ID,
      });
      else if (foreignAgent) expect(peer).toEqual({
        kind: "agent", actor_id: { kind: "account", account_id: BOB_HELPER_ACCOUNT_ID },
        controller_account_id: BOB_ACCOUNT_ID,
      });
      else expect(peer).toEqual({ kind: "human", account_id: BOB_ACCOUNT_ID });
      const pairKey = inksonWire<{ pair_key: string }>("direct-conversation-pair-key", {
        trust_domain: "ak:trust_domain:server.local",
        holder: CURRENT_ACCOUNT_ID,
        body,
      }).pair_key;
      return json(route, {
        state: "found",
        coordinates: {
          pair_key: pairKey,
          realm_id: ownedAgent ? DIRECT_OWN_AGENT_REALM
            : foreignAgent ? DIRECT_BOB_HELPER_REALM : DIRECT_BOB_REALM,
          main_strand_id: ownedAgent ? DIRECT_OWN_AGENT_STRAND
            : foreignAgent ? DIRECT_BOB_HELPER_STRAND : DIRECT_BOB_STRAND,
          binding_event_ref: ownedAgent
            ? "ak:event:AUsIM7jMWF-QEkZ3Fd8dVqgxiIcM5iASgTtudL5PCcGL"
            : foreignAgent ? "ak:event:ARhOgV4T1qZleEVITbO4iNd_ggoy771-VwFQBRHzRm4x"
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
              // The self face carries the Station-verified projection. The
              // origin attestation and its proof stay on the peer face and
              // never reach a client.
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
      // Structural UI fixture, not a substitute for Station admission or
      // signature verification. The real service accepts one lifecycle Event;
      // subordinate authorization cleanup is not client-authored input.
      validateMockSchema(
        "schemas/agent-operations.schema.json#/$defs/agent_deactivate_request_body",
        body,
      );
      expect(event?.scope_ref).toEqual({
        kind: "realm",
        realm_id: keyState.principal_control_realm_id,
      });
      expect(event?.realm_id).toBe(keyState.principal_control_realm_id);
      expect(event?.actor_id).toEqual(accountActorIdFor(agentId));
      expect(event?.executed_by).toEqual(accountActorId);
      expect(event?.authorization_ref).toBe(keyState.controller_authorization_ref);
      const proof = event?.producer_proof;
      expect(proof?.kind).toBe("detached_jws");
      expect(proof?.verification_method).toBe(
        `${didFromCoreId(accountPrincipalCoreId)}#${currentDeviceId}`,
      );
      expect(proof?.event_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
      const [protectedHeader, detachedPayload, signature] = proof.jws.split(".");
      expect(JSON.parse(Buffer.from(protectedHeader, "base64url").toString())).toEqual({
        alg: "Ed25519",
      });
      expect(detachedPayload).toBe("");
      expect(Buffer.from(signature, "base64url")).toHaveLength(64);
      expect(event?.payload?.previous_status).toBe(agent.lifecycle);
      expect(event?.payload?.transition).toBe("deactivate");
      expect(event?.payload?.reason).toBe(body.reason);
      agent.lifecycle = "deactivated";
      agent.updated_at = "2026-07-19T08:00:00.000Z";
      keyState.active_authorizations = [];
      personalAgentGrants.set(agentId, []);
      return json(route, { status: "deactivated" });
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
      const keyState: Record<string, unknown> = {
        ...(personalAgentKeyStates.get(agentId) ?? {}),
        pairing_request_id: `pair-renew-${personalAgentCounter}`,
        pairing_code: "13579100",
        pairing_expires_at: renewedExpiresAt,
      };
      const controllerAccount = keyState.controller_account_id;
      if (
        typeof controllerAccount !== "object" || controllerAccount === null ||
        !("principal_id" in controllerAccount) ||
        typeof controllerAccount.principal_id !== "string"
      ) {
        throw new Error("Agent key renewal requires its accepted controller Account");
      }
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
          controller_principal_id: controllerAccount.principal_id,
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
      const savedKeyState = personalAgentKeyStates.get(agentId);
      const storedKeyState =
        agentId === activeAssistantId && options.assistantKeyBinding === "missing"
          ? undefined
          : agentId === activeAssistantId &&
              options.assistantKeyBinding === "mismatched" && savedKeyState
            ? { ...savedKeyState, agent_id: "ak:did_core:web:agents.example:other" }
            : savedKeyState;
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
        deliveries: [],
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
      const reference = url.searchParams.get("blob_ref");
      const encoded = reference ? demoNative.public_blobs?.[reference] : undefined;
      if (encoded) {
        return route.fulfill({ status: 200, contentType: "application/octet-stream", body: Buffer.from(encoded, "base64url") });
      }
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
          trust_domain: policy.trust_domain ?? "ak:trust_domain:coland.local",
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
      const accountDataKey = decodeURIComponent(accountDataMatch[1]);
      return json(route, {
        account_data_key: accountDataKey,
        revision: accountDataKey === "ak.account.invite_delivery" && inviteDeliveryContent ? 1 : 0,
        content:
          accountDataKey === "ak.account.invite_delivery"
            ? inviteDeliveryContent
            : null,
        updated_at: accountDataKey === "ak.account.invite_delivery" && inviteDeliveryContent
          ? inviteDeliveryContent.updated_at : "2026-04-28T12:00:00.000Z",
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
      if (decodeURIComponent(url.pathname.split("/")[4]) === currentDirectoryServiceResolution.service_id) {
        return json(route, currentDirectoryServiceResolution);
      }
      return json(route, inksonWire("service-resolution", {}));
    }

    return route.fulfill({ status: 404 });
  });
  return { demoRealm: DEMO_REALM, demoBoardSpace: DEMO_BOARD_SPACE };
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
    service_id: currentDirectoryServiceResolution.service_id,
    service_resolution: {
      did: currentDirectoryDid,
      method_history_head: currentDirectoryServiceResolution.method_history_evidence.boundary.to_method_history_head,
      version_id: currentDirectoryServiceResolution.method_history_evidence.boundary.to_version_id,
    },
    trust_domain: "ak:trust_domain:server.local",
    service_kind: "directory_service",
    protocol_version: "1.0",
    supported_profiles: [],
    ...currentHttpDescribeCapabilities(
      [DIRECTORY_DESCRIBE_BUNDLE, DIRECTORY_PUBLIC_READ_BUNDLE],
      "https://directory.example/",
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

function principalServiceDescribe(baseUrl = "https://local.host/") {
  // The local HTTP listener is a proxy for the canonical HTTPS Station.
  // ServiceDescribe advertises the canonical binding, never the proxy ingress.
  const transport = new URL(baseUrl);
  if (transport.protocol === "http:" && transport.port === "8787" &&
    ["127.0.0.1", "localhost", "[::1]"].includes(transport.hostname)) {
    baseUrl = "https://local.host/";
  }
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
    ], baseUrl),
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

function snapshotUnavailable(route: Route) {
  return json(route, {
    type: snapshotUnavailableDescriptor.type_uri,
    title: snapshotUnavailableDescriptor.title,
    status: snapshotUnavailableDescriptor.http_status,
    detail: "The requested snapshot is not available in this fixture.",
  }, snapshotUnavailableDescriptor.http_status, "application/problem+json");
}

function json(route: Route, body: unknown, status = 200, contentType = "application/json") {
  validateMockResponse(route, status, body, contentType);
  return route.fulfill({
    status,
    contentType,
    body: JSON.stringify(body),
  });
}
