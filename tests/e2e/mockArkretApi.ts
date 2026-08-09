import { expect, type Page, type Route } from "@playwright/test";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { mockArkretContract } from "./mockArkretContract";

const DEMO_REALM = "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j";
const STRAND_POSITION_CELL_FAMILY = "ak.component.strand.position.v1";
const DEMO_FRONTIER_EVENT = "ak:event:Ad0EZUHcfLJv92Of4w-RJec6fkNlWP11fsQAQ4dqUOHS";
const SETUP_REALM = "ak:realm:01js0setupflow000000000000";
const LOW_FLOOR_REALM = "ak:realm:01lowfloor0000000000000000";
const CHILD_REALM = "ak:realm:AajANEG2ah2GJghhdat8rziaz1qjK25iQAYUUR6kcIeW";
const GRANDCHILD_REALM = "ak:realm:AY4xhb3ZNeBXAhtM2T1YS3-9sqDdRdVeL3cVRBQ9LTAt";
const DIRECT_BOB_REALM = "ak:realm:AUEAoXMJeJWBETvkqm7gk4imduk7g-l8bim19OPFQDaO";
const DIRECT_BOB_STRAND = "ak:strand:Ae9PN2rTd0Dojs9yS8iLnfheJtjSEZ3mgDDyONpztHUd";
const DIRECT_OWN_AGENT_REALM = "ak:realm:AbhO_nhWEZ7jojF3JULUGyzIUTiHNshUWblbkJCr7NbP";
const DIRECT_OWN_AGENT_STRAND =
  "ak:strand:ASy992JMe_xzh5pluAqo5YuyCnAfDdFni4lmeHQldlUM";
const DEMO_CIRCLE = "ak:circle:AVhDoodj6EFMf5ZQ1JXfSmM5ZNZrK3ekqYa4-EOvqSiE";
const DEMO_BOARD_SPACE = "ak:space:AY61QviMxoJ0ALEn5U39bA7Qbi1BxHCrOq4950m2JRjM";
const DEMO_SECOND_BOARD_SPACE = "ak:space:AUqXxLkoB6IUAy7p6DSMGyoUVhO0KevW5ZzWGTP_4xIh";
const DEMO_TODO_LIST = "ak:space:AZLgY4qsY8KB47PSg9tg4oYHPmyQf7A7JlzMa0JMmmVi";
const DEMO_PROGRESS_LIST = "ak:space:ARC32_kqx5-YFlPdEX0StqbYHhqEo2Inh25kKZPcW3u-";
const DEMO_DONE_LIST = "ak:space:AeFSLuUZ7jW2w3xVl0s9ZTzojGeaOIrzzn4yQeweskV0";
const DEMO_SECOND_LIST = "ak:space:AXIKcuc3xUnThWU2npxUFVgxgvnRP1_U_ZC8EvSFAWy5";
const DEMO_STRAND_LEGAL_REVIEW =
  "ak:strand:AUftf_3k2fRKMG0NFlHe5iEMBOUpxMwYMRu-yhMJl-yz";
const DEMO_STRAND_ONBOARDING_COPY =
  "ak:strand:ASZZoDGudNfXFZynKh4xcEpb5d8kLZQXRpycxlg1qyW-";
const DEMO_STRAND_SECURITY_SIGNOFF =
  "ak:strand:AQmnyvvBmKOWOEOSD2rAYsVBQn6vJ_wdbdUY8CKUGB5c";
const DEMO_STRAND_SECONDARY_CARD =
  "ak:strand:AeuYGIMbDLHP-zzs9g6vzWrgtPNhcol9h_doKgtHxKqd";
const DEMO_BLOB_REF =
  "ak:blob:sha256:431ced6916a2a21a156e38701afe55bbd7f88969fbbfc56d7fe099d47f265460";
const DEMO_AVATAR_PNG_BASE64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";
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

type MockArkretApiOptions = {
  advertiseListHandlesForSubject?: boolean;
  accountPrincipalId?: string;
  primaryHandle?: string | null;
  directoryPrimaryHandle?: string | null;
  currentDeviceId?: string;
  accountDevices?: MockAccountDevice[];
  includeDemoRealms?: boolean;
  includeLowFloorRealm?: boolean;
  personalAgentPairingExpiresAt?: string;
  sidecarPendingMemberReconciliations?: Array<Record<string, unknown>>;
  includeSidecarInCircleList?: boolean;
  additionalActiveAgents?: Array<{
    agent_id: string;
    display_name: string;
    slug: string;
  }>;
  demoPrimaryCardTitle?: string;
  preseedRecoveryMaterial?: boolean;
  seedSharedHistoryCount?: number;
  seedDefaultActiveAgent?: boolean;
  emptyBoard?: boolean;
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
type InksonWireCommand =
  | "canonical-json"
  | "sha256-canonical-json"
  | "mls-governance-proof"
  | "control-proposal-ack"
  | "ingress-receipts"
  | "range-completeness";
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

function canonicalNdjsonLine(value: unknown): string {
  assertJsonTransportable(value, "$");
  const sort = (item: unknown): unknown => {
    if (Array.isArray(item)) {
      return item.map(sort);
    }
    if (item !== null && typeof item === "object") {
      return Object.fromEntries(
        Object.entries(item as Record<string, unknown>)
          .sort(([left], [right]) => left.localeCompare(right))
          .map(([key, child]) => [key, sort(child)]),
      );
    }
    return item;
  };
  return JSON.stringify(sort(value));
}

function realmActorFrontier(
  realmId: string,
  actorId: string,
  nextActorSeq = 0,
  frontierEventIds: string[] = [],
) {
  const transcript = {
    kind: "realm_actor",
    realm_id: realmId,
    actor_id: actorId,
    next_actor_seq: nextActorSeq,
    frontier_event_ids: frontierEventIds,
  };
  const digest = createHash("sha256")
    .update("ak-realm-actor-frontier-v1\0", "utf8")
    .update(canonicalJson(transcript), "utf8")
    .digest("hex");
  return {
    ...transcript,
    frontier_digest: `sha256:${digest}`,
  };
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
  delete digestPayload.actor_kind;
  delete digestPayload.event_id;
  return canonicalSha256(digestPayload);
}

export async function mockArkretApi(
  page: Page,
  options: MockArkretApiOptions = {},
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
  const sidecarPendingMemberReconciliations =
    options.sidecarPendingMemberReconciliations ?? [];
  const includeSidecarInCircleList =
    options.includeSidecarInCircleList ?? false;
  const includeLowFloorRealm = options.includeLowFloorRealm ?? false;
  const personalAgentPairingExpiresAt =
    options.personalAgentPairingExpiresAt ?? "2099-07-06T00:10:00.000Z";
  const accountDevices = new Map<string, MockAccountDevice>();
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
  let serverDidDocument: Record<string, unknown> = {
    id: "did:web:server.local",
  };
  let sidecarAgentIds = ["did:web:agents.example:assistant"];
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
    [DEMO_CIRCLE, [accountPrincipalId]],
  ]);
  let circleCounter = 2;
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
    history_visibility: "joined",
    content_encryption_floor: "e2ee_required",
    metadata_encryption_floor: "e2ee_required",
    encryption_profile:
      circleMetadata.get(circleId)?.encryption_profile ?? "mls_rfc9420",
    mls_group_ref: "ak:mls:mls_rfc9420:demo-circle",
    pending_mls_removals: [],
    state: circleStates.get(circleId) ?? "active",
    member_count: circleMembers.get(circleId)?.length ?? 0,
    viewer_membership: circleMembers.get(circleId)?.includes(accountPrincipalId)
      ? "join"
      : undefined,
    members: circleMembers.get(circleId) ?? [],
    created_by: accountPrincipalId,
    created_at: "2026-06-23T00:00:00.000Z",
    updated_by: accountPrincipalId,
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
          principal_id: accountPrincipalId,
          version: 1,
          acceptance_basis: `ak:seal:sha256:${"a".repeat(64)}`,
          trust_domain: "ak:trust_domain:soland.local",
          allowed_proof_kinds: ["principal_signing"],
          supersedes: null,
          expires_at: null,
          issued_at: "2026-07-29T00:00:00.000Z",
          accepted_at: "2026-07-29T00:00:01.000Z",
          policy: {
            schema: "ak.schema.recovery_policy.v1",
            policy_id: seededRecoveryPolicyId,
            principal_id: accountPrincipalId,
            version: 1,
            supersedes: null,
            trust_domain: "ak:trust_domain:soland.local",
            allowed_proof_kinds: ["principal_signing"],
            publication_authorization_rules: [
              {
                rule_id: "principal_signing",
                proof_kind: "principal_signing",
                issuer_role: "identity_recovery",
                allowed_actions: ["ak.device.reanchor"],
                issuers: [
                  {
                    verification_method: `${accountPrincipalId}#${currentDeviceId}`,
                  },
                ],
                threshold: 1,
              },
            ],
            recovery_key_agreements: [
              {
                key_agreement_ref: `${accountPrincipalId}#backup-hpke-0`,
                alg: "X25519",
                public_key_multibase: seededBackupHpkeKey,
                hpke_suites: ["ak.hpke_x25519_aead_chacha20poly1305.v1"],
                use: "backup_hpke",
                not_before: "2026-07-29T00:00:00.000Z",
                expires_at: "2036-07-29T00:00:00.000Z",
              },
            ],
            issued_at: "2026-07-29T00:00:00.000Z",
            auth_data: {
              verification_method: `${accountPrincipalId}#${currentDeviceId}`,
              signature_algorithm: "Ed25519",
              signature: "fixture",
              signed_fields: [
                "schema",
                "policy_id",
                "principal_id",
                "version",
                "supersedes",
                "trust_domain",
                "allowed_proof_kinds",
                "publication_authorization_rules",
                "recovery_key_agreements",
                "issued_at",
              ],
            },
          },
        }
      : null;
  const keyBackups = new Map<string, Record<string, unknown>>();
  if (options.preseedRecoveryMaterial === true) {
    const backupId = "ak:backup:019a6aa0-0000-7000-8000-000000000002";
    keyBackups.set(backupId, {
      backup_id: backupId,
      actor_id: accountPrincipalId,
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
      contents: [],
    });
  }
  const personalAgents = new Map<string, Record<string, unknown>>();
  const personalAgentKeyStates = new Map<string, Record<string, unknown>>();
  const personalAgentGrants = new Map<string, Array<Record<string, unknown>>>();
  const managedPcrRealmIds = new Set<string>();
  const managedPcrSealHeads = new Map<string, Record<string, unknown>>();
  const managedPcrSealPaths = new Map<string, Array<Record<string, unknown>>>();
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
    const pairingMode = String(ks?.pairing_mode ?? "");
    const pairingExpiresAt = String(ks?.pairing_expires_at ?? "");
    const pairingOpen =
      Boolean(ks?.pairing_request_id) &&
      pairingExpiresAt > "2026-08-03T00:00:00.000Z" &&
      (pairingMode === "replacement" || !keyed);
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
              axes.runtime_state === "pending_runtime_key"
                ? "runtime_key_missing"
                : axes.runtime_state === "replacing"
                  ? "pairing_open"
                  : "session_missing",
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
  const activeAssistantId = "did:web:agents.example:assistant";
  const activeAssistantScope = {
    actions: ["ak.event.read"],
    resources: [{ kind: "operation", operation: "ak.self.events.read.scan" }],
  };
  const activeAssistantKeyState = {
    agent_id: activeAssistantId,
    controller_id: accountPrincipalId,
    principal_control_realm_id: "ak:realm:AS7wchHFRbXWnMQPln42BrokXsPCf18uboKMm-yhYquI",
    controller_authorization_ref: `${activeAssistantId}#managed-controller`,
    pcr_recovery: {
      status: "ready",
      backup_id: "ak:backup:01964137-0000-7000-8000-0000000000c1",
      series_id: "ak:backup_series:01964137-0000-7000-8000-0000000000c2",
      series_seq: 1,
      managed_frontier_ref: {
        frontier_digest:
          "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        seal_ref:
          "ak:seal:sha256:4444444444444444444444444444444444444444444444444444444444444444",
        mls_epoch: 0,
      },
    },
    requested_scope: activeAssistantScope,
    requested_scope_digest: canonicalSha256({
      agent_id: activeAssistantId,
      controller_id: accountPrincipalId,
      kind: "ak.agent.requested_scope_commitment.v1",
      requested_scope: activeAssistantScope,
    }),
    authorized_event_ref: "ak:event:AfoRpfP-sl-s9gK_9-GfLiYW9eincnIfCJF8xRcVowkj",
    active_authorizations: [
      {
        key_id: "runtime-key-1",
        verification_method: `${activeAssistantId}#runtime-key-1`,
        authorized_event_ref: "ak:event:AfoRpfP-sl-s9gK_9-GfLiYW9eincnIfCJF8xRcVowkj",
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
  for (const agent of options.additionalActiveAgents ?? []) {
    personalAgents.set(agent.agent_id, {
      ...agent,
      lifecycle: "active",
      created_at: "2026-07-06T00:00:00.000Z",
      updated_at: "2026-07-06T00:05:00.000Z",
    });
    personalAgentKeyStates.set(agent.agent_id, {
      ...activeAssistantKeyState,
      agent_id: agent.agent_id,
      controller_authorization_ref: `${agent.agent_id}#managed-controller`,
      authorized_event_ref: "ak:event:Ad-rGYKVGY9i32DG2R9ZwMezGzT5g2rmdYjrifmGO6Fe",
      active_authorizations: [
        {
          key_id: "runtime-key-2",
          verification_method: `${agent.agent_id}#runtime-key-2`,
          authorized_event_ref: "ak:event:Ad-rGYKVGY9i32DG2R9ZwMezGzT5g2rmdYjrifmGO6Fe",
        },
      ],
    });
  }
  personalAgents.set("did:web:agents.example:deactivated", {
    agent_id: "did:web:agents.example:deactivated",
    display_name: "Deactivated Agent",
    slug: "deactivated",
    lifecycle: "deactivated",
    created_at: "2026-07-05T00:00:00.000Z",
    updated_at: "2026-07-06T00:10:00.000Z",
  });
  if (personalAgentPairingExpiresAt.startsWith("2000-")) {
    const expiredAgentId = "did:web:agents.example:summary";
    const expiredRealmId = "ak:realm:AQ4lJ43jR05ytJIf7AGNbPU_MuY1FqT_ny_e8MhCCnwc";
    const expiredScope = {
      actions: [
        "ak.event.read",
        "ak.message.create",
        "ak.reaction.add",
        "ak.self.events.stream.subscribe",
        "ak.self.events.read.scan",
        "ak.self.events.command.submit",
      ],
      resources: [
        {
          kind: "operation",
          operation: "ak.self.events.stream.subscribe",
        },
      ],
    };
    const expiredScopeDigest = canonicalSha256({
      agent_id: expiredAgentId,
      controller_id: accountPrincipalId,
      kind: "ak.agent.requested_scope_commitment.v1",
      requested_scope: expiredScope,
    });
    personalAgents.set(expiredAgentId, {
      agent_id: expiredAgentId,
      slug: "summary",
      lifecycle: "active",
      created_at: "2026-07-06T00:00:00.000Z",
      updated_at: "2026-07-06T00:10:00.000Z",
    });
    personalAgentKeyStates.set(expiredAgentId, {
      agent_id: expiredAgentId,
      controller_id: accountPrincipalId,
      principal_control_realm_id: expiredRealmId,
      controller_authorization_ref: `${expiredAgentId}#managed-controller`,
      pcr_recovery: {
        status: "ready",
        backup_id: "ak:backup:01964137-0000-7000-8000-0000000000b1",
        series_id: "ak:backup_series:01964137-0000-7000-8000-0000000000b2",
        series_seq: 1,
        managed_frontier_ref: {
          frontier_digest:
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
          seal_ref:
            "ak:seal:sha256:1111111111111111111111111111111111111111111111111111111111111111",
          mls_epoch: 0,
        },
      },
      requested_scope: expiredScope,
      requested_scope_digest: expiredScopeDigest,
    });
    personalAgentGrants.set(expiredAgentId, []);
  }
  const reconcileAgentPcrRecovery = () => {
    const activeSeriesPayloads = projectionEvents
      .filter((event) => event.kind === "ak.key_backup.active_series")
      .map((event) => event.payload)
      .filter(
        (payload): payload is Record<string, any> =>
          typeof payload === "object" && payload !== null,
      );
    for (const backup of keyBackups.values()) {
      if (
        backup.backup_kind !== "mls_history" ||
        typeof backup.backup_id !== "string" ||
        typeof backup.series_id !== "string" ||
        typeof backup.series_seq !== "number"
      ) {
        continue;
      }
      const activeSeries = activeSeriesPayloads.find(
        (payload) =>
          payload.actor_id === backup.actor_id &&
          payload.backup_kind === backup.backup_kind &&
          payload.active_series_id === backup.series_id,
      );
      if (!activeSeries || !Array.isArray(backup.contents)) {
        continue;
      }
      for (const content of backup.contents) {
        const binding = content?.managed_principal_binding;
        const agentId = binding?.managed_principal_id;
        const managedFrontierRef = binding?.managed_frontier_ref;
        if (
          typeof agentId !== "string" ||
          typeof managedFrontierRef !== "object" ||
          managedFrontierRef === null
        ) {
          continue;
        }
        const keyState = personalAgentKeyStates.get(agentId);
        if (!keyState) {
          continue;
        }
        personalAgentKeyStates.set(agentId, {
          ...keyState,
          pcr_recovery: {
            status: "ready",
            backup_id: backup.backup_id,
            series_id: backup.series_id,
            series_seq: backup.series_seq,
            managed_frontier_ref: managedFrontierRef,
          },
        });
      }
    }
  };
  const eventRealmId = (event: Record<string, unknown>) =>
    String(event.realm_id ?? "");
  const accountDeviceSummaries = () =>
    Array.from(accountDevices.values()).map((device) => {
      const summary: Record<string, unknown> = {
        device_id: device.device_id,
        status: device.status ?? (device.authorized_at ? "active" : "unknown"),
        verification_state:
          device.verification_state ??
          (device.status === "revoked" ? "needs_reverification" : "verified"),
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
  const boardSpaceContainers: SpaceContainerProjection[] = options.emptyBoard
    ? []
    : [
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
  const boardStrandProjections: StrandProjection[] = options.emptyBoard
    ? []
    : [
        {
          strand_id: DEMO_STRAND_LEGAL_REVIEW,
          realm_id: DEMO_REALM,
          title: options.demoPrimaryCardTitle ?? "Legal review for public beta",
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
          summary:
            "Projection detected a stale column head after an offline move.",
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
  const canonicalProjectionEvent = (
    eventId: string,
    kind: string,
    actorSeq: number,
    payload: Record<string, unknown>,
  ) => ({
    event_id: eventId,
    kind,
    realm_id: DEMO_REALM,
    scope_ref: { kind: "realm", realm_id: DEMO_REALM },
    actor_id: accountPrincipalId,
    actor_seq: actorSeq,
    created_at: `2026-04-28T12:${String(actorSeq - 200).padStart(2, "0")}:00.000Z`,
    hlc: `01964137${String(actorSeq).padStart(4, "0")}-0000-12345678`,
    prev_refs: [],
    payload,
    proofs: [],
  });
  projectionEvents.push(
    ...boardSpaceContainers.map((space, index) =>
      canonicalProjectionEvent(
        `ak:event:0196419b-0000-8000-8000-00000000b0${String(index + 1).padStart(2, "0")}`,
        "ak.space.create",
        200 + index,
        {
          object: {
            id: space.container_space_id,
            schema: "ak.schema.space.v1",
            realm_id: space.realm_id,
            kind: space.kind,
            title: space.title,
            ...(space.rank ? { rank: space.rank } : {}),
            ...(space.parent_space_id
              ? { parent_space_id: space.parent_space_id }
              : {}),
          },
        },
      ),
    ),
    ...boardStrandProjections.map((strand, index) =>
      canonicalProjectionEvent(
        `ak:event:0196419b-0000-8000-8000-00000000c0${String(index + 1).padStart(2, "0")}`,
        "ak.strand.create",
        210 + index,
        {
          object: {
            id: strand.strand_id,
            schema: "ak.schema.strand.v1",
            realm_id: strand.realm_id,
            created_by: accountPrincipalId,
            created_at: `2026-04-28T12:${10 + index}:00.000Z`,
            metadata: {
              title: strand.title,
              summary: strand.summary,
              fields: {
                ...strand.fields,
                board_space_id: strand.board_space_id,
                list_space_id: strand.list_space_id,
                rank: strand.rank,
                strand_kind: "card",
              },
            },
          },
        },
      ),
    ),
  );
  const seedSharedHistoryCount = options.seedSharedHistoryCount ?? 0;
  for (let index = 0; index < seedSharedHistoryCount; index += 1) {
    const suffix = (0xd000 + index).toString(16).padStart(12, "0");
    const historyActor = "did:web:history.example";
    projectionEvents.push({
      ...canonicalProjectionEvent(
        `ak:event:0196419b-0000-8000-8000-${suffix}`,
        "ak.message.create",
        230 + index,
        {
          message_id: `ak:message:0196419b-0000-8000-8000-${suffix}`,
          strand_id: DEMO_STRAND_LEGAL_REVIEW,
          track_name: "discussion",
          content: {
            kind: "ak.content.text",
            body: `shared history row ${String(index).padStart(2, "0")}`,
          },
        },
      ),
      actor_id: historyActor,
      proofs: [
        {
          kind: "detached_jws",
          alg: "Ed25519",
          verification_method: `${historyActor}#device`,
          event_digest:
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          created_at: "2026-04-28T12:30:00.000Z",
          jws: "eyJhbGciOiJFZDI1NTE5In0..AA",
        },
      ],
    });
  }

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
      url.pathname === "/_arkret/describe" &&
      route.request().method() === "GET"
    ) {
      if (url.hostname === "auth.local.host") {
        return json(route, {
          service_id: "did:web:auth.local.host",
          service_kind: "auth_server",
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
        service_id: "did:web:server.local",
        trust_domain: "ak:trust_domain:server.local",
        service_kind: "principal_server",
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
          "ak.server.read.describe",
          "ak.self.account.stream.subscribe",
          "ak.self.account.read.describe",
          "ak.self.account.read.viewer",
          "ak.self.account.command.update_profile",
          "ak.self.events.read.scan",
          "ak.self.events.stream.subscribe",
          "ak.self.events.read.describe",
          "ak.self.events.command.submit",
          "ak.self.space.read.list",
          "ak.self.strand.read.list",
          "ak.find.directory.read.search_realms",
          "ak.find.directory.read.resolve_realm",
          "ak.find.directory.read.describe",
          "ak.find.directory.read.search_organizations",
          "ak.find.directory.read.search_actors",
          "ak.find.directory.read.resolve_handle",
          ...(advertiseListHandlesForSubject
            ? ["ak.find.directory.read.list_handles_for_subject"]
            : []),
          "ak.self.authz.read.check",
          "ak.self.authz.grants.read.effective",
          "ak.self.authz.invites.read.list",
          "ak.root.identity.registry.read.describe",
          "ak.root.identity.read.resolve",
          "ak.root.identity.recovery_policy.resource.get",
          "ak.root.identity.recovery_policy.command.publish",
          "ak.gate.account.command.register",
          "ak.gate.account.command.pair_device",
          "ak.gate.account.command.revoke_session",
          "ak.self.contact.read.list",
          "ak.self.contact.command.request",
          "ak.self.contact.command.respond",
          "ak.self.contact.command.tombstone",
          "ak.self.invite_receive_policy.resource.get",
          "ak.self.invite_receive_policy.resource.replace",
          "ak.self.direct_conversation.read.resolve",
          "ak.self.circle.command.create",
          "ak.self.circle.read.list",
          "ak.self.circle.resource.get",
          "ak.self.circle.member.command.add",
          "ak.self.circle.member.resource.delete",
          "ak.self.circle.command.rotate_scope",
          "ak.self.circle.command.archive",
          "ak.self.circle.command.restore",
          "ak.self.circle.command.tombstone",
          "ak.self.keys.upload.create",
          "ak.self.keys.read.lookup",
          "ak.self.keys.command.claim",
          "ak.self.keys.backups.read.list",
          "ak.self.keys.backups.resource.replace",
          "ak.self.device_messages.read.list",
          "ak.self.device_messages.command.send",
          "ak.self.device_messages.command.ack",
          "ak.edge.push.command.register_device",
          "ak.edge.push.command.unregister_device",
          "ak.self.blob.upload.create",
          "ak.self.blob.resource.get",
          "ak.self.media.read.ice_config",
          "ak.self.moderation.command.report",
          "ak.open.mimi.read.provider_directory",
          "ak.open.mimi.exchange.request_key_material",
          "ak.open.mimi.read.group_info",
          "ak.open.mimi.command.update_room",
          "ak.open.mimi.command.notify",
          "ak.open.mimi.command.submit_message",
          "ak.open.mimi.command.request_consent",
          "ak.open.mimi.command.update_consent",
          "ak.open.mimi.read.identifiers",
          "ak.open.mimi.command.report_abuse",
          "ak.open.mimi.command.proxy_download",
          "ak.open.invite_locator.read.resolve",
          "ak.self.signal.command.send",
        ],
        supported_schema_profiles: ["ak.schema.core.v1"],
        supported_reducer_profiles: ["ak.reducer.core.v1"],
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
        limits: { x_storage: "memory" },
        rate_limit_policy: {
          policy_version: "1",
          entries: [
            {
              endpoint: "*",
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
        implemented_features: [],
        claimed_profiles: [],
        verified_profiles: [],
        experimental_features: [],
        compat_surfaces: [],
        development_mode: true,
        frontier: [DEMO_FRONTIER_EVENT],
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
        next_cursor: null,
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
      const circleId = `ak:circle:0196419b-0000-8000-8000-${String(circleCounter).padStart(12, "0")}`;
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
        actor_id: request.actor_id,
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
        actor_id: decodeURIComponent(actorId),
        membership: "leave",
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
      url.pathname === "/_arkret/self/events/frontier" &&
      route.request().method() === "QUERY"
    ) {
      const selector = (await route.request().postDataJSON()) as Record<
        string,
        unknown
      >;
      const actorId =
        typeof selector.actor_id === "string" ? selector.actor_id : null;
      const realmId =
        typeof selector.realm_id === "string" ? selector.realm_id : null;
      if (actorId && realmId) {
        const actorEvents = projectionEvents.filter(
          (event) =>
            eventRealmId(event) === realmId && event.actor_id === actorId,
        );
        const referenced = new Set(
          actorEvents.flatMap((event) =>
            Array.isArray(event.prev_refs)
              ? event.prev_refs.filter(
                  (eventId): eventId is string => typeof eventId === "string",
                )
              : [],
          ),
        );
        const heads = actorEvents
          .map((event) => event.event_id)
          .filter(
            (eventId): eventId is string =>
              typeof eventId === "string" && !referenced.has(eventId),
          )
          .sort();
        const nextActorSeq =
          actorEvents.reduce(
            (highest, event) =>
              typeof event.actor_seq === "number"
                ? Math.max(highest, event.actor_seq)
                : highest,
            -1,
          ) + 1;
        return json(route, {
          frontier: realmActorFrontier(realmId, actorId, nextActorSeq, heads),
        });
      }
      if (actorId) {
        return json(route, {
          frontier: {
            kind: "actor_aggregate",
            actor_id: actorId,
            realms: [],
          },
        });
      }
      if (realmId) {
        if (managedPcrRealmIds.has(realmId)) {
          const seal = managedPcrSealHeads.get(realmId);
          if (!seal) {
            return json(
              route,
              {
                ok: false,
                error: {
                  code: "not_found",
                  message: "managed Agent PCR has no accepted Seal yet",
                },
              },
              404,
            );
          }
          return json(route, {
            frontier: {
              kind: "realm_seal",
              realm_id: realmId,
              seal_id: seal.id,
              control_event_set_root: seal.control_event_set_root,
              state_root: seal.state_root,
              governance_health: {
                status: "healthy",
                pending_proposals: [],
                retained_faults: [],
              },
              hlc: seal.hlc,
            },
            receipts: [
              {
                kind: "ak.managed_agent_pcr.seal_head.v1",
                seal,
              },
            ],
          });
        }
        return json(route, {
          frontier: {
            kind: "realm_seal",
            realm_id: realmId,
            seal_id:
              "ak:seal:sha256:1111111111111111111111111111111111111111111111111111111111111111",
            control_event_set_root:
              "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            state_root:
              "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            governance_health: {
              status: "healthy",
              pending_proposals: [],
              retained_faults: [],
            },
          },
        });
      }
      return json(
        route,
        {
          ok: false,
          error: {
            code: "invalid_param",
            message: "frontier selector is required",
          },
        },
        400,
      );
    }

    if (
      url.pathname === "/_arkret/self/events/seals" &&
      route.request().method() === "POST"
    ) {
      const seal = (await route.request().postDataJSON()) as Record<
        string,
        unknown
      >;
      const realmId = typeof seal.realm_id === "string" ? seal.realm_id : "";
      if (
        !managedPcrRealmIds.has(realmId) ||
        typeof seal.id !== "string" ||
        !Array.isArray(seal.delta) ||
        typeof seal.state_root !== "string"
      ) {
        return json(
          route,
          {
            ok: false,
            error: {
              code: "schema_violation",
              message: "invalid managed Agent PCR Seal",
            },
          },
          400,
        );
      }
      managedPcrSealHeads.set(realmId, seal);
      managedPcrSealPaths.set(realmId, [
        ...(managedPcrSealPaths.get(realmId) ?? []),
        seal,
      ]);
      return json(route, {
        seal_id: seal.id,
        accepted_event_digests: seal.delta,
        post_state_root: seal.state_root,
      });
    }

    if (
      url.pathname === "/_arkret/self/events/mls-governance-proof" &&
      route.request().method() === "QUERY"
    ) {
      const request = (await route.request().postDataJSON()) as Record<
        string,
        unknown
      >;
      const realmId =
        typeof request.realm_id === "string" ? request.realm_id : "";
      const seal = managedPcrSealHeads.get(realmId);
      if (!seal) {
        return json(
          route,
          {
            ok: false,
            error: {
              code: "frontier_unavailable",
              message: "managed Agent PCR Seal is unavailable",
            },
          },
          503,
        );
      }
      const events = projectionEvents.filter(
        (event) => eventRealmId(event) === realmId,
      );
      const bundle = inksonWire<Record<string, unknown>>(
        "mls-governance-proof",
        { request, events, seals: managedPcrSealPaths.get(realmId) ?? [seal] },
      );
      return json(route, bundle);
    }

    if (
      url.pathname === "/_arkret/self/control-proposal-acks" &&
      route.request().method() === "POST"
    ) {
      const request = await route.request().postDataJSON();
      const outcome = inksonWire<Record<string, unknown>>("control-proposal-ack", {
        request,
        device_id: currentDeviceId,
      });
      return json(route, outcome);
    }

    if (
      url.pathname === "/_arkret/self/authorization-leases" &&
      route.request().method() === "POST"
    ) {
      const body = ((await contractRequestBody(route)) ?? {}) as Record<
        string,
        unknown
      >;
      const events = Array.isArray(body.events)
        ? (body.events as Array<Record<string, any>>)
        : [];
      const issuedAt = new Date().toISOString();
      const expiresAt = new Date(
        Date.parse(issuedAt) + 30 * 60 * 1_000,
      ).toISOString();
      const isAnchorUnit =
        events.length > 0 &&
        events.every(
          (event) =>
            event.seal_ref === undefined && event.seal_basis === undefined,
        );
      const anchorEventDigests = isAnchorUnit
        ? events.map((event) => String(event.proofs?.[0]?.event_digest ?? ""))
        : [];
      const anchorRealmId = isAnchorUnit
        ? String(events[0]?.realm_id ?? "")
        : "";
      const anchorUnitBasis = isAnchorUnit
        ? {
            anchor_unit: {
              realm_id: anchorRealmId,
              event_digests: anchorEventDigests,
              unit_digest: canonicalSha256({
                realm_id: anchorRealmId,
                event_digests: anchorEventDigests,
              }),
            },
          }
        : undefined;
      const authorizationLeases = events.map((event, index) => {
        const basisRef = anchorUnitBasis ?? event.seal_ref ?? event.seal_basis;
        const sourceRef = isAnchorUnit
          ? `anchor-unit:${anchorUnitBasis!.anchor_unit.unit_digest}`
          : typeof event.seal_ref === "string"
            ? event.seal_ref
            : String(event.seal_basis?.leaves?.[0] ?? "principal-control");
        const verificationMethod = `${event.actor_id}#e2e-device-key`;
        const authoritySetPolicy = {
          schema: "ak.schema.authority_set_policy.v1",
          authority_set_id: "ak.authority_set.principal_control.e2e",
          policy_kind: "principal_control",
          scope_ref: event.scope_ref,
          source: {
            source_kind: "realm_control",
            source_ref: sourceRef,
            source_digest: canonicalSha256({ source_ref: sourceRef }),
            generation_ref: "1",
          },
          authorization_rules: [
            {
              rule_id: "principal_control",
              issuer_role: "accepted_device",
              allowed_actions: [event.kind],
              issuers: [{ verification_method: verificationMethod }],
              threshold: 1,
            },
          ],
        };
        const leaseWithoutProofs = {
          authorization_lease_id: `ak:authorization_lease:01964137-0000-7000-8000-${String(
            index + 1,
          ).padStart(12, "0")}`,
          basis_ref: basisRef,
          actor_id: event.actor_id,
          device_id: currentDeviceId,
          scope_ref: event.scope_ref,
          action: event.kind,
          authorization_rule_id: "principal_control",
          risk_tier: "high",
          issued_at: issuedAt,
          expires_at: expiresAt,
          authority_set_ref: {
            authority_set_id: authoritySetPolicy.authority_set_id,
            authority_set_digest: canonicalSha256(authoritySetPolicy),
          },
          authority_set_policy: authoritySetPolicy,
        };
        return {
          ...leaseWithoutProofs,
          proofs: [
            {
              kind: "detached_jws",
              alg: "Ed25519",
              verification_method: verificationMethod,
              payload_digest: canonicalSha256(leaseWithoutProofs),
              created_at: issuedAt,
              jws: "e2e..signature",
            },
          ],
        };
      });
      return json(route, { authorization_leases: authorizationLeases });
    }

    if (
      url.pathname === "/_arkret/self/events/describe" &&
      route.request().method() === "QUERY"
    ) {
      // Spec ak.self.events.read.describe -> canonical ServiceDescribe shape
      // (17 required fields; inkson decodes the SDK ServerDescription).
      return json(route, {
        service_id: "did:web:server.local",
        trust_domain: "ak:trust_domain:server.local",
        service_kind: "principal_server",
        protocol_version: "1.0",
        supported_profiles: ["ak.profile.core_event_store.v1"],
        supported_operations: [
          "ak.self.events.command.submit",
          "ak.self.events.read.describe",
        ],
        supported_bindings: [{ kind: "http_json" }],
        supported_features: ["events_query_range_completeness"],
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
        limits: { x_storage: "memory" },
        rate_limit_policy: {
          policy_version: "1",
          entries: [
            {
              endpoint: "*",
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
        implemented_features: ["events_query_range_completeness"],
        claimed_profiles: [],
        verified_profiles: [],
        experimental_features: [],
        compat_surfaces: [],
        development_mode: true,
        frontier: [DEMO_FRONTIER_EVENT],
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
      const receiptableSubmissions = submittedEntries.filter(
        (entry: Record<string, any>) =>
          entry.event !== undefined && entry.authorization_lease !== undefined,
      );
      const ingressReceipts =
        receiptableSubmissions.length > 0
          ? inksonWire<Array<Record<string, unknown>>>("ingress-receipts", {
              submissions: receiptableSubmissions,
            })
          : [];
      for (const event of submittedEvents) {
        if (
          typeof event.event_id === "string" &&
          !projectionEvents.some(
            (projected) => projected.event_id === event.event_id,
          )
        ) {
          projectionEvents.push(event);
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
      reconcileAgentPcrRecovery();
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
          created_at: body.created_at ?? "2026-04-28T12:00:00.000Z",
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
          created_at: body.created_at ?? "2026-04-28T12:00:00.000Z",
          payload: body.payload,
        });
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
        ingress_receipts: ingressReceipts,
        control_proposal_acks: [],
        duplicate: [],
        rejected: [],
        quarantine: [],
        realm_actor_frontiers: [],
        realm_frontiers: [],
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
        event_ref: "ak:event:AX-AFSYZHl0U2MQP-Ng7mU-aOm_Flhf0pVBoHYUK6Shg",
        delivery: {
          status: "accepted",
          delivered_to: ["did:web:remote.example"],
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
          group_info: "ZTItdGVzdC1ncm91cC1pbmZv",
        },
        room_binding_ref: "ak:event:AaU-Qm8ThSLazMkDDaRlYzKtWfb_bSLS6zNfyROi2aoe",
        proofs: [],
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
        proofs: [],
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
        expires_at: "2026-04-30T12:00:00.000Z",
      });
    }

    if (
      url.pathname === "/_arkret/gate/account/register" &&
      route.request().method() === "POST"
    ) {
      const body = await route.request().postDataJSON();
      const identityCreation = body.identity_creation as
        | Record<string, any>
        | undefined;
      const genesisEvents = identityCreation?.pcr_genesis_unit?.events;
      const createEvent = Array.isArray(genesisEvents) ? genesisEvents[0] : undefined;
      const authorizeEvent = Array.isArray(genesisEvents)
        ? genesisEvents[1]
        : undefined;
      const authorizePayload = authorizeEvent?.payload ?? {};
      const descriptor = createEvent?.payload?.object?.founding_device_descriptor;
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
          status: identityCreation ? "active" : "unknown",
          display_name: "Current device",
          verification_state: identityCreation ? "verified" : "unverified",
        });
      }
      const creationOutcome = (() => {
        if (!identityCreation || !createEvent || !authorizeEvent || !descriptor) {
          return {};
        }
        const createDigest = signedEventDigest(createEvent);
        const authorizeDigest = signedEventDigest(authorizeEvent);
        const receiptEvents = [
          {
            event_id: createEvent.event_id,
            event_digest: createDigest,
            kind: "ak.realm.create",
          },
          {
            event_id: authorizeEvent.event_id,
            event_digest: authorizeDigest,
            kind: "ak.device.authorize",
          },
        ].sort((left, right) =>
          canonicalJson(left).localeCompare(canonicalJson(right)),
        );
        const receiptIssuer = "did:web:server.local";
        const createdAt = "2026-08-09T00:00:00.000Z";
        return {
          binding_receipt: {
            binding_state: "bound",
            identity_creation_lease_id:
              identityCreation.identity_creation_lease_id,
            lease_fence: identityCreation.lease_fence,
            operation_status: "accepted",
            operation_digest: identityCreation.control_proof.operation_digest,
            head_event_digest: identityCreation.control_proof.operation_digest,
          },
          pcr_genesis_receipt: {
            schema: "ak.schema.event_batch_receipt.v1",
            receipt_id: "ak:receipt:019a6413-7000-7000-8000-000000000001",
            issuer: receiptIssuer,
            scope: {
              kind: "pcr_genesis_unit",
              principal_id: body.principal_id,
              realm_id: createEvent.realm_id,
              create_digest: createDigest,
              founding_authorize_digest: authorizeDigest,
              accepted_device_id: registrationDeviceId,
              device_key_digest: descriptor.device_key_digest,
              hpke_key_digest: descriptor.hpke_key_digest,
              accepted_at: createdAt,
              audience: identityCreation.control_proof.audience,
            },
            frontier: {
              actor_seq: authorizeEvent.actor_seq,
              event_id: authorizeEvent.event_id,
              event_digest: authorizeDigest,
              hlc: authorizeEvent.hlc,
            },
            events: receiptEvents,
            created_at: createdAt,
            proofs: [
              {
                kind: "detached_jws",
                verification_method: `${receiptIssuer}#receipt`,
                event_digest: authorizeDigest,
                created_at: createdAt,
                jws: "e2e..pcr-genesis-receipt",
              },
            ],
          },
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
            granted_scope: identityCreation.initial_session.requested_scope,
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
          principal_id: "did:web:alice.example",
          actor_kind: "user",
          display_name: displayName,
          handle: "alice.example",
          avatar_blob_ref: avatarBlobRef,
          profile_fields: bio ? { bio } : {},
          accountable_principal_ids: [],
          created_at: "2026-04-28T12:00:00.000Z",
          updated_at: "2026-04-28T12:10:00.000Z",
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
      if (url.searchParams.has("after")) {
        await new Promise((resolve) => setTimeout(resolve, 5_000));
        return route.fulfill({
          status: 200,
          contentType: "application/x-ndjson",
          body: `${canonicalNdjsonLine({ kind: "frontier", cursor: "ak:cursor:e2e-2" })}\n${canonicalNdjsonLine({ kind: "catchup_complete", cursor: "ak:cursor:e2e-2" })}\n`,
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
              actor_id: accountPrincipalId,
              actor_seq: 101,
              created_at: "2026-04-28T12:01:00.000Z",
              hlc: "019641370001-0000-12345678",
              prev_refs: [],
              payload: {
                schema: "ak.schema.notification.v1",
                notification_id: "notif-msg-1",
                title: "New message",
                body: "Alice sent a message in Demo Realm",
                realm_id: DEMO_REALM,
                notification_kind: "message",
                type: "message",
                timestamp: "2026-04-28T12:01:00.000Z",
                read: false,
              },
              proofs: [],
            },
            {
              event_id: "ak:event:Aaa8behhWSeKSNCcHiTuAoq1xiTXvuVAQxja-XifnQv2",
              kind: "ak.account_data.set",
              realm_id: DEMO_REALM,
              scope_ref: { kind: "realm", realm_id: DEMO_REALM },
              actor_id: accountPrincipalId,
              actor_seq: 102,
              created_at: "2026-04-28T12:02:00.000Z",
              hlc: "019641370002-0000-12345678",
              prev_refs: [],
              payload: {
                schema: "ak.schema.notification.v1",
                notification_id: "notif-invite-1",
                invite_id: "ak:invite:AUG1Kl2NbYdRAAzJBfSrn_CbrHrnLV9R_axxiJTGm8yG",
                title: "New invite",
                body: "You were invited to review Demo Realm",
                realm_id: DEMO_REALM,
                notification_kind: "invite",
                type: "invite",
                timestamp: "2026-04-28T12:02:00.000Z",
                read: false,
              },
              proofs: [],
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
                  actor_profiles: {},
                  realm_metadata: {
                    title: realm.title,
                    summary: realm.summary,
                  },
                  e2ee_epoch:
                    realm.encryption_profile === "mls_rfc9420"
                      ? { epoch: 0, key_ref: `mock-key:${realm.id}` }
                      : null,
                },
                summary: { joined_member_count: 1 },
                timeline: {
                  events: projectionEvents.filter(
                    (event) => eventRealmId(event) === realm.id,
                  ),
                  limited: false,
                },
                state: { events: [] },
                unread_notifications: {
                  notification_count: 0,
                  highlight_count: 0,
                },
              },
            ]),
          ),
          ...(includeDemoRealms
            ? {
                [DEMO_REALM]: {
                  state_at_window_start: {
                    actor_profiles: {},
                    realm_metadata: {
                      title: "Arkret Demo Realm",
                      summary: "Shared demo Realm served by mocked server",
                    },
                    e2ee_epoch: {
                      epoch: 0,
                      key_ref: `mock-key:${DEMO_REALM}`,
                    },
                  },
                  summary: { joined_member_count: 2 },
                  members: [
                    { actor_id: accountPrincipalId, membership: "join" },
                    { actor_id: activeAssistantId, membership: "join" },
                    ...(options.additionalActiveAgents ?? []).map((agent) => ({
                      actor_id: agent.agent_id,
                      membership: "join",
                    })),
                  ],
                  timeline: { events: demoProjectionEvents, limited: false },
                  state: {
                    events: [
                      {
                        event_id:
                          "ak:event:AQfzUAkYTPWEIwpvJkyWp5j_6qhL3cTW6yorhD_LEjNz",
                        kind: "ak.realm.create",
                        realm_id: DEMO_REALM,
                        scope_ref: { kind: "realm", realm_id: DEMO_REALM },
                        actor_id: accountPrincipalId,
                        actor_seq: 1,
                        created_at: "2026-04-28T12:00:00.000Z",
                        hlc: "019641370000-0000-12345678",
                        prev_refs: [],
                        payload: {
                          object: {
                            encryption_profile: "mls_rfc9420",
                          },
                        },
                        proofs: [],
                      },
                    ],
                  },
                  unread_notifications: {
                    notification_count: 0,
                    highlight_count: 0,
                  },
                },
                [CHILD_REALM]: {
                  state_at_window_start: {
                    actor_profiles: {},
                    realm_metadata: {
                      title: "Launch Realm",
                      summary: "Board and discussion scope",
                    },
                    e2ee_epoch: null,
                  },
                  summary: { joined_member_count: 1 },
                  timeline: { events: [], limited: false },
                  state: { events: [] },
                  unread_notifications: {
                    notification_count: 0,
                    highlight_count: 0,
                  },
                },
                [GRANDCHILD_REALM]: {
                  state_at_window_start: {
                    actor_profiles: {},
                    realm_metadata: {
                      title: "Launch Deep Realm",
                      summary: "Related scope fixture",
                    },
                    e2ee_epoch: null,
                  },
                  summary: { joined_member_count: 1 },
                  timeline: { events: [], limited: false },
                  state: { events: [] },
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
                    actor_profiles: {},
                    realm_metadata: {
                      title: "Low floor fixture Realm",
                      summary:
                        "Mocks the live first-account PCR floor advisory condition",
                    },
                    e2ee_epoch: null,
                  },
                  summary: { joined_member_count: 1 },
                  timeline: { events: [], limited: false },
                  state: { events: [] },
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
        account_data: { events: notificationEvents },
        device_lists: { changed: [], left: [] },
        notifications: { items: [] },
      };
      return route.fulfill({
        status: 200,
        contentType: "application/x-ndjson",
        body: `${canonicalNdjsonLine(withRequiredEventScopeRefs(frame))}\n${canonicalNdjsonLine({ kind: "catchup_complete", cursor: "ak:cursor:e2e-2" })}\n`,
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
            as_of: "2026-06-19T00:00:00.000Z",
            // No `source_refs`: a mocked entry has no Event provenance, and
            // directory-operations.schema.json forbids synthesizing an id for
            // an Event the implementation never authored.
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
        recipient_service_id: "did:web:server.local",
        issued_at: "2026-06-07T00:00:00.000Z",
        expires_at: "2026-06-07T00:15:00.000Z",
        locator_ref_digest: `sha256:${"1".repeat(64)}`,
        proofs: [
          {
            proof_purpose: "recipient_service_acceptance",
            proof: {
              kind: "detached_jws",
              verification_method: "did:web:server.local#server-key-1",
              alg: "Ed25519",
              payload_digest: `sha256:${"2".repeat(64)}`,
              created_at: "2026-06-07T00:00:00.000Z",
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
        recipient_service_id: "did:web:server.local",
        recipient_service_kind: "principal_server",
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
          as_of: "2026-04-28T12:00:00.000Z",
          has_more: false,
          claims: [],
        });
      }
      return json(route, {
        subject,
        primary_handle: subjectPrimaryHandle,
        as_of: "2026-04-28T12:00:00.000Z",
        has_more: false,
        claims: [
          {
            subject,
            handle: subjectPrimaryHandle,
            issuer: "did:web:server.local",
            issuer_service_id: "did:web:server.local",
            binding_state: "verified",
            claim_kind: "handle_binding",
            visibility: "public",
            audience: "did:web:server.local",
            created_at: "2026-04-28T12:00:00.000Z",
            verified_at: "2026-04-28T12:00:00.000Z",
            expires_at: "2027-04-28T12:00:00.000Z",
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
        service_id: "did:web:server.local",
        trust_domain: "ak:trust_domain:server.local",
        service_kind: "directory_service",
        protocol_version: "1.0",
        supported_profiles: ["ak.profile.directory_service.v1"],
        supported_operations: ["ak.find.directory.read.describe"],
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

    if (
      url.pathname === "/_arkret/self/events/subscribe" &&
      route.request().method() === "GET"
    ) {
      const cursor = "ak:cursor:e2e-events-2";
      if (url.searchParams.has("after")) {
        await new Promise((resolve) => setTimeout(resolve, 5_000));
        return route.fulfill({
          status: 200,
          contentType: "application/x-ndjson",
          body: `${canonicalNdjsonLine({ kind: "frontier", cursor })}\n${canonicalNdjsonLine({ kind: "catchup_complete", cursor })}\n`,
        });
      }
      const requestedRealms = (url.searchParams.get("realms") ?? "")
        .split(",")
        .map((realm) => realm.trim())
        .filter(Boolean);
      const frames: Array<Record<string, unknown>> = projectionEvents
        .filter(
          (event) =>
            requestedRealms.length === 0 ||
            requestedRealms.includes(eventRealmId(event)),
        )
        .map((payload) => ({
          kind: "event",
          realm_id: eventRealmId(payload),
          cursor,
          payload,
        }));
      frames.push({ kind: "catchup_complete", cursor });
      return route.fulfill({
        status: 200,
        contentType: "application/x-ndjson",
        body: `${frames.map(canonicalNdjsonLine).join("\n")}\n`,
      });
    }

    if (
      url.pathname === "/_arkret/self/events" &&
      route.request().method() === "QUERY"
    ) {
      const requestBody = (await route.request().postDataJSON()) as Record<
        string,
        unknown
      >;
      const requestedRealms = Array.isArray(requestBody.realms)
        ? requestBody.realms.filter(
            (realm): realm is string => typeof realm === "string",
          )
        : [];
      const events = requestedRealms.length
        ? projectionEvents.filter((event) =>
            requestedRealms.includes(eventRealmId(event)),
          )
        : projectionEvents;
      const response: Record<string, unknown> = {
        events,
        next_cursor: null,
        has_more: false,
      };
      if (
        (requestBody.include_completeness === true ||
          url.searchParams.get("include_completeness") === "true") &&
        events.length >= 2 &&
        events.some((event) => event.kind === "ak.key_backup.active_series")
      ) {
        const realmId = eventRealmId(events[0]);
        const fixture = inksonWire<{
          range_completeness: Record<string, unknown>;
          did_document: Record<string, unknown>;
        }>("range-completeness", {
          realm_id: realmId,
          events,
        });
        response.range_completeness = fixture.range_completeness;
        serverDidDocument = fixture.did_document;
      }
      return json(route, response);
    }

    // NB: no `/_arkret/self/snapshot/head` route. The mock's describe does
    // not advertise `ak.self.snapshot.read.manifest_head`, so the client falls back to
    // event replay before issuing the request. The current wire shape is the
    // full signed `ak.schema.snapshot.v1` manifest (self-id field `id`); the
    // removed `snapshot_ref` pointer DTO is hard-rejected and MUST NOT be
    // reintroduced here.
    if (
      url.pathname === "/_arkret/root/identity/describe" &&
      route.request().method() === "GET"
    ) {
      return json(route, {
        service_id: "did:web:server.local",
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
        did_document:
          body.did === "did:web:server.local"
            ? serverDidDocument
            : { id: body.did },
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
        service_id: "did:web:server.local",
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
        grants: ["ak:grant:Aa1lsSUPO6wXCITbk8eNFN84GlTcykTUKRcvz1PQJsau"],
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
            grant_id: "ak:grant:Aa1lsSUPO6wXCITbk8eNFN84GlTcykTUKRcvz1PQJsau",
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
      return json(route, { invites: [], next_cursor: null });
    }

    if (
      url.pathname === "/_arkret/self/contacts" &&
      route.request().method() === "GET"
    ) {
      return json(route, {
        contacts: [
          {
            peer: { kind: "human", principal_id: "did:web:bob.example" },
            state: "accepted",
            request_event_ref: "ak:event:AUftf_3k2fRKMG0NFlHe5iEMBOUpxMwYMRu-yhMJl-yz",
            response_event_ref: "ak:event:ASZZoDGudNfXFZynKh4xcEpb5d8kLZQXRpycxlg1qyW-",
            granted_to_peer_scopes: ["direct_message", "invite"],
            granted_by_peer_scopes: ["direct_message", "invite"],
            bidirectional_scopes: ["direct_message", "invite"],
            effective_scopes: ["direct_message", "invite"],
            direct_conversation: {
              realm_id: DIRECT_BOB_REALM,
              main_strand_id: DIRECT_BOB_STRAND,
              binding_event_ref:
                "ak:event:AQmnyvvBmKOWOEOSD2rAYsVBQn6vJ_wdbdUY8CKUGB5c",
              state: "found",
            },
            agents: [
              {
                agent_id: "did:web:agents.example:bob-helper",
                controller_id: "did:web:bob.example",
                display_name: "Bob Helper",
                agent_slug: "helper",
                avatar_blob_ref: DEMO_BLOB_REF,
                direct_conversation: {
                  realm_id: "ak:realm:Ab8b2glgQEo48OSA-g8P4SfHSFLwgN1jG8Jv-AlcdVnI",
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
            peer: { kind: "human", principal_id: "did:web:carol.example" },
            state: "pending_outgoing",
            request_event_ref: "ak:event:AeuYGIMbDLHP-zzs9g6vzWrgtPNhcol9h_doKgtHxKqd",
            granted_to_peer_scopes: ["invite"],
            granted_by_peer_scopes: [],
            bidirectional_scopes: [],
            effective_scopes: ["invite"],
          },
          {
            peer: { kind: "human", principal_id: "did:web:dave.example" },
            state: "pending_incoming",
            request_event_ref: "ak:event:AfUd7HcEmfmwsRFkj7CqmUVveoEJlBBWuSOdaVh5sssk",
            granted_to_peer_scopes: [],
            granted_by_peer_scopes: ["direct_message"],
            bidirectional_scopes: [],
            effective_scopes: ["direct_message"],
            // Cross-PS incoming request: respond must reverse-deliver to this PS.
            peer_service_id: "did:web:ps.dave.example",
          },
          {
            // Accepted contact with a bidirectional invite scope.
            peer: { kind: "human", principal_id: "did:web:erin.example" },
            state: "accepted",
            request_event_ref: "ak:event:AW8EyDFBpa5LQ_gV2o4w2e4G_ZHUIXLeF8U1S8DsE0yp",
            response_event_ref: "ak:event:AUsVcYxtowFdhb8kT-GukB4O9uvp6FzoXSCnnCLmV8j1",
            granted_to_peer_scopes: ["direct_message", "invite"],
            granted_by_peer_scopes: ["direct_message", "invite"],
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
        request_event_ref: "ak:event:Ac0ppqD4MwXzM_wG3nnX6dRTTTETTV6R6FC5dQMJpNKg",
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
        response_event_ref: "ak:event:ASrCVYDLWrTzqCRodpngZ6LK9iIwwIgL7l6-ajIUdfMm",
        consent_grant_refs:
          body.action === "accept"
            ? ["ak:event:AesHEt8JYmIG0EOAQhG0vgNb-fdkllGCSFjb28OLN3OY"]
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
        tombstone_event_ref: "ak:event:Ae9AOYURRtmDHAs3Nw_dqE_a9UIwCkI1yPGQQmxYgszW",
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
        holder_allowed_introduction_kinds: [
          "consent_grant",
          "locator_ref",
          "shared_realm",
        ],
        explicit_address_behavior: "quarantine",
        unknown_invites: "quarantine",
        denied_subjects: ["did:web:spammer.example"],
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
        | string
        | { agent_id?: string; principal_id?: string }
        | undefined;
      const peerId =
        typeof peer === "string"
          ? peer
          : (peer?.agent_id ?? peer?.principal_id ?? "");
      const ownedAgent = peerId === "did:web:agents.example:assistant";
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
        rejected: [],
        key_package_refs: keyPackages
          .map((entry) => entry.keypackage_ref)
          .filter((value): value is string => typeof value === "string"),
        available_count: keyPackages.length,
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
      const requestedDeviceKeys =
        typeof body.device_keys === "object" && body.device_keys !== null
          ? (body.device_keys as Record<string, unknown>)
          : {};
      const requestedPrincipalId =
        Object.keys(requestedDeviceKeys)[0] ?? accountPrincipalId;
      const requestedDevices = requestedDeviceKeys[requestedPrincipalId];
      const requestedDeviceId =
        Array.isArray(requestedDevices) &&
        typeof requestedDevices[0] === "string"
          ? requestedDevices[0]
          : currentDeviceId;
      const generationRef = "1-did-version-e2e";
      return json(route, {
        device_keys: {
          [requestedPrincipalId]: {
            [requestedDeviceId]: {
              algorithms: {},
              device_status: "active",
              device_signing_key:
                "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX",
              device_authorize_event_id:
                "ak:event:Ad-rGYKVGY9i32DG2R9ZwMezGzT5g2rmdYjrifmGO6Fe",
              authorized_generation_ref: generationRef,
            },
          },
        },
        failures: [],
        device_generations: {
          [requestedPrincipalId]: {
            current_device_generation_ref: generationRef,
            device_generation_status: "active",
          },
        },
      });
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
          id: "ak:actor_profile:AbhO_nhWEZ7jojF3JULUGyzIUTiHNshUWblbkJCr7NbP",
          schema: "ak.schema.actor_profile.v1",
          principal_id: accountPrincipalId,
          actor_kind: "user",
          display_name: "inkson",
          created_at: "2026-04-28T12:00:00.000Z",
        },
        current_device_id: currentDeviceId,
        devices: accountDeviceSummaries(),
      };
      if (primaryHandle) {
        viewer.primary_handle_claim = {
          schema: "ak.schema.handle_claim.v1",
          handle: primaryHandle,
          subject: accountPrincipalId,
          binding_state: "verified",
        };
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
        locator_token: "e2e_invite_locator_token",
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
        private_strand_id: "ak:strand:ASy992JMe_xzh5pluAqo5YuyCnAfDdFni4lmeHQldlUM",
        private_relation_id: "ak:relation:Adfmbl2dMLTHsS64Yqhc6HgCYJkB-HAVr2AGwL-KZC1d",
        access_readiness:
          sidecarPendingMemberReconciliations.length === 0
            ? "ready"
            : "access_reconciliation_pending",
        pending_access_reconciliations: sidecarPendingMemberReconciliations.map(
          (item) => ({
            provisioning_phase: "backing_scope_membership",
            ...item,
          }),
        ),
      });
    }

    if (
      url.pathname === "/_arkret/self/agent-sidecars" &&
      route.request().method() === "GET"
    ) {
      const sidecarId = "ak:sidecar:ARtoYyyaAqwT8z7xX2YLO-x_zdkPXEy8ygoDx-tu-5fm";
      const backingCircleId = "ak:circle:AbhO_nhWEZ7jojF3JULUGyzIUTiHNshUWblbkJCr7NbP";
      const desiredAgentIds = [...sidecarAgentIds].sort();
      const principalIds = [accountPrincipalId, ...desiredAgentIds].sort();
      const ready = sidecarPendingMemberReconciliations.length === 0;
      return json(route, {
        items: [
          {
            sidecar: {
              id: sidecarId,
              schema: "ak.schema.agent_sidecar.v1",
              realm_id: DEMO_REALM,
              controller_id: accountPrincipalId,
              backing_circle_id: backingCircleId,
              encryption_profile: "mls_rfc9420",
              state: "active",
              created_at: "2026-07-20T00:00:00.000Z",
            },
            desired_agent_ids: desiredAgentIds,
            effective_agent_ids: ready ? desiredAgentIds : [],
            mls_context: {
              desired_access_digest: canonicalSha256({
                domain: "ak.sidecar.desired_access.v1",
                sidecar_id: sidecarId,
                realm_id: DEMO_REALM,
                controller_id: accountPrincipalId,
                principal_ids: principalIds,
              }),
              control_frontier: [
                "ak:event:ASxjW4aTY3IHG1S2ppEjlCLLjAWhegQuSyKadYw7T3oh",
              ],
              ...(ready
                ? {
                    mls_group_id: "e2e-sidecar-group",
                    epoch: 1,
                    genesis_event_ref:
                      "ak:event:ASxjW4aTY3IHG1S2ppEjlCLLjAWhegQuSyKadYw7T3oh",
                  }
                : {}),
              current_controller_device_ready: ready,
            },
            access_readiness: ready ? "ready" : "access_reconciliation_pending",
            pending_access_reconciliations:
              sidecarPendingMemberReconciliations.map((item) => ({
                provisioning_phase: "backing_scope_membership",
                ...item,
              })),
          },
        ],
        next_cursor: null,
      });
    }

    if (
      url.pathname.startsWith("/_arkret/self/agent-sidecars/") &&
      route.request().method() === "GET"
    ) {
      const sidecarId = "ak:sidecar:ARtoYyyaAqwT8z7xX2YLO-x_zdkPXEy8ygoDx-tu-5fm";
      const backingCircleId = "ak:circle:AbhO_nhWEZ7jojF3JULUGyzIUTiHNshUWblbkJCr7NbP";
      const desiredAgentIds = [...sidecarAgentIds].sort();
      const principalIds = [accountPrincipalId, ...desiredAgentIds].sort();
      const ready = sidecarPendingMemberReconciliations.length === 0;
      return json(route, {
        sidecar: {
          id: sidecarId,
          schema: "ak.schema.agent_sidecar.v1",
          realm_id: DEMO_REALM,
          controller_id: accountPrincipalId,
          backing_circle_id: backingCircleId,
          encryption_profile: "mls_rfc9420",
          state: "active",
          created_at: "2026-07-20T00:00:00.000Z",
        },
        desired_agent_ids: desiredAgentIds,
        effective_agent_ids: ready ? desiredAgentIds : [],
        mls_context: {
          desired_access_digest: canonicalSha256({
            domain: "ak.sidecar.desired_access.v1",
            sidecar_id: sidecarId,
            realm_id: DEMO_REALM,
            controller_id: accountPrincipalId,
            principal_ids: principalIds,
          }),
          control_frontier: ["ak:event:ASxjW4aTY3IHG1S2ppEjlCLLjAWhegQuSyKadYw7T3oh"],
          ...(ready
            ? {
                mls_group_id: "e2e-sidecar-group",
                epoch: 1,
                genesis_event_ref:
                  "ak:event:ASxjW4aTY3IHG1S2ppEjlCLLjAWhegQuSyKadYw7T3oh",
              }
            : {}),
          current_controller_device_ready: ready,
        },
        access_readiness: ready ? "ready" : "access_reconciliation_pending",
        pending_access_reconciliations: sidecarPendingMemberReconciliations.map(
          (item) => ({
            provisioning_phase: "backing_scope_membership",
            ...item,
          }),
        ),
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
            error: { code: "invalid_param", message: "slug is required" },
          },
          400,
        );
      }
      const phase = typeof body.phase === "string" ? body.phase : "";
      const agentId =
        phase === "commit" && typeof body.agent_id === "string"
          ? body.agent_id
          : `did:web:agents.example:${slug}`;
      const principalControlRealmId =
        "ak:realm:AQ4lJ43jR05ytJIf7AGNbPU_MuY1FqT_ny_e8MhCCnwc";
      const controllerRealmId = DEMO_REALM;
      const controllerAuthorizationRef = `${agentId}#managed-controller`;
      const requestedScopeDigest = canonicalSha256({
        agent_id: agentId,
        controller_id: accountPrincipalId,
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
              code: "invalid_param",
              message: "phase must be prepare or commit",
            },
          },
          400,
        );
      }
      const provisionEvent =
        typeof body.provision_event === "object" && body.provision_event !== null
          ? (body.provision_event as Record<string, unknown>)
          : {};
      const event =
        typeof provisionEvent.event === "object" && provisionEvent.event !== null
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
        controller_id: accountPrincipalId,
        principal_control_realm_id: principalControlRealmId,
        controller_authorization_ref: controllerAuthorizationRef,
        pcr_recovery: { status: "pending" },
        pairing_mode: "bootstrap",
        pairing_request_id: `pair-${personalAgentCounter}`,
        pairing_code: "246810",
        pairing_expires_at: personalAgentPairingExpiresAt,
        requested_scope: body.requested_scope,
        requested_scope_digest: requestedScopeDigest,
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
        pcr_recovery: { status: "pending" },
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
        payload?.agent_id === agentId &&
        payload?.controller_id === accountPrincipalId &&
        payload?.transition === action &&
        payload?.previous_status === expectedFrom &&
        payload?.reason === expectedReason;
      if (!valid) {
        return json(
          route,
          {
            ok: false,
            error: {
              code: "invalid_param",
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
        event?.payload?.agent_id === agentId &&
        event?.payload?.controller_id === accountPrincipalId &&
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
      const renewKeyed = renewAxes.runtime_state === "ready";
      const pairingMode = renewKeyed ? "replacement" : "bootstrap";
      const keyState = {
        ...(personalAgentKeyStates.get(agentId) ?? {}),
        pairing_mode: pairingMode,
        pairing_request_id: `pair-renew-${personalAgentCounter}`,
        pairing_code: "135791",
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
        requested_scope_digest: keyState.requested_scope_digest,
        pcr_recovery: keyState.pcr_recovery,
        pairing_mode: pairingMode,
        pairing_request_id: keyState.pairing_request_id,
        pairing_code: keyState.pairing_code,
        expires_at: keyState.pairing_expires_at,
      });
    }

    const agentGrantsMatch = url.pathname.match(
      /^\/_arkret\/self\/agents\/([^/]+)\/grants$/,
    );
    if (agentGrantsMatch && route.request().method() === "POST") {
      const agentId = decodeURIComponent(agentGrantsMatch[1]);
      const body = ((await contractRequestBody(route)) ?? {}) as Record<
        string,
        unknown
      >;
      const grants = personalAgentGrants.get(agentId) ?? [];
      const grant = {
        grant_id: `ak:grant:01964137-0000-7000-8000-${String(grants.length + 1).padStart(12, "0")}`,
        ...(typeof body.grant === "object" && body.grant !== null
          ? (body.grant as Record<string, unknown>)
          : {}),
      };
      grants.push(grant);
      personalAgentGrants.set(agentId, grants);
      return json(route, {
        ok: true,
        grant_id: grant.grant_id,
      });
    }

    const agentParticipationMatch = url.pathname.match(
      /^\/_arkret\/self\/agents\/([^/]+)\/participation$/,
    );
    if (agentParticipationMatch && route.request().method() === "GET") {
      return json(route, { entries: [] });
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
        key_state: storedKeyState ?? null,
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
      const agentId = String(body.agent_id ?? "");
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
      const authorizedEventRef =
        "ak:event:Ad-rGYKVGY9i32DG2R9ZwMezGzT5g2rmdYjrifmGO6Fe";
      agent.lifecycle = "active";
      agent.updated_at = "2026-07-06T00:05:00.000Z";
      const previousKeyState = personalAgentKeyStates.get(agentId) ?? {};
      const nextKeyState: Record<string, unknown> = {
        ...previousKeyState,
        authorized_event_ref: authorizedEventRef,
        active_authorizations: [
          {
            key_id:
              String(body.verification_method ?? "")
                .split("#")
                .pop() ?? "runtime-key-1",
            verification_method: body.verification_method,
            authorized_event_ref: authorizedEventRef,
          },
        ],
      };
      delete nextKeyState.pairing_request_id;
      delete nextKeyState.pairing_mode;
      delete nextKeyState.pairing_code;
      delete nextKeyState.pairing_expires_at;
      personalAgentKeyStates.set(agentId, nextKeyState);
      return json(route, {
        ok: true,
        agent_id: agentId,
        activation_state: "active",
        authorize_event_ref: authorizedEventRef,
        signing_key_binding: body.signing_key_binding,
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
        authorized_event_ref: "ak:event:AQUeFABQK9MQb8JmkZyP7wD2QfYOSDaCH1LDepfyMD-G",
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
        gate_audience: url.origin,
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
          alg: "Ed25519",
          key: "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
        },
        client_nonce: "Y290ZXN0LWRldmljZS1wYWlyaW5nLW5vbmNl",
        gate_audience: url.origin,
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
        authorized_event_ref: "ak:event:AQUeFABQK9MQb8JmkZyP7wD2QfYOSDaCH1LDepfyMD-G",
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
        size_bytes: 68,
        media_type: "image/jpeg",
        content_digest:
          "sha256:431ced6916a2a21a156e38701afe55bbd7f88969fbbfc56d7fe099d47f265460",
        upload_receipt: null,
      });
    }

    if (
      url.pathname === "/_arkret/self/rtc/ice-config" &&
      route.request().method() === "POST"
    ) {
      const body = await route.request().postDataJSON();
      return json(route, {
        realm_id: body.realm_id ?? DEMO_REALM,
        call_id: body.call_id ?? "ak:call:AbhvODyrIRCskAIoS9IXLjMfD-Zsr8lwDpiCU_zLR4it",
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
        issued_at: "2026-05-19T00:00:00.000Z",
        signature: {
          alg: "Ed25519",
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
        contentType: "image/png",
        body: Buffer.from(DEMO_AVATAR_PNG_BASE64, "base64"),
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
        recoveryPolicy = {
          policy_id: policy.policy_id,
          principal_id: policy.principal_id,
          version: policy.version,
          acceptance_basis: `ak:seal:sha256:${"a".repeat(64)}`,
          trust_domain: policy.trust_domain,
          allowed_proof_kinds: Array.isArray(policy.allowed_proof_kinds)
            ? policy.allowed_proof_kinds
            : [],
          supersedes: policy.supersedes ?? null,
          expires_at: policy.expires_at ?? null,
          issued_at: policy.issued_at,
          accepted_at: acceptedAt,
          policy,
        };
        return json(route, {
          ok: true,
          policy_id: policy.policy_id,
          principal_id: policy.principal_id,
          version: policy.version,
          acceptance_basis: `ak:seal:sha256:${"a".repeat(64)}`,
          accepted_at: acceptedAt,
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
        reconcileAgentPcrRecovery();
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
      const backupClass = url.searchParams.get("backup_kind");
      const backups = Array.from(keyBackups.values()).filter((backup) =>
        backupClass ? backup.backup_kind === backupClass : true,
      );
      return json(route, { backups, has_more: false });
    }

    const contractResponse = mockArkretContract({
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
    as_of: "2026-06-13T00:00:00.000Z",
    // No `source_refs`: a mocked entry has no Event provenance.
    policy_revision: "mock-policy-rev",
  };
}

function joinCandidate() {
  return {
    realm_id: DEMO_REALM,
    service_id: "did:web:server.local",
    service_kind: "principal_server",
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
      governance_health: {
        status: "healthy",
        pending_proposals: [],
        retained_faults: [],
      },
    },
    as_of: "2026-05-30T00:00:00.000Z",
    expires_at: "2099-01-01T00:00:00.000Z",
  };
}

function mimiProviderDirectory() {
  return {
    service_kind: "mimi_provider",
    supported_profiles: ["ak.profile.mimi_interop.v1"],
    mimi: {
      protocol_draft: "draft-ietf-mimi-protocol-06",
      content_draft: "draft-ietf-mimi-content-08",
      base_url: "https://mimi.example.com/_arkret/open/mimi",
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
    },
  };
}

function withRequiredEventScopeRefs(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(withRequiredEventScopeRefs);
  }
  if (value === null || typeof value !== "object") {
    return value;
  }
  const record = Object.fromEntries(
    Object.entries(value).map(([key, child]) => [
      key,
      withRequiredEventScopeRefs(child),
    ]),
  );
  const isEvent =
    typeof record.event_id === "string" &&
    typeof record.kind === "string" &&
    typeof record.realm_id === "string";
  if (isEvent && record.scope_ref === undefined) {
    record.scope_ref = {
      kind: "realm",
      realm_id: record.realm_id,
    };
  }
  return record;
}

function json(route: Route, body: unknown, status = 200) {
  return route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(withRequiredEventScopeRefs(body)),
  });
}
