import { readFileSync } from "node:fs";
import type { MockOperation } from "./mockShapeDriver";

// Transcript coordinates are test plumbing. Protocol bodies remain opaque and
// are checked by the SDK schema gate and the native producing contract.
export const NATIVE_READ_OPERATIONS = new Set([
  "ak.edge.applet.actor.read.resolve.v1", "ak.edge.applet.third_party_users.read.list.v1",
  "ak.open.identity.read.resolution.v1", "ak.self.identity.read.resolution_audit.v1",
  "ak.self.actor_profile.read.resolve.v1", "ak.self.consent.read.list.v1",
  "ak.self.consent.resource.get.v1", "ak.self.media_service_binding.read.resolve.v1",
  "ak.self.mls.read.group_state_material.v1", "ak.self.mls.read.roster_authority.v1",
  "ak.peer.mls.read.group_state_material.v1", "ak.peer.mls.read.roster_authority.v1",
  "ak.self.realm_actor.read.material.v1", "ak.peer.realm_actor.read.material.v1",
]);
export type NativeReadTranscript = {
  operation_id: string; method: string; path: string; request_body: unknown;
  response_body: unknown; verified_at: string; accepted_originals: unknown;
};
let cached: NativeReadTranscript[] | undefined;
export function nativeReadTranscripts(): NativeReadTranscript[] {
  if (cached) return cached;
  const corpus = JSON.parse(readFileSync(new URL("./fixtures/native-read-evidence.json", import.meta.url), "utf8"));
  if (corpus.format_version !== 1 || corpus.semantics !== "archival_native_read_transcript") throw new Error("native read transcript semantics drift");
  const records = corpus.operations as NativeReadTranscript[];
  if (records.length !== 14 || new Set(records.map(row => row.operation_id)).size !== 14
      || records.some(row => !NATIVE_READ_OPERATIONS.has(row.operation_id) || !row.accepted_originals || !row.response_body)) {
    throw new Error("native read evidence requires all fourteen real successful responses");
  }
  return cached = records;
}
export const ARCHIVAL_READ_CREDENTIAL = "Bearer archival-native-read-fixture";
export function nativeReadProbe(operation: MockOperation) {
  if (!NATIVE_READ_OPERATIONS.has(operation.operation_id)) return undefined;
  const row = nativeReadTranscripts().find(row => row.operation_id === operation.operation_id)!;
  return { method: row.method, url: `https://native-read-archive.example${row.path}`,
    headers: { "arkret-operation": row.operation_id, ...(row.operation_id.startsWith("ak.open.") ? {} : { authorization: ARCHIVAL_READ_CREDENTIAL }) },
    ...(row.request_body === null ? {} : { postData: structuredClone(row.request_body) }) };
}
