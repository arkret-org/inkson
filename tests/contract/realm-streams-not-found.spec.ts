import { expect, test } from "@playwright/test";
import {
  DEMO_REALM, INVITED_REALM, mockArkretApi,
  validateMockResponseForOperation, validateMockSchema,
} from "../e2e/mockArkretApi";
import { captureRouteHandler, driveOnce, mockOperations } from "./mockShapeDriver";

const operationId = "ak.self.realm.read.streams.v1";
const absentRealm = "ak:realm:AUEAoXMJeJWBETvkqm7gk4imduk7g-l8bim19OPFQDaO";

test("Realm stream enumeration returns the same closed not_found for absent and invisible Realms, preserving accepted stream anchors", async () => {
  const { page, handler } = captureRouteHandler();
  await mockArkretApi(page as never, { invitePreview: "disclosed" });
  const read = (realm: string) => driveOnce(handler(), {
    method: "GET", url: `https://local.host/_arkret/self/realms/${encodeURIComponent(realm)}/streams?limit=500`,
  });
  const missing = await read(absentRealm);
  expect(missing?.status).toBe(404);
  expect(missing).toEqual(await read(INVITED_REALM));
  expect(missing?.body).toMatchObject({
    type: "https://arkret.org/problems/not_found", title: "Not found", status: 404,
  });
  expect(Object.keys(missing!.body as object).sort()).toEqual(["detail", "status", "title", "type"]);
  validateMockSchema("schemas/http-problem-details.schema.json", missing!.body);
  const accepted = await read(DEMO_REALM);
  expect(accepted?.status).toBe(200);
  validateMockSchema("schemas/realm-read-operations.schema.json#/$defs/realm_stream_list", accepted!.body);
  expect(accepted).toEqual(await read(DEMO_REALM));
  expect(JSON.stringify(accepted!.body)).toContain("head_commit_ref");

  const operations = mockOperations();
  const operation = operations.find(row => row.operation_id === operationId)!;
  const validate = (status: number, body: unknown, type = "application/problem+json") =>
    validateMockResponseForOperation(operation, status, body, type);
  expect(() => validate(404, missing!.body)).not.toThrow();
  for (const status of [200, 403, 500]) expect(() => validate(status, missing!.body)).toThrow();
  expect(() => validate(404, missing!.body, "application/json")).toThrow();
  for (const change of [
    { status: 403 }, { title: "Wrong title" }, { type: "https://arkret.org/problems/unregistered" },
    { streams: [] }, { detail: "" },
  ]) expect(() => validate(404, { ...(missing!.body as object), ...change })).toThrow();
  const unrelated = operations.find(row => row.operation_id !== operationId && !row.responses["404"] && !row.responses.default)!;
  expect(() => validateMockResponseForOperation(unrelated, 404, missing!.body, "application/problem+json")).toThrow();
});
