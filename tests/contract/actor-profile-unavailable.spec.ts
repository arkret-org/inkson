import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { mockArkretApi, validateMockResponseForOperation, validateMockSchema } from "../e2e/mockArkretApi";
import { captureRouteHandler, driveOnce, mockOperations } from "./mockShapeDriver";
import { nativeReadProbe, nativeReadTranscripts, NATIVE_READ_OPERATIONS } from "./nativeReadEvidence";
import { IMPLEMENTED_REMAINING_OPERATIONS } from "./remainingOperationProbes";

const OPERATION = "ak.self.actor_profile.read.resolve.v1";
const ENDPOINT = "https://local.host/_arkret/self/actor-profiles/query";

test("ordinary Actor Profile reads refuse without borrowing archival profile authority", async () => {
  const captured = captureRouteHandler();
  await mockArkretApi(captured.page as never);
  const record = nativeReadTranscripts().find(row => row.operation_id === OPERATION)!;
  validateMockSchema("schemas/actor-profile-operations.schema.json#/$defs/resolve_request_body", record.request_body);
  const request = { method: "POST", url: ENDPOINT, postData: structuredClone(record.request_body),
    headers: { authorization: "Bearer sx:e2e-token", "arkret-operation": OPERATION } };
  const response = await driveOnce(captured.handler(), request);
  expect(response?.status).toBe(501);
  expect(response?.contentType).toBe("application/problem+json");
  expect(response?.body).toMatchObject({ type: "https://arkret.org/problems/not_implemented", title: "Not implemented", status: 501 });
  expect(Object.keys(response!.body as object).sort()).toEqual(["detail", "status", "title", "type"]);
  const operation = mockOperations().find(row => row.operation_id === OPERATION)!;
  expect(() => validateMockResponseForOperation(operation, 501, response?.body, "application/problem+json")).not.toThrow();
  expect(() => validateMockResponseForOperation(operation, 200, response?.body, "application/json")).toThrow();
  await expect(driveOnce(captured.handler(), { ...request, headers: { authorization: "Bearer sx:e2e-token", "arkret-operation": "ak.self.consent.read.list.v1" } })).rejects.toThrow();
  await expect(driveOnce(captured.handler(), { ...request, method: "GET", postData: undefined })).rejects.toThrow();
});

test("Actor Profile refusal preserves the fourteen exact native archival replay contracts", async () => {
  const review = JSON.parse(readFileSync(new URL("./mock-operation-review.json", import.meta.url), "utf8"));
  expect(review.operations.find((row: any) => row.operation_id === OPERATION)).toMatchObject({ verification_need: "native_fixture_replay" });
  expect(IMPLEMENTED_REMAINING_OPERATIONS.has(OPERATION)).toBe(false);
  expect(NATIVE_READ_OPERATIONS.size).toBe(14);
  expect(NATIVE_READ_OPERATIONS.has(OPERATION)).toBe(true);
  const captured = captureRouteHandler();
  await mockArkretApi(captured.page as never, { nativeReadEvidence: true });
  const operation = mockOperations().find(row => row.operation_id === OPERATION)!;
  const original = nativeReadTranscripts().find(row => row.operation_id === OPERATION)!;
  const probe = nativeReadProbe(operation)!;
  const denied = await driveOnce(captured.handler(), { ...probe, headers: { ...probe.headers, authorization: "Bearer sx:e2e-token" } });
  expect(denied?.status).toBe(401);
  expect(Object.keys(denied!.body as object).sort()).toEqual(["detail", "status", "title", "type"]);
  const accepted = await driveOnce(captured.handler(), probe);
  expect(accepted?.status).toBe(200);
  expect(accepted?.body).toEqual(original.response_body);
});
