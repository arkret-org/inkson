import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { mockArkretApi, validateMockResponseForOperation } from "../e2e/mockArkretApi";
import { captureRouteHandler, driveOnce, mockOperations } from "./mockShapeDriver";
import { IMPLEMENTED_REMAINING_OPERATIONS } from "./remainingOperationProbes";
import { NATIVE_READ_OPERATIONS } from "./nativeReadEvidence";
import { UNIMPLEMENTED_OPERATIONS, UNIMPLEMENTED_PROBLEM_OPERATIONS } from "./mockOperationCoverage";

const OPERATION = "ak.self.keys.backups.command.issue_unlock_challenge.v1";
const BACKUPS = "https://local.host/_arkret/self/keys/backups";

test("unimplemented native backup challenges refuse without minting authority or changing summaries", async () => {
  const captured = captureRouteHandler();
  await mockArkretApi(captured.page as any, { preseedRecoveryMaterial: true });
  const handler = captured.handler();
  const before = await driveOnce(handler, { method: "GET", url: BACKUPS });
  const backupId = (before!.body as any).backups[0].backup_id;
  const response = await driveOnce(handler, {
    method: "POST", url: `${BACKUPS}/${backupId}/unlock-challenge`,
    postData: { request_id: Buffer.alloc(16, 1).toString("base64url") },
  });
  expect(response!.status).toBe(501);
  expect(response!.contentType).toBe("application/problem+json");
  expect(response!.body).toMatchObject({ type: "https://arkret.org/problems/not_implemented", title: "Not implemented", status: 501 });
  expect(Object.keys(response!.body as object).sort()).toEqual(["detail", "status", "title", "type"]);
  for (const field of ["nonce", "challenge", "challenge_id", "proof", "signature"]) {
    expect(response!.body).not.toHaveProperty(field);
  }
  const operation = mockOperations().find(row => row.operation_id === OPERATION)!;
  expect(() => validateMockResponseForOperation(operation, 200, response!.body, "application/json")).toThrow();
  expect(await driveOnce(handler, { method: "GET", url: BACKUPS })).toEqual(before);
});

test("a refusal does not grant native backup coverage or suppress other missing operations", async () => {
  const review = JSON.parse(readFileSync(new URL("./mock-operation-review.json", import.meta.url), "utf8"));
  expect(review.operations.find((row: any) => row.operation_id === OPERATION)).toMatchObject({ verification_need: "native_authority", mock_test: null });
  expect(IMPLEMENTED_REMAINING_OPERATIONS.has(OPERATION)).toBe(false);
  expect(NATIVE_READ_OPERATIONS.has(OPERATION)).toBe(false);
  expect(UNIMPLEMENTED_OPERATIONS.has(OPERATION)).toBe(true);
  expect(UNIMPLEMENTED_PROBLEM_OPERATIONS.has(OPERATION)).toBe(true);
  const captured = captureRouteHandler();
  await mockArkretApi(captured.page as any);
  await expect(driveOnce(captured.handler(), {
    method: "POST", url: `${BACKUPS}/ak:backup:01964137-0000-7000-8000-0000000000b1/unlock`, postData: {},
  })).rejects.toThrow("mock operation is not implemented");
});
