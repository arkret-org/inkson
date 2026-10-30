import { expect, test } from "@playwright/test";
import { randomBytes } from "node:crypto";
import { mockArkretApi, validateMockSchema } from "../e2e/mockArkretApi";
import { captureRouteHandler, driveOnce, mockOperations } from "./mockShapeDriver";
import { MOCK_INSTALLS } from "./mockOperationCoverage";
import { NATIVE_READ_OPERATIONS, nativeReadProbe, nativeReadTranscripts } from "./nativeReadEvidence";

for (const [index, install] of MOCK_INSTALLS.entries()) {
  for (const id of NATIVE_READ_OPERATIONS) {
    test(`native accepted read replay preserves original contract: ${id}, install ${index}`, async () => {
      const captured = captureRouteHandler();
      await mockArkretApi(captured.page as never, { ...install, nativeReadEvidence: true });
      const operation = mockOperations().find(row => row.operation_id === id)!;
      const request = nativeReadProbe(operation)!;
      const row = nativeReadTranscripts().find(row => row.operation_id === id)!;
      let emitted = 0;
      const response = await driveOnce(captured.handler(), { ...request, onFulfill: () => { emitted += 1; } });
      expect(response?.status).toBe(200); expect(emitted).toBe(1);
      expect(response?.body).toEqual(row.response_body);
      const reference = operation.responses["200"].schema_ref!;
      expect(() => validateMockSchema(reference, { ...(response!.body as object), obsolete_result: {} })).toThrow();
      const missingSelector = await driveOnce(captured.handler(), { ...request, headers: {} });
      expect(missingSelector?.status).toBe(400);
      expect(String((missingSelector!.body as Record<string, unknown>).type)).toContain("operation_selector_required");
      for (const selector of ["", "ak.unregistered.operation.v1", "ak.open.service.read.describe.v1", `${id}, ${id}`]) {
        const unsupported = await driveOnce(captured.handler(), {
          ...request, headers: { ...request.headers, "arkret-operation": selector, authorization: "Bearer another-mock-account" },
        });
        expect(unsupported?.status).toBe(422);
        expect(String((unsupported!.body as Record<string, unknown>).type)).toContain("unsupported_operation_version");
      }
      const changed = row.request_body === null
        ? { ...request, url: `${request.url}${request.url.includes("?") ? "&" : "?"}unknown_selector=1` }
        : { ...request, postData: { ...(request.postData as object), obsolete_selector: true } };
      expect((await driveOnce(captured.handler(), changed))?.status).toBe(422);
      expect((await driveOnce(captured.handler(), { ...request, headers: { ...request.headers, authorization: "Bearer another-mock-account" } }))?.status).toBe(id.startsWith("ak.open.") ? 200 : 401);
      expect((await driveOnce(captured.handler(), { ...request, url: request.url.replace("native-read-archive.example", "another-archive.example") }))?.status).toBe(503);
      expect((await driveOnce(captured.handler(), request))?.body).toEqual(row.response_body);
    });
  }
}

test("archival authority responses cannot be rebound to a fresh valid challenge", async () => {
  const captured = captureRouteHandler();
  await mockArkretApi(captured.page as never, { nativeReadEvidence: true });
  for (const id of ["ak.self.realm_actor.read.material.v1", "ak.peer.realm_actor.read.material.v1"]) {
    const operation = mockOperations().find(row => row.operation_id === id)!;
    const request = nativeReadProbe(operation)!;
    const body = structuredClone(request.postData) as Record<string, any>;
    const selector = id.startsWith("ak.peer.") ? body.request : body;
    selector.request_nonce = randomBytes(32).toString("base64url");
    expect((await driveOnce(captured.handler(), { ...request, postData: body }))?.status).toBe(503);
    expect((await driveOnce(captured.handler(), request))?.body).toEqual(nativeReadTranscripts().find(row => row.operation_id === id)!.response_body);
  }
});
