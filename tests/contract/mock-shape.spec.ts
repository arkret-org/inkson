import { expect, test } from "@playwright/test";
import { readFileSync, writeFileSync } from "node:fs";
import { mockArkretApi } from "../e2e/mockArkretApi";
import { captureRouteHandler, driveOnce, mockOperations } from "./mockShapeDriver";
import { ACCOUNT_AUTHORITY_OPERATIONS, CONDITIONAL_OPERATIONS, MOCK_INSTALLS, PROVIDER_FIXTURE_OPERATIONS, UNIMPLEMENTED_OPERATIONS } from "./mockOperationCoverage";
import { IMPLEMENTED_REMAINING_OPERATIONS } from "./remainingOperationProbes";
import { NATIVE_READ_OPERATIONS } from "./nativeReadEvidence";
const review = JSON.parse(readFileSync(new URL("./mock-operation-review.json", import.meta.url), "utf8")) as { operations: { operation_id: string; verification_need: string }[] };
import { operationProbe, VALID_REQUEST_OPERATIONS } from "./mockOperationProbes";

test("operation inventory separates response observations from uncovered native contracts", async () => {
  test.setTimeout(240_000);
  const operations = mockOperations();
  const ids = new Set(operations.map(operation => operation.operation_id));
  const classifications = [UNIMPLEMENTED_OPERATIONS, PROVIDER_FIXTURE_OPERATIONS, ACCOUNT_AUTHORITY_OPERATIONS];
  for (const group of classifications) for (const id of group) expect(ids.has(id), `stale classification: ${id}`).toBe(true);
  const nonProducing = classifications.flatMap(group => [...group]);
  expect(new Set(nonProducing).size, "operation classifications must be disjoint").toBe(nonProducing.length);
  const validated = new Set<string>();
  const validRequests = new Set<string>();
  const failures: string[] = [];
  const evidence: unknown[] = [];
  for (const [index, install] of MOCK_INSTALLS.entries()) {
    const { page, handler } = captureRouteHandler();
    await mockArkretApi(page as never, { ...install, nativeReadEvidence: true });
    for (const operation of operations) {
      const id = operation.operation_id;
      const unsupported = UNIMPLEMENTED_OPERATIONS.has(id) || (index === 0 && CONDITIONAL_OPERATIONS.has(id));
      const expected = unsupported ? `mock operation is not implemented: ${id}`
        : PROVIDER_FIXTURE_OPERATIONS.has(id) ? "provider-only MIMI POST requires a native authenticated provider fixture"
        : ACCOUNT_AUTHORITY_OPERATIONS.has(id) ? "account registration requires a native authenticated Account Authority fixture"
        : undefined;
      let emitted = 0;
      try {
        let active = handler();
        if (["ak.self.agent.command.deactivate.v1", "ak.self.agent.command.pause.v1", "ak.self.agent.command.resume.v1"].includes(id)) {
          const isolated = captureRouteHandler();
          await mockArkretApi(isolated.page as never, { ...install, nativeReadEvidence: true });
          active = isolated.handler();
        }
        const request = await operationProbe(operation, active);
        const response = await driveOnce(active, { ...request, onFulfill: () => { emitted += 1; } });
        if (expected) throw new Error(`stale non-producing classification emitted a response: ${id}`);
        expect(response, `${id} must produce a validated response, not continue/abort`).not.toBeNull();
        expect(emitted).toBe(1);
        validated.add(id);
        if (VALID_REQUEST_OPERATIONS.has(id) || IMPLEMENTED_REMAINING_OPERATIONS.has(id) || NATIVE_READ_OPERATIONS.has(id)) {
          expect(response?.status, `${id} valid request must succeed`).toBe(200);
          validRequests.add(`${index}:${id}`);
        }
        evidence.push({ install: index, operation_id: id, verdict: NATIVE_READ_OPERATIONS.has(id) ? "archival_native_response_contract" : IMPLEMENTED_REMAINING_OPERATIONS.has(id) ? "mock_contract" : "response_schema", native_authority_contract: "not_run_in_mock", status: response?.status, media_type: response?.contentType });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (expected && message === expected && emitted === 0) evidence.push({ install: index, operation_id: id, verdict: "uncovered", boundary_rejection_observed: true, native_authority_contract: "not_run", verification_need: review.operations.find(row => row.operation_id === id)?.verification_need ?? "conditional_fixture", reason: expected });
        else failures.push(`${index}:${id}: ${message}`);
      }
    }
  }
  if (process.env.MOCK_COVERAGE_REPORT) writeFileSync(process.env.MOCK_COVERAGE_REPORT, JSON.stringify({ evidence, failures }, null, 2));
  await test.info().attach("mock-operation-coverage", { body: JSON.stringify({ evidence, failures }, null, 2), contentType: "application/json" });
  expect(failures, failures.join("\n")).toEqual([]);
  const expectedProducing = [...ids].filter(id => !nonProducing.includes(id)).sort();
  expect([...validated].sort(), "every response-producing operation must be judged").toEqual(expectedProducing);
  expect(validRequests.size, "all valid-request operations must succeed in both installs").toBe(new Set([...VALID_REQUEST_OPERATIONS, ...IMPLEMENTED_REMAINING_OPERATIONS, ...NATIVE_READ_OPERATIONS]).size * MOCK_INSTALLS.length);
  expect(evidence).toHaveLength(operations.length * MOCK_INSTALLS.length);
  console.log(`mock response inventory: ${ids.size} operations classified; ${validated.size} response producers validated; ${IMPLEMENTED_REMAINING_OPERATIONS.size} newly implemented mock contracts; ${nonProducing.length} uncovered operations (boundary rejection is not coverage)`);
});
