import { expect, test } from "@playwright/test";
import { buildMockProblem, validateRegisteredMockProblem, validateMockResponseForOperation, mockArkretApi } from "../e2e/mockArkretApi";
import { captureRouteHandler, driveOnce, mockOperations } from "./mockShapeDriver";

test("error producers use registered flat Problem members and media type", () => {
  for (const code of ["not_found", "param_invalid", "failed_precondition", "schema_violation"]) {
    const problem = buildMockProblem(code, "contract rejection");
    expect(problem).not.toHaveProperty("error");
    expect(problem).not.toHaveProperty("code");
    validateRegisteredMockProblem(problem.status, problem, "application/problem+json");
    expect(() => validateRegisteredMockProblem(problem.status, problem, "application/json")).toThrow();
    expect(() => validateRegisteredMockProblem(problem.status + 1, problem, "application/problem+json")).toThrow();
    for (const key of ["code", "message", "details", "ok"]) {
      expect(() => validateRegisteredMockProblem(problem.status, { ...problem, [key]: "legacy" }, "application/problem+json")).toThrow(/legacy aliases/);
    }
    expect(() => validateRegisteredMockProblem(problem.status, { error: { code } }, "application/problem+json")).toThrow();
  }
  expect(() => buildMockProblem("circle_not_active", "unregistered transport code")).toThrow();
  expect(() => buildMockProblem("failed_precondition", "rejected", "unregistered_reason")).toThrow();
  const signal = mockOperations().find(entry => entry.operation_id === "ak.self.signal.stream.subscribe.v1")!;
  expect(() => validateMockResponseForOperation(signal, 403, undefined)).toThrow();
  expect(() => validateMockResponseForOperation(signal, 403, buildMockProblem("capability_denied", "denied"), "application/problem+json")).not.toThrow();
  const noContent = mockOperations().find(entry => entry.responses["204"]?.schema_ref === null)!;
  expect(() => validateMockResponseForOperation(noContent, 204, undefined)).not.toThrow();
  expect(() => validateMockResponseForOperation(noContent, 204, {}, "application/json")).toThrow("forbids a JSON body");
  const operation = { operation_id: "ak.self.agent.resource.get.v1", method: "GET", path_template: "/_arkret/self/agents/{agent_id}", responses: {} };
  const allowed = buildMockProblem("not_found", "unknown Agent");
  validateMockResponseForOperation(operation, allowed.status, allowed, "application/problem+json");
  const unrelated = buildMockProblem("realm_state_snapshot_unavailable", "wrong operation");
  expect(() => validateMockResponseForOperation(operation, unrelated.status, unrelated, "application/problem+json")).toThrow(/registered error surface/);
});

test("actual Agent mock failures satisfy the same Problem contract", async () => {
  const { page, handler } = captureRouteHandler();
  await mockArkretApi(page as never, { includeDemoRealms: false });
  for (const request of [
    { method: "GET", url: "https://local.host/_arkret/self/agents/ak%3Adid_core%3Aweb%3Aunknown.example" },
    { method: "POST", url: "https://local.host/_arkret/self/agents", postData: {} },
  ]) {
    const response = await driveOnce(handler(), request);
    expect(response).not.toBeNull();
    validateRegisteredMockProblem(response!.status, response!.body, response!.contentType);
  }
});
