import { expect, test } from "@playwright/test";
import {
  CURRENT_ASSISTANT_CORE_ID,
  mockArkretApi,
  validateMockSchema,
} from "../e2e/mockArkretApi";
import { captureRouteHandler, driveOnce } from "./mockShapeDriver";

const ASSISTANT_ID = CURRENT_ASSISTANT_CORE_ID;
const ASSISTANT_URL = `https://local.host/_arkret/self/agents/${encodeURIComponent(ASSISTANT_ID)}`;

for (const binding of ["missing", "mismatched"] as const) {
  test(`deactivation ${binding} binding fixture preserves the selected Agent`, async () => {
    const { page, handler } = captureRouteHandler();
    await mockArkretApi(page as never, { assistantKeyBinding: binding });
    const response = await driveOnce(handler(), {
      url: ASSISTANT_URL, method: "GET",
    });
    expect(response?.status).toBe(200);
    const body = response?.body as Record<string, any>;
    expect(body.agent.agent_id).toBe(ASSISTANT_ID);
    expect(body.agent.lifecycle).toBe("active");
    if (binding === "missing") {
      expect(body.key_state).toBeUndefined();
    } else {
      expect(body.key_state.agent_id).not.toBe(ASSISTANT_ID);
    }
  });
}

test("invalid deactivation submission cannot mutate the Agent fixture", async () => {
  const { page, handler } = captureRouteHandler();
  await mockArkretApi(page as never);
  await expect(
    driveOnce(handler(), {
      url: `${ASSISTANT_URL}/deactivate`,
      method: "POST",
      postData: { key_revocation_events: [], capability_revocation_events: [] },
    }),
  ).rejects.toThrow("agent_deactivate_request_body");
  const response = await driveOnce(handler(), {
    url: ASSISTANT_URL, method: "GET",
  });
  const body = response?.body as Record<string, any>;
  expect(body.agent.lifecycle).toBe("active");
  expect(body.key_state.active_authorizations).toHaveLength(1);
});

test("Agent lifecycle outcome remains closed status-only", () => {
  const schema = "schemas/agent-operations.schema.json#/$defs/agent_lifecycle_state";
  expect(() => validateMockSchema(schema, { status: "deactivated" })).not.toThrow();
  expect(() => validateMockSchema(schema, {
    status: "deactivated",
    lifecycle_ref: {
      event_id: "ak:event:AfoRpfP-sl-s9gK_9-GfLiYW9eincnIfCJF8xRcVowkj",
      commit_id: "ak:realm_commit:AfoRpfP-sl-s9gK_9-GfLiYW9eincnIfCJF8xRcVowkj",
      stream_ref: {
        kind: "realm",
        realm_id: "ak:realm:AS7wchHFRbXWnMQPln42BrokXsPCf18uboKMm-yhYquI",
      },
      stream_position: 0,
    },
  })).toThrow("additionalProperties");
});
