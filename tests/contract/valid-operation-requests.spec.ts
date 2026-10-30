import { expect, test } from "@playwright/test";
import { mockArkretApi, CURRENT_ASSISTANT_CORE_ID } from "../e2e/mockArkretApi";
import { captureRouteHandler, driveOnce, mockOperations } from "./mockShapeDriver";
import { MOCK_INSTALLS } from "./mockOperationCoverage";
import { operationProbe, VALID_REQUEST_OPERATIONS } from "./mockOperationProbes";

for (const [index, install] of MOCK_INSTALLS.entries()) {
  for (const id of VALID_REQUEST_OPERATIONS) {
    test(`valid request and closed negative for ${id} under install ${index}`, async () => {
      const captured = captureRouteHandler();
      await mockArkretApi(captured.page as never, install);
      const operation = mockOperations().find(op => op.operation_id === id)!;
      const request = await operationProbe(operation, captured.handler());
      let emitted = 0;
      await expect(driveOnce(captured.handler(), { ...request, postData: { ...(request.postData as object), obsolete: true }, onFulfill: () => { emitted += 1; } })).rejects.toThrow();
      expect(emitted).toBe(0);
      if (operation.method === "DELETE") {
        await expect(driveOnce(captured.handler(), { ...request, url: request.url.replace(/[^/]+$/, "foreign-actor"), onFulfill: () => { emitted += 1; } })).rejects.toThrow();
        expect(emitted).toBe(0);
      }
      const response = await driveOnce(captured.handler(), request);
      expect(response?.status).toBe(200);
      const body = request.postData as Record<string, any>;
      if (id.startsWith("ak.self.circle.member.")) expect(response?.body).toEqual({
        circle_id: body.member_event.event.payload.circle_id, member_id: body.member_event.event.payload.member_id,
        membership: body.member_event.event.payload.membership,
      });
      else if (id.startsWith("ak.self.agent.command.")) {
        const state = id.includes("deactivate") ? "deactivated" : id.includes("resume") ? "active" : "paused";
        expect(response?.body).toEqual({ status: state });
        const current = await driveOnce(captured.handler(), { method: "GET", url: `https://local.host/_arkret/self/agents/${encodeURIComponent(CURRENT_ASSISTANT_CORE_ID)}` });
        expect((current?.body as any).agent.lifecycle).toBe(state);
      } else if (id.includes("ice_config")) expect(response?.body).toMatchObject({ realm_id: body.realm_id, call_id: body.call_id, actor_id: body.actor_id, device_id: body.device_id });
      else expect(response?.body).toEqual(request.postData);
    });
  }
}
