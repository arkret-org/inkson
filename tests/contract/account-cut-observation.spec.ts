import { expect, test } from "@playwright/test";
import { deliveredMockAccountBody, mockArkretApi, observeSuccessfulSignerQueries } from "../e2e/mockArkretApi";
import { captureRouteHandler } from "./mockShapeDriver";

test("Account cut observation binds actual fulfilled bytes to one request without requiring body EOF", async () => {
  const captured = captureRouteHandler();
  await mockArkretApi(captured.page as any);
  const request = {
    method: () => "GET",
    url: () => "https://server.local/_arkret/self/account/subscribe?catchup=false",
    headers: () => ({ authorization: "Bearer sx:e2e-token" }),
    postDataJSON: () => ({}),
  };
  const response = {
    request: () => request,
    status: () => 200,
    headers: () => ({ "content-type": "application/x-ndjson; charset=utf-8" }),
    finished: () => { throw new Error("consumer cancelled after its first delta"); },
    text: () => { throw new Error("whole body is unavailable after cancellation"); },
  };
  await expect(deliveredMockAccountBody(response as any)).rejects.toThrow("no matching fulfilled mock request");
  let entered!: () => void;
  const fulfilling = new Promise<void>(resolve => { entered = resolve; });
  let release!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  let sent: any;
  const handling = captured.handler()({
    request: () => request,
    fulfill: async (value: any) => { sent = value; entered(); await held; },
    continue: async () => {},
  });
  await fulfilling;
  let resolved = false;
  const observed = deliveredMockAccountBody(response as any).then(body => { resolved = true; return body; });
  await new Promise<void>(resolve => setImmediate(resolve));
  expect(resolved).toBe(false);
  release();
  await handling;
  const body = await observed;
  expect(body).toBe(sent.body);
  expect(sent.status).toBe(200);
  expect(sent.contentType).toBe("application/x-ndjson");
  const frames = body.trim().split("\n").map(line => JSON.parse(line));
  expect(frames[0].kind).toBe("delta");
  expect(frames[0].cursor).toMatch(/^ak:cursor:/);
  expect(frames.some(frame => frame.kind === "catchup_complete")).toBe(false);
  await expect(deliveredMockAccountBody({ ...response, request: () => ({ ...request }) } as any))
    .rejects.toThrow("no matching fulfilled mock request");
  for (const changed of [
    { status: () => 503 },
    { headers: () => ({ "content-type": "application/json" }) },
    { request: () => ({ ...request, method: () => "POST" }) },
    { request: () => ({ ...request, url: () => "https://server.local/_arkret/self/contacts" }) },
  ]) {
    await expect(deliveredMockAccountBody({ ...response, ...changed } as any))
      .rejects.toThrow("exact successful NDJSON response");
  }
});

test("signer query observation retains early exact HTTP responses without accepting other requests", () => {
  let receive!: (response: any) => void;
  const seen = observeSuccessfulSignerQueries({ on: (_event: string, listener: any) => { receive = listener; } } as any);
  const response = (eventId: string, method = "POST", status = 200, path = "/_arkret/self/signer-keys/query") => ({
    request: () => ({ method: () => method, postDataJSON: () => ({ queries: [{ committed_event_ref: { event_id: eventId } }] }) }),
    status: () => status,
    url: () => `https://server.local${path}`,
    text: () => { throw new Error("response body must not be read"); },
  });
  receive(response("early-event"));
  expect(seen("early-event")).toBe(true);
  expect(seen("different-event")).toBe(false);
  receive(response("failed-event", "POST", 503));
  receive(response("wrong-method", "GET"));
  receive(response("wrong-path", "POST", 200, "/_arkret/self/keys/query"));
  expect(seen("failed-event")).toBe(false);
  expect(seen("wrong-method")).toBe(false);
  expect(seen("wrong-path")).toBe(false);
});
