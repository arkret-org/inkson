import { expect, test } from "@playwright/test";
import { mockArkretApi, validateMockSchema } from "../e2e/mockArkretApi";
import { captureRouteHandler, driveOnce } from "./mockShapeDriver";

test("the account fixture serves a native signed directory and never invents provider authority", async () => {
  const { page, handler } = captureRouteHandler();
  await mockArkretApi(page as never);
  const response = await driveOnce(handler(), {
    method: "GET", url: "https://local.host/_arkret/open/mimi/provider-directory",
  });
  expect(response?.status).toBe(200);
  validateMockSchema("schemas/mimi-interop.schema.json#/$defs/provider_directory", response!.body);
  const directory = response!.body as Record<string, any>;
  expect(directory.mimi.base_url).toBe("https://local.host/_arkret/open/mimi");
  expect(directory.mimi.features).toEqual([...directory.mimi.features].sort());
  expect(directory.proof.payload_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  expect(directory.proof.payload_digest).not.toBe(`sha256:${"0".repeat(64)}`);
  expect(directory.proof.jws.split("..")[1].length).toBeGreaterThan(80);
  expect(Math.abs(Date.now() - Date.parse(directory.proof.created_at))).toBeLessThan(30_000);
  for (const path of [
    "key-material", "identifiers/query", "consent/request", "consent/update", "report-abuse", "proxy-download",
    "strands/fixture-room/update", "strands/fixture-room/notify", "strands/fixture-room/messages",
  ]) {
    await expect(driveOnce(handler(), {
      method: "POST", url: `https://local.host/_arkret/open/mimi/${path}`, postData: {},
    })).rejects.toThrow("requires a native authenticated provider fixture");
  }
});
