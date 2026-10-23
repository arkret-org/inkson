import { expect, test } from "@playwright/test";
import { inksonWire } from "../e2e/mockArkretApi";

test("native fixture stdin preserves large UTF-8 input and completes after rejected input", () => {
  const payload = "\u6d4b\u8bd5\u0000\n".repeat(32_768);
  const actual = inksonWire<{ canonical: string }>("canonical-json", {
    value: { z: payload, a: "complete stdin" },
  });
  expect(actual.canonical).toBe(JSON.stringify({ a: "complete stdin", z: payload }));
  expect(() => inksonWire("service-resolution", { service_kind: "invalid" }))
    .toThrow(/inkson-wire service-resolution failed/);
  for (let index = 0; index < 20; index += 1) {
    expect(inksonWire<{ canonical: string }>("canonical-json", { value: index }).canonical)
      .toBe(String(index));
  }
});
