import { expect, test } from "@playwright/test";
import {
  assertNoRetiredMockFields,
  mockArkretApi,
} from "./mockArkretApi";

test("mock installation preflights static response builders", async ({ page }) => {
  await mockArkretApi(page, { includeDemoRealms: false });
});

test("retired mock response fields fail closed", () => {
  const mode = ["mo", "de"].join("");
  const retiredFixtures = [
    { [["registry", "mode"].join("_")]: "development" },
    { [["supported", "receipts"].join("_")]: [] },
    { auth_metadata: { [mode]: "development" } },
    { method_evidence: { [mode]: "development_local" } },
  ];

  for (const fixture of retiredFixtures) {
    expect(() => assertNoRetiredMockFields(fixture)).toThrow(
      /retired mock response field/,
    );
  }
});
