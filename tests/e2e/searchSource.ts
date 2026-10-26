import { expect, type Locator } from "@playwright/test";

/** Source references belong to the rendered admitted result, never the fixture. */
export function searchReference(row: Locator, kind: "event" | "commit" | "realm"): Locator {
  return row.locator(`.global-search-result-provenance .global-search-result-${kind}-reference`);
}

export async function assertSearchSource(row: Locator) {
  const description = row.locator(".global-search-result-provenance");
  await expect(description).toHaveCount(1);
  const id = await description.getAttribute("id");
  expect(id).toBeTruthy();
  await expect(row).toHaveAttribute("aria-describedby", id!);
  await expect(searchReference(row, "event")).toHaveText(/^ak:event:/);
  await expect(searchReference(row, "commit")).toHaveText(/^ak:realm_commit:/);
}
