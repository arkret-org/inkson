import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { expect, test, type Page } from "@playwright/test";

test.setTimeout(180_000);

async function mount(page: Page) {
  const base = process.env.INKSON_LAYOUT_BASE_URL ?? process.env.INKSON_E2E_BASE_URL ?? "http://127.0.0.1:4727";
  await page.goto(new URL("/?__inkson_fixture=attachment-lifetime", base).href, { waitUntil: "domcontentloaded" });
  await page.evaluate(async () => {
    const wasmUrl = "/assets/pkg/inkson.js";
    const module = await import(wasmUrl);
    await module.default();
    if (typeof module.mountAttachmentLifetimeFixture !== "function") {
      throw new Error("Build Inkson WASM with spec-conformance to exercise the real attachment provider");
    }
    const root = document.getElementById("app");
    if (!root) throw new Error("Inkson application root is missing");
    module.mountAttachmentLifetimeFixture(root);
  });
  await expect(page.getByRole("button", { name: "Read attachment", exact: true })).toBeVisible();
}

async function selectFile(page: Page) {
  const bytes = Buffer.alloc(3 * 65_536 + 173);
  for (let index = 0; index < bytes.length; index++) bytes[index] = (index * 37 + 11) % 251;
  const file = test.info().outputPath("attachment-lifetime.bin");
  if (process.platform === "win32" && !/^D:[\\/]/i.test(resolve(file))) {
    throw new Error("Attachment fixture output must stay on D:");
  }
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, bytes);
  const next = page.waitForEvent("filechooser");
  await page.getByRole("button", { name: "Read attachment", exact: true }).click();
  const picker = await next;
  const input = picker.element();
  await picker.setFiles(file);
  await expect(page.locator(".attachment-lifetime-status")).toHaveText("paused:65536");
  return { input, bytes, hash: createHash("sha256").update(bytes).digest("hex") };
}

test("a real browser file grant pauses across an inert gap and resumes on the same picker", async ({ page }) => {
  await mount(page);
  const { input, bytes, hash } = await selectFile(page);
  const surface = page.locator(".chat-retained-target");
  await expect(surface).toHaveAttribute("hidden", "");
  await expect(surface).toHaveAttribute("inert", "");
  await expect(surface).toHaveCSS("display", "none");
  expect(await input.evaluate(node => node.isConnected)).toBe(true);
  await expect(page.getByRole("button", { name: "Read attachment", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Resume attachment", exact: true }).click();
  await expect(page.locator(".attachment-lifetime-status")).toHaveText(`complete:${bytes.length}:${hash}`);
  expect(await input.evaluate(node => node.isConnected)).toBe(true);
  await expect(surface).not.toHaveAttribute("hidden", "");
  await expect(surface).not.toHaveAttribute("inert", "");
  await expect(page.getByRole("button", { name: "Read attachment", exact: true })).toBeVisible();
});

test("retiring the real picker owner ends a suspended file read without publishing completion", async ({ page }) => {
  await mount(page);
  const { input } = await selectFile(page);
  await page.getByRole("button", { name: "Retire picker", exact: true }).click();
  await expect(page.locator(".attachment-lifetime-status")).toHaveText(/^error:attachment picker owner retired/);
  expect(await input.evaluate(node => node.isConnected)).toBe(false);
  await expect(page.getByRole("button", { name: "Resume attachment", exact: true })).toBeDisabled();
  await expect(page.locator(".chat-retained-target")).toHaveCount(0);
});
