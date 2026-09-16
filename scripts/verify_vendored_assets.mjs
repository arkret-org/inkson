import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifestPath = resolve(repositoryRoot, "assets/vendor/manifest.json");
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));

if (manifest.schema !== "inkson.vendored-assets.v1" || !Array.isArray(manifest.assets)) {
  throw new Error("invalid vendored asset manifest");
}

for (const asset of manifest.assets) {
  const bytes = await readFile(resolve(repositoryRoot, asset.path));
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== asset.sha256) {
    throw new Error(`${asset.path}: SHA-256 mismatch; expected ${asset.sha256}, got ${actual}`);
  }
  console.log(`verified ${asset.path} (${asset.version})`);
}
