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

// Font subsets are self-hosted copies of the original UI font. Native SFNT
// fallbacks use the same outlines and metrics; keep both formats pinned.
const fontRoot = resolve(repositoryRoot, "assets/fonts");
const fontManifest = JSON.parse(await readFile(resolve(fontRoot, "SOURCE.json"), "utf8"));
for (const font of fontManifest.files) {
  for (const entry of [font, font.nativeTtf]) {
    if (!entry || !/^[a-z0-9-]+\.(woff2|ttf)$/.test(entry.file)) {
      throw new Error("invalid packaged font entry");
    }
    const bytes = await readFile(resolve(fontRoot, entry.file));
    const digest = createHash("sha256").update(bytes).digest("hex");
    if (bytes.length !== entry.bytes || digest !== entry.sha256) {
      throw new Error(`assets/fonts/${entry.file}: font integrity mismatch`);
    }
    console.log(`verified assets/fonts/${entry.file} (${fontManifest.version})`);
  }
}
