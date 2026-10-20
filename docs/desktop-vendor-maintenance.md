# Desktop renderer vendor inputs

The application patches `dioxus-desktop` through the root `Cargo.toml`.
Run Cargo from the Inkson workspace and use its root `Cargo.lock`, including
for `--features desktop` builds. The vendor directory is a dependency, not a
workspace member or an independently locked application. Its inherited lock
is removed and ignored; do not restore it when refreshing the vendor tree.

## Source and local patch

The base is the published `dioxus-desktop 0.7.10` archive, SHA-256
`236deb81f1a04de704fb80cf7838c65607441c76914de2e036709540c540a39d`.
`.cargo_vcs_info.json` records upstream commit
`57d6794ad60b949e5bd8aa282f6f8c3dc97a365e` and `packages/desktop`; the
published archive is the byte-level baseline (its upstream dirty flag is
retained). `Cargo.toml.orig` is upstream provenance, not the effective patched
manifest. Keep both license files and `GTK4-MAINTENANCE.json`.

The complete local code/dependency patch relative to that archive is confined
to four files:

| File | Required change |
| --- | --- |
| `Cargo.toml` | Pin Tao/Wry GTK4 forks; use GTK4 Muda and KSNI tray; adapt removed Wry features without changing the package version. |
| `src/ipc.rs` | Carry a one-shot custom-protocol request through the event loop without moving Rc-backed UI state across threads. |
| `src/launch.rs` | Dispatch protocol requests to their owning webview, rejecting closed windows. |
| `src/webview.rs` | Keep handlers on the UI thread; forward only Send request/responder data; reject stale window instances. |

The baseline Inkson commit containing these exact four patched files is
`a92ff9769a7bb48559f0484b06c897c640c3b8e2`. To reproduce the patch, obtain the
published archive from
`https://static.crates.io/crates/dioxus-desktop/dioxus-desktop-0.7.10.crate`,
verify its SHA-256, extract it outside the Arkret workspace, and copy each of
the four files from `git show <baseline>:vendor/dioxus-desktop/<file>` into
that extracted directory. A unified diff against a second clean extraction
is the full local code/dependency patch; no generated source is needed.
Copy the two license files and maintenance JSON from the same Inkson commit.
Then remove the three inventory-only files listed below. All other archive
files remain byte-identical. Do not overwrite patched files with
`Cargo.toml.orig` or regenerate runtime assets during inventory refreshes.

`GTK4-MAINTENANCE.json` records pinned fork revisions and historical platform
receipts. Its PR states and historical passes are observations from that
maintenance work, not a claim about current upstream or current application
acceptance. The current pins remain:

- Tao: `1879ad839cb8caaf7b4c733392c21f68a86787f4`.
- Wry: `006d0155eb46dedb6c43fa3aa152e55d162a4aa5`.

## Input classification

| Retained input | Consumer / reason |
| --- | --- |
| Effective `Cargo.toml`, `build.rs`, all `src/*.rs` | Cargo library/build targets, Rust module graph, feature and platform cfgs. No platform capability is pruned. |
| `src/readme.md`, root `README.md` | `src/lib.rs` embeds crate docs; package metadata names the root readme. |
| `src/assets/default_icon.bin` | `default_icon.rs` embeds RGBA bytes used by the window and tray fallback. |
| `src/assets/default_icon.png` | Source image for regenerating that RGBA fallback; conversion is documented in `src/config.rs`. Retained as maintenance input even though only the binary is embedded. |
| `src/assets/dev.index.html`, `prod.index.html` | `protocol.rs` embeds the debug/release HTML shells. |
| `src/js/native_eval.js` | `document.rs` embeds native JavaScript evaluation support. |
| `src/ts/native_eval.ts`, `src/js/hash.txt`, `tsconfig.json` | `build.rs` invokes `lazy-js-bundle` to watch/hash TS and regenerate JS when necessary; retain source, hash and compiler settings together. |
| `headless_tests/*.rs` | Four explicit Cargo test targets plus their shared helper. These are upstream maintenance material, not ordinary root application tests. Their presence does not assert they pass standalone outside the upstream workspace. |
| `.cargo_vcs_info.json`, `Cargo.toml.orig`, maintenance JSON, both licenses | Source attribution, original manifest, required patch history and license obligations. |

The following inherited inventory has no build, runtime or required patch
maintenance consumer and is removed:

| Removed file | Bytes | Evidence |
| --- | ---: | --- |
| `Cargo.lock` | 124170 | Cargo metadata identifies only Inkson as a workspace member and resolves this renderer as a path patch under the unchanged application lock. Removing it leaves the complete desktop metadata/resolve graph unchanged under `--locked`. |
| `.vscode/settings.json` | 65 | Contains only a commented-out Android rust-analyzer target. No active editor setting, Cargo target, resource or patch input. |
| `architecure/Desktop Event Architecture.png` | 352279 | Upstream explanatory diagram, outside source/resource roots; neither readme links it. No Rust include, build-script directory traversal, runtime asset path, test, packaging or maintenance script consumes it. |

The actual root `cargo package --list` excludes this entire nested Cargo
package: before/after lists contain no `vendor/` entries. Packaging the root
crate therefore cannot establish renderer resource coverage. Inkson's Docker
build copies the source tree, compiles the web client, and copies only the
completed web public directory into nginx. Native package scripts consume the
built executable; they do not install the vendor tree. Runtime asset requests
use Dioxus asset resolution and the application's assets, not a traversal of
the vendor directory. The renderer build script watches `src/ts`; its
upstream-only `DIOXUS_RELEASE` branch traverses `examples/assets`, not the
removed directories. Do not set `DIOXUS_RELEASE` for application builds.

The total deleted inventory is 476514 bytes. This is source-tree reduction;
it does not imply an executable-size reduction.

## Refresh and exit conditions

For an inventory-only refresh, retain the application lock and compare full
`cargo metadata --locked --format-version 1 --features desktop` before/after,
including package IDs, source revisions, features and targets. Verify remaining
vendor files against the archive plus the four-file patch. Check
`cargo package --locked --list --allow-dirty -p inkson`, and the actual native
and web builds/resource startup for the affected host. Platform-specific
input changes require that platform's executor.

Removing this vendor patch requires verification of a real upstream candidate,
not an assumed fixed version. It must provide the GTK4/KSNI integration and
custom-protocol thread/lifetime guarantees above, preserve public renderer
behavior, pass the existing strict desktop advisory gate without exemptions,
and pass the existing Linux package/X11/Wayland/SecretService and Windows/macOS
renderer checks. Dependency/fork replacement and the remaining full platform
and authenticated business acceptance belong to the existing 0932 task and
`packages.yml` executors. No upstream replacement was evaluated by this
inventory cleanup.
