# Tag releases

Pushing a `v*` tag builds and publishes a GitHub Release after every required
build succeeds. `workflow_dispatch` builds the same artifacts without publishing
a release; use it before tagging. Existing source versions are not changed.

Sibling checkout revisions in the workflow are part of the release source set.
Before tagging, update those pins to a compatible tested set and commit any
required Cargo.lock changes. Do not replace pinned revisions with `main`. Each
archive includes `build-info.json` with the source commits and lockfile hash,
and a companion SHA-256 file. Verify it from the download directory with
`sha256sum --check ./*.sha256`.

Cross-repository private dependencies require `CI_REPO_TOKEN` with read access;
`GITHUB_TOKEN` only supplies the current repository's permissions. Publishing
uses the release job's `contents: write` permission.

Desktop archives contain Dioxus application bundles and processed assets for
Linux x64/ARM64, Windows x64 and macOS ARM64. macOS archives preserve the `.app`
layout; Windows and Linux archives keep the executable and its adjacent assets.
These are unsigned portable builds, not notarized macOS or Authenticode-signed
Windows installers. Existing local signing checks remain documented in
`docs/RELEASING.md`. Linux requires Ubuntu 24.04 or equivalent glibc and
GTK4/WebKitGTK 6.0, D-Bus, libxdo and a working system secret service.
