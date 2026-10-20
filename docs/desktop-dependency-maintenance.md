# Desktop dependency maintenance

Rust dependency fixes live in Arkret organization forks, never as source copies
inside Inkson or the SDK. Work on a named non-main integration branch and pin a
complete Git revision in Cargo.toml. Cargo.lock records the resolved source.
The branch name describes maintenance ownership; the revision controls builds.

| Dependency | Fork | Maintenance branch | Consumer |
| --- | --- | --- | --- |
| Dioxus desktop | https://github.com/arkret-org/dioxus | `arkret/desktop-gtk4` | Inkson root crates.io patch |
| KSNI | https://github.com/arkret-org/ksni | `arkret/zbus-6` | Inkson root crates.io patch |
| Secret Service | https://github.com/arkret-org/secret-service-rs | `arkret/zbus-6` | SDK workspace dependency |

The Dioxus branch starts at the upstream 0.7.10 release commit
`57d6794ad60b949e5bd8aa282f6f8c3dc97a365e`. Its desktop manifest keeps the
published registry identities of shared Dioxus types rather than pulling sibling
workspace crates into the application. The renderer uses GTK4/WebKitGTK6 via
Tao `1879ad839cb8caaf7b4c733392c21f68a86787f4` and Wry
`006d0155eb46dedb6c43fa3aa152e55d162a4aa5`, Muda GTK4 and KSNI tray support.
Protocol callbacks carry only Send request/response data to the event loop;
Rc-backed handlers stay on their owning UI thread. Stale windows are rejected.
The fork retains upstream history, license files, and the desktop maintenance
record. Historical receipts in that record retain their original source scope.

The KSNI and Secret Service branches start at upstream published 0.3.6 and
5.2.0 commits respectively. They migrate actual D-Bus consumers to zbus 6,
including its integrated wire types. No package version is disguised and no
advisory waiver is introduced. SDK KeyStore retains its synchronous interface;
its asynchronous D-Bus operations and cross-process mutation lease remain
internal implementation details.

To update a dependency, fetch and review the maintenance branch, test the
specific candidate revision, then change its full Cargo.toml revision and
resolve Cargo.lock. Preserve package identities, license terms and the original
strict advisory policy. Ask Cargo metadata for the target directory. Validate
native and web builds and resource startup. Changes to Linux D-Bus, GTK4 or
renderer inputs require their actual platform executor; an advisory or metadata
pass alone is insufficient. The existing 0932 Packages workflow owns the Linux
package/X11/Wayland/SecretService and Windows/macOS renderer gates.

Return to an upstream release only after confirming that it contains the needed
fixes and passes the same affected gates. Do not reintroduce local source copies
or replace a revision pin with a moving main branch.
