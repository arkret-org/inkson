# clientx Product TODOs

本项目为对 E:\Works\contrix-dev\contrix-spec 协议的实现. 本程序为前端跨平台应用. 应该包含 web, ios, linux, windows 等版本. 对应后端实现是 E:\Works\contrix-dev\serverx.

## Product Baseline

- [x] Scaffold Dioxus 0.7 cross-platform client with web, iOS/mobile, Windows, and Linux desktop build features.
- [x] Implement initial API client, UI metrics, and contract tests against serverx skeleton.
- [x] Replace status-demo UI with a usable Contrix client shell: spaces, timeline, composer, directory, settings, devices, and sync status.
- [x] Add persisted client configuration for server URL, account DID, device ID, and session token.
- [x] Add robust loading, empty, error, reconnecting, and offline states.
- [x] Add platform notes for web, Windows/Linux desktop, and iOS/mobile.

## Protocol Alignment Follow-ups

- [x] Verify client endpoint coverage against `contrix-spec/en/sync/service-http-binding.md` common client API namespaces.
- [x] Align E2EE client behavior with `contrix-spec/en/crypto-media/encrypted-envelope-schema.md`: MLS envelope generation, digest verification, pending ciphertext preservation, and joined-group decrypt flow.
- [x] Use SDK OpenMLS helpers rather than custom crypto for KeyPackage, Welcome, Commit, encrypted payload compose, and decrypt-or-preserve.

## API Client and Auth

- [x] Implement typed client calls for every serverx product endpoint.
- [x] Add bearer session handling and auth failure recovery.
- [x] Add request timeout, retry, and backoff policies.
- [x] Add standard Contrix error decoding.
- [x] Add local session/device bootstrap flow.

## E2EE and Local State

- [x] Integrate SDK MLS helpers for device identity and encrypted message payloads.
- [x] Create local encrypted message compose flow.
- [x] Create local decrypt flow for joined MLS groups.
- [x] Preserve encrypted payloads when a key is unavailable.
- [x] Add local stores for raw operations, sync cursors, projections, and drafts.
- [x] Add device/key management screens.

## UI Features

- [x] Space list with directory search and exact resolve.
- [x] Space timeline with message, redaction, reaction, and backfill support.
- [x] Message composer supporting plaintext dev mode and encrypted mode.
- [x] Sync status panel showing next batch, backfill cursor, and device queue counts.
- [x] Repo/audit panel for commits and operation history.
- [x] Directory browser for spaces, organizations, actors, and handles.
- [x] Settings for server, account, device, encryption, and push.
- [x] Push registration controls.
- [x] Moderation report action from timeline item.

## Tests and Documentation

- [x] Add contract tests for all typed API calls.
- [x] Add client/server E2EE workflow test.
- [x] Add UI compile tests for desktop/web feature set.
- [x] Add docs for running each platform, auth bootstrap, E2EE workflow, and known limits.
- [x] Run `cargo fmt`, `cargo test`, and server integration smoke before marking complete.

## Business Workflow Inventory

- [x] Define current supported account bootstrap flow: dev-login session bootstrap, DID/device binding, token persistence, auth failure visibility.
- [x] Define current supported discovery flow: server connect, directory search, exact space resolve, select space, sync timeline and backfill.
- [x] Define current supported messaging flow: plaintext dev compose, local MLS encrypted compose, pending encrypted payload preservation, moderation report, to-device queue send.
- [x] Define current supported device/security flow: key upload/query/claim, device messages receive, push register/unregister, device queue metrics.
- [x] Define current supported data lifecycle flow: repo describe, commits/operations/sync, blob upload/download, audit/status panels.
- [x] Capture missing product flows that need serverx/protocol endpoints before UI completion: production registration, password/passkey login, device verification UX, contacts/friends, create/update/delete Space, invite/add/kick member, leave Space, account recovery, Space archival/deletion.

## Playwright E2E Flow Design

- [x] Add stable UI selectors for shell, settings, directory, composer, device, status, timeline, and metric regions.
- [x] Add Playwright project configuration and npm scripts for local web e2e.
- [x] Add mocked Contrix API fixture covering server describe, dev-login, sync, directory, repo, authz, keys, device messages, push, moderation, and blob paths.
- [x] Test bootstrap/login/sync flow from offline state to connected shell with token, space, timeline, repo, push, and device metrics.
- [x] Test settings identity/device update flow before bootstrap.
- [x] Test directory search, exact resolve, and selected space navigation.
- [x] Test plaintext compose and local MLS encrypted compose in the timeline.
- [x] Test moderation report and to-device queue request from the timeline action.
- [x] Test devices/security panel after bootstrap.
- [x] Test invalid server URL error state.
- [x] Document Playwright execution in README.

## Production Release Readiness

- [x] Add release-readiness inventory in code so major unsupported business flows are visible in the product, not only in notes.
- [x] Add UI panel for production blockers: registration, production login, device verification, contacts/friends, create Space, invite/add/kick member, leave/archive/delete Space, canonical message persistence, and release packaging.
- [x] Add Playwright coverage that the product explicitly says it is not production-ready while those blockers remain.
- [ ] Implement production registration with DID proof challenge, device bootstrap, verification, and recovery policy.
- [ ] Implement production login with password/passkey/OIDC, token refresh, logout, soft-logout recovery, and device-bound session grants.
- [ ] Implement contacts/friends: discoverable contact request, accept/reject, block, privacy-preserving directory lookup, and notification handling.
- [ ] Implement Space lifecycle: create Space, edit metadata, set policy, invite/add member, accept invite, leave, kick/remove member, archive, delete/tombstone, and history retention rules.
- [ ] Implement canonical message persistence: local compose -> encrypted/plain operation -> signed commit -> repo submit -> sync projection.
- [ ] Implement web-grade E2EE crypto store instead of wasm placeholder envelope compose.
- [ ] Implement production local encrypted storage, offline queue, retry reconciliation, and crash-safe draft/message recovery.
- [ ] Implement release engineering: signed desktop/mobile builds, web deployment config, updater, crash telemetry, privacy/security review, and release channels.
