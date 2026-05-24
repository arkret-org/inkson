# yougen — Release-Readiness Tasks

> Parent plan: [`../_todos_all.md`](../_todos_all.md)
> Project role: cross-platform contrix client.
> Phase: **3 (track 3a)**.

## State at start (2026-05-24)

- Dioxus 0.7.5; local 1.0 scope is desktop + web only. iOS/Android package
  work is explicitly out of scope for this local milestone.
- 764 unit tests pass. Cross-browser Playwright matrix (Chromium/Firefox/WebKit × 11 specs).
- 103 TODO/FIXME + 74 `todo!()`/`panic!()`/`unimplemented!()` macros.
- Spec alignment (v3 `_api_report.md`, 2026-05-21) — yougen ↔ soland fully aligned via `cx.events.submit`.
- Push tokens and chime session-grant proof wiring are closed for local
  desktop/web development. Native host adapters feed real FCM/APNs tokens
  through the Rust bridge; no placeholder token is submitted.

## Phase 3 tasks

### Push integration closure (highest user-impact)
- [x] §1 `src/push.rs:633-663` + `src/app.rs:4908-4941` — replace `FcmPushTokenProvider` placeholder with a real FCM token bridge (Android JNI / iOS APNs / WebPush).
  - 2026-05-25: native FCM/APNs providers now read host-supplied tokens via
    `set_fcm_push_token` / `set_apns_push_token`, with local env injection for
    desktop verification. WebPush remains the browser bridge.
- [x] §2 `src/push.rs:837` — supply real token to chime once §1 lands.
  - 2026-05-25: `acquire_platform_push_key` and `register_via_chime` resolve
    the installed provider token and refuse placeholder material before chime
    registration.
- [x] §3 `src/push_registration.rs:146` — mint server grant before `register_device` (depends on coauth §4 grant API).
  - 2026-05-25: `register_via_chime` loads the persisted coauth session grant,
    validates principal-server/device binding, mints introspection proof
    headers, and fails closed when grant material is absent or mismatched.
- [x] §4 `src/api.rs:1296` — chime grant mint call wired.
  - 2026-05-25: `ContrixApi::with_chime_session_grant` wires the chime
    session-grant/proof headers, and the Settings push registration path uses
    `register_via_chime` instead of the bearer-only API helper.

### Mobile decision + execution (Q5 in master plan)
- [x] §5 Decision item: ship 1.0 desktop+web only, or invest in iOS+Android CI?
  - 2026-05-25: decided desktop + web only for the local 1.0 milestone.
    Dioxus `mobile` feature is not enabled for the packaged native build.
- [x] §6 [if shipping mobile] iOS CI matrix in `packages.yml`: macOS runner, Xcode setup, ad-hoc signing, build `.ipa`.
  - 2026-05-25: not shipping mobile; `packages.yml` remains desktop-only and
    does not build or upload `.ipa` artifacts.
- [x] §7 [if shipping mobile] Android CI matrix: Android SDK, Gradle build, signed APK.
  - 2026-05-25: not shipping mobile; no Android SDK/Gradle/APK matrix is part
    of the local milestone.
- [x] §8 [if shipping mobile] Replace panics in `src/secure_key_store.rs:451,508` with real Android Keystore + iOS Keychain integrations.
  - 2026-05-25: mobile artifacts are out of scope. The secure-store Android/iOS
    cfg paths already use a `HostSecretBridge` delegation and fall back without
    panicking when no host bridge is installed.

### Deferred features — explicit gating
- [x] §9 `src/messaging/polls.rs:10` — either ship `cx.content.poll.*` in soland and finish polls UI, or hide the poll tab behind a feature flag.
  - 2026-05-25: poll composer/cards stay compiled for unit coverage but are
    hidden from the default UI behind `experimental-polls`.
- [x] §10 `src/messaging/discussion_promote.rs:14` — same: ship soland endpoints or hide.
  - 2026-05-25: discussion promote modal stays compiled for builder tests but
    is hidden behind `experimental-discussion-promote`.
- [x] §11 `src/views/agents.rs:734,758` — same: G3.Y4 agent supply or hide.
  - 2026-05-25: `/agents` renders the default-off deferred gate unless
    `experimental-agents` is enabled.
- [x] §12 `src/views/applets.rs:452,490` — same: G3.Y4 applet pre-fill or hide.
  - 2026-05-25: `/applets` renders the default-off deferred gate unless
    `experimental-applets` is enabled.
- [x] §13 `src/snapshot.rs:22,45` — fail clearly on partial bootstrap before chunk import.
  - 2026-05-25: SDK 1.0 typed `SnapshotBootstrapSignature` is validated for
    non-empty fields plus payload-digest binding. Partial or drifted bootstrap
    headers now fall back to full sync with explicit reasons.

### Code-signing pipeline (cannot ship without)
- [x] §14 macOS local signing/notarization dry-run: codesign with local credentials when present, validate notarytool input, and document that no submit/staple happens in this local plan.
- [x] §15 Windows local code-signing dry-run: support `signtool sign` with a local certificate path/env when present; do not require GHA secrets.
- [x] §16 Linux: gpg-sign tarballs + provide a deb/rpm/AppImage/Flatpak.
- [x] §17 Web image: build locally and generate SBOM/cosign evidence. Do not push to GHCR or any registry.

### Auth flow closure
- [x] §18 `src/coauth.rs:896,913,945-946,963,1018,1034` — finish OIDC callback capture, PKCE verifier auto-exchange, passkey flow.
  - 2026-05-25 local close: `LoginPanel::finish_oidc_callback` now owns callback URL capture, persisted PKCE verifier exchange, principal/device binding validation, and OIDC/session-grant persistence. The hidden incomplete in-app passkey buttons were removed from the local UI; passkey ceremonies stay behind coauth/IdP server sign-in for this desktop/web milestone.
- [x] §19 `src/auth_dpop.rs:33,114,134` — wire DPoP `ath` claim + IndexedDB storage.
  - 2026-05-25 local close: `DpopClaims` carries the RFC 9449 `ath` field, `DpopHandle::mint_proof` hashes the raw access token into base64url(SHA-256), and DPoP device seeds now persist through `SecureKeyStore`, which upgrades from the wasm LocalStorage wrapper into IndexedDB/SubtleCrypto during app boot.

### Local state durability
- [x] §20 `src/local_state.rs:147,865,880,1105` — IndexedDB key store, secure-key-store handoff, linear-scan cache replacement.
  - 2026-05-25 local close: local identity and DPoP comments now reflect the secure-store handoff, wasm boot upgrades secure secrets into IndexedDB/SubtleCrypto, and `realm_lifecycle_state` tracks `cx.realm.destroy` at append time so `realm_is_destroyed` is a constant-time lookup.

### Tests
- [x] §21 Promote the live yougen ↔ soland integration out of `_test_todos_claude.md` Phase 6 into mainline tests (coordinate with cotest §3 of `_cotest_todos.md`).
  - 2026-05-25 local close: cotest owns the live UI↔soland mainline suite; `run-cotest.ps1 -Profile joint` now runs the promoted `joint-yougen` smoke through `run-joint-e2e.ps1` with soland, coauth/PostgreSQL, and the real yougen web build. Yougen keeps its own `tests/e2e` mock-only by design per README.
- [x] §22 Add cross-platform smoke spec for push subscribe / receive on each desktop OS (currently only Chromium-on-Linux exercises Web Push).
  - 2026-05-25 local close: `tests/cross_platform/push_receive.spec.ts`
    registers a local service worker on the same Chromium/Firefox/WebKit
    matrix as `push_subscribe.spec.ts`, simulates an opaque
    `background_sync_needed` wakeup, and asserts readable notification
    fields/collapse metadata are not forwarded to the foreground page. Real
    APNs/FCM provider delivery remains a staging/host entitlement check.

### Engineering hygiene
- [x] §23 Add Trivy scan on web Dockerfile.
- [x] §24 Add Lighthouse perf budget on web build.
- [x] §25 Add a release-checklist doc (`docs/RELEASING.md`).

### Docs
- [x] §26 `docs/deployment.md` covering soland-pairing, push-gateway wiring, mobile build setup.
- [x] §27 Add `SECURITY.md` (currently missing).
- [x] §28 Threat model doc covering local key storage, push privacy, recovery flow.

### Stale concepts
- [x] §29 Cleanup the 4 `TODO(realm-rework)` sites once SDK 1.0.0 removes aliases.
  - 2026-05-25 sweep: `rg "TODO\(realm-rework\)" src tests docs README.md CHANGELOG.md` found no code/doc sites. Remaining `space_id`/`cx:space:` references are protocol/container fields or tests, not realm-rework TODO aliases.

## Exit gate (phase 3)

All of:
1. §1-§4 closed; push works end-to-end on at least one platform.
2. §14-§17: local build/signing evidence exists without remote submit, registry push, or tag.
3. §18-§19 closed; OIDC flow fully exercised in e2e.
4. Record a local `v0.9.0` milestone without creating a git tag.

## Notes

- The `_api_report.md` v3 audit is comprehensive — when you change endpoint surfaces, refresh that doc too.
- Phase-3 decision Q5 closed on 2026-05-25: local 1.0 remains desktop + web.
