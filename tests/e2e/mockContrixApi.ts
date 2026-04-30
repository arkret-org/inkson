import type { Page, Route } from "@playwright/test";

const DEMO_SPACE = "cx:space:01js0sp0000000000000000000";
const PRODUCT_SPACE = "cx:space:01js0productflow000000000000";

export async function mockContrixApi(page: Page) {
  let contactRequested = false;
  let productSpaceDeleted = false;
  let productMembers = ["did:web:alice.example", "did:web:bob.example"];
  let messageCounter = 0;
  let commitCounter = 0;

  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/health") {
      return json(route, { ok: true, service: "serverx", storage: "memory" });
    }
    if (!url.pathname.startsWith("/api/v1/")) {
      return route.continue();
    }

    if (url.pathname === "/api/v1/server/describe") {
      return json(route, {
        service_did: "did:web:serverx.local",
        service_type: "principal_server",
        protocol_version: "1.0",
        supported_profiles: ["cx.profile.mimi_interop.v1"],
        supported_features: ["sync.client_sync", "directory.search_spaces", "mimi_provider_facade"],
        supported_operations: ["cx.sync.client_sync", "cx.directory.search_spaces", "cx.mimi.provider_directory"],
        limits: { storage: "memory" },
      });
    }

    if (url.pathname === "/api/v1/mimi/provider-directory") {
      return json(route, mimiProviderDirectory());
    }

    if (url.pathname === "/api/v1/mimi/key-material") {
      return json(route, {
        ok: true,
        key_packages: [{ key_package_ref: "mimi:key-package:e2e", target: "mimi://remote.example/alice" }],
        receipt: { kind: "cx.mimi.key_material", profile: "cx.profile.mimi_interop.v1" },
      });
    }

    if (url.pathname.match(/^\/api\/v1\/mimi\/rooms\/[^/]+\/update$/) && route.request().method() === "PUT") {
      const roomId = decodeURIComponent(url.pathname.split("/")[5]);
      return json(route, {
        ok: true,
        room_id: roomId,
        receipt: { kind: "cx.mimi.room_update", operation_id: "cx:operation:mimi-room-update" },
      });
    }

    if (url.pathname.match(/^\/api\/v1\/mimi\/rooms\/[^/]+\/notify$/)) {
      return json(route, {
        ok: true,
        accepted: ["did:web:remote.example"],
        receipt: { kind: "cx.mimi.notify", notification_id: "cx:mimi:notify:e2e" },
      });
    }

    if (url.pathname.match(/^\/api\/v1\/mimi\/rooms\/[^/]+\/messages$/)) {
      return json(route, {
        ok: true,
        mimi_message_id: "mimi-msg-e2e",
        mapped_operation_id: "cx:operation:mimi-submit-e2e",
        contrix_event_id: "cx:event:mimi-submit-e2e",
        receipt: {
          kind: "cx.mimi.mapping_receipt",
          profile: "cx.profile.mimi_interop.v1",
          mimi_room_uri: "mimi://mimi.example.com/rooms/01JSMIMI",
          source_format: "text/markdown;variant=GFM-MIMI",
          target_format: "cx.message.create",
          original_envelope_hash: "sha256:e2e-mimi-envelope",
          mapped_operation_id: "cx:operation:mimi-submit-e2e",
          mimi_message_id: "mimi-msg-e2e",
        },
      });
    }

    if (url.pathname.match(/^\/api\/v1\/mimi\/rooms\/[^/]+\/group-info$/)) {
      const roomId = decodeURIComponent(url.pathname.split("/")[5]);
      return json(route, {
        room_id: roomId,
        mimi_room_uri: "mimi://mimi.example.com/rooms/01JSMIMI",
        group_info: { epoch: 7, mls_group_id: "mls-group-01", policy_root: "sha256:e2e-policy-root" },
        participants: [
          { identifier: "mimi://mimi.example.com/alice", did: "did:web:alice.example", role: "admin" },
          { identifier: "mimi://remote.example/bob", did: "did:web:bob.example", role: "member" },
        ],
        receipt: { kind: "cx.mimi.group_info", profile: "cx.profile.mimi_interop.v1" },
      });
    }

    if (url.pathname === "/api/v1/mimi/consent/request") {
      return json(route, {
        ok: true,
        consent_id: "cx:mimi-consent:e2e",
        state: "requested",
        receipt: { kind: "cx.mimi.request_consent" },
      });
    }

    if (url.pathname === "/api/v1/mimi/consent/update") {
      return json(route, {
        ok: true,
        consent_id: "cx:mimi-consent:e2e",
        state: "accepted",
        receipt: { kind: "cx.mimi.update_consent" },
      });
    }

    if (url.pathname === "/api/v1/mimi/identifiers/query") {
      const body = await route.request().postDataJSON();
      return json(route, {
        query: body.query,
        reachable: true,
        mapped_did: "did:web:alice.example",
        provider_id: "mimi://mimi.example.com",
        proofs: [{ type: "private_contact_discovery", expires_at: "2026-04-30T12:00:00Z" }],
        receipt: { kind: "cx.mimi.identifier_query", privacy_mode: body.privacy_mode },
      });
    }

    if (url.pathname === "/api/v1/mimi/report-abuse") {
      return json(route, {
        ok: true,
        report_id: "cx:report:mimi-e2e",
        status: "queued",
        receipt: { kind: "cx.mimi.report_abuse" },
      });
    }

    if (url.pathname === "/api/v1/mimi/proxy-download") {
      return json(route, {
        ok: true,
        blob_ref: "cx:blob:sha256:e2e",
        media_type: "application/octet-stream",
        size: 23,
        proxy_url: "/api/v1/mimi/proxy-download/cx:blob:sha256:e2e",
        receipt: { kind: "cx.mimi.proxy_download", direct_object_store_url: null },
      });
    }

    if (url.pathname === "/api/v1/auth/dev-login") {
      const body = await route.request().postDataJSON();
      return json(route, {
        access_token: "sx_playwright_token",
        token_type: "Bearer",
        actor: body.actor,
        device_id: body.device_id,
        expires_at: "2026-04-28T12:00:00Z",
      });
    }

    if (url.pathname === "/api/v1/auth/passkey/challenge") {
      const body = await route.request().postDataJSON();
      return json(route, {
        challenge: "playwright-passkey-challenge",
        rp_id: "127.0.0.1",
        user_did: body.user_did,
        expires_at: "2026-04-28T12:05:00Z",
      });
    }

    if (url.pathname === "/api/v1/auth/oidc/authorize") {
      return json(route, {
        redirect_url: "https://idp.example/authorize?state=oidc-state-e2e",
        state: "oidc-state-e2e",
      });
    }

    if (url.pathname === "/api/v1/auth/token/refresh") {
      return json(route, {
        access_token: "sx_playwright_refreshed",
        token_type: "Bearer",
        expires_at: "2026-04-28T13:00:00Z",
      });
    }

    if (url.pathname === "/api/v1/account/register") {
      const body = await route.request().postDataJSON();
      return json(route, {
        did: body.did,
        handle: body.handle,
        display_name: body.display_name,
        created_at: "2026-04-28T12:00:00Z",
      }, 201);
    }

    if (url.pathname === "/api/v1/directory/search-users") {
      return json(route, {
        results: [
          {
            did: "did:web:bob.example",
            handle: "bob.example",
            display_name: "Bob Example",
          },
        ],
        next_cursor: null,
      });
    }

    if (url.pathname === "/api/v1/account/me") {
      return json(route, {
        did: "did:web:alice.example",
        handle: "alice.example",
        display_name: "yougen",
        created_at: "2026-04-28T12:00:00Z",
      });
    }

    if (url.pathname === "/api/v1/auth/logout") {
      return json(route, { ok: true });
    }

    if (url.pathname === "/api/v1/contacts/request") {
      contactRequested = true;
      const body = await route.request().postDataJSON();
      return json(route, contact(body.target, "pending"), 201);
    }

    if (url.pathname === "/api/v1/contacts/respond") {
      const body = await route.request().postDataJSON();
      return json(route, {
        requester: body.requester,
        target: "did:web:alice.example",
        status: body.action === "accept" ? "accepted" : "rejected",
        created_at: "2026-04-28T12:00:00Z",
        updated_at: "2026-04-28T12:00:00Z",
      });
    }

    if (url.pathname === "/api/v1/contacts") {
      return json(route, {
        contacts: contactRequested ? [contact("did:web:bob.example", "pending")] : [],
      });
    }

    if (url.pathname === "/api/v1/spaces" && route.request().method() === "POST") {
      const body = await route.request().postDataJSON();
      productSpaceDeleted = false;
      productMembers = ["did:web:alice.example", ...(body.invitees ?? [])];
      return json(route, spaceLifecycle(PRODUCT_SPACE, productMembers, productSpaceDeleted), 201);
    }

    if (url.pathname.match(/^\/api\/v1\/spaces\/[^/]+$/) && route.request().method() === "PATCH") {
      const spaceId = decodeURIComponent(url.pathname.split("/").pop() ?? DEMO_SPACE);
      return json(route, { ok: true, space_id: spaceId });
    }

    if (url.pathname.match(/^\/api\/v1\/spaces\/[^/]+\/policy$/) && route.request().method() === "PUT") {
      const body = await route.request().postDataJSON();
      const spaceId = decodeURIComponent(url.pathname.split("/")[4]);
      return json(route, {
        ok: true,
        space_id: spaceId,
        join_rule: body.join_rule,
        history_visibility: body.history_visibility,
      });
    }

    if (url.pathname.match(/^\/api\/v1\/spaces\/[^/]+\/invite$/) && route.request().method() === "POST") {
      const body = await route.request().postDataJSON();
      const spaceId = decodeURIComponent(url.pathname.split("/")[4]);
      return json(route, {
        ok: true,
        invite_id: "cx:invite:e2e",
        space_id: spaceId,
        target: body.target,
        state: "pending",
      });
    }

    if (url.pathname.match(/^\/api\/v1\/spaces\/[^/]+\/invite\/accept$/) && route.request().method() === "POST") {
      const body = await route.request().postDataJSON();
      const spaceId = decodeURIComponent(url.pathname.split("/")[4]);
      return json(route, {
        ok: true,
        invite_id: body.invite_id,
        space_id: spaceId,
        target: "did:web:carol.example",
        state: "accepted",
      });
    }

    if (url.pathname.match(/^\/api\/v1\/spaces\/[^/]+\/invite\/reject$/) && route.request().method() === "POST") {
      const body = await route.request().postDataJSON();
      const spaceId = decodeURIComponent(url.pathname.split("/")[4]);
      return json(route, {
        ok: true,
        invite_id: body.invite_id,
        space_id: spaceId,
        target: "did:web:carol.example",
        state: "canceled",
      });
    }

    if (url.pathname.match(/^\/api\/v1\/spaces\/[^/]+\/archive$/) && route.request().method() === "POST") {
      const spaceId = decodeURIComponent(url.pathname.split("/")[4]);
      return json(route, { ok: true, space_id: spaceId, archived: true });
    }

    if (url.pathname.match(/^\/api\/v1\/spaces\/[^/]+\/leave$/) && route.request().method() === "POST") {
      const spaceId = decodeURIComponent(url.pathname.split("/")[4]);
      return json(route, { ok: true, space_id: spaceId });
    }

    if (url.pathname.match(/^\/api\/v1\/spaces\/[^/]+\/members\/.+\/ban$/) && route.request().method() === "POST") {
      const parts = url.pathname.split("/");
      return json(route, {
        ok: true,
        space_id: decodeURIComponent(parts[4]),
        member: decodeURIComponent(parts[6]),
        banned: true,
      });
    }

    if (url.pathname === "/api/v1/mls/rotate") {
      const body = await route.request().postDataJSON();
      return json(route, { ok: true, epoch: 2, group_id: body.group_id });
    }

    if (url.pathname === `/api/v1/spaces/${PRODUCT_SPACE}/members` && route.request().method() === "POST") {
      const body = await route.request().postDataJSON();
      if (!productMembers.includes(body.member)) {
        productMembers.push(body.member);
      }
      return json(route, spaceLifecycle(PRODUCT_SPACE, productMembers, productSpaceDeleted));
    }

    if (url.pathname === `/api/v1/spaces/${PRODUCT_SPACE}/members/did:web:bob.example` && route.request().method() === "DELETE") {
      productMembers = productMembers.filter((member) => member !== "did:web:bob.example");
      return json(route, spaceLifecycle(PRODUCT_SPACE, productMembers, productSpaceDeleted));
    }

    if (url.pathname === `/api/v1/spaces/${PRODUCT_SPACE}` && route.request().method() === "DELETE") {
      productSpaceDeleted = true;
      return json(route, spaceLifecycle(PRODUCT_SPACE, productMembers, productSpaceDeleted));
    }

    if (url.pathname === "/api/v1/messages/send") {
      if (!route.request().headers()["x-contrix-request-id"]) {
        return json(route, {
          ok: false,
          error: { errcode: "missing_request_id", error: "missing x-contrix-request-id" },
        }, 428);
      }

      const body = await route.request().postDataJSON();
      if (body.content?.body === "persisted product flow message") {
        return json(route, {
          event_id: "cx:event:e2e-product",
          operation_id: "cx:operation:e2e-product",
          commit_id: "cx:commit:e2e-product",
          head_commit: "cx:commit:e2e-product",
          sync_token: "sx:e2e:product",
        }, 201);
      }

      messageCounter += 1;
      return json(route, {
        event_id: `cx:event:e2e-message-${messageCounter}`,
        operation_id: `cx:operation:e2e-message-${messageCounter}`,
        commit_id: `cx:commit:e2e-message-${messageCounter}`,
        head_commit: `cx:commit:e2e-message-${messageCounter}`,
        sync_token: `sx:e2e:message-${messageCounter}`,
      }, 201);
    }

    if (url.pathname.match(/^\/api\/v1\/messages\/[^/]+$/) && route.request().method() === "PATCH") {
      if (!route.request().headers()["x-contrix-request-id"]) {
        return json(route, {
          ok: false,
          error: { errcode: "missing_request_id", error: "missing x-contrix-request-id" },
        }, 428);
      }
      const messageId = decodeURIComponent(url.pathname.split("/")[4]);
      return json(route, {
        event_id: messageId,
        operation_id: `cx:operation:e2e-edit:${messageId}`,
        commit_id: `cx:commit:e2e-edit:${messageId}`,
      });
    }

    if (url.pathname.match(/^\/api\/v1\/messages\/[^/]+\/redact$/) && route.request().method() === "POST") {
      if (!route.request().headers()["x-contrix-request-id"]) {
        return json(route, {
          ok: false,
          error: { errcode: "missing_request_id", error: "missing x-contrix-request-id" },
        }, 428);
      }
      const messageId = decodeURIComponent(url.pathname.split("/")[4]);
      return json(route, {
        event_id: messageId,
        redaction_id: `cx:redaction:e2e:${messageId}`,
      });
    }

    if (url.pathname === "/api/v1/sync") {
      return json(route, {
        next_batch: "sx:e2e:2",
        spaces: {
          [DEMO_SPACE]: {
            summary: {
              title: "Contrix Demo Space",
              summary: "Shared demo Space served by mocked serverx",
            },
            timeline: { events: [], limited: false },
            state: [],
            ephemeral: [],
            unread: { notification_count: 0, highlight_count: 0 },
          },
        },
        to_device: [{ type: "cx.mls.welcome", content: { ciphertext: "opaque" } }],
        account_data: [],
        device_lists: { changed: [], left: [] },
      });
    }

    if (url.pathname === "/api/v1/directory/search-spaces") {
      return json(route, {
        results: [spacePreview()],
        next_cursor: null,
      });
    }

    if (url.pathname === "/api/v1/directory/search-organizations") {
      return json(route, {
        results: [
          {
            id: "did:web:org.contrix.example",
            did: "did:web:org.contrix.example",
            handle: "contrix.example",
            name: "Contrix Labs",
            description: "Protocol and product engineering for Contrix deployments.",
            discoverability: "listed",
            profile_visibility: "public",
            directory_services: ["did:web:serverx.local"],
            proofs: [{ type: "org_membership" }],
          },
        ],
        next_cursor: null,
      });
    }

    if (url.pathname === "/api/v1/directory/search-actors") {
      return json(route, {
        results: [
          {
            did: "did:web:bob.example",
            handle: "bob.example",
            display_name: "Bob Example",
          },
        ],
        next_cursor: null,
      });
    }

    if (url.pathname === "/api/v1/directory/resolve-handle") {
      const body = await route.request().postDataJSON();
      return json(route, {
        did: "did:web:alice.example",
        handle: body.handle,
        did_document: {
          id: "did:web:alice.example",
          alsoKnownAs: [`acct:${body.handle}`],
        },
      });
    }

    if (url.pathname === "/api/v1/directory/resolve-space") {
      return json(route, {
        space_preview: spacePreview(),
        stripped_state: [],
        join_rule: "public",
        via_services: ["did:web:serverx.local"],
      });
    }

    if (url.pathname === "/api/v1/directory/describe") {
      return json(route, {
        service_did: "did:web:serverx.local",
        resource_types: ["space", "organization", "actor"],
        discovery_profiles: ["cx.profile.directory.v1"],
        restricted_query_proof: false,
      });
    }

    if (url.pathname === "/api/v1/repo/describe") {
      return json(route, {
        repo_did: "did:web:serverx.local",
        head_commit: "cx:commit:e2e",
        supported_signatures: ["detached_jws"],
        limits: { max_commits: 100 },
      });
    }

    if (url.pathname === "/api/v1/repo/commits") {
      return json(route, {
        commits: [
          {
            commit_id: "cx:commit:e2e",
            signatures: [{ alg: "none", signer: "did:web:serverx.local" }],
          },
        ],
        next_cursor: null,
        has_more: false,
      });
    }

    if (url.pathname === "/api/v1/repo/submit-commit") {
      const body = await route.request().postDataJSON();
      commitCounter += 1;
      return json(route, {
        status: "accepted",
        commit_id: body.commit?.commit_id ?? `cx:commit:e2e-submit-${commitCounter}`,
        head_commit: body.commit?.commit_id ?? `cx:commit:e2e-submit-${commitCounter}`,
        sync_token: `sx:e2e:commit-${commitCounter}`,
      }, 202);
    }

    if (url.pathname === "/api/v1/repo/operations") {
      return json(route, {
        operations: [
          {
            operation_id: "cx:op:audit",
            kind: "cx.message.send",
            actor: "did:web:alice.example",
            timestamp: "2026-04-28T12:00:00Z",
            preview: "audit operation preview",
          },
        ],
        missing: [],
        unauthorized: [],
      });
    }

    if (url.pathname === "/api/v1/repo/sync") {
      return json(route, { operations: [], next_cursor: "sx:e2e:2", has_more: false });
    }

    if (url.pathname === "/api/v1/sync/backfill") {
      return json(route, { events: [], prev_cursor: null, next_cursor: null, limited: false });
    }

    if (url.pathname === "/api/v1/sync/snapshot-head") {
      return json(route, {
        snapshot_ref: `cx:snapshot:${DEMO_SPACE}:head`,
        state_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        frontier: { space_id: DEMO_SPACE },
        signature: { alg: "none" },
      });
    }

    if (url.pathname === "/api/v1/identity/describe") {
      return json(route, {
        service_did: "did:web:serverx.local",
        registry_mode: "development_local",
        supported_receipts: ["local"],
        protocol_version: "1.0",
        profiles: ["cx.identity.local-dev.v1"],
      });
    }

    if (url.pathname === "/api/v1/identity/resolve") {
      const body = await route.request().postDataJSON();
      return json(route, {
        did_document: { id: body.did },
        key_log_head: null,
        seq: 0,
        receipts: [],
        method_evidence: { mode: "development_local" },
      });
    }

    if (url.pathname === "/api/v1/identity/submit-did-operation") {
      return json(route, {
        ok: true,
        operation_id: "cx:didop:e2e",
        status: "accepted",
      }, 202);
    }

    if (url.pathname === "/api/v1/sync/describe") {
      return json(route, {
        service_did: "did:web:serverx.local",
        supported_sync_profiles: ["initial", "incremental"],
        limits: {},
        frontier: {},
      });
    }

    if (url.pathname === "/api/v1/index/describe") {
      return json(route, {
        service_did: "did:web:serverx.local",
        reducer_profiles: ["cx.reducer.v1"],
        schema_profiles: ["cx.schema.core.v1"],
        query_features: ["space_preview"],
        frontier: {},
      });
    }

    if (url.pathname === "/api/v1/index/query") {
      return json(route, {
        results: [
          {
            kind: "space_preview",
            space_id: DEMO_SPACE,
            title: "Contrix Demo Space",
            entity_type: "space",
            facets: ["renderable", "com.example.preview"],
            renderer: "card",
            item_facets: ["stateful", "rankable"],
          },
        ],
        next_cursor: null,
        frontier: {},
      });
    }

    if (url.pathname === "/api/v1/index/notifications") {
      return json(route, {
        notifications: [
          {
            notification_id: "notif-msg-1",
            title: "New message",
            body: "Alice sent a message in Demo Space",
            space_id: DEMO_SPACE,
            kind: "message",
            timestamp: "2026-04-28T12:01:00Z",
            read: false,
          },
          {
            notification_id: "notif-invite-1",
            title: "New invite",
            body: "You were invited to review Demo Space",
            space_id: DEMO_SPACE,
            kind: "invite",
            timestamp: "2026-04-28T12:02:00Z",
            read: false,
          },
        ],
        next_cursor: null,
        unread_count: 2,
      });
    }

    if (url.pathname === "/api/v1/authz/check") {
      return json(route, {
        allowed: true,
        reason_code: "frontier_current",
        grants: ["cx:grant:e2e"],
        obligations: [{ type: "audit", reason_required: false }],
      });
    }

    if (url.pathname === "/api/v1/authz/effective-grants") {
      return json(route, {
        grants: [
          {
            grant_id: "cx:grant:e2e",
            issuer: "did:web:admin.example",
            subject: url.searchParams.get("subject"),
            actions: ["space.read", "message.send"],
            resource_selectors: ["space:cx:space:01js0sp0000000000000000000/**"],
            constraints: [
              { type: "temporal", not_after: "2026-12-31T00:00:00Z" },
              {
                type: "type_restriction",
                params: { allowed_types: ["space"], allowed_entity_facets: ["renderable", "stateful"] },
              },
            ],
            delegation_chain: ["cx:grant:root", "cx:grant:e2e"],
          },
        ],
        state_hash: "cx:statehash:e2e",
        evaluated_at: "2026-04-28T12:00:00Z",
      });
    }

    if (url.pathname === "/api/v1/authz/invites") {
      return json(route, { invites: [], next_cursor: null });
    }

    if (url.pathname === "/api/v1/profile/presence") {
      return json(route, { actor: url.searchParams.get("did"), presence: "online" });
    }

    if (url.pathname === "/api/v1/keys/upload") {
      return json(route, { one_time_key_counts: { signed_curve25519: 1 }, fallback_keys: {} });
    }

    if (url.pathname === "/api/v1/keys/query") {
      return json(route, { device_keys: {}, failures: {} });
    }

    if (url.pathname === "/api/v1/keys/claim") {
      return json(route, { one_time_keys: {}, failures: {} });
    }

    if (url.pathname === "/api/v1/device_messages" && route.request().method() === "GET") {
      return json(route, { events: [], next_batch: "sx:devmsg:1", limited: false });
    }

    if (url.pathname.startsWith("/api/v1/device_messages/")) {
      return json(route, { ok: true, delivered: { "did:web:alice.example": ["dev_yougen"] }, unknown_devices: {} });
    }

    if (url.pathname === "/api/v1/push/register-device") {
      return json(route, { ok: true, registration_id: "cx:push:e2e", expires_at: null });
    }

    if (url.pathname === "/api/v1/push/unregister-device") {
      return json(route, { ok: true });
    }

    if (url.pathname === "/api/v1/blob/upload") {
      return json(route, {
        blob_ref: "cx:blob:sha256:e2e",
        size: 23,
        media_type: "application/octet-stream",
        sha256: "e2e",
        upload_receipt: { service_did: "did:web:serverx.local" },
      });
    }

    if (url.pathname === "/api/v1/media/ice-config") {
      return json(route, {
        ice_servers: [
          { urls: ["stun:stun.serverx.local:3478"] },
          {
            urls: ["turn:turn.serverx.local:3478?transport=udp"],
            username: "turn-user",
            credential: "turn-secret",
          },
        ],
        ttl_seconds: 600,
      });
    }

    if (url.pathname === "/api/v1/blob/get") {
      return route.fulfill({ status: 200, contentType: "application/octet-stream", body: "yougen encrypted bytes" });
    }

    if (url.pathname === "/api/v1/moderation/report") {
      return json(route, { report_id: "cx:report:e2e", status: "queued", routed_to: ["did:web:serverx.local#moderation"] });
    }

    return json(route, { ok: false, error: { errcode: "not_found", error: `No e2e mock for ${url.pathname}` } }, 404);
  });
}

function spacePreview() {
  return {
    space_id: DEMO_SPACE,
    name: "Contrix Demo Space",
    description: "Shared demo Space served by mocked serverx",
    tags: ["demo"],
    public: true,
    category: "collaboration",
  };
}

function contact(target: string, status: string) {
  return {
    requester: "did:web:alice.example",
    target,
    status,
    created_at: "2026-04-28T12:00:00Z",
    updated_at: "2026-04-28T12:00:00Z",
  };
}

function spaceLifecycle(spaceId: string, members: string[], deleted: boolean) {
  return {
    ok: true,
    space_id: spaceId,
    owner: "did:web:alice.example",
    members,
    deleted,
  };
}

function mimiProviderDirectory() {
  return {
    schema: "cx.schema.mimi_interop.v1",
    service_did: "did:web:mimi.example.com",
    service_type: "mimi_provider_facade",
    supported_profiles: ["cx.profile.mimi_interop.v1"],
    mimi: {
      protocol_draft: "draft-ietf-mimi-protocol-06",
      content_draft: "draft-ietf-mimi-content-08",
      room_policy_draft: "draft-ietf-mimi-room-policy-03",
      identifier_draft: "draft-kohbrok-mimi-identifiers-01",
      base_url: "https://mimi.example.com/api/v1/mimi",
      provider_id: "mimi://mimi.example.com",
      features: [
        "key_material",
        "room_update",
        "notify",
        "submit_message",
        "group_info",
        "consent",
        "identifier_query",
        "report_abuse",
        "proxy_download",
      ],
      mls_cipher_suites: ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
      content_profiles: [
        "application/mimi-content",
        "text/plain;charset=utf-8",
        "text/markdown;variant=GFM-MIMI",
        "application/vnd.contrix.content+json",
      ],
      room_policy_components: ["roles", "join_rules", "history_visibility"],
    },
    proof: { type: "mock-http-message-signature" },
  };
}

function json(route: Route, body: unknown, status = 200) {
  return route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}
