// Yougen-internal parity guard.
//
// `mockCokretContract.ts` is the parity-tested baseline (compared against a
// real soland process by `cotest/tests/yougen_mock_parity.rs`). The richer
// `mockCokretApi.ts` route stub is what every yougen Playwright spec
// actually consumes. The two can drift silently because mockCokretApi has
// explicit per-path handlers that bypass the trailing contract fallback at
// the bottom of the route hook.
//
// This spec keeps them aligned: for every path the contract handles, the
// api stub MUST return a response whose top-level key set is a superset of
// the contract's. api can carry UI-flavored extras (e.g. `frontier`); it
// MUST NOT drop or rename a key the contract — and therefore real soland —
// emits.

import { expect, test } from "@playwright/test";
import { mockCokretApi } from "./mockCokretApi";
import { mockCokretContract } from "./mockCokretContract";

type Probe = {
  label: string;
  method: "GET" | "POST";
  path: string;
  body?: Record<string, unknown>;
};

const PROBES: Probe[] = [
  { label: "server_describe", method: "GET", path: "/api/v1/server/describe" },
  {
    label: "events_submit",
    method: "POST",
    path: "/api/v1/events",
    body: {
      event_id: "ck:event:alignment-1",
      kind: "cx.message.create",
      realm_id: "ck:realm:0196419b-0000-7000-8000-000000000000",
      actor_id: "did:web:alice.example",
      created_at: "2026-04-28T12:00:00Z",
      payload: { body: "alignment probe" },
    },
  },
  { label: "events_list", method: "GET", path: "/api/v1/events" },
  { label: "account_me", method: "GET", path: "/api/v1/account/me" },
  { label: "directory_describe", method: "GET", path: "/api/v1/directory/describe" },
  {
    label: "directory_search_realms",
    method: "POST",
    path: "/api/v1/directory/search-realms",
    body: { query: "demo", limit: 20 },
  },
  { label: "keys_backups", method: "GET", path: "/api/v1/keys/backups" },
  {
    label: "devices_pairing_challenge",
    method: "POST",
    path: "/api/v1/devices/pairing-challenge",
    body: { device_id: "dev_alignment_probe" },
  },
  {
    label: "ephemeral_typing",
    method: "POST",
    path: "/api/v1/ephemeral",
    body: {
      kind: "cx.typing",
      realm_id: "ck:realm:0196419b-0000-7000-8000-000000000000",
      actor_id: "did:web:alice.example",
      sent_at: "2026-04-28T12:00:00Z",
      expires_at: "2026-04-28T12:00:30Z",
      payload: { typing: true },
    },
  },
];

// Some api-mock paths intentionally embed extra UI-facing fields. Record
// the contract keys these probes MUST still return so the superset check is
// asymmetric in the helpful direction (api ⊇ contract).
const CONTRACT_REQUIRED: Record<string, string[]> = {
  server_describe: [
    "service_did",
    "service_type",
    "protocol_version",
    "supported_profiles",
    "supported_features",
    "supported_operations",
    "limits",
  ],
  events_submit: ["event_id", "status", "canonical_digest", "sync_token", "receipt"],
  events_list: ["events"],
  account_me: ["did", "handle", "display_name"],
  directory_describe: [
    "service_did",
    "resource_types",
    "discovery_profiles",
    "restricted_query_proof",
  ],
  directory_search_realms: ["results"],
  keys_backups: ["backups"],
  devices_pairing_challenge: ["challenge_id", "device_id", "expires_at"],
  ephemeral_typing: ["accepted", "kind", "realm_id"],
};

test.describe("mockCokretApi ↔ mockCokretContract alignment @contract-parity", () => {
  test.beforeEach(async ({ page }) => {
    await mockCokretApi(page);
    await page.addInitScript(() => {
      if (localStorage.getItem("yougen.config.v1")) {
        return;
      }
      localStorage.setItem(
        "yougen.config.v1",
        JSON.stringify({
          server_url: "https://local.host",
          account_did: "did:web:alice.example",
          device_id: "ck:device:01964137-0000-7000-8000-0000000000a1",
          session_token: "sx:e2e-token",
        }),
      );
    });
    await page.goto("/", { waitUntil: "domcontentloaded", timeout: 120_000 });
    await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
  });

  for (const probe of PROBES) {
    test(`${probe.label} — api response covers contract key set`, async ({ page }) => {
      const apiResponse = await page.evaluate(async (req) => {
        const init: RequestInit = {
          method: req.method,
          headers: { "x-cokret-request-id": `alignment-${req.label}` },
        };
        if (req.body !== undefined) {
          (init.headers as Record<string, string>)["content-type"] = "application/json";
          init.body = JSON.stringify(req.body);
        }
        const response = await fetch(req.path, init);
        const text = await response.text();
        let parsed: unknown = null;
        if (text.length > 0) {
          try {
            parsed = JSON.parse(text);
          } catch {
            parsed = text;
          }
        }
        return { status: response.status, body: parsed };
      }, probe);

      const contractResponse = mockCokretContract({
        method: probe.method,
        path: probe.path,
        body: probe.body ?? {},
      });

      expect(contractResponse, `contract must define ${probe.label}`).not.toBeUndefined();

      expect(
        apiResponse.status,
        `${probe.label}: api status differs from contract`,
      ).toBe(contractResponse!.status);

      const apiKeys = new Set(Object.keys((apiResponse.body ?? {}) as Record<string, unknown>));
      const contractKeys = Object.keys(
        (contractResponse!.body ?? {}) as Record<string, unknown>,
      );
      const missing = contractKeys.filter((key) => !apiKeys.has(key));
      expect(
        missing,
        `${probe.label}: api is missing contract keys ${missing.join(", ")}`,
      ).toEqual([]);

      const required = CONTRACT_REQUIRED[probe.label] ?? [];
      const missingRequired = required.filter((key) => !apiKeys.has(key));
      expect(
        missingRequired,
        `${probe.label}: api is missing required keys ${missingRequired.join(", ")}`,
      ).toEqual([]);
    });
  }
});
