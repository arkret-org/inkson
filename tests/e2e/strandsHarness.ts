import { expect, test } from "@playwright/test";
import {
  CURRENT_STATION_ID,
  mockArkretApi,
} from "./mockArkretApi";

export { CURRENT_STATION_ID };

export function submittedEvent(body: any) {
  const entry = Array.isArray(body.events)
    ? body.events[0]
    : (body.event ?? body);
  return entry?.event ?? entry;
}

export const DEMO_REALM =
  "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk";
export const DEMO_BOARD_SPACE =
  "ak:space:AY61QviMxoJ0ALEn5U39bA7Qbi1BxHCrOq4950m2JRjM";
const DEFAULT_SERVER_URL = "https://local.host";
const DEFAULT_SERVER_AUDIENCE = CURRENT_STATION_ID;
const DEFAULT_ACCOUNT_DID = "did:web:alice.example";
const DEFAULT_ACCOUNT_CORE_ID = "ak:did_core:web:alice.example";
const DEFAULT_DEVICE_ID = "ak:device:01964137-0000-7000-8000-0000000000a1";
const DEFAULT_SESSION_CREDENTIAL = "sx:e2e-token";
const DEFAULT_SERVICE_ACCOUNT_ID = "account-1";
const TEST_SESSION_INJECTION_KEY = "inkson.test.session_injection.v1";
const DEFAULT_DPOP_SEED_B64URL = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const DEFAULT_EVENT_SIGNING_SEED_B64URL =
  "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const apiObservations = new WeakMap<
  import("@playwright/test").Page,
  Array<{ method: string; path: string; status: number }>
>();

async function settleWithin<T>(
  operation: Promise<T>,
  fallback: T,
  timeoutMs = 2_000,
) {
  return Promise.race([
    operation.catch(() => fallback),
    new Promise<T>((resolve) => setTimeout(() => resolve(fallback), timeoutMs)),
  ]);
}

function coreIdForDid(did: string) {
  if (did.startsWith("did:web:")) {
    return `ak:did_core:web:${did.slice("did:web:".length)}`;
  }
  throw new Error(`unsupported E2E account DID method: ${did}`);
}

export function testLocalConfig(
  overrides: Partial<{
    serverUrl: string;
    did: string;
    deviceId: string;
  }> = {},
) {
  const serverUrl = overrides.serverUrl ?? DEFAULT_SERVER_URL;
  const did = overrides.did ?? DEFAULT_ACCOUNT_DID;
  const deviceId = overrides.deviceId ?? DEFAULT_DEVICE_ID;
  return {
    stations: [serverUrl],
    active_account: {
      profile_id: "ak:profile:e2e-alice",
      authority: {
        principal_id:
          did === DEFAULT_ACCOUNT_DID
            ? DEFAULT_ACCOUNT_CORE_ID
            : coreIdForDid(did),
        station_id: DEFAULT_SERVER_AUDIENCE,
      },
      resolution: {
        did: did,
        method_history_head: "e2e-method-history-head",
        version_id: "1",
        resolution_event_ref: `ak:event:${"A".repeat(44)}`,
        updated_at: "2026-08-23T00:00:00.000Z",
      },
      device_id: deviceId,
      server_url: serverUrl,
    },
  };
}

const defaultLocalConfig = testLocalConfig();

export function latestTestId(
  page: import("@playwright/test").Page,
  testId: string,
) {
  return page.getByTestId(testId).last();
}

export async function dismissBlockingRecoveryModal(
  page: import("@playwright/test").Page,
) {
  // Dismiss a CHAIN of blocking account-health modals. Dismissing the
  // recovery-missing modal can auto-open the one-time recovery-key setup nudge
  // (account_health::should_auto_prompt_recovery_setup); both expose a
  // "Dismiss"/"Not now" button. Re-query each iteration and don't assert a
  // specific modal hidden — a freshly spawned modal must not fail the helper.
  for (let i = 0; i < 8; i += 1) {
    const modal = page.getByRole("dialog").last();
    const timeout = i === 0 ? 8_000 : 800;
    const visible = await modal
      .waitFor({ state: "visible", timeout })
      .then(() => true)
      .catch(() => false);
    if (!visible) {
      break;
    }
    const recoverySetup = page.getByTestId("recovery-key-setup-modal").last();
    if (await recoverySetup.isVisible().catch(() => false)) {
      const dismissSetup = recoverySetup.getByTestId(
        "recovery-key-setup-dismiss",
      );
      if (await dismissSetup.isVisible().catch(() => false)) {
        await dismissSetup.click();
        await expect(recoverySetup).toBeHidden({ timeout: 8_000 });
        continue;
      }
    }
    const dismiss = modal.getByRole("button", {
      name: /^(Not now|Dismiss|Do this later|Continue with limited access|Continue without history)$/,
    });
    if ((await dismiss.count()) === 0) {
      break;
    }
    await dismiss.first().evaluate((button: HTMLElement) => button.click());
    await page.waitForTimeout(150);
  }
  const authorizeLater = page
    .getByRole("button", {
      name: /^(Do this later|Continue with limited access|Continue without history)$/,
    })
    .last();
  if (await authorizeLater.isVisible().catch(() => false)) {
    await authorizeLater.click();
  }
}

export async function openServerSwitcher(
  page: import("@playwright/test").Page,
) {
  await dismissBlockingRecoveryModal(page);
  const menu = latestTestId(page, "server-switch-menu");
  if (await menu.isVisible()) {
    return;
  }
  await latestTestId(page, "server-switch-button").click();
  await expect(menu).toBeVisible();
}

export async function refreshServer(page: import("@playwright/test").Page) {
  await openServerSwitcher(page);
  await page
    .getByTestId("server-option")
    .filter({ hasText: "https://local.host" })
    .click();
}

export async function gotoAndDismissRecovery(
  page: import("@playwright/test").Page,
  url: string,
) {
  await page.goto(url, { waitUntil: "domcontentloaded" });
  await dismissHistoryRecoveryModal(page);
  await dismissBlockingRecoveryModal(page);
}

export async function dismissHistoryRecoveryModal(
  page: import("@playwright/test").Page,
) {
  const modal = page.getByTestId("mls-recovery-missing-modal").last();
  const appeared = await modal
    .waitFor({ state: "visible", timeout: 5_000 })
    .then(() => true)
    .catch(() => false);
  if (!appeared) {
    return;
  }
  await modal.getByTestId("mls-recovery-missing-dismiss").click();
  await expect(modal).toBeHidden({ timeout: 8_000 });
}

// The default mock account has encrypted history but no local key/backup, so
// the highest-priority account-health prompt (RecoverySetupMissing) shows as a
// blocking modal. Wait for it to settle, then dismiss it so the setup form
// underneath becomes interactable. No-op when the modal never appears.
export async function dismissRecoveryMissingModal(
  page: import("@playwright/test").Page,
) {
  const modal = page.getByTestId("mls-recovery-missing-modal").last();
  const appeared = await modal
    .waitFor({ state: "visible", timeout: 8_000 })
    .then(() => true)
    .catch(() => false);
  if (appeared) {
    // Dismiss the recovery-missing modal AND the recovery-key setup nudge it
    // auto-opens, so the surface underneath becomes interactable.
    await dismissBlockingRecoveryModal(page);
  }
}

export async function openSettings(page: import("@playwright/test").Page) {
  await dismissBlockingRecoveryModal(page);
  await latestTestId(page, "account-menu-button").click();
  await latestTestId(page, "account-menu-settings").click();
}

export async function openDiscussion(page: import("@playwright/test").Page) {
  await openKanban(page);
  await page.getByTestId("kanban-card").first().click();
  await expect(page.getByTestId("card-detail-modal")).toBeVisible();
  await page.getByTestId("card-detail-tab-discussion").click();
  await expect(page.getByTestId("chat-panel")).toBeVisible();
}

export async function openKanban(page: import("@playwright/test").Page) {
  await refreshServer(page);
  await assertRealmTreeSeeded(page);
  await page.goto(`/kanban/${DEMO_REALM}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
  await dismissHistoryRecoveryModal(page);
  await dismissBlockingRecoveryModal(page);
}

export async function assertRealmTreeSeeded(
  page: import("@playwright/test").Page,
) {
  await dismissBlockingRecoveryModal(page);
  const seededRealm = page
    .getByTestId("realm-tree-node-button")
    .filter({ hasText: "Arkret Demo Realm" })
    .first();
  try {
    await expect(seededRealm).toBeVisible({ timeout: 15_000 });
  } catch (error) {
    const diagnostics = {
      url: page.url(),
      emptyState: await page
        .getByTestId("realm-tree-empty-state")
        .allTextContents()
        .catch(() => []),
      selectedRealm: await page
        .getByTestId("selected-realm-id")
        .allTextContents()
        .catch(() => []),
      accountSubscribe: (apiObservations.get(page) ?? []).filter((entry) =>
        entry.path.includes("/_arkret/self/account/subscribe"),
      ),
    };
    throw new Error(
      `Realm tree seed failed before product assertions: ${JSON.stringify(diagnostics)}\n${String(error)}`,
    );
  }
}

export async function createDiscussion(
  page: import("@playwright/test").Page,
  name = "Test Discussion",
) {
  void name;
  await expect(page.getByTestId("chat-panel")).toBeVisible();
}

export async function writeLocalConfig(
  page: import("@playwright/test").Page,
  overrides: Partial<{
    server_url: string;
    did: string;
    device_id: string;
  }>,
) {
  const nextConfig = testLocalConfig({
    serverUrl: overrides.server_url,
    did: overrides.did,
    deviceId: overrides.device_id,
  });
  await page.evaluate((config) => {
    localStorage.setItem("inkson.config.v1", JSON.stringify(config));
  }, nextConfig);
}

function sessionInjectionRecord(
  overrides: Partial<{
    grant_jwt: string;
    grant_id: string;
    audience: string;
    service_account_id: string;
    dpop_seed_b64url: string;
    local_recovery_state: Record<string, unknown>;
    mls_recovery_backup_state: Record<string, unknown>;
    recovery_gate_verified: boolean;
  }> = {},
) {
  return {
    grant_jwt: DEFAULT_SESSION_CREDENTIAL,
    grant_id: "ak:session_grant:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7",
    audience: DEFAULT_SERVER_AUDIENCE,
    service_account_id: DEFAULT_SERVICE_ACCOUNT_ID,
    principal_id: DEFAULT_ACCOUNT_CORE_ID,
    dpop_seed_b64url: DEFAULT_DPOP_SEED_B64URL,
    event_signing_seed_b64url: DEFAULT_EVENT_SIGNING_SEED_B64URL,
    ...overrides,
  };
}

export async function addSessionGrantInjection(
  page: import("@playwright/test").Page,
  overrides: Partial<{
    grant_jwt: string;
    grant_id: string;
    audience: string;
    service_account_id: string;
    dpop_seed_b64url: string;
    local_recovery_state: Record<string, unknown>;
    mls_recovery_backup_state: Record<string, unknown>;
    recovery_gate_verified: boolean;
  }> = {},
) {
  await page.addInitScript(
    ({ record, injectionKey }) => {
      if (localStorage.getItem(injectionKey)) {
        return;
      }
      localStorage.setItem(injectionKey, JSON.stringify(record));
    },
    {
      record: sessionInjectionRecord(overrides),
      injectionKey: TEST_SESSION_INJECTION_KEY,
    },
  );
}

export async function writeSessionGrantInjection(
  page: import("@playwright/test").Page,
  overrides: Partial<{
    grant_jwt: string;
    grant_id: string;
    audience: string;
    service_account_id: string;
    dpop_seed_b64url: string;
  }> = {},
) {
  await addSessionGrantInjection(page, overrides);
  await page.evaluate(
    ({ record, injectionKey, defaults }) => {
      localStorage.setItem("inkson.config.v1", JSON.stringify(defaults));
      localStorage.setItem(injectionKey, JSON.stringify(record));
    },
    {
      record: sessionInjectionRecord(overrides),
      injectionKey: TEST_SESSION_INJECTION_KEY,
      defaults: defaultLocalConfig,
    },
  );
}

export async function writeLocalConfigAndReload(
  page: import("@playwright/test").Page,
  overrides: Partial<{
    server_url: string;
    did: string;
    device_id: string;
  }>,
) {
  await writeLocalConfig(page, overrides);
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForLoadState("domcontentloaded");
}

export async function readLocalConfig(page: import("@playwright/test").Page) {
  return page.evaluate(() =>
    JSON.parse(localStorage.getItem("inkson.config.v1") ?? "{}"),
  );
}

export async function seedLocalRecoveryKeyMetadata(
  page: import("@playwright/test").Page,
) {
  // Account main state is IndexedDB-only. Extend the existing test-only
  // session injection so Rust writes these public recovery metadata records
  // through the real LocalStateStore after secure-store hydration.
  await page.addInitScript(() => {
    const injectionKey = "inkson.test.session_injection.v1";
    const injection = JSON.parse(localStorage.getItem(injectionKey) ?? "{}");
    injection.local_recovery_state = {
      recovery_key_fingerprint: "sha256:e2e-local-recovery-key",
      backup_hpke_public_key_multibase:
        "z6LSbsw3xDCtsMcRWf8HqYViCDXmadAiioEcZCiefbnKxNjt",
      recovery_key_rotated_at: "2026-06-12T12:00:00.000Z",
      sss_threshold: 3,
      sss_total: 5,
      guardians: [],
      passkey_wraps: [],
      last_rehearsed_at: "",
    };
    // mls.recovery_backup.v1 — presence of a backup_id makes
    // mls_recovery_backup_configured() true, which both bypasses the S6 create
    // gate and drives the backup prompt's "use existing key" branch.
    injection.mls_recovery_backup_state = {
      backup_id: "ak:backup:e2e-existing-0000",
    };
    localStorage.setItem(injectionKey, JSON.stringify(injection));
  });
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(latestTestId(page, "client-shell")).toBeVisible({
    timeout: 120_000,
  });
}

// Dismiss the "Protect your encrypted history" backup prompt (needs_mls_backup)
// when it pops up, so a subsequent interaction underneath becomes clickable.
// No-op when the modal isn't shown.
export async function dismissMlsBackupModal(
  page: import("@playwright/test").Page,
) {
  const modal = page.getByTestId("mls-backup-modal").last();
  const appeared = await modal
    .waitFor({ state: "visible", timeout: 4_000 })
    .then(() => true)
    .catch(() => false);
  if (appeared) {
    await page.getByTestId("mls-backup-dismiss").last().click();
    await expect(modal).toBeHidden({ timeout: 8_000 });
  }
}

export function registerStrandsBeforeEach() {
  test.beforeEach(async ({ page }, testInfo) => {
    const observations: Array<{
      method: string;
      path: string;
      status: number;
    }> = [];
    apiObservations.set(page, observations);
    page.on("response", (response) => {
      const url = new URL(response.url());
      if (url.pathname.startsWith("/_arkret/")) {
        observations.push({
          method: response.request().method(),
          path: `${url.pathname}${url.search}`,
          status: response.status(),
        });
      }
    });
    const initialDeviceId = testInfo.title.startsWith(
      "fresh browser requires device authorization",
    )
      ? "ak:device:01964137-0000-7000-8000-0000000000b2"
      : DEFAULT_DEVICE_ID;
    const exercisesRecoveryKeySetup =
      testInfo.title.startsWith("new Recovery Key");
    await mockArkretApi(page, {
      currentDeviceId: initialDeviceId,
      currentDeviceSigningSeedB64url: DEFAULT_EVENT_SIGNING_SEED_B64URL,
      directoryPrimaryHandle: testInfo.title.startsWith(
        "account menu keeps the viewer fallback when the handle directory returns an empty page",
      )
        ? null
        : undefined,
      personalAgentPairingExpiresAt: testInfo.title.startsWith(
        "expired personal agent pairing",
      )
        ? "2000-01-01T00:00:00.000Z"
        : undefined,
      includeSidecarInCircleList: testInfo.title.startsWith(
        "ordinary Circle list",
      ),
      includePrincipalControlRealm: testInfo.title.startsWith(
        "PCR stays out of product navigation",
      ),
      emptyBoard: testInfo.title.startsWith(
        "kanban hides list creation until a board exists",
      ),
      preseedRecoveryMaterial:
        testInfo.title.startsWith("configured recovery session") ||
        testInfo.title.startsWith("setup, onboarding, and Board entry") ||
        testInfo.title.startsWith(
          "agent deactivation submits controller-signed",
        ) ||
        testInfo.title.startsWith(
          "account settings split account/server info",
        ) ||
        testInfo.title.startsWith(
          "kanban hides list creation until a board exists",
        ) ||
        testInfo.title.startsWith(
          "kanban queues canonical event submissions",
        ) ||
        testInfo.title.startsWith("card detail embeds discussion directly"),
      seedDefaultActiveAgent: !testInfo.title.startsWith(
        "account settings split account/server info",
      ),
    });
    if (testInfo.title.startsWith("login page")) {
      return;
    }
    await addSessionGrantInjection(
      page,
      exercisesRecoveryKeySetup
        ? {}
        : {
            local_recovery_state: {
              recovery_key_fingerprint: "sha256:e2e-configured-recovery-key",
              backup_hpke_public_key_multibase:
                "z6LSbsw3xDCtsMcRWf8HqYViCDXmadAiioEcZCiefbnKxNjt",
              recovery_key_rotated_at: "2026-06-12T12:00:00.000Z",
              sss_threshold: 3,
              sss_total: 5,
              guardians: [],
              passkey_wraps: [],
              last_rehearsed_at: "",
            },
            mls_recovery_backup_state: {
              backup_id: "ak:backup:e2e-configured-0000",
            },
            recovery_gate_verified: true,
          },
    );
    await page.addInitScript(
      (initialConfig) => {
        if (localStorage.getItem("inkson.config.v1")) {
          return;
        }
        localStorage.setItem("inkson.config.v1", JSON.stringify(initialConfig));
      },
      {
        ...defaultLocalConfig,
        active_account: {
          ...defaultLocalConfig.active_account,
          device_id: initialDeviceId,
        },
      },
    );
    await page.goto("/", { waitUntil: "domcontentloaded", timeout: 120_000 });
    await expect(latestTestId(page, "client-shell")).toBeVisible({
      timeout: 120_000,
    });
  });

  test.afterEach(async ({ page }, testInfo) => {
    const observations = apiObservations.get(page) ?? [];
    const counts = observations.reduce<Record<string, number>>(
      (current, entry) => {
        const key = `${entry.method} ${entry.path} ${entry.status}`;
        current[key] = (current[key] ?? 0) + 1;
        return current;
      },
      {},
    );
    await testInfo.attach("arkret-request-counts.json", {
      body: Buffer.from(JSON.stringify({ counts, observations }, null, 2)),
      contentType: "application/json",
    });
    await testInfo.attach("inkson-ui-state.json", {
      body: Buffer.from(
        JSON.stringify(
          {
            url: page.url(),
            selectedRealm: await settleWithin(
              page.getByTestId("selected-realm-id").allTextContents(),
              [],
            ),
            sidecarMode: await settleWithin(
              page
                .locator("[data-testid^='sidecar-mode-'].active")
                .allTextContents(),
              [],
            ),
            draft: await settleWithin(
              page.getByTestId("chat-input").last().inputValue(),
              null,
            ),
          },
          null,
          2,
        ),
      ),
      contentType: "application/json",
    });
    const screenshot = await settleWithin(
      page.screenshot({ animations: "disabled", type: "png" }),
      Buffer.alloc(0),
    );
    if (screenshot.length > 0) {
      await testInfo.attach("inkson-final-state.png", {
        body: screenshot,
        contentType: "image/png",
      });
    }
  });
}
