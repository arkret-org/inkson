// The offline half of the e2e mock's contract check.
//
// `tests/e2e` proves the client behaves; this proves the mock it behaves
// against still matches the spec. Keeping them apart matters because the e2e
// config builds the client to WASM before it runs a single line, so a stale
// mock field used to cost a twenty-minute build to find — and the next stale
// field cost another one, because each rejection stops at the first.
//
// Run it with `npm run contract`. It launches no browser and builds nothing;
// it only needs `inkson-wire`, which is what validates the bodies.

import { expect, test } from "@playwright/test";

import { mockArkretApi } from "../e2e/mockArkretApi";
import {
  captureRouteHandler,
  concretePath,
  driveOnce,
  isShapeViolation,
  mockOperations,
  violationFingerprint,
  violationSummary,
} from "./mockShapeDriver";

const BASE_URL = "https://local.host";

// Two different synthetic request bodies per operation. A response the mock
// hard-codes rejects identically under both, and that is a real drift from the
// spec. A response assembled out of the request echoes the driver's filler
// back and rejects differently, which says nothing about the spec — only that
// the driver cannot author a valid request for that operation.
type Probe = { query: string; body: Record<string, unknown> };

const PROBES: Probe[] = [
  {
    query: "?realms=ak:realm:AXLdBpLtU052snUYmC7z6ugXuYM9JDBd4PUF5AwhZ39K&subject=ak:did_core:web:bob.example",
    body: {
      actor_id: "ak:did_core:web:bob.example",
      handle: "bob:local.host",
      limit: 1,
      events: [{ realm_id: "ak:realm:AXLdBpLtU052snUYmC7z6ugXuYM9JDBd4PUF5AwhZ39K" }],
    },
  },
  {
    query: "?realms=ak:realm:AajANEG2ah2GJghhdat8rziaz1qjK25iQAYUUR6kcIeW&subject=ak:did_core:web:carol.example",
    body: {
      actor_id: "ak:did_core:web:carol.example",
      handle: "carol:local.host",
      limit: 2,
      events: [
        { realm_id: "ak:realm:AajANEG2ah2GJghhdat8rziaz1qjK25iQAYUUR6kcIeW" },
        { realm_id: "ak:realm:AajANEG2ah2GJghhdat8rziaz1qjK25iQAYUUR6kcIeW" },
      ],
    },
  },
];

// Several routes only exist under an option — the seeded recovery policy, the
// Sidecar Circle row, the low-floor Realm. Driving the default install alone
// leaves those branches unchecked, which is how
// `recovery_policy_active_outcome` stayed stale while this gate was green.
const INSTALLS: Record<string, unknown>[] = [
  {},
  {
    preseedRecoveryMaterial: true,
    includeSidecarInCircleList: true,
    includeLowFloorRealm: true,
    includePrincipalControlRealm: true,
    seedDefaultActiveAgent: true,
  },
];

test("every mock response the inventory names still matches its schema", async () => {
  const violations: string[] = [];
  const requestDependent: string[] = [];
  const covered = new Set<string>();

  for (const install of INSTALLS) {
    const { page, handler } = captureRouteHandler();
    // Installing the mock already validates the static response fixtures, so a
    // drift in those fails here before a single request is driven.
    await mockArkretApi(page as never, install as never);
    const route = handler();
    await driveInstall(route, violations, requestDependent, covered);
  }

  // Recorded, not asserted: these are the operations whose response the driver
  // cannot judge, and the list is the honest statement of this gate's blind
  // spot. They stay covered by `tests/e2e`.
  console.log(
    `mock shape gate: ${covered.size} operations reached, ` +
      `${requestDependent.length} request-dependent and therefore unjudged`,
  );

  expect(violations, violations.join("\n")).toEqual([]);
  // Two ways the assertion above could be vacuously true, both guarded here: a
  // refactor that makes every branch fall through, so nothing is reached; and
  // one that makes every response echo the request, so nothing is judgeable.
  expect(covered.size).toBeGreaterThan(20);
  expect(
    requestDependent.length,
    `too many operations are request-dependent for this gate to mean anything:\n${requestDependent.join("\n")}`,
  ).toBeLessThan(40);
});

async function driveInstall(
  route: ReturnType<ReturnType<typeof captureRouteHandler>["handler"]>,
  violations: string[],
  requestDependent: string[],
  covered: Set<string>,
) {
  for (const operation of mockOperations()) {
    const url = `${BASE_URL}${concretePath(operation.path_template)}`;
    const seen: ({ summary: string; fingerprint: string } | null)[] = [];
    for (const probe of PROBES) {
      try {
        const response = await driveOnce(route, {
          url: `${url}${probe.query}`,
          method: operation.method,
          postData: operation.method === "GET" ? undefined : probe.body,
        });
        if (response) {
          covered.add(operation.operation_id);
        }
        seen.push(null);
      } catch (error) {
        // Anything that is not a schema rejection is the driver failing to
        // satisfy a branch, not a spec drift.
        seen.push(
          isShapeViolation(error)
            ? {
                summary: violationSummary(error),
                fingerprint: violationFingerprint(error),
              }
            : null,
        );
      }
    }

    const label = `${operation.method} ${operation.path_template} (${operation.operation_id})`;
    if (seen[0] && seen[1] && seen[0].fingerprint === seen[1].fingerprint) {
      violations.push(`${label}: ${seen[0].summary}`);
    } else if (seen.some((entry) => entry)) {
      requestDependent.push(label);
    }
  }
}
