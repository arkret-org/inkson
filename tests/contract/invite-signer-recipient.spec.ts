import { expect, test } from "@playwright/test";
import { inksonWire, nativeSignerRecipientMatches } from "../e2e/mockArkretApi";

type Fixture = Parameters<typeof nativeSignerRecipientMatches>[0];
let invitation: Fixture;
test.beforeAll(() => {
  invitation = inksonWire<Fixture>("mock-realm-fixture", { salt: 10, title: "Invited Realm", directed_invite: true });
});

// These tests select the exact declared recipient only. Membership and signer
// history still require nativeReadable and the unchanged native verifier.
test("directed signer fixture selects the complete invitation recipient, not its inviter", () => {
  const recipient = invitation.invite_recipient!.identity.account_id;
  expect(recipient).not.toEqual(invitation.identity.account_id);
  expect(nativeSignerRecipientMatches(invitation, recipient)).toBe(true);
});

for (const dimension of ["inviter", "Station", "principal"] as const) {
  test(`directed signer fixture rejects the wrong ${dimension} recipient`, () => {
    const recipient = invitation.invite_recipient!.identity.account_id;
    const wrong = dimension === "inviter" ? invitation.identity.account_id : {
      ...recipient,
      ...(dimension === "Station" ? { station_id: "ak:did_core:web:other.example" } : { principal_id: "ak:did_core:web:mallory.example" }),
    };
    expect(nativeSignerRecipientMatches(invitation, wrong)).toBe(false);
  });
}

test("ordinary signer fixtures retain the complete original identity fallback", () => {
  const ordinary = { identity: invitation.identity };
  expect(nativeSignerRecipientMatches(ordinary, invitation.identity.account_id)).toBe(true);
  expect(nativeSignerRecipientMatches(ordinary, invitation.invite_recipient!.identity.account_id)).toBe(false);
});
