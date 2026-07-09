# R3 Error Codes — User Perspective

This page is the user-facing reference for the new error codes that R3
introduced. Each entry describes what the error means in plain terms,
the most likely cause from the user's perspective, and the recommended
next step.

For the protocol-level definitions see
`arkret-rust-sdk/docs/architecture.md`. For the operator-side narrative
(why the error fires) see the soland and coauth runbooks. **This page is
deliberately user-first**: it does not require protocol knowledge to
read.

## `agent_paused`

**What you see:** an action you tried to take through an agent (a bot,
personal assistant, or scheduled task) failed with a message like
"agent is paused".

**What it means:** the agent has been paused by you or by an
administrator. It is **not** broken; it is intentionally not accepting
new work right now.

**What to do:**

1. Open **Settings → Agents** (or `/agents` on the web).
2. Find the agent in the list. Its status badge will read **Paused**.
3. If you paused it on purpose (e.g. for a maintenance window), no
   action is needed — just wait until you're ready to **Resume**.
4. If you didn't pause it, check whether an admin in your realm paused
   it (the agent detail page shows the most recent pause event). Ask
   the admin to resume it, or resume it yourself if you have the
   privilege.
5. After resuming, retry the action that failed.

**Will I lose data?** No. Pause is reversible; nothing you queued
before the pause is lost. Resume the agent and pending work continues.

## `pairing_request_expired`

**What you see:** pairing a new agent fails with a message like
"pairing request expired" or "the pairing window has closed".

**What it means:** the 10-minute window between starting agent pairing
and completing it elapsed before you finished. The pairing handshake is
deliberately short-lived to limit the risk of a stale pairing being
hijacked.

**What to do:**

1. Start the pairing strand again from **Settings → Agents → Add new
   agent**.
2. This time, complete each step without leaving the screen for long.
3. If you're consistently hitting the timeout, check your device
   clock. The pairing strand needs your device clock to be within ~5
   minutes of real time; if your clock is wrong, every pairing will
   fail. On macOS: **System Settings → General → Date & Time → Set
   automatically**. On Windows: **Settings → Time & language → Date &
   time → Set time automatically**.
4. If the clock is fine but pairing still fails, capture the
   timestamps from both your client and the agent's client and share
   them with support.

**Will I lose data?** No. An expired pairing produces no side effects;
you can simply retry.

## `handle_homograph_forbidden`

**What you see:** when creating or updating a handle (e.g. a username
on a Realm), you get a message like "this handle isn't allowed" or
"this handle could be confused with another one".

**What it means:** the system detected that the handle you chose
visually resembles another existing handle to the point that an
attacker could use one to impersonate the other. Common examples:

- Using Cyrillic letters that look identical to Latin (`а` vs `a`).
- Mixed scripts (Latin + Greek + Cyrillic) in the same handle.
- Confusable digits / letter combinations (`rn` vs `m`, `0` vs `O`).

This check is enforced **before** rate-limiting, so even a single
attempt with a confusable handle will fail.

**What to do:**

1. Pick a handle that uses a single, consistent script (all Latin, all
   Cyrillic, all Han, etc.).
2. Avoid substituting one letter for a visually similar one.
3. If you genuinely need a handle that the system thinks is confusable
   (for example, your name in your native language conflicts with an
   existing handle in another script), contact your Realm admin to
   request a review.

**Why is this strict?** Impersonation attacks via lookalike handles are
a well-documented social-engineering pattern. The system errs on the
side of refusing the handle rather than silently allowing a confusable
collision.

## `participant_binding_invalid`

**What you see:** when joining a call, the join attempt fails with a
message like "the call connection couldn't be verified" or "this
session's credentials don't match".

**What it means:** the cryptographic binding that ties your device to
this specific call participant slot couldn't be verified. There are
three common causes:

1. **Stale token.** The token your client used to join the call has
   expired. Tokens live for at most 10 minutes; if the call lasted
   longer or you were briefly disconnected, the token may have
   expired during the gap.
2. **Wrong focus.** The call moved between media foci (different SFU
   servers) and your token was bound to a focus that's no longer
   accepting connections.
3. **Clock skew.** Your device's clock is far enough off real time
   that the token appears already-expired or not-yet-valid.

**What to do:**

1. Leave the call cleanly (don't just close the window) and rejoin.
   The rejoin issues a fresh token bound to the current focus.
2. If rejoin fails the same way, check your device clock as described
   under `pairing_request_expired` above.
3. If both rejoin and clock are fine, the realm may have a media
   service configuration issue — contact your realm admin and provide
   the timestamp and call ID.

**Will I lose call history?** No. The call's transcript and any
recordings are stored at the realm level, not on your device's token.
Rejoining picks up where you left off.

## See also

For administrators dealing with the operator side of these errors:

- Agent FSM operational handling: `soland/docs/runbook.md` → Agent FSM
  transitions.
- Strict-reject accountability posture (which can produce additional
  user-visible rejects): `sodmin/docs/operator-runbook.md`.
- Push delivery failures (which produce different errors but show
  similar symptoms): `floria/docs/en/runbook.md`.
