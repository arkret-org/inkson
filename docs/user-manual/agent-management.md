# inkson — Agent Management

> How to register, govern, and revoke automated members (bots / personal
> agents / services). Spec source: `arkret-spec/spec/v1/zh/extensions/agent-integration.md`.

Agents are first-class principals. They get their own DID + signing key
and act under explicit capability proofs — never your personal device key.

The agent surface lives under **Settings → Agents**.

---

## 1. Concepts

| Concept | What it is |
| --- | --- |
| **Native** actor | A real device (yours). Stamped by the reducer as `actor_kind="native"`. |
| **Ghost** actor | An applet-bound bot. Tagged `actor_kind="ghost"` (amber badge). |
| **Service** actor | A first-party service principal (blue badge). |
| **Personal Agent** | A user-owned automation actor (green badge). |
| **Private Sidecar** | A controller-private, Realm-scoped AI object hosted inside the current Strand. Eligible owned Agents derive its access; its backing MLS scope is not a user-visible Circle. |
| **Capability proof** | A signed grant that lets the agent invoke specific operations. 14 capability actions land in v1. |

<!-- TODO(screenshot): agents-panel-overview.png -->

---

## 2. Provision a personal agent

The richer path. Use `PersonalAgentAdminPanel` for a real personal agent
with a Private Sidecar.

1. Click **+ Provision personal agent**.
2. Walk through the provision wizard:
   - **Identity** — agent DID + handle.
   - **Controller** — confirm the owning controller account.
   - **Sidecar** — `sidecar_home_policy` defaults to
     `context_realm_preferred`.
   - **Capabilities** — pick from the 14-action set.
3. Confirm via the **DangerousActionDialog**. Type `DEACTIVATE` to enable
   later destructive paths.

<!-- TODO(screenshot): personal-agent-provision-wizard.png -->

---

## 3. Day-to-day operations

Each agent row exposes:

- **Pause / Resume** — temporarily revoke without deleting the agent.
- **Rotate key** — issue a fresh signing key while preserving the DID.
- **Attach / Detach grant** — bind / unbind individual capability proofs.
- **Sidecar ensure** — reconcile the Realm-private Sidecar and its eligible Agent access.
- **Deactivate** — permanent revocation. Type `DEACTIVATE` to confirm.

<!-- TODO(screenshot): personal-agent-admin-actions.png -->

---

## 4. Action approval

When an agent requests a capability action you'll see an
`ActionApproveDialog` with:

- **Payload digest** — sha256 of the requested operation.
- **Expiry** — single-use nonce window.
- **Sidecar exposure disclosure** — `AKP-0009 §3 invariant 10`. Read it.

<!-- TODO(screenshot): action-approve-dialog.png -->

Approving emits the canonical agent action-approval event bound to the
request digest and single-use nonce. Accountability remains anchored by
the agent signature, `agent_context`, and the referenced grant.

---

## 5. Audit trail

Visit `/audit` and filter by the agent's DID. Agent-authored events retain
their signer, `agent_context`, and authorization reference so operators can
trace execution back to its controller grant.

<!-- TODO(screenshot): agent-audit-verify-result.png -->

---

## 6. Revoke / decommission

1. Click **Deactivate** on the agent row.
2. Type `DEACTIVATE` in the confirmation field.
3. Click **Confirm — destructive**.
4. inkson publishes the canonical personal-agent deactivate operation. The agent
   can no longer be summoned by any controller.

<!-- TODO(screenshot): agent-deactivate-confirm.png -->

After deactivation:

- The Agent is removed from derived Sidecar access; new addressing is blocked while MLS removal and epoch rotation reconcile.

---

## 7. Safety checklist

Before granting a capability:

- [ ] Capability scope is the minimum required for the agent's job.
- [ ] Expiry is set (none of the 14 actions should be open-ended).
- [ ] Sidecar exposure disclosure was read and acknowledged.
- [ ] You have a deactivation path on this device (don't grant from a
      device you cannot revoke from).
