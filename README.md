# inkson

Inkson is the Arkret clean-break reference client. Its protocol boundary is
small on purpose: producer-signed Events are submitted to the authenticated
current governance Station and become visible only through Station-signed
`RealmCommit` records.

## Ordering model

- A Realm has one Realm stream.
- Every Circle has its own Circle stream.
- Every Sidecar has its own Sidecar stream.
- A `RealmCommit.previous_commit_ref` links only to the preceding commit in
  that same stream.
- Producer Events contain no predecessor pointer, and there is no total order
  across the Realm, Circle, and Sidecar streams.

Local state is reconstructed from a signed snapshot plus one tail per visible
stream. Inkson stores per-stream heads; it does not synthesize a cross-stream
sequence.

## Joining and authority changes

An invitation supplies discovery material, not a durable trust anchor. Join
requests a fresh nonce-bound `RealmAuthorityBundle`, verifies the complete
genesis-to-current handoff chain and current assertion, then obtains the
snapshot and stream tails from the authenticated current Station. The inviter
and the original Station are never implicit fallback sources.

Wire-shape validation is followed by a mandatory host cryptographic verifier;
callers cannot select a Station from unverified detached signatures.

A Station change is installed only when the SDK validates the signed handoff,
the complete per-stream head manifest, the signed snapshot, and the updated
public authority bundle as one package.

## MLS

An MLS Commit is staged alongside its producer Event. Inkson installs the MLS
state transition only after the governance Station returns an accepted
`RealmCommit`. Welcome objects are then released into a separate delivery
queue, so delivery retry cannot replay the MLS state transition.

## Local verification

The repository uses the sibling `../arkret-rust-sdk` checkout.

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo check --target wasm32-unknown-unknown
```

The pre-clean-break implementation remains available on the `old-decenter`
branch.
