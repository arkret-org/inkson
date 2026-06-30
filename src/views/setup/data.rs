//! Static option tables for the Realm / Space create forms.

pub(super) const DISCOVERABILITY_OPTIONS: [(&str, &str, &str); 6] = [
    (
        "public",
        "Public",
        "Findable in Search. Existence and join surface can be broadly disclosed.",
    ),
    (
        "listed",
        "Listed",
        "Visible in Search, but still separate from how people join or what history they see.",
    ),
    (
        "restricted",
        "Restricted",
        "Directory presence is limited to principals that already satisfy server-side policy.",
    ),
    (
        "unlisted",
        "Unlisted",
        "Not browseable in Search. Entry depends on a direct link or explicit reference.",
    ),
    (
        "invite_only",
        "Invite only",
        "Existence is disclosed only to specifically invited principals.",
    ),
    (
        "secret",
        "Secret",
        "The Realm should not disclose that it exists to unauthorized viewers.",
    ),
];

pub(super) const JOIN_RULE_OPTIONS: [(&str, &str, &str); 4] = [
    (
        "public",
        "Public",
        "Anyone who can see the Realm can join without a separate approval step.",
    ),
    (
        "invite",
        "Invite",
        "Joining requires a member or admin to grant admission explicitly.",
    ),
    (
        "knock",
        "Knock",
        "Applicants can request entry and wait for review.",
    ),
    (
        "restricted",
        "Restricted",
        "Joining depends on policy or claims, even if the Realm is discoverable.",
    ),
];

pub(super) const HISTORY_VISIBILITY_OPTIONS: [(&str, &str, &str); 5] = [
    (
        "world_readable",
        "World readable",
        "Past history is readable without joining. Use only with intentionally open Realms.",
    ),
    (
        "shared",
        "Shared",
        "New members can read the pre-join history that is meant to be shared with the whole Realm.",
    ),
    (
        "invited",
        "Invited",
        "History is visible only from the point an invite made the principal eligible.",
    ),
    (
        "joined",
        "Joined",
        "History starts when the principal actually becomes a member.",
    ),
    (
        "restricted",
        "Restricted",
        "Past history stays tightly scoped; new members see only what policy re-discloses.",
    ),
];

// Spec realm-and-space.md §2.3 — `encryption_profile` enum on the
// Realm create event. `create-locked`, so this choice is permanent for
// the lifetime of the Realm.
pub(super) const ENCRYPTION_PROFILE_OPTIONS: [(&str, &str, &str); 2] = [
    (
        "mls_rfc9420",
        "Encrypted",
        "Recommended. Metadata and content use MLS E2EE.",
    ),
    (
        "none",
        "No encryption",
        "Plaintext is visible to the server. Use only for public Realms.",
    ),
];

// encryption-and-audit.md §2.10 — Realm `content_scheme` (the capability axis,
// orthogonal to `history_visibility` which is the runtime delivery toggle).
// `mls-exporter-aead-v1` makes every epoch's content structurally shareable to
// late joiners (forward secrecy degrades to per-epoch, §2.10.5);
// `mls-rfc9420` keeps per-message forward secrecy and makes pre-join history
// permanently unshareable. Default capable — matches most collaboration needs.
pub(super) const CONTENT_SCHEME_OPTIONS: [(&str, &str, &str); 2] = [
    (
        "mls-exporter-aead-v1",
        "MLS exporter AEAD",
        "content_scheme=mls-exporter-aead-v1. New members can be granted history from before they joined. Forward secrecy is per-epoch.",
    ),
    (
        "mls-rfc9420",
        "MLS PrivateMessage",
        "content_scheme=mls-rfc9420. Pre-join history can never be shared with late joiners. Per-message forward secrecy.",
    ),
];

// Spec realm-and-space.md §2.3 — `security_class`. `high_assurance`
// automatically locks `federation_policy` to one of
// `{closed, restricted, quarantine}`; client UI hint reflects this.
pub(super) const SECURITY_CLASS_OPTIONS: [(&str, &str, &str); 2] = [
    (
        "standard",
        "Standard",
        "Default posture. Federation policy can be open or restricted per Realm settings.",
    ),
    (
        "high_assurance",
        "High assurance",
        "Tightened defaults: federation is forced to restricted/closed/quarantine, audit signals are recorded.",
    ),
];

// Spec realm-and-space.md §2.3 — `federation_policy` reducer-derived
// from `ck.realm.policy` events but seeded at create time. `open` is
// forbidden when security_class=high_assurance.
pub(super) const FEDERATION_POLICY_OPTIONS: [(&str, &str, &str); 4] = [
    (
        "open",
        "Open",
        "Any peer can interact. Not allowed when security_class=high_assurance.",
    ),
    (
        "restricted",
        "Restricted",
        "Allow-list of peers (governance / org-vetted). Default for high_assurance.",
    ),
    (
        "closed",
        "Closed",
        "No federation at all. Use for fully internal Realms.",
    ),
    (
        "quarantine",
        "Quarantine",
        "Inbound is accepted but held for review. Outbound is blocked.",
    ),
];

// Spec realm-and-space.md §2.3 — `notary_profile`. Create-locked.
// `single_did` is the dev / single-operator default; the others are
// for production deployments with multiple notary principals.
pub(super) const ANCHOR_PROFILE_OPTIONS: [(&str, &str, &str); 4] = [
    (
        "single_did",
        "Single DID",
        "One principal signs seals. Simplest setup; default.",
    ),
    (
        "threshold",
        "Threshold",
        "k-of-n signature; configure the participating DIDs in policy.",
    ),
    (
        "open_set",
        "Open set",
        "Any holder of the notary capability may sign.",
    ),
    (
        "mixed",
        "Mixed",
        "Combination of the above — configure via policy.",
    ),
];

// Spec realm-and-space.md §2.3 — `digest_algorithm`. Create-locked.
// `sha256` is the universal default; other choices target hardened
// or interop-with-other-hash-systems deployments.
pub(super) const HASH_PROFILE_OPTIONS: [(&str, &str, &str); 4] = [
    (
        "sha256",
        "SHA-256",
        "Default. Interoperable everywhere in Cokret v1.",
    ),
    (
        "sha512",
        "SHA-512",
        "Wider digest. Choose only if your deployment policy requires it.",
    ),
    (
        "sha3_256",
        "SHA3-256",
        "Keccak family. Use for FIPS-compatible deployments that mandate SHA-3.",
    ),
    (
        "blake3",
        "BLAKE3",
        "Faster on modern CPUs. Use only when all peers support BLAKE3.",
    ),
];

// Spec realm-and-space.md §3.2 — `kind` enum for Space. v1 catalogue
// is `space` (generic) / `project` / `folder` / `board` / `list`;
// profiles may register additional kinds.
pub(super) const SPACE_KIND_OPTIONS: [(&str, &str, &str); 5] = [
    ("space", "Space (generic)", ""),
    (
        "project",
        "Project",
        "Top-level scope for a piece of work; usually contains boards / lists.",
    ),
    (
        "folder",
        "Folder",
        "Pure navigation container. Holds child Spaces / Strands but isn't a workflow.",
    ),
    (
        "board",
        "Board",
        "Kanban / pipeline view. Cells track strand placement (rank cas-register).",
    ),
    (
        "list",
        "List",
        "Ordered list view. Useful for backlog / triage / queue surfaces.",
    ),
];
