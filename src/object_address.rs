//! R3.3 (CXP-0011, contrix-spec @ cced4b8) — client-side shareable object
//! links.
//!
//! A user can share a Realm / Flow / Message as a link. This module is the
//! yougen-side glue on top of the SDK's client-agnostic addressing grammar
//! ([`contrix_sdk::model::parse_address`] / [`build_address`] /
//! [`build_https_landing`]) plus the [`target_digest`] invite-token binding:
//!
//! * [`ShareTarget`] — a typed "thing I want to share" (realm / flow / message)
//!   plus routing hints. [`ShareTarget::build_links`] produces both output
//!   forms.
//! * [`ShareLinks`] — the HTTPS landing form (default copy-paste) and the
//!   `web+contrix:` "open in app" form.
//! * [`OpenedLink`] — the result of parsing + resolving a pasted link, routed
//!   to a local [`crate::routes::Route`] by `target_kind`.
//!
//! ## Privacy / fail-closed posture
//! * The HTTPS landing form puts the target + token in the URL FRAGMENT
//!   (everything after `#`). The landing host never receives the object id or
//!   the invite token — that is the whole point of using the fragment.
//! * The open-link path never distinguishes `not_found` from `unauthorized`:
//!   any resolve failure collapses to a single friendly
//!   `object_link.error.unavailable` message (anti-enumeration).
//! * Reference links carry no authorization. Invite links bind the
//!   [`TargetDescriptor`] digest so a token minted for object A cannot be
//!   replayed onto object B (scope-confusion defence lives in the SDK's
//!   [`contrix_sdk::model::verify_token_target`]).
//!
//! ## Web protocol-handler registration — design choice
//! yougen deliberately ships the **HTTPS-fragment-only** landing path and does
//! NOT register a `web+contrix:` web protocol handler by default. Rationale:
//! `navigator.registerProtocolHandler('web+contrix', template)` is only privacy
//! safe if the template substitutes `%s` INSIDE its own fragment
//! (`https://app.example/open#%s`); a template that puts `%s` in the path or
//! query would leak the substituted object id / invite token to the handler
//! host. [`web_protocol_handler_template`] enforces that invariant for callers
//! who explicitly opt in, and [`register_web_protocol_handler`] performs the
//! fragment-only registration on wasm. The default UI flow simply hands out the
//! HTTPS-fragment link, which is leak-proof without any registration.
//!
//! Native OS deep-link registration (Info.plist `CFBundleURLTypes` /
//! AndroidManifest `<intent-filter>` / freedesktop `.desktop` `MimeType` /
//! Windows `HKCR\web+contrix` registry) is out of scope here.
// TODO(R3.3.1): native OS deep-link registration for the `web+contrix:` scheme.

use contrix_sdk::model::{
    AddressAction, LinkType, ParsedAddress, RealmRef, TargetDescriptor, TargetKind, build_address,
    build_https_landing, parse_address, target_digest,
};

use crate::routes::Route;

/// The local object a user is sharing. Mirrors the SDK address hierarchy
/// `realm ⊃ flow ⊃ message`. `realm` is a bare uuid or a domain-style alias
/// (the `cx:realm:` sigil is stripped); `flow`/`message` are bare uuids.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShareTarget {
    Realm {
        realm: String,
    },
    Flow {
        realm: String,
        flow: String,
    },
    Message {
        realm: String,
        flow: String,
        message: String,
    },
}

impl ShareTarget {
    /// Build a [`ShareTarget`] from possibly-`cx:`-prefixed ids, stripping the
    /// sigil so the SDK grammar receives the bare path segments it expects.
    pub fn realm(realm_id: &str) -> Self {
        ShareTarget::Realm {
            realm: strip_sigil(realm_id),
        }
    }

    pub fn flow(realm_id: &str, flow_id: &str) -> Self {
        ShareTarget::Flow {
            realm: strip_sigil(realm_id),
            flow: strip_sigil(flow_id),
        }
    }

    pub fn message(realm_id: &str, flow_id: &str, message_id: &str) -> Self {
        ShareTarget::Message {
            realm: strip_sigil(realm_id),
            flow: strip_sigil(flow_id),
            message: strip_sigil(message_id),
        }
    }

    fn realm_seg(&self) -> &str {
        match self {
            ShareTarget::Realm { realm }
            | ShareTarget::Flow { realm, .. }
            | ShareTarget::Message { realm, .. } => realm,
        }
    }

    fn flow_seg(&self) -> Option<&str> {
        match self {
            ShareTarget::Realm { .. } => None,
            ShareTarget::Flow { flow, .. } => Some(flow),
            ShareTarget::Message { flow, .. } => Some(flow),
        }
    }

    fn message_seg(&self) -> Option<&str> {
        match self {
            ShareTarget::Message { message, .. } => Some(message),
            _ => None,
        }
    }

    /// Lower the target into a [`ParsedAddress`] with the supplied routing
    /// hints. `via` MUST be non-empty for flow/message targets — a global
    /// flow_id is never guessable, so the SDK fails closed when reparsing a
    /// flow/message link with no `via`.
    pub fn to_parsed_address(
        &self,
        via: &[String],
        action: AddressAction,
        link_type: LinkType,
        token: Option<String>,
    ) -> ParsedAddress {
        ParsedAddress {
            realm: RealmRef::parse(self.realm_seg()),
            flow: self.flow_seg().map(str::to_owned),
            message: self.message_seg().map(str::to_owned),
            via: via.to_vec(),
            action,
            // A stray token on a reference link is dropped by the SDK builder.
            link_type,
            token: if link_type == LinkType::Invite {
                token
            } else {
                None
            },
        }
    }

    /// Build both shareable link forms for this target.
    ///
    /// `landing` is the configured HTTPS landing host (e.g.
    /// `https://share.contrix.example`); the target + token always live in the
    /// fragment so the host never sees them. `via` is the routing-service DID
    /// hint set; for flow/message links it MUST contain at least one entry.
    pub fn build_links(
        &self,
        landing: &str,
        via: &[String],
        action: AddressAction,
        link_type: LinkType,
        token: Option<String>,
    ) -> ShareLinks {
        let parsed = self.to_parsed_address(via, action, link_type, token);
        ShareLinks {
            https_landing: build_https_landing(landing, &parsed),
            web_contrix: build_address(&parsed),
            link_type,
        }
    }

    /// Build a `reference` link pair (no token). This is the default share
    /// action — references carry no authorization.
    pub fn build_reference_links(
        &self,
        landing: &str,
        via: &[String],
        action: AddressAction,
    ) -> ShareLinks {
        self.build_links(landing, via, action, LinkType::Reference, None)
    }

    /// Compute the [`TargetDescriptor`] digest this target would bind into an
    /// `invite` token's signed payload. The digest covers ONLY the identity
    /// tuple + `link_type`, never the via/action hints, so a server can mint a
    /// token bound to this exact object.
    ///
    /// Fails closed when the realm segment is an alias (the digest is
    /// meaningless over an alias — the caller must resolve the alias to a
    /// canonical `cx:realm:<uuid>` first).
    // TODO(R3.3.1): once an alias-bearing share is supported, resolve the alias
    // via the directory before digesting (TargetDescriptor::set_realm_id).
    pub fn invite_target_digest(&self) -> anyhow::Result<String> {
        let parsed = self.to_parsed_address(&[], AddressAction::View, LinkType::Invite, None);
        let mut descriptor = TargetDescriptor::from_parsed(&parsed);
        descriptor.link_type = LinkType::Invite;
        if !descriptor.realm_id.starts_with("cx:realm:") {
            return Err(anyhow::anyhow!(
                "cannot bind an invite token to an alias realm — resolve to a canonical realm_id first"
            ));
        }
        target_digest(&descriptor).map_err(|err| anyhow::anyhow!("target_digest failed: {err}"))
    }
}

/// The two output forms of a shareable object link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareLinks {
    /// Canonical HTTPS landing link — the default copy-paste form. Target +
    /// token live in the `#` fragment and never reach the landing server.
    pub https_landing: String,
    /// `web+contrix:` URI — the "open in app" form for OS / browser handlers.
    pub web_contrix: String,
    /// The link type both forms encode.
    pub link_type: LinkType,
}

/// A parsed shareable link plus the local route it resolves to. `address` is
/// the SDK [`ParsedAddress`]; `token` is lifted out for the resolve request
/// body (present iff the link was an invite link).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedLink {
    pub address: ParsedAddress,
    pub token: Option<String>,
}

impl OpenedLink {
    /// Parse a pasted `web+contrix:` or HTTPS-fragment link. Fails closed on
    /// any malformed grammar (the SDK parser owns the fail-closed rules).
    pub fn parse(input: &str) -> anyhow::Result<Self> {
        let address =
            parse_address(input.trim()).map_err(|err| anyhow::anyhow!("invalid link: {err}"))?;
        let token = address.token.clone();
        Ok(OpenedLink { address, token })
    }

    /// The canonical address string to send to `directory_resolve_target`. We
    /// re-serialize through [`build_address`] so the server receives the
    /// canonical `web+contrix:` form regardless of which envelope the user
    /// pasted.
    pub fn resolve_address(&self) -> String {
        build_address(&self.address)
    }

    /// Map a resolved [`TargetKind`] onto the local [`Route`]. The realm path
    /// segment must already be a canonical `realm_id` (uuid form) for the
    /// route to be navigable; an alias-only address routes to the directory so
    /// the user can resolve it there.
    ///
    /// yougen models a Realm/Flow as a "space" route (`/spaces/:space_id`,
    /// `/timeline/:space_id`) and a Message as
    /// `/timeline/:space_id/message/:message_id`. We route flow targets to the
    /// flow's timeline and message targets to the message anchor.
    pub fn route_for(&self, target_kind: TargetKind) -> Route {
        match target_kind {
            TargetKind::Realm => match &self.address.realm {
                RealmRef::RealmId(uuid) => Route::Space {
                    space_id: typed_realm(uuid),
                },
                RealmRef::Alias(_) => Route::Directory,
            },
            TargetKind::Flow => match self.address.flow.as_deref() {
                Some(flow) => Route::TimelineSpace {
                    space_id: typed_flow(flow),
                },
                None => Route::Directory,
            },
            TargetKind::Message => match (
                self.address.flow.as_deref(),
                self.address.message.as_deref(),
            ) {
                (Some(flow), Some(message)) => Route::TimelineMessage {
                    space_id: typed_flow(flow),
                    message_id: typed_message(message),
                },
                _ => Route::Directory,
            },
        }
    }
}

/// Strip a leading `cx:<kind>:` sigil so the SDK grammar receives the bare
/// path segment (uuid or alias). Idempotent on already-bare input.
fn strip_sigil(id: &str) -> String {
    let id = id.trim();
    if let Some(rest) = id.strip_prefix("cx:") {
        // `cx:realm:<uuid>` → `<uuid>`; alias strings have no `cx:` prefix.
        rest.split_once(':')
            .map(|(_, v)| v.to_owned())
            .unwrap_or_else(|| id.to_owned())
    } else {
        id.to_owned()
    }
}

fn typed_realm(bare: &str) -> String {
    if bare.starts_with("cx:realm:") {
        bare.to_owned()
    } else {
        format!("cx:realm:{bare}")
    }
}

fn typed_flow(bare: &str) -> String {
    if bare.starts_with("cx:flow:") {
        bare.to_owned()
    } else {
        format!("cx:flow:{bare}")
    }
}

fn typed_message(bare: &str) -> String {
    if bare.starts_with("cx:message:") {
        bare.to_owned()
    } else {
        format!("cx:message:{bare}")
    }
}

/// Build the privacy-safe web protocol-handler template for `web+contrix:`.
///
/// Returns `https://<landing>/open#%s` — the `%s` lives in the FRAGMENT, so
/// the browser-substituted `web+contrix:` URI stays out of the path/query and
/// never reaches the landing host. Callers who register a handler MUST use a
/// template shaped like this; see the module-level design note.
pub fn web_protocol_handler_template(landing: &str) -> String {
    format!("{}/open#%s", landing.trim_end_matches('/'))
}

/// wasm-only: opt-in registration of the `web+contrix:` web protocol handler,
/// using the fragment-only template from [`web_protocol_handler_template`].
///
/// This is NOT called by the default UI flow (yougen prefers the
/// HTTPS-fragment landing link, which needs no registration). It exists for
/// embedders that want the "open in app from the browser" affordance and have
/// confirmed the privacy posture of the fragment-only template.
#[cfg(target_arch = "wasm32")]
pub fn register_web_protocol_handler(landing: &str) -> Result<(), String> {
    let window = web_sys::window().ok_or_else(|| "no window".to_owned())?;
    let navigator = window.navigator();
    let template = web_protocol_handler_template(landing);
    // This web-sys pin exposes the legacy 3-arg signature
    // `registerProtocolHandler(scheme, url, title)`; the `title` arg was
    // dropped from the living standard but is still required by the binding.
    navigator
        .register_protocol_handler("web+contrix", &template, "Contrix")
        .map_err(|err| format!("registerProtocolHandler failed: {err:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const R: &str = "01904100-0000-7000-8000-0000000000aa";
    const F: &str = "01904100-0000-7000-8000-0000000000bb";
    const M: &str = "01904100-0000-7000-8000-0000000000dd";
    const VIA: &str = "did:web:relay.example";
    const LANDING: &str = "https://share.contrix.example";

    #[test]
    fn strip_sigil_handles_typed_and_bare_ids() {
        assert_eq!(strip_sigil("cx:realm:abc"), "abc");
        assert_eq!(strip_sigil("cx:flow:def"), "def");
        assert_eq!(strip_sigil("bare-uuid"), "bare-uuid");
        assert_eq!(strip_sigil("team.example.com"), "team.example.com");
    }

    #[test]
    fn realm_links_use_fragment_for_https() {
        let target = ShareTarget::realm(&format!("cx:realm:{R}"));
        let links = target.build_reference_links(LANDING, &[], AddressAction::View);
        // HTTPS landing keeps the target in the fragment.
        assert!(
            links
                .https_landing
                .starts_with("https://share.contrix.example/#realm/")
        );
        assert!(links.https_landing.contains(R));
        // The web+contrix: form is the canonical scheme.
        assert_eq!(links.web_contrix, format!("web+contrix:realm/{R}"));
        assert_eq!(links.link_type, LinkType::Reference);
    }

    #[test]
    fn flow_links_carry_via_and_roundtrip() {
        let target = ShareTarget::flow(&format!("cx:realm:{R}"), &format!("cx:flow:{F}"));
        let links = target.build_reference_links(LANDING, &[VIA.to_owned()], AddressAction::View);
        assert!(links.web_contrix.contains(&format!("realm/{R}/flow/{F}")));
        assert!(links.web_contrix.contains(&format!("via={VIA}")));
        // Both forms reparse to the same address.
        let from_https = OpenedLink::parse(&links.https_landing).unwrap();
        let from_web = OpenedLink::parse(&links.web_contrix).unwrap();
        assert_eq!(from_https.address, from_web.address);
        assert!(from_web.address.is_flow());
    }

    #[test]
    fn message_link_routes_to_message_anchor() {
        let target = ShareTarget::message(
            &format!("cx:realm:{R}"),
            &format!("cx:flow:{F}"),
            &format!("cx:message:{M}"),
        );
        let links = target.build_links(
            LANDING,
            &[VIA.to_owned()],
            AddressAction::Reply,
            LinkType::Reference,
            None,
        );
        let opened = OpenedLink::parse(&links.web_contrix).unwrap();
        assert!(opened.address.is_message());
        match opened.route_for(TargetKind::Message) {
            Route::TimelineMessage {
                space_id,
                message_id,
            } => {
                assert_eq!(space_id, format!("cx:flow:{F}"));
                assert_eq!(message_id, format!("cx:message:{M}"));
            }
            other => panic!("expected TimelineMessage route, got {other:?}"),
        }
    }

    #[test]
    fn realm_target_routes_to_space() {
        let opened = OpenedLink::parse(&format!("web+contrix:realm/{R}")).unwrap();
        match opened.route_for(TargetKind::Realm) {
            Route::Space { space_id } => assert_eq!(space_id, format!("cx:realm:{R}")),
            other => panic!("expected Space route, got {other:?}"),
        }
    }

    #[test]
    fn alias_realm_routes_to_directory() {
        let opened = OpenedLink::parse("web+contrix:realm/team.example.com").unwrap();
        assert_eq!(opened.route_for(TargetKind::Realm), Route::Directory);
    }

    #[test]
    fn invite_link_roundtrips_token_and_binds_digest() {
        let target = ShareTarget::flow(&format!("cx:realm:{R}"), &format!("cx:flow:{F}"));
        let links = target.build_links(
            LANDING,
            &[VIA.to_owned()],
            AddressAction::Join,
            LinkType::Invite,
            Some("opaque-tok-123".to_owned()),
        );
        assert!(links.web_contrix.contains("lt=invite"));
        assert!(links.web_contrix.contains("tok=opaque-tok-123"));
        let opened = OpenedLink::parse(&links.web_contrix).unwrap();
        assert_eq!(opened.token.as_deref(), Some("opaque-tok-123"));
        // The digest is stable and prefixed.
        let digest = target.invite_target_digest().unwrap();
        assert!(digest.starts_with("sha256:"));
    }

    #[test]
    fn invite_digest_fails_closed_on_alias_realm() {
        let target = ShareTarget::realm("team.example.com");
        assert!(target.invite_target_digest().is_err());
    }

    #[test]
    fn reference_link_drops_stray_token() {
        let target = ShareTarget::realm(&format!("cx:realm:{R}"));
        // Even if a token is passed, a reference link must not carry it.
        let links = target.build_links(
            LANDING,
            &[],
            AddressAction::View,
            LinkType::Reference,
            Some("should-be-dropped".to_owned()),
        );
        assert!(!links.web_contrix.contains("tok="));
        assert!(!links.web_contrix.contains("should-be-dropped"));
    }

    #[test]
    fn parse_fails_closed_on_garbage() {
        assert!(OpenedLink::parse("not-a-link").is_err());
        assert!(OpenedLink::parse(&format!("web+contrix:space/{R}")).is_err());
        // Flow link with no via fails closed (no guessable global flow_id).
        assert!(OpenedLink::parse(&format!("web+contrix:realm/{R}/flow/{F}")).is_err());
    }

    #[test]
    fn protocol_handler_template_keeps_substitution_in_fragment() {
        let template = web_protocol_handler_template(LANDING);
        assert_eq!(template, "https://share.contrix.example/open#%s");
        // The `%s` MUST be in the fragment, never the path/query.
        let (before_fragment, fragment) = template.split_once('#').unwrap();
        assert!(!before_fragment.contains("%s"));
        assert!(fragment.contains("%s"));
    }
}
