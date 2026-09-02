//! Client-side shareable object links (inbound half).
//!
//! A user can paste a shared Realm / Strand / Message link. This module is the
//! inkson-side glue on top of the SDK's client-agnostic addressing grammar
//! ([`arkret_wire::parse_address`] / [`build_address`]):
//!
//! * [`OpenedLink`] — the result of parsing a pasted link, routed to a local
//!   [`crate::routes::Route`] by `target_kind`.
//!
//! ## Privacy / fail-closed posture
//! * The HTTPS landing form puts the target + token in the URL FRAGMENT (everything after `#`). The
//!   landing host never receives the object id or the invite token — that is the whole point of
//!   using the fragment.
//! * The open-link path never distinguishes `not_found` from `unauthorized`: any resolve failure
//!   collapses to a single friendly `object_link.error.unavailable` message (anti-enumeration).
//! * Reference links carry no authorization. Invite and preview links bind a `TargetDescriptor`
//!   digest so a token minted for object A cannot be replayed onto object B (scope-confusion
//!   defence lives in the SDK's [`arkret_wire::verify_token_target`]).
//! * inkson never registers a `web+arkret:` web protocol handler:
//!   `navigator.registerProtocolHandler` is only privacy safe when the template substitutes `%s`
//!   INSIDE its own fragment, and the HTTPS-fragment landing link is leak-proof with no
//!   registration at all.

use arkret_models_discovery::TargetKind;
use arkret_wire::{ParsedAddress, RealmRef, build_address, parse_address};

use crate::routes::Route;

/// A parsed shareable link plus the local route it resolves to. `address` is
/// the SDK [`ParsedAddress`]; `token` is lifted out for the resolve request
/// body (present iff the link was an invite or preview link).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedLink {
    pub address: ParsedAddress,
    pub token: Option<String>,
}

impl OpenedLink {
    /// Parse a pasted `web+arkret:` or HTTPS-fragment link. Fails closed on
    /// any malformed grammar (the SDK parser owns the fail-closed rules).
    pub fn parse(input: &str) -> anyhow::Result<Self> {
        let address =
            parse_address(input.trim()).map_err(|err| anyhow::anyhow!("invalid link: {err}"))?;
        let token = address.token.clone();
        Ok(OpenedLink { address, token })
    }

    /// The canonical address string to send to `directory_resolve_target`. We
    /// re-serialize through [`build_address`] so the server receives the
    /// canonical `web+arkret:` form regardless of which envelope the user
    /// pasted.
    pub fn resolve_address(&self) -> String {
        build_address(&self.address)
    }

    /// Map a resolved [`TargetKind`] onto the local [`Route`]. The realm path
    /// segment must already be a canonical event-derived `realm_id` for the
    /// route to be navigable; an alias-only address routes to the directory so
    /// the user can resolve it there.
    ///
    /// inkson routes a Realm through the default Realm surface, a Strand to its
    /// Board task deep link, and a Message to the Realm discussion surface.
    pub fn route_for(&self, target_kind: TargetKind) -> Route {
        match target_kind {
            TargetKind::Realm => match typed_realm_route_id(&self.address.realm) {
                Some(realm_id) => Route::Realm { realm_id },
                None => Route::Directory,
            },
            TargetKind::Strand => match (
                typed_realm_route_id(&self.address.realm),
                self.address.strand.as_deref(),
            ) {
                (Some(realm_id), Some(strand)) => Route::KanbanTask {
                    realm_id,
                    task_id: typed_strand(strand),
                },
                _ => Route::Directory,
            },
            TargetKind::Message => match typed_realm_route_id(&self.address.realm) {
                Some(realm_id) => Route::Chat {
                    realm_id,
                    message: String::new(),
                },
                _ => Route::Directory,
            },
        }
    }
}

fn typed_realm(bare: &str) -> String {
    if bare.starts_with("ak:realm:") {
        bare.to_owned()
    } else {
        format!("ak:realm:{bare}")
    }
}

fn typed_realm_route_id(realm: &RealmRef) -> Option<String> {
    match realm {
        RealmRef::RealmId(token) => Some(typed_realm(token)),
        RealmRef::Alias(_) => None,
    }
}

fn typed_strand(bare: &str) -> String {
    if bare.starts_with("ak:strand:") {
        bare.to_owned()
    } else {
        format!("ak:strand:{bare}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const R: &str = "ASJxhbdgpkgbgjZdFxJI9alVkyjdkTIoiU4EsA9SC_TU";
    const F: &str = "Ae5NKrBlFWIp8_rB4VWC0WK2l3QJSfUEOQ796BrZ7XPc";

    #[test]
    fn realm_target_routes_to_realm() {
        let opened = OpenedLink::parse(&format!("web+arkret:realm/{R}")).unwrap();
        match opened.route_for(TargetKind::Realm) {
            Route::Realm { realm_id } => assert_eq!(
                realm_id,
                "ak:realm:ASJxhbdgpkgbgjZdFxJI9alVkyjdkTIoiU4EsA9SC_TU".to_owned()
            ),
            other => panic!("expected Realm route, got {other:?}"),
        }
    }

    #[test]
    fn alias_realm_routes_to_directory() {
        let opened = OpenedLink::parse("web+arkret:realm/team.example.com").unwrap();
        assert_eq!(opened.route_for(TargetKind::Realm), Route::Directory);
    }

    #[test]
    fn parse_fails_closed_on_garbage() {
        assert!(OpenedLink::parse("not-a-link").is_err());
        assert!(OpenedLink::parse(&format!("web+arkret:space/{R}")).is_err());
        assert!(OpenedLink::parse(&format!("web+arkret:realm/{R}/strand/{F}")).is_ok());
    }
}
