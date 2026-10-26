//! Actor-private holder-quarantine review surface.
//!
//! The canonical inbox is the server-written Station-CAS account-data cell
//! `ak.account.holder_quarantine`, restored from the account-subscribe
//! `account_data.station_cas` complete baseline and its cursor-covered
//! upsert/remove deltas. Its JSON value is plaintext to the holder's Station but
//! actor-private on the sync surface; it is not a coauth administration queue
//! and never acts as an authorization root.
//!
//! The cell carries two closed `surface_kind` branches and this panel reviews
//! them separately, because `consent-model.md` section 6.1.1 gives them
//! different terminal semantics: accepting an `invite_delivery` builds a section
//! complete consent replacement and MAY additionally accept the original invite, while
//! accepting a `consent_request` replaces the related scope and stops. Neither is a
//! consent cell -- an entry grants nothing and never appears in
//! `ak.self.consent.query.cells.v1` -- and neither is the Contact surface: a
//! Contact request keeps its own `pending_incoming` state and deliberately
//! produces no entry here.
//!
//! Until the complete replacement authoring flow is connected the panel stays
//! read-only and does not invent an approval action.

use std::rc::Rc;

use arkret_models_collaboration::governance::holder_quarantine::{
    HolderQuarantine, HolderQuarantineSurfaceKind,
};
use glory::Scope;

use crate::presentation::{InksonContext, View};
use crate::views::settings::widgets::*;

/// Decode the restored Station-CAS row into the closed cell shape.
///
/// A cell this client cannot decode is not rendered as a partial list: the
/// entries are an admission record, so a half-parsed one would understate what
/// is waiting on the holder.
pub(crate) fn decode_holder_quarantine(
    content: Option<&serde_json::Value>,
) -> Option<HolderQuarantine> {
    serde_json::from_value(content?.clone()).ok()
}

pub fn page(_scope: &Scope, context: Rc<InksonContext>, _route: crate::routes::Route) -> View {
    let revision = context.state_revision;
    let render = context.clone();
    reactive(revision, move |scope, _| {
        let context = render.clone();
        let state = context.snapshot();
        let cell = decode_holder_quarantine(
            state
                .station_cas_account_data
                .get(arkret_wire::AccountDataKey::ACCOUNT_HOLDER_QUARANTINE)
                .map(|row| &row.content),
        );
        let mut children = vec![card(
            scope,
            context.clone(),
            "quarantine.title",
            vec![paragraph(
                "muted",
                context.translated(scope, "quarantine.status"),
            )],
        )];
        let mut total = 0_usize;
        if let Some(cell) = cell {
            for (surface, title, hint, key) in [
                (
                    HolderQuarantineSurfaceKind::InviteDelivery,
                    "quarantine.invite_delivery_title",
                    "quarantine.invite_delivery_hint",
                    "quarantine-invite-delivery",
                ),
                (
                    HolderQuarantineSurfaceKind::ConsentRequest,
                    "quarantine.consent_request_title",
                    "quarantine.consent_request_hint",
                    "quarantine-consent-request",
                ),
            ] {
                let entries: Vec<_> = cell.entries_for(surface).collect();
                if entries.is_empty() {
                    continue;
                }
                total += entries.len();
                let mut rows = vec![paragraph("muted", context.translated(scope, hint))];
                for entry in entries {
                    rows.push(line(
                        "event-row",
                        vec![
                            paragraph(
                                "mono",
                                serde_json::to_string(&entry.source_peer_actor_id)
                                    .unwrap_or_default(),
                            ),
                            paragraph(
                                "muted",
                                format!(
                                    "{} {}",
                                    context.tr("quarantine.scope_label"),
                                    entry.consent_scope()
                                ),
                            ),
                            paragraph(
                                "muted",
                                format!(
                                    "{} {}",
                                    context.tr("quarantine.expires_label"),
                                    entry.expires_at.format("%Y-%m-%d")
                                ),
                            ),
                        ],
                    ));
                }
                children.push(stack(
                    format!("event {key}"),
                    vec![
                        heading(3, "event-head", context.translated(scope, title)),
                        stack("quarantine-entries", rows),
                    ],
                ));
            }
        }
        if total == 0 {
            children.push(paragraph(
                "event quarantine-empty",
                context.translated(scope, "quarantine.empty"),
            ));
        }
        stack("timeline quarantine-panel", children)
    })
}
#[cfg(test)]
mod tests {
    use arkret_models_collaboration::governance::holder_quarantine::HolderQuarantineSurface;
    use arkret_wire::ConsentRequestScope;
    use serde_json::json;

    use super::*;

    fn cell_value() -> serde_json::Value {
        json!({
            "schema": "ak.schema.holder_quarantine.v1",
            "updated_at": "2026-09-05T12:00:00.000Z",
            "quarantine_entries": [
                {
                    "entry_digest": format!("sha256:{}", "a".repeat(64)),
                    "account_id": {
                        "principal_id": "ak:did_core:web:holder.example",
                        "station_id": "ak:did_core:web:station.example"
                    },
                    "source_peer_principal_id": "ak:did_core:web:inviter.example",
                    "source_peer_actor_id": {
                        "kind": "account",
                        "account_id": {
                            "principal_id": "ak:did_core:web:inviter.example",
                            "station_id": "ak:did_core:web:peer-station.example"
                        }
                    },
                    "source_id": "ak:did_core:web:peer-station.example",
                    "surface_kind": "invite_delivery",
                    "consent_scope": "invite",
                    "introduction_kind": "locator_ref",
                    "effective_kind": "locator_ref",
                    "trust_tier": "high",
                    "invite_event_id": "ak:event:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5",
                    "request_digest": format!("sha256:{}", "b".repeat(64)),
                    "idempotency_key_digest": format!("sha256:{}", "c".repeat(64)),
                    "received_at": "2026-09-05T10:00:00.000Z",
                    "expires_at": "2026-10-05T10:00:00.000Z"
                },
                {
                    "entry_digest": format!("sha256:{}", "d".repeat(64)),
                    "account_id": {
                        "principal_id": "ak:did_core:web:holder.example",
                        "station_id": "ak:did_core:web:station.example"
                    },
                    "source_peer_principal_id": "ak:did_core:web:asker.example",
                    "source_peer_actor_id": {
                        "kind": "account",
                        "account_id": {
                            "principal_id": "ak:did_core:web:asker.example",
                            "station_id": "ak:did_core:web:station.example"
                        }
                    },
                    "source_id": "ak:did_core:web:station.example",
                    "surface_kind": "consent_request",
                    "consent_scope": "voice_call",
                    "received_at": "2026-09-05T11:00:00.000Z",
                    "expires_at": "2026-10-05T11:00:00.000Z"
                }
            ]
        })
    }

    #[test]
    fn the_two_surfaces_are_reviewed_separately() {
        let cell = decode_holder_quarantine(Some(&cell_value())).expect("closed cell decodes");
        let invite_deliveries = cell
            .entries_for(HolderQuarantineSurfaceKind::InviteDelivery)
            .collect::<Vec<_>>();
        let consent_requests = cell
            .entries_for(HolderQuarantineSurfaceKind::ConsentRequest)
            .collect::<Vec<_>>();
        assert_eq!(invite_deliveries.len(), 1);
        assert_eq!(consent_requests.len(), 1);
        assert!(matches!(
            consent_requests[0].surface,
            HolderQuarantineSurface::ConsentRequest {
                consent_scope: ConsentRequestScope::VoiceCall
            }
        ));
        // A quarantine entry is not a consent cell: it carries no consent_id and
        // no grant dots, only the pending-review pointer.
        let encoded = serde_json::to_value(consent_requests[0]).unwrap();
        assert!(encoded.get("consent_id").is_none());
        assert!(encoded.get("grant_dots").is_none());
    }

    #[test]
    fn a_cell_this_client_cannot_decode_is_not_half_rendered() {
        let mut missing_actor = cell_value();
        missing_actor["quarantine_entries"][0]
            .as_object_mut()
            .unwrap()
            .remove("source_peer_actor_id");
        assert!(decode_holder_quarantine(Some(&missing_actor)).is_none());
        let mut malformed = cell_value();
        // Cross-filling the consent_request branch with invite evidence is a
        // schema violation, so the whole cell is refused rather than rendering
        // the entry that did parse.
        malformed["quarantine_entries"][1]["invite_event_id"] =
            json!("ak:event:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5");
        assert!(decode_holder_quarantine(Some(&malformed)).is_none());
        assert!(decode_holder_quarantine(None).is_none());
    }
}
