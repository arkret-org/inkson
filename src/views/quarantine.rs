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
//! 3.2 consent grant and MAY additionally accept the original invite, while
//! accepting a `consent_request` builds the grant and stops. Neither is a
//! consent cell -- an entry grants nothing and never appears in
//! `ak.self.consent.query.cells.v1` -- and neither is the Contact surface: a
//! Contact request keeps its own `pending_incoming` state and deliberately
//! produces no entry here.
//!
//! Until the consent-grant authoring flow is connected the panel stays
//! read-only and does not invent an approval action.

use arkret_models_collaboration::governance::holder_quarantine::{
    HolderQuarantine, HolderQuarantineEntry, HolderQuarantineSurfaceKind,
};
use dioxus::prelude::*;

use crate::i18n::tr;
use crate::views::helpers::short_protocol_id;

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

#[component]
pub fn QuarantinePanel() -> Element {
    let state_store = crate::app::SessionContext::get().state_store;
    let local_state = state_store.read().load();
    let cell = decode_holder_quarantine(
        local_state
            .station_cas_account_data
            .get(arkret_wire::AccountDataKey::ACCOUNT_HOLDER_QUARANTINE)
            .map(|row| &row.content),
    );
    let mut invite_deliveries: Vec<HolderQuarantineEntry> = Vec::new();
    let mut consent_requests: Vec<HolderQuarantineEntry> = Vec::new();
    if let Some(record) = cell.as_ref() {
        // Holder review is per surface: the two branches share this record but
        // not their terminal semantics, so they are never merged into one list.
        invite_deliveries = record
            .entries_for(HolderQuarantineSurfaceKind::InviteDelivery)
            .cloned()
            .collect();
        consent_requests = record
            .entries_for(HolderQuarantineSurfaceKind::ConsentRequest)
            .cloned()
            .collect();
    }
    let is_empty = invite_deliveries.is_empty() && consent_requests.is_empty();

    rsx! {
        div { class: "timeline", "data-testid": "quarantine-panel",
            div { class: "event", "data-testid": "quarantine-header",
                div { class: "event-head",
                    span { {tr("quarantine.title")} }
                }
                div { class: "muted", "data-testid": "quarantine-status",
                    {tr("quarantine.status")}
                }
            }
            if is_empty {
                div { class: "event", "data-testid": "quarantine-empty",
                    div { class: "muted", {tr("quarantine.empty")} }
                }
            } else {
                QuarantineSurfaceSection {
                    testid: "quarantine-invite-delivery".to_owned(),
                    title_key: "quarantine.invite_delivery_title".to_owned(),
                    hint_key: "quarantine.invite_delivery_hint".to_owned(),
                    entries: invite_deliveries,
                }
                QuarantineSurfaceSection {
                    testid: "quarantine-consent-request".to_owned(),
                    title_key: "quarantine.consent_request_title".to_owned(),
                    hint_key: "quarantine.consent_request_hint".to_owned(),
                    entries: consent_requests,
                }
            }
        }
    }
}

#[component]
fn QuarantineSurfaceSection(
    testid: String,
    title_key: String,
    hint_key: String,
    entries: Vec<HolderQuarantineEntry>,
) -> Element {
    if entries.is_empty() {
        return rsx! {};
    }
    rsx! {
        div { class: "event", "data-testid": "{testid}",
            div { class: "event-head",
                span { {tr(&title_key)} }
                span { class: "badge", "{entries.len()}" }
            }
            div { class: "muted", {tr(&hint_key)} }
            for entry in entries.iter() {
                div { class: "event-row", "data-testid": "{testid}-row",
                    span { class: "mono",
                        {short_protocol_id(entry.source_peer_principal_id.as_str())}
                    }
                    span { class: "muted",
                        {format!("{} {}", tr("quarantine.scope_label"), entry.consent_scope())}
                    }
                    span { class: "muted",
                        {format!(
                            "{} {}",
                            tr("quarantine.expires_label"),
                            entry.expires_at.format("%Y-%m-%d"),
                        )}
                    }
                }
            }
        }
    }
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
