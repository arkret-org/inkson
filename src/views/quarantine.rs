//! Actor-private invite-quarantine surface.
//!
//! The canonical inbox is encrypted account data under
//! `ak.account.invite_quarantine`. It is not a coauth administration queue and
//! never acts as an authorization root. Until the typed account-data
//! projection and consent-grant authoring strand are connected, the UI stays
//! read-only and does not invent a private transport or approval action.

use dioxus::prelude::*;

#[component]
pub fn QuarantinePanel() -> Element {
    rsx! {
        div { class: "timeline", "data-testid": "quarantine-panel",
            div { class: "event", "data-testid": "quarantine-header",
                div { class: "event-head",
                    span { "Invite quarantine" }
                }
                div { class: "muted", "data-testid": "quarantine-status",
                    "Pending invites are private encrypted account data. Review controls will appear after the typed consent-grant flow is available."
                }
            }
        }
    }
}
