//! Actor-private invite-quarantine surface.
//!
//! The canonical inbox is the server-written Station-CAS account-data cell
//! `ak.account.invite_quarantine`. Its JSON value is plaintext to the holder's
//! Station but actor-private on the sync surface; it is not a coauth
//! administration queue and never acts as an authorization root. Until the
//! typed quarantine projection and consent-grant authoring strand are
//! connected, the UI stays read-only and does not invent an approval action.

use dioxus::prelude::*;

#[component]
pub fn QuarantinePanel() -> Element {
    rsx! {
        div { class: "timeline", "data-testid": "quarantine-panel",
            div { class: "event", "data-testid": "quarantine-header",
                div { class: "event-head",
                    span { {crate::i18n::tr("quarantine.title")} }
                }
                div { class: "muted", "data-testid": "quarantine-status",
                    {crate::i18n::tr("quarantine.status")}
                }
            }
        }
    }
}
