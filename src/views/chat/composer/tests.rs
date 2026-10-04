use std::cell::RefCell;
use std::rc::Rc;

use dioxus::dioxus_core::{AttributeValue, ElementId, Mutation};

use super::*;

type SendState = Rc<RefCell<Option<Signal<(bool, bool, bool)>>>>;

fn send_actions_harness(control: SendState) -> Element {
    let state = use_signal(|| (false, true, false));
    *control.borrow_mut() = Some(state);
    let (plaintext, pending, checking) = state();
    rsx! {
        OrdinarySendActions {
            plaintext,
            plaintext_disabled: pending,
            secure_disabled: pending,
            mls_binding_pending: pending,
            creator_bootstrap_pending: pending,
            secure_title: if pending { "Waiting for verified current" } else { "" },
            opening: false,
            readiness_checking: checking,
            on_plaintext: move |_| {},
            on_secure: move |_| {},
        }
    }
}

fn primary_send_id(edits: &[Mutation]) -> ElementId {
    let ids: Vec<_> = edits
        .iter()
        .filter_map(|edit| match edit {
            Mutation::SetAttribute {
                name: "data-testid",
                value: AttributeValue::Text(value),
                id,
                ..
            } if value == "send-chat-button" => Some(*id),
            _ => None,
        })
        .collect();
    assert_eq!(ids.len(), 1, "there must be exactly one primary Send");
    ids[0]
}

fn assert_primary_disabled(edits: &[Mutation], primary: ElementId, disabled: bool) {
    assert!(
        edits.iter().any(|edit| matches!(
            edit,
            Mutation::SetAttribute {
                name: "disabled",
                value: AttributeValue::Bool(value),
                id,
                ..
            } if *id == primary && *value == disabled
        )),
        "the mounted primary Send must receive the current send gate"
    );
}

#[test]
fn primary_send_keeps_its_dom_identity_across_scope_probe_and_encryption_changes() {
    let control = Rc::new(RefCell::new(None));
    let mut dom = VirtualDom::new_with_props(send_actions_harness, control.clone());
    let initial = dom.rebuild_to_vec();
    let primary = primary_send_id(&initial.edits);
    assert_primary_disabled(&initial.edits, primary, true);

    for (plaintext, pending, checking) in [
        (true, false, false),
        (false, true, true),
        (false, false, false),
        (true, true, false),
        (true, false, false),
    ] {
        dom.in_runtime(|| {
            control
                .borrow()
                .unwrap()
                .set((plaintext, pending, checking));
        });
        let update = dom.render_immediate_to_vec();
        assert_primary_disabled(&update.edits, primary, pending);
        for edit in &update.edits {
            match edit {
                Mutation::Remove { id } | Mutation::ReplaceWith { id, .. } => {
                    assert_ne!(*id, primary, "scope probes must not replace primary Send");
                }
                Mutation::SetAttribute {
                    name: "data-testid",
                    value: AttributeValue::Text(value),
                    id,
                    ..
                } if *id == primary => {
                    assert_eq!(value, "send-chat-button");
                }
                _ => {}
            }
        }
    }
}
