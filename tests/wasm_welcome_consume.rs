//! Browser regression for the owed `keypackages/consume` of a joined Welcome
//! (device-lifecycle.md §9, decision 0121): a lost response keeps the command
//! owed and the next pass resends the exact same signed bytes.
#![cfg(target_arch = "wasm32")]

use std::cell::RefCell;

use inkson::mls::welcome_consume::{ConsumeAttempt, drain_owed_consumes};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn a_lost_consume_response_resends_the_same_command() {
    let sent = RefCell::new(Vec::new());
    let first = drain_owed_consumes(vec!["signed-consume".to_owned()], |command| {
        sent.borrow_mut().push(command);
        async { ConsumeAttempt::Retry("response lost".to_owned()) }
    })
    .await;
    let owed = first
        .into_iter()
        .filter(|(_, attempt)| !attempt.settled())
        .map(|(command, _)| command)
        .collect::<Vec<_>>();
    assert_eq!(owed, vec!["signed-consume".to_owned()]);
    let second = drain_owed_consumes(owed, |command| {
        sent.borrow_mut().push(command);
        async { ConsumeAttempt::Consumed }
    })
    .await;
    assert!(second.iter().all(|(_, attempt)| attempt.settled()));
    assert_eq!(
        sent.into_inner(),
        vec!["signed-consume".to_owned(), "signed-consume".to_owned()]
    );
}

#[wasm_bindgen_test]
async fn a_refused_consume_is_settled_and_never_resent() {
    let attempts = drain_owed_consumes(vec![1_u8], |_| async {
        ConsumeAttempt::Refused("conflict".to_owned())
    })
    .await;
    assert!(attempts.iter().all(|(_, attempt)| attempt.settled()));
}
