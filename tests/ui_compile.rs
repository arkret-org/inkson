#![cfg(not(target_arch = "wasm32"))]

use glory::Scope;
use inkson::presentation::View;

#[test]
fn glory_root_keeps_the_native_and_browser_entry_signature() {
    let _: fn(&Scope) -> View = inkson::app::root;
}
