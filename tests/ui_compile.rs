#![cfg(not(target_arch = "wasm32"))]

use dioxus::prelude::Element;

#[test]
fn dioxus_root_component_keeps_stable_signature() {
    let _: fn() -> Element = inkson::App;
}
