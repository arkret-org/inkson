#![cfg(target_arch = "wasm32")]

use inkson::config::{ClientConfig, station_options_for};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn hosted_station_seeds_fresh_config_and_rejects_invalid_metadata() {
    let document = web_sys::window().unwrap().document().unwrap();
    let meta = document.create_element("meta").unwrap();
    meta.set_attribute("name", "inkson-station-url").unwrap();
    meta.set_attribute("content", "https://arkret.example")
        .unwrap();
    document
        .document_element()
        .unwrap()
        .append_child(&meta)
        .unwrap();
    let config = ClientConfig::default();
    assert_eq!(config.stations[0].as_str(), "https://arkret.example/");
    assert_eq!(station_options_for("", &[]), ["https://arkret.example/"]);
    assert!(config.active_account.is_none());
    assert!(config.session_credential.is_empty());
    meta.set_attribute("content", "https://user:secret@arkret.example")
        .unwrap();
    assert_eq!(
        ClientConfig::default().stations[0].as_str(),
        "https://local.host/"
    );
    meta.remove();
}
