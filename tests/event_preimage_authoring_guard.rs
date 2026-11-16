#![cfg(not(target_arch = "wasm32"))]

//! Delegate the Event preimage authoring gate to the SDK's single checker.

use std::path::Path;
use std::process::Command;

#[test]
fn no_source_file_hand_rolls_the_event_digest_preimage() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sdk = manifest
        .parent()
        .expect("Inkson has a workspace parent")
        .join("arkret-rust-sdk");
    let checker = sdk.join("tools/lint-event-preimage-authoring.py");
    let allowlist = sdk.join("tools/event_preimage_allowlist.json");
    for input in [&checker, &allowlist] {
        assert!(
            input.is_file(),
            "missing SDK authoring gate input: {}",
            input.display()
        );
    }
    let output = Command::new("python")
        .arg(&checker)
        .arg("--root")
        .arg(manifest)
        .arg("--allowlist")
        .arg(&allowlist)
        .output()
        .expect("run the SDK authoring checker with Python");
    assert!(
        output.status.success(),
        "SDK Event preimage authoring gate failed ({}):\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
