fn main() {
    if let Err(err) = yougen::event_signer::bootstrap_default_signer("yougen") {
        eprintln!("yougen signer bootstrap failed: {err}");
    }
    dioxus::launch(yougen::App);
}
