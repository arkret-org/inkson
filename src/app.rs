use dioxus::prelude::*;

const STYLE: &str = r#"
:root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
body { margin: 0; background: #07110e; color: #e8f5ef; }
main { max-width: 980px; margin: 0 auto; padding: 72px 28px; }
.eyebrow { color: #72e0ad; font-size: 13px; font-weight: 700; letter-spacing: .14em; text-transform: uppercase; }
h1 { font-size: clamp(38px, 7vw, 72px); line-height: .98; margin: 18px 0 22px; max-width: 850px; }
.lead { max-width: 760px; color: #acc5ba; font-size: 19px; line-height: 1.65; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; margin-top: 42px; }
.card { background: #0d1d17; border: 1px solid #204a39; border-radius: 16px; padding: 20px; }
.card h2 { font-size: 16px; margin: 0 0 9px; }
.card p { color: #94b3a5; line-height: 1.5; margin: 0; }
.flow { margin-top: 34px; padding: 18px 20px; background: #10271e; border-left: 3px solid #72e0ad; border-radius: 8px; color: #cfe6dc; }
code { color: #8ff0c1; }
"#;

#[allow(non_snake_case)]
pub fn App() -> Element {
    rsx! {
        document::Style { {STYLE} }
        main {
            div { class: "eyebrow", "Arkret clean-break client" }
            h1 { "Authority commits, without a hidden global chain." }
            p { class: "lead",
                "Inkson authors producer-signed Events, queues them at the authenticated current governance Station, and advances local state only from committed RealmCommit records. Realm, Circle, and Sidecar remain independent streams."
            }
            section { class: "grid",
                article { class: "card",
                    h2 { "Current authority" }
                    p { "Join resolves a fresh nonce-bound authority bundle and follows its verified handoff chain. Inviter and original Station are discovery hints only." }
                }
                article { class: "card",
                    h2 { "Independent streams" }
                    p { "Each Realm, Circle, and Sidecar has its own position and same-stream previous_commit_ref. Cross-stream ordering is intentionally undefined." }
                }
                article { class: "card",
                    h2 { "MLS after commit" }
                    p { "An MLS change stays staged until its Event receives an accepted RealmCommit. Welcome objects live in a separate delivery queue." }
                }
            }
            div { class: "flow",
                code { "queued Event → governance Station → committed RealmCommit → projection" }
            }
        }
    }
}
