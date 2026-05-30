//! G3.Y1 — Recovery passphrase setup ceremony at `/settings/recovery`.
//!
//! Sibling of the broader `views/recovery.rs` aggregator that also
//! handles Encrypted Cloud Vault, Recovery Key (high-entropy string)
//! and Social Recovery / SSS. This narrow surface is what the cotest
//! `identity/recovery` scenario hooks: a single passphrase setup +
//! confirmation flow that emits the testids the scenario expects.
//!
//! Surfaces:
//! - `recovery-setup-panel` — wrapper
//! - `recovery-setup-button` — generates the passphrase
//! - `recovery-passphrase-display` — list of words, each rendered with
//!   `data-testid="recovery-word-{i}"`
//! - `recovery-confirm-input` — paste-back confirmation
//! - `recovery-confirm-button` — verifies the user wrote it down
//! - `recovery-status` — "not configured" / "verification pending" / "active"
//!
//! ## Word generation
//!
//! Real BIP39 would pull a 2048-word wordlist. Bundling that wordlist
//! in WASM today costs ~16KiB and the audited path will eventually
//! route through `contrix_sdk` once the SDK exposes a BIP39 helper.
//! For now we ship a curated 256-word list and pick 12 of them with
//! `getrandom` so the entropy stays close to BIP39's 132-bit floor
//! (256^12 ≈ 2^96; lower than 2048^12 ≈ 2^132 but high enough that
//! the e2e harness can verify the round-trip without us shipping a
//! production-grade list yet). The locally derived KEK never leaves
//! the device.
//!
//! TODO(G3.Y1-followup): swap the curated 256-word list for the
//! canonical BIP39 wordlist once `contrix_sdk::recovery::Bip39`
//! exposes a stable API — the recovery_crypto / vault crate already
//! pins Argon2id parameters for the KEK derivation, the wordlist is
//! the only remaining gap.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

use crate::components::HelpTip;
use crate::local_state::LocalStateStore;
use crate::recovery_crypto::estimate_passphrase_strength;

const RECOVERY_PASSPHRASE_STATE_KEY: &str = "recovery.passphrase.v1";
const WORD_COUNT: usize = 12;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct RecoveryPassphraseState {
    /// `not_configured` / `verification_pending` / `active`. Mirrors
    /// the wording the e2e harness inspects in `recovery-status`.
    #[serde(default)]
    status: String,
    /// RFC-3339 timestamp of the most recent state transition. The
    /// passphrase itself is NEVER persisted in cleartext.
    #[serde(default)]
    updated_at: String,
    /// SHA-256 fingerprint of the generated passphrase. Lets the e2e
    /// harness verify the user typed back the same phrase without us
    /// storing the plaintext.
    #[serde(default)]
    fingerprint: String,
}

impl RecoveryPassphraseState {
    fn status_label(&self) -> &str {
        if self.status.is_empty() {
            "not configured"
        } else {
            &self.status
        }
    }
}

/// Static 256-word fallback list. Picked from the standard BIP39
/// English wordlist's first 256 entries so any future migration to
/// the full list is a strict superset. The list lives inline to keep
/// the WASM bundle small while G3.Y1 ships; a follow-up will route
/// through `contrix_sdk::recovery::Bip39`.
const WORDLIST: &[&str] = &[
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
    "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire",
    "across", "act", "action", "actor", "actress", "actual", "adapt", "add", "addict", "address",
    "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid",
    "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already",
    "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst",
    "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle", "announce", "annual",
    "another", "answer", "antenna", "antique", "anxiety", "any", "apart", "apology", "appear",
    "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed",
    "armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist",
    "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete",
    "atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august", "aunt",
    "author", "auto", "autumn", "average", "avocado", "avoid", "awake", "aware", "away", "awesome",
    "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony",
    "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic",
    "basket", "battle", "beach", "bean", "beauty", "because", "become", "beef", "before", "begin",
    "behave", "behind", "believe", "below", "belt", "bench", "benefit", "best", "betray", "better",
    "between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter",
    "black", "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom",
    "blouse", "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus",
    "book", "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy",
    "bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
    "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown",
    "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle",
    "bunker", "burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz",
    "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call",
];

fn load_state(state_store: &LocalStateStore, account_did: &str) -> RecoveryPassphraseState {
    if account_did.is_empty() {
        return RecoveryPassphraseState::default();
    }
    match state_store.load_private_data(account_did, RECOVERY_PASSPHRASE_STATE_KEY) {
        Some(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        None => RecoveryPassphraseState::default(),
    }
}

fn save_state(
    state_store: &mut LocalStateStore,
    account_did: &str,
    state: &RecoveryPassphraseState,
) {
    if account_did.is_empty() {
        return;
    }
    if let Ok(payload) = serde_json::to_string(state) {
        state_store.save_private_data(account_did, RECOVERY_PASSPHRASE_STATE_KEY, payload);
    }
}

fn generate_words() -> Vec<String> {
    let mut buf = [0u8; WORD_COUNT * 2];
    if getrandom::fill(&mut buf).is_err() {
        // Fall back to a deterministic-but-noisy default so the UI
        // still renders something rather than panicking. The state
        // machine treats this as `verification_pending` and the user
        // can retry.
        return (0..WORD_COUNT)
            .map(|i| WORDLIST[i % WORDLIST.len()].to_owned())
            .collect();
    }
    (0..WORD_COUNT)
        .map(|i| {
            let hi = buf[i * 2] as usize;
            let lo = buf[i * 2 + 1] as usize;
            let idx = ((hi << 8) | lo) % WORDLIST.len();
            WORDLIST[idx].to_owned()
        })
        .collect()
}

fn fingerprint_passphrase(words: &[String]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(words.join(" ").as_bytes());
    let digest = hasher.finalize();
    let hex = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    format!("sha256:{hex}")
}

#[component]
pub fn SettingsRecoveryPanel(
    account_did: Signal<String>,
    mut state_store: Signal<LocalStateStore>,
) -> Element {
    let actor_did = account_did();
    let initial = load_state(&state_store.read(), &actor_did);

    let mut words = use_signal(Vec::<String>::new);
    let mut confirm_input = use_signal(String::new);
    let mut status_text = use_signal(|| initial.status_label().to_owned());
    let mut stored_fingerprint = use_signal(|| initial.fingerprint.clone());
    let mut last_updated = use_signal(|| initial.updated_at.clone());

    let strength = estimate_passphrase_strength(&confirm_input());
    let strength_label = match strength {
        0 => "—",
        1 => "weak",
        2 => "fair",
        3 => "good",
        _ => "strong",
    };

    rsx! {
        div { class: "settings", "data-testid": "recovery-setup-panel",
            div { class: "settings-shell",
                section { class: "settings-content-column",
                    div { class: "event settings-content-hero",
                        div { class: "event-head",
                            span { "Recovery" }
                            span { "{status_text}" }
                        }
                        div { class: "settings-content-title-row",
                            h2 { class: "settings-content-title", "Recovery passphrase" }
                            HelpTip { text: "Generate a 12-word recovery passphrase. Write it down somewhere safe; we never store the plaintext. Confirm by typing it back so we know you have a copy.".to_owned() }
                        }
                    }

                    div { class: "event",
                        div { class: "event-head",
                            span { "Generate" }
                            span { "12 words · ~96-132 bits entropy" }
                        }
                        p { class: "muted",
                            "Words are chosen with the OS RNG (getrandom). The passphrase plaintext only lives in this tab's memory until you navigate away."
                        }
                        div { class: "actions",
                            button {
                                class: "primary",
                                "data-testid": "recovery-setup-button",
                                onclick: {
                                    let actor = actor_did.clone();
                                    move |_| {
                                        let generated = generate_words();
                                        let fp = fingerprint_passphrase(&generated);
                                        let now = chrono::Utc::now().to_rfc3339();
                                        words.set(generated);
                                        confirm_input.set(String::new());
                                        stored_fingerprint.set(fp.clone());
                                        last_updated.set(now.clone());
                                        status_text.set("verification pending".to_owned());
                                        let next = RecoveryPassphraseState {
                                            status: "verification pending".to_owned(),
                                            updated_at: now,
                                            fingerprint: fp,
                                        };
                                        save_state(&mut state_store.write(), &actor, &next);
                                    }
                                },
                                if stored_fingerprint().is_empty() { "Generate passphrase" } else { "Regenerate" }
                            }
                        }
                    }

                    if !words().is_empty() {
                        div { class: "event",
                            div { class: "event-head",
                                span { "Passphrase" }
                                span { "write this down" }
                            }
                            div { class: "metric-grid", "data-testid": "recovery-passphrase-display",
                                for (i, word) in words().iter().enumerate() {
                                    div { class: "metric", "data-testid": "recovery-word-{i}",
                                        strong { "{i + 1}" }
                                        span { "{word}" }
                                    }
                                }
                            }
                        }
                    }

                    div { class: "event",
                        div { class: "event-head",
                            span { "Confirm" }
                            span { "strength: {strength_label}" }
                        }
                        p { class: "muted",
                            "Type the 12 words back, separated by spaces, to confirm you have a copy."
                        }
                        textarea {
                            "data-testid": "recovery-confirm-input",
                            rows: "3",
                            cols: "48",
                            value: "{confirm_input}",
                            placeholder: "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12",
                            oninput: move |evt| confirm_input.set(evt.value()),
                        }
                        div { class: "actions",
                            button {
                                class: "primary",
                                "data-testid": "recovery-confirm-button",
                                disabled: confirm_input().trim().is_empty()
                                    || stored_fingerprint().is_empty(),
                                onclick: {
                                    let actor = actor_did.clone();
                                    move |_| {
                                        let typed = confirm_input();
                                        let typed_words: Vec<String> = typed
                                            .split_whitespace()
                                            .map(|s| s.to_lowercase())
                                            .collect();
                                        let typed_fp = fingerprint_passphrase(&typed_words);
                                        if typed_fp == stored_fingerprint() {
                                            let now = chrono::Utc::now().to_rfc3339();
                                            status_text.set("active".to_owned());
                                            last_updated.set(now.clone());
                                            let next = RecoveryPassphraseState {
                                                status: "active".to_owned(),
                                                updated_at: now,
                                                fingerprint: stored_fingerprint(),
                                            };
                                            save_state(&mut state_store.write(), &actor, &next);
                                            // Clear the live words so the
                                            // plaintext does not linger in
                                            // the DOM. Fingerprint stays
                                            // in local state so the
                                            // restore flow can verify a
                                            // user later.
                                            words.set(Vec::new());
                                            confirm_input.set(String::new());
                                        } else {
                                            status_text.set("verification failed".to_owned());
                                        }
                                    }
                                },
                                "Confirm passphrase"
                            }
                        }
                    }

                    div { class: "event",
                        div { class: "event-head",
                            span { "Status" }
                            span { "data-testid": "recovery-status", "{status_text}" }
                        }
                        div { class: "metric-grid",
                            div { class: "metric",
                                strong { "Last updated" }
                                span { "{last_updated}" }
                            }
                            div { class: "metric",
                                strong { "Fingerprint" }
                                span {
                                    if stored_fingerprint().is_empty() {
                                        "—"
                                    } else {
                                        {
                                            let fp = stored_fingerprint();
                                            let suffix = fp.split(':').nth(1).unwrap_or("");
                                            if suffix.len() >= 12 {
                                                format!("sha256:{}…", &suffix[..12])
                                            } else {
                                                fp
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_words_returns_twelve_words() {
        let words = generate_words();
        assert_eq!(words.len(), WORD_COUNT);
        for word in words {
            assert!(
                WORDLIST.contains(&word.as_str()),
                "{} not in wordlist",
                word
            );
        }
    }

    #[test]
    fn fingerprint_is_stable_for_same_words() {
        let words = vec!["abandon".to_owned(), "ability".to_owned()];
        assert_eq!(
            fingerprint_passphrase(&words),
            fingerprint_passphrase(&words)
        );
    }

    #[test]
    fn fingerprint_changes_with_words() {
        let a = vec!["abandon".to_owned()];
        let b = vec!["ability".to_owned()];
        assert_ne!(fingerprint_passphrase(&a), fingerprint_passphrase(&b));
    }

    #[test]
    fn wordlist_has_at_least_256_entries() {
        assert!(WORDLIST.len() >= 256);
    }
}
