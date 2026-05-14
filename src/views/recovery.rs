//! Recovery / Encrypted Cloud Vault / Social Recovery 视图。
//!
//! - claude-design `desktop/recovery.html`
//! - 协议：`crypto-media/devices-and-auth.md` §4 + `identity/key-management.md`
//!
//! 此视图集中展示恢复方案的三层并存：加密云保险箱（默认 Argon2id + xchacha20poly1305）、
//! 社交恢复（Shamir's Secret Sharing 阈值方案）与独立 Recovery Key。
//! 任意一层成功 → 写入 `cx.identity.recovery` + 设备授权流程。

use dioxus::prelude::*;

use crate::components::HelpTip;

#[component]
pub fn RecoveryPanel(base_url: String, token: Signal<String>) -> Element {
    let _ = (base_url, token);

    rsx! {
        div { class: "timeline", "data-testid": "recovery-panel", role: "region", "aria-label": "Recovery and key backup",
            div { class: "event error-banner", "data-testid": "recovery-preview-banner",
                div { class: "event-head",
                    span { "Recovery" }
                    span { class: "badge", "Preview" }
                }
                div { class: "muted",
                    "This surface is a visual preview while we wire the recovery flows. Values shown below are illustrative and the action buttons are disabled — nothing here writes to the server. Real account recovery setup will land in an upcoming release."
                }
            }
            div { class: "event",
                div { class: "event-head",
                    span { "Recovery options" }
                    span { "Encrypted Vault · Social Recovery · Recovery Key" }
                    HelpTip { text: "Contrix never stores your passphrase on the server. Backups are encrypted on-device before upload. Any one recovery path is enough to re-authorize a new device on your account." }
                }
                div { class: "metric-grid", "data-testid": "recovery-overview",
                    div { class: "metric",
                        strong { "Primary" }
                        span { "Encrypted Cloud Vault" }
                        div { class: "muted", "Argon2id + xchacha20poly1305" }
                    }
                    div { class: "metric",
                        strong { "Backup" }
                        span { "SSS 3 of 5" }
                        div { class: "muted", "3 guardians online" }
                    }
                    div { class: "metric",
                        strong { "Unbacked content" }
                        span { "0" }
                        div { class: "muted", "Everything is uploaded encrypted" }
                    }
                    div { class: "metric",
                        strong { "Last rehearsal" }
                        span { "14 days ago" }
                        div { class: "muted", "Rehearse at least every 30 days" }
                    }
                }
            }

            // Encrypted Cloud Vault — devices-and-auth §4.1
            div { class: "event", "data-testid": "vault-section",
                div { class: "event-head",
                    span { "Encrypted Cloud Vault" }
                    span { "client-side encrypted blob" }
                    HelpTip { text: "A strong passphrase is stretched on-device (Argon2id by default: m=128MiB, t=3, p=4) and the resulting key is used to encrypt your master key, recovery key, and any unbacked MLS state before upload. FIPS deployments can drop down to PBKDF2 + AES-GCM, recorded in the backup metadata." }
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Key derivation" }
                        span { "Argon2id (m=128MiB, t=3, p=4)" }
                        div { class: "muted", "PBKDF2 only as a constrained fallback" }
                    }
                    div { class: "metric",
                        strong { "Encryption" }
                        span { "xchacha20poly1305" }
                        div { class: "muted", "FIPS profile may switch to AES-GCM" }
                    }
                    div { class: "metric",
                        strong { "Storage" }
                        span { "did:web:vault.contrix.social" }
                        div { class: "muted", "Ciphertext blob; the server cannot decrypt it" }
                    }
                    div { class: "metric",
                        strong { "Passphrase strength" }
                        span { "4.6 / 5" }
                        div { class: "muted", "Estimated locally; entropy is not uploaded" }
                    }
                }
                div { class: "actions",
                    button { class: "primary", "data-testid": "vault-rekey", disabled: true, title: "Preview — recovery write path is not yet wired", "Re-encrypt and upload" }
                    button { class: "secondary", "data-testid": "vault-export", disabled: true, title: "Preview", "Export .keystore.json" }
                    button { class: "secondary", "data-testid": "vault-rotate-passphrase", disabled: true, title: "Preview", "Rotate passphrase" }
                }
            }

            // Social recovery — devices-and-auth §4.2
            div { class: "event", "data-testid": "social-recovery-section",
                div { class: "event-head",
                    span { "Social Recovery · Shamir's Secret Sharing" }
                    span { "3 of 5 threshold" }
                    HelpTip { text: "The recovery key is split into 5 shares; any 3 can reconstruct it. Guardians can be individuals, an organization's IT, family, or a trusted HSM. Rotating the polynomial invalidates every prior share." }
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Mei" }
                        span { "did:plc:8djrfj4…" }
                        div { class: "muted", "Person · share confirmed" }
                    }
                    div { class: "metric",
                        strong { "Carlos" }
                        span { "did:plc:cl91fr…" }
                        div { class: "muted", "Person · share confirmed" }
                    }
                    div { class: "metric",
                        strong { "acme.example IT" }
                        span { "did:web:it.acme.example" }
                        div { class: "muted", "Organization guardian · confirmed" }
                    }
                    div { class: "metric",
                        strong { "Mom" }
                        span { "did:plc:mum2x…" }
                        div { class: "muted", "Family · share not yet acknowledged" }
                    }
                    div { class: "metric",
                        strong { "Backup HSM" }
                        span { "did:web:hsm.contrix.social" }
                        div { class: "muted", "Trusted service · 1 use per year" }
                    }
                }
                div { class: "actions",
                    button { class: "primary", "data-testid": "social-add-guardian", disabled: true, title: "Preview — guardian onboarding is not yet wired", "+ Add guardian" }
                    button { class: "secondary", "data-testid": "social-rotate", disabled: true, title: "Preview", "Rotate share polynomial" }
                    button { class: "secondary", "data-testid": "social-recover-now", disabled: true, title: "Preview", "Rehearse social recovery" }
                }
            }

            // Recovery key — fallback path
            div { class: "event", "data-testid": "recovery-key-section",
                div { class: "event-head",
                    span { "Recovery Key" }
                    span { "high-entropy string · keep offline" }
                }
                div { class: "muted",
                    "A fallback for when every device is lost and no guardian is reachable. Contrix never stores this on the server — print it or write it down and keep it somewhere physically safe."
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Current Recovery Key" }
                        span { "EAGLE—HARP—SUNDAY—ROOK—9F2C—Q1A0" }
                        div { class: "muted", "High entropy, generated locally, regeneratable anytime" }
                    }
                    div { class: "metric",
                        strong { "Last rotated" }
                        span { "32 days ago" }
                        div { class: "muted", "Recommended: rotate at least every 90 days" }
                    }
                }
                div { class: "actions",
                    button { class: "primary", "data-testid": "recovery-key-copy", disabled: true, title: "Preview", "Copy" }
                    button { class: "secondary", "data-testid": "recovery-key-print", disabled: true, title: "Preview", "Print" }
                    button { class: "secondary", "data-testid": "recovery-key-regenerate", disabled: true, title: "Preview", "Regenerate" }
                }
            }

            // Recovery write path
            div { class: "event", "data-testid": "recovery-writeback-explainer",
                div { class: "event-head",
                    span { "What happens when recovery succeeds" }
                    span { "method-specific evidence" }
                }
                div { class: "muted",
                    "The new device generates its own key, the recovery is recorded against your account, your DID/key log is updated with method-specific evidence, the new device is re-authorized, and your encrypted Spaces roll their epoch to include it. Existing devices are notified."
                }
            }
        }
    }
}
