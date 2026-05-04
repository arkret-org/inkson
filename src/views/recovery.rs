//! Recovery / Encrypted Cloud Vault / Social Recovery 视图。
//!
//! - claude-design `desktop/recovery.html`
//! - 协议：`crypto-media/devices-and-auth.md` §4 + `identity/key-management.md`
//!
//! 此视图集中展示恢复方案的三层并存：加密云保险箱（默认 Argon2id + xchacha20poly1305）、
//! 社交恢复（Shamir's Secret Sharing 阈值方案）与独立 Recovery Key。
//! 任意一层成功 → 写入 `cx.identity.recovery` + 设备授权流程。

use dioxus::prelude::*;

#[component]
pub fn RecoveryPanel(base_url: String, token: Signal<String>) -> Element {
    let _ = (base_url, token);

    rsx! {
        div { class: "timeline", "data-testid": "recovery-panel", role: "region", "aria-label": "Recovery and key backup",
            div { class: "event",
                div { class: "event-head",
                    span { "恢复方案" }
                    span { "Encrypted Vault · Social Recovery · Recovery Key" }
                }
                div { class: "muted",
                    "Contrix 不在服务端存口令；备份是客户端加密后再上传。任意一层完成恢复都会写入 cx.identity.recovery，再走 cx.device.authorized 流程把新设备并入 device set。"
                }
                div { class: "metric-grid", "data-testid": "recovery-overview",
                    div { class: "metric",
                        strong { "主方案" }
                        span { "Encrypted Cloud Vault" }
                        div { class: "muted", "Argon2id + xchacha20poly1305" }
                    }
                    div { class: "metric",
                        strong { "备用方案" }
                        span { "SSS 3 / 5" }
                        div { class: "muted", "3 名 guardian 在线" }
                    }
                    div { class: "metric",
                        strong { "未备份内容" }
                        span { "0" }
                        div { class: "muted", "全部已加密上传" }
                    }
                    div { class: "metric",
                        strong { "最近一次演练" }
                        span { "14 天前" }
                        div { class: "muted", "建议每 30 天演练一次" }
                    }
                }
            }

            // Encrypted Cloud Vault — devices-and-auth §4.1
            div { class: "event", "data-testid": "vault-section",
                div { class: "event-head",
                    span { "加密云保险箱" }
                    span { "client-side encrypted blob" }
                }
                div { class: "muted",
                    "客户端用强口令派生密钥（Argon2id 默认 m=128MiB, t=3, p=4）后，使用 AEAD 加密主钥、recovery key 与未备份的 MLS 状态再上传。FIPS profile 可降级为 PBKDF2 + AES-GCM，但必须在 backup metadata 中显式声明。"
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "KDF" }
                        span { "Argon2id (m=128MiB, t=3, p=4)" }
                        div { class: "muted", "PBKDF2 仅作为 fallback / constrained" }
                    }
                    div { class: "metric",
                        strong { "AEAD" }
                        span { "xchacha20poly1305" }
                        div { class: "muted", "FIPS profile 可切到 AES-GCM" }
                    }
                    div { class: "metric",
                        strong { "存储" }
                        span { "did:web:vault.contrix.social" }
                        div { class: "muted", "ciphertext blob; 不可被服务端解密" }
                    }
                    div { class: "metric",
                        strong { "Passphrase 强度" }
                        span { "4.6 / 5" }
                        div { class: "muted", "本地估测；entropy 不上传" }
                    }
                }
                div { class: "actions",
                    button { class: "primary", "data-testid": "vault-rekey", "立即重新加密上传" }
                    button { class: "secondary", "data-testid": "vault-export", "导出 .keystore.json" }
                    button { class: "secondary", "data-testid": "vault-rotate-passphrase", "更换口令" }
                }
            }

            // Social recovery — devices-and-auth §4.2
            div { class: "event", "data-testid": "social-recovery-section",
                div { class: "event-head",
                    span { "社交恢复 · Shamir's Secret Sharing" }
                    span { "3 / 5 阈值" }
                }
                div { class: "muted",
                    "Recovery key 切成 5 份，3 份即可重构。Guardian 可以是个人、组织 IT、家人或受信 HSM。轮换 polynomial 即作废所有旧 share。"
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Mei" }
                        span { "did:plc:8djrfj4…" }
                        div { class: "muted", "个人 · 已确认 share" }
                    }
                    div { class: "metric",
                        strong { "Carlos" }
                        span { "did:plc:cl91fr…" }
                        div { class: "muted", "个人 · 已确认 share" }
                    }
                    div { class: "metric",
                        strong { "acme.example IT" }
                        span { "did:web:it.acme.example" }
                        div { class: "muted", "组织 guardian · 已确认" }
                    }
                    div { class: "metric",
                        strong { "Mom" }
                        span { "did:plc:mum2x…" }
                        div { class: "muted", "家人 · share 未签收" }
                    }
                    div { class: "metric",
                        strong { "Backup HSM" }
                        span { "did:web:hsm.contrix.social" }
                        div { class: "muted", "受信服务 · 1 次/年配额" }
                    }
                }
                div { class: "actions",
                    button { class: "primary", "data-testid": "social-add-guardian", "＋ 新增 guardian" }
                    button { class: "secondary", "data-testid": "social-rotate", "重新分发碎片（轮换 polynomial）" }
                    button { class: "secondary", "data-testid": "social-recover-now", "演练社交恢复" }
                }
            }

            // Recovery key — fallback path
            div { class: "event", "data-testid": "recovery-key-section",
                div { class: "event-head",
                    span { "Recovery Key" }
                    span { "高熵字符串 · 物理介质保存" }
                }
                div { class: "muted",
                    "全部设备丢失 + guardian 不可达时回退使用。Contrix 不在服务端存它；建议打印或写在物理介质保存。"
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "当前 Recovery Key" }
                        span { "EAGLE—HARP—SUNDAY—ROOK—9F2C—Q1A0" }
                        div { class: "muted", "高熵；本地生成；可随时重生成" }
                    }
                    div { class: "metric",
                        strong { "上次轮换" }
                        span { "32 天前" }
                        div { class: "muted", "≥90 天建议轮换" }
                    }
                }
                div { class: "actions",
                    button { class: "primary", "data-testid": "recovery-key-copy", "复制" }
                    button { class: "secondary", "data-testid": "recovery-key-print", "打印备份" }
                    button { class: "secondary", "data-testid": "recovery-key-regenerate", "重新生成" }
                }
            }

            // Recovery write path
            div { class: "event", "data-testid": "recovery-writeback-explainer",
                div { class: "event-head",
                    span { "恢复成功后的写入路径" }
                    span { "method-specific evidence" }
                }
                div { class: "muted",
                    "新设备生成 device key → cx.identity.recovery → DID/key-log 更新（method-specific evidence）→ cx.device.authorized → MLS 重新加入旧 group（必要时 epoch++）。其它设备会收到撤销通知。"
                }
            }
        }
    }
}
