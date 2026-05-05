//! Onboarding 步进器 — claude-design `desktop/onboarding.html`.
//!
//! 与 `views/register.rs` 不同：
//! - `/register` 是详细的注册向导（包含 DID method 选择、handle、profile、proof、recovery 全流程，
//!   面向"我要新建一个 Contrix 账号"的场景）。
//! - `/onboarding` 是轻量步进器，把同一组步骤拆成 4 个独立 step view，每步只暴露最少必要决策，
//!   面向"已有 DID 但希望按引导走完一遍"或"邀请链接落地后的承接页"。
//!
//! 协议依据：
//! - `identity/identity-did.md` §3 — v1 core 默认 principal DID method = `did:web`
//! - `identity/identity-handles.md` — handle 仅作为人类可读入口
//! - `crypto-media/device-lifecycle.md` §1-§3 — 登录因子 → cx.session.grant；
//!   设备授权 → cx.device.authorized；设备验证 → cx.key.verification.*
//! - `crypto-media/device-lifecycle.md` §10-§13 — 加密云保险箱 / SSS / Recovery Key
//!
//! 步骤：
//!   1. 选择 DID method（v1 core: did:web；high-trust: did:webvh；其它 v1.1+ extension）
//!   2. 绑定 handle
//!   3. 生成本设备 device key + cx.device.authorized
//!   4. 配置恢复策略（vault passphrase / SSS guardian / recovery key）

use dioxus::prelude::*;
use dioxus_router::Link;

use crate::routes::Route;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OnboardingStep {
    DidMethod,
    Handle,
    Device,
    Recovery,
}

impl OnboardingStep {
    fn index(self) -> usize {
        match self {
            Self::DidMethod => 1,
            Self::Handle => 2,
            Self::Device => 3,
            Self::Recovery => 4,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::DidMethod => "DID method",
            Self::Handle => "Handle",
            Self::Device => "Device key",
            Self::Recovery => "Recovery",
        }
    }
}

#[component]
pub fn OnboardingPanel(base_url: String, token: Signal<String>) -> Element {
    let _ = (base_url, token);
    let mut step = use_signal(|| OnboardingStep::DidMethod);
    let mut did_method = use_signal(|| "did:web".to_owned());
    let mut handle_local = use_signal(|| "alice".to_owned());
    let mut handle_domain = use_signal(|| "users.contrix.social".to_owned());
    let mut recovery_choice = use_signal(|| "vault".to_owned());

    rsx! {
        div { class: "timeline", "data-testid": "onboarding-panel", role: "region", "aria-label": "Onboarding stepper",
            // Header / progress
            div { class: "event", "data-testid": "onboarding-header",
                div { class: "event-head",
                    span { "Onboarding" }
                    span { "step {step().index()} / 4 · {step().label()}" }
                }
                div { class: "muted",
                    "建立可恢复身份。每步对应一组 canonical event；本页是步进入口，详细注册见 /register。"
                }
                div { class: "actions", "data-testid": "onboarding-progress", role: "tablist",
                    for s in [OnboardingStep::DidMethod, OnboardingStep::Handle, OnboardingStep::Device, OnboardingStep::Recovery] {
                        button {
                            class: if step() == s { "primary" } else { "secondary" },
                            role: "tab",
                            "aria-selected": if step() == s { "true" } else { "false" },
                            onclick: move |_| step.set(s),
                            "{s.index()}. {s.label()}"
                        }
                    }
                }
            }

            // Step 1: DID method
            if step() == OnboardingStep::DidMethod {
                div { class: "event", "data-testid": "onboarding-step-did",
                    div { class: "event-head",
                        span { "Step 1 · DID method" }
                        span { "identity-did.md §3" }
                    }
                    div { class: "muted",
                        "v1 core 默认 principal method 是 did:web；high-trust 升级到 did:webvh；did:plc / did:key / did:pkh / KERI / TSP 都是 v1.1+ interop extension。"
                    }
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { "did:web" }
                            span { class: if did_method() == "did:web" { "badge accent" } else { "badge" }, "v1 core default" }
                            div { class: "muted", "HTTPS + 域名；Auth Server 可在子域代为托管" }
                        }
                        div { class: "metric",
                            strong { "did:webvh" }
                            span { class: if did_method() == "did:webvh" { "badge accent" } else { "badge" }, "high-trust" }
                            div { class: "muted", "did:web + did.jsonl 历史 + SCID + witness" }
                        }
                        div { class: "metric",
                            strong { "did:plc" }
                            span { class: "badge amber", "v1.1+ extension" }
                            div { class: "muted", "AT Protocol interop only" }
                        }
                        div { class: "metric",
                            strong { "did:key / did:pkh / did:keri" }
                            span { class: "badge muted", "受限 / extension" }
                            div { class: "muted", "临时 / 钱包 / KERI interop" }
                        }
                    }
                    div { class: "actions",
                        button {
                            class: if did_method() == "did:web" { "primary" } else { "secondary" },
                            "data-testid": "did-method-web",
                            onclick: move |_| did_method.set("did:web".to_owned()),
                            "Use did:web (default)"
                        }
                        button {
                            class: if did_method() == "did:webvh" { "primary" } else { "secondary" },
                            "data-testid": "did-method-webvh",
                            onclick: move |_| did_method.set("did:webvh".to_owned()),
                            "Use did:webvh (high-trust)"
                        }
                        button { class: "secondary", "data-testid": "next-handle", onclick: move |_| step.set(OnboardingStep::Handle), "Next →" }
                    }
                }
            }

            // Step 2: Handle binding
            if step() == OnboardingStep::Handle {
                div { class: "event", "data-testid": "onboarding-step-handle",
                    div { class: "event-head",
                        span { "Step 2 · Handle binding" }
                        span { "identity-handles.md" }
                    }
                    div { class: "muted",
                        "Handle 是人类可读入口，不是权限主键。绑定后可被反向解析回你的 DID。"
                    }
                    div { class: "workflow-form",
                        label { "Local part" }
                        input {
                            "data-testid": "handle-local-input",
                            value: "{handle_local}",
                            oninput: move |evt| handle_local.set(evt.value()),
                        }
                        label { "Domain" }
                        input {
                            "data-testid": "handle-domain-input",
                            value: "{handle_domain}",
                            oninput: move |evt| handle_domain.set(evt.value()),
                        }
                    }
                    div { class: "muted",
                        "= @{handle_local}@{handle_domain} → {did_method}:{handle_domain}:{handle_local}"
                    }
                    div { class: "muted",
                        "Handle 反向解析回 DID 的证据通过 cx.did.proof event 在公共 directory 中保留（content-addressed proof）。"
                    }
                    div { class: "actions",
                        button { class: "secondary", onclick: move |_| step.set(OnboardingStep::DidMethod), "← Back" }
                        button { class: "secondary", "data-testid": "next-device", onclick: move |_| step.set(OnboardingStep::Device), "Next →" }
                    }
                }
            }

            // Step 3: Device key + authorization
            if step() == OnboardingStep::Device {
                div { class: "event", "data-testid": "onboarding-step-device",
                    div { class: "event-head",
                        span { "Step 3 · Device key" }
                        span { "device-lifecycle §1-§3" }
                    }
                    div { class: "muted",
                        "本设备生成 device key（ed25519，本地仅）。授权 device set 是独立步骤，登录因子只能签发短期 cx.session.grant；改变长期 device set 必须 cx.device.authorized。"
                    }
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { "Device key" }
                            span { "ed25519/Q4n…F9" }
                            div { class: "muted", "本地生成；私钥永不上传" }
                        }
                        div { class: "metric",
                            strong { "Session grant" }
                            span { "cx.session.grant" }
                            div { class: "muted", "ttl=15m；不持有 E2EE 历史密钥" }
                        }
                        div { class: "metric",
                            strong { "Device authorization" }
                            span { "cx.device.authorized" }
                            div { class: "muted", "改变长期 device set 的唯一 event" }
                        }
                        div { class: "metric",
                            strong { "Verification" }
                            span { "cx.key.verification.*" }
                            div { class: "muted", "可选 SAS / QR ceremony 后由其它成员 cross-sign" }
                        }
                    }
                    div { class: "actions",
                        button { class: "secondary", onclick: move |_| step.set(OnboardingStep::Handle), "← Back" }
                        button { class: "secondary", "data-testid": "next-recovery", onclick: move |_| step.set(OnboardingStep::Recovery), "Next →" }
                    }
                }
            }

            // Step 4: Recovery configuration
            if step() == OnboardingStep::Recovery {
                div { class: "event", "data-testid": "onboarding-step-recovery",
                    div { class: "event-head",
                        span { "Step 4 · Recovery" }
                        span { "device-lifecycle §10-§13" }
                    }
                    div { class: "muted",
                        "三层独立可叠加。任一层成功 → 写入 cx.identity.recovery + 新 device 授权。"
                    }
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { "Encrypted Cloud Vault" }
                            span { class: if recovery_choice() == "vault" { "badge accent" } else { "badge" }, "Argon2id + xchacha20poly1305" }
                            div { class: "muted", "强口令派生 → 加密 master key + recovery key 上传" }
                        }
                        div { class: "metric",
                            strong { "Social Recovery (SSS)" }
                            span { class: if recovery_choice() == "social" { "badge accent" } else { "badge" }, "3 / 5 threshold" }
                            div { class: "muted", "Shamir's Secret Sharing 切片分给 guardian" }
                        }
                        div { class: "metric",
                            strong { "Recovery Key" }
                            span { class: if recovery_choice() == "key" { "badge accent" } else { "badge" }, "high-entropy" }
                            div { class: "muted", "物理介质保存；服务端不存" }
                        }
                    }
                    div { class: "actions",
                        button {
                            class: if recovery_choice() == "vault" { "primary" } else { "secondary" },
                            "data-testid": "recovery-vault",
                            onclick: move |_| recovery_choice.set("vault".to_owned()),
                            "Vault"
                        }
                        button {
                            class: if recovery_choice() == "social" { "primary" } else { "secondary" },
                            "data-testid": "recovery-social",
                            onclick: move |_| recovery_choice.set("social".to_owned()),
                            "Social Recovery"
                        }
                        button {
                            class: if recovery_choice() == "key" { "primary" } else { "secondary" },
                            "data-testid": "recovery-key",
                            onclick: move |_| recovery_choice.set("key".to_owned()),
                            "Recovery Key"
                        }
                    }
                    div { class: "actions",
                        button { class: "secondary", onclick: move |_| step.set(OnboardingStep::Device), "← Back" }
                        Link {
                            class: "primary",
                            "data-testid": "onboarding-finish",
                            to: Route::Dashboard,
                            "Finish onboarding →"
                        }
                    }
                }
            }
        }
    }
}
