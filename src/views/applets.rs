//! Applets / Bots / Bridges / Agents / Portal Spaces 集中管理。
//!
//! - claude-design `desktop/applets.html`
//! - 协议：`extensions/applet-integration.md` + `extensions/agent-protocol-interop.md` + `extensions/mimi-interop.md`
//!
//! Applet 注册声明 namespace 与可接收 transaction，但每个写入仍需 capability + 签名。
//! Ghost actor 必须可审计，不应伪装人类 DID。Agent 输出通过 signed Event 才成为协议事实。

use dioxus::prelude::*;

#[component]
pub fn AppletsPanel(base_url: String, token: Signal<String>) -> Element {
    let _ = (base_url, token);

    rsx! {
        div { class: "timeline", "data-testid": "applets-panel", role: "region", "aria-label": "Applets and agents",
            // Protocol invariant banner
            div { class: "event", "data-testid": "applets-protocol-banner",
                div { class: "event-head",
                    span { "Applet ≠ 自动获得权限" }
                    span { "extensions/applet-integration.md" }
                }
                div { class: "muted",
                    "Applet namespace 只表示 \"该 Applet 可声明或接收这些对象\"，不等于权限通过。每个写入仍需 capability + 签名。Ghost actor 必须可审计，不应伪装人类 DID。Agent 输出通过 signed Event 才成为协议事实。"
                }
                div { class: "actions",
                    span { class: "badge blue", "applet_registration" }
                    span { class: "badge", "namespace claim" }
                    span { class: "badge amber", "ghost actor accountable" }
                    span { class: "badge green", "signed event = truth" }
                }
            }

            // Installed Applets
            div { class: "event", "data-testid": "installed-applets",
                div { class: "event-head",
                    span { "已注册 Applet" }
                    span { "active in current Spaces" }
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Build-bot" }
                        span { "did:web:bot.acme.example" }
                        div { class: "muted", "受信 · cx.message.create + reaction · 30d cap" }
                    }
                    div { class: "metric",
                        strong { "Slack Bridge" }
                        span { "did:web:slack-bridge.example" }
                        div { class: "muted", "桥接 · portal_space + ghost_actor.write · plaintext_visible(portal)" }
                    }
                    div { class: "metric",
                        strong { "GitHub Mirror" }
                        span { "did:web:github-mirror.acme.example" }
                        div { class: "muted", "桥接 · cx.flow.create + cx.morph.create + cx.relation.create" }
                    }
                    div { class: "metric",
                        strong { "MIMI Provider Facade" }
                        span { "did:web:mimi.acme.example" }
                        div { class: "muted", "互操作 · cx.mimi.room_binding · 仅密文" }
                    }
                }
            }

            // Agents
            div { class: "event", "data-testid": "agents-section",
                div { class: "event-head",
                    span { "Agents · A2A / ACP / MCP" }
                    span { "extensions/agent-protocol-interop.md" }
                }
                div { class: "muted",
                    "Agent 的 capability 必须显式（read_flow / write_message / write_morph 等），高风险动作叠加 approval_constraint；Agent 输出通过 signed Event 落地。"
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Researcher Agent" }
                        span { "agent.copy.acme.example" }
                        div { class: "muted", "acp / a2a · read_flow + write_message + write_morph · approval pending 1/2" }
                    }
                    div { class: "metric",
                        strong { "Triage Agent" }
                        span { "mcp.acme.example" }
                        div { class: "muted", "mcp · read_flow + reorder + label · running" }
                    }
                    div { class: "metric",
                        strong { "Compliance Auditor" }
                        span { "partner.example" }
                        div { class: "muted", "a2a · read_only + write_morph(audit_report) · weekly" }
                    }
                }
            }

            // Portal Spaces
            div { class: "event", "data-testid": "portal-spaces",
                div { class: "event-head",
                    span { "Portal Spaces" }
                    span { "applet-integration.md §3.5" }
                }
                div { class: "muted",
                    "外部网络 location 在 Contrix 中的镜像 Space。明文边界由 Space policy 列出的 plaintext_visible_services 限定。"
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "portal:slack-acme" }
                        span { "23 ghost actors" }
                        div { class: "muted", "plaintext visible to slack-bridge.example" }
                    }
                    div { class: "metric",
                        strong { "portal:github-acme/contrix" }
                        span { "issue → flow · pr → flow + morph(diff)" }
                        div { class: "muted", "受 OAuth scope 与 capability 共同限制" }
                    }
                }
            }

            // Register new Applet
            div { class: "event", "data-testid": "register-applet",
                div { class: "event-head",
                    span { "注册新 Applet" }
                    span { "cx.applet.registration" }
                }
                div { class: "muted",
                    "提交 signed cx.applet.registration（含 service DID、controller DID、namespace、要求 capability 集合、plaintext 可见性）。Space owner / org admin / authz service 决定是否接受。"
                }
                div { class: "actions",
                    button { class: "primary", "data-testid": "register-applet-button", "提交 cx.applet.registration" }
                    button { class: "secondary", "data-testid": "validate-applet-signature", "校验注册签名" }
                }
            }
        }
    }
}
