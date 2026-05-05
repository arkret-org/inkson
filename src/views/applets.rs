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

            // Protocol session event family — extensions/applet-integration + agent-protocol-interop
            // Applet 与 Agent 的协议会话生命周期由下列 canonical events 驱动：
            //   cx.applet.protocol_session.start / status         (bridge / bot 发起 + 状态汇报)
            //   cx.applet.bridge_error                            (桥接异常)
            //   cx.agent.protocol_session.start / status / result (agent 发起 + 状态 + 最终结果)
            // Agent 输出最终通过 signed Event（Flow / Message / Morph）落入 Space 才成为协议事实；
            // protocol_session.result 是会话级签名 receipt，便于审计 / 二次入仓。
            div { class: "event", "data-testid": "protocol-session-events",
                div { class: "event-head",
                    span { "Protocol session events" }
                    span { "applet + agent lifecycle" }
                }
                div { class: "muted",
                    "Applet 桥接与 Agent 协议会话都通过下列 event 落入审计链；result 是 agent 会话的 canonical 签名 receipt。原始正文 / 工具调用细节通过 Flow / Morph 派生，不堆在 status event 里。"
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Applet session" }
                        span { "cx.applet.protocol_session.start · cx.applet.protocol_session.status" }
                        div { class: "muted", "桥接 / Bot 发起的会话生命周期" }
                    }
                    div { class: "metric",
                        strong { "Bridge error" }
                        span { "cx.applet.bridge_error" }
                        div { class: "muted", "桥接异常 / 外部网络断连" }
                    }
                    div { class: "metric",
                        strong { "Agent session" }
                        span { "cx.agent.protocol_session.start · cx.agent.protocol_session.status" }
                        div { class: "muted", "A2A / ACP / MCP 会话生命周期" }
                    }
                    div { class: "metric",
                        strong { "Agent endpoint" }
                        span { "cx.agent.endpoint" }
                        div { class: "muted", "声明 agent 可达性 / 协议版本" }
                    }
                    div { class: "metric",
                        strong { "Agent result" }
                        span { "cx.agent.protocol_session.result" }
                        div { class: "muted", "签名会话 receipt（最终输出 + 工具调用摘要）" }
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
