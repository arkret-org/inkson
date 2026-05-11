use dioxus::prelude::*;
use serde_json::Value;

use crate::views::helpers::authed_api;

const DEMO_SPACE_ID: &str = "cx:space:0196419b-0000-7000-8000-000000000000";

#[component]
pub fn AuditPanel(base_url: String, token: Signal<String>) -> Element {
    let mut next_batch = use_signal(|| String::new());
    let mut event_count = use_signal(|| 0usize);
    let mut frontier_ref = use_signal(|| String::new());
    let mut status_msg = use_signal(|| String::new());
    let mut capability_actor = use_signal(|| "did:web:alice.example".to_owned());
    let mut capability_action = use_signal(|| "space.read".to_owned());
    let mut capability_resource =
        use_signal(|| "cx:space:0196419b-0000-7000-8000-000000000000".to_owned());
    let mut capability_grants = use_signal(Vec::<Value>::new);
    let mut capability_state_hash = use_signal(|| Option::<String>::None);
    let mut capability_decision = use_signal(|| String::new());
    let mut capability_reason = use_signal(|| String::new());

    rsx! {
        div { class: "timeline", "data-testid": "audit-panel",
            div { class: "event", "data-testid": "projection-origin-banner",
                div { class: "event-head",
                    span { "Projection origin" }
                    span { "signed Event → reducer → projection" }
                }
                div { class: "muted",
                    "本页所有视图都源于 signed Event Envelope；projection 缓存丢失后必须能从 prev_refs / refs 重新计算。Principal Server 不可伪造 Event；Capability cache 命中必须绑定 causal frontier 与 policy version，否则 fail closed 重新执行 authz。"
                }
                div { class: "actions",
                    span { class: "badge blue", "actor event chain" }
                    span { class: "badge", "refs" }
                    span { class: "badge", "prev_refs" }
                    span { class: "badge green", "reducer profile" }
                    span { class: "badge amber", "fail-closed on cache miss" }
                }
            }

            div { class: "event", "data-testid": "conflict-trail",
                div { class: "event-head",
                    span { "Conflict trail" }
                    span { "concurrent cx.flow.move convergence" }
                }
                div { class: "muted",
                    "并发 cx.flow.move 收敛规则：取更晚 HLC 胜出，被 superseded 的事件保留在审计链便于复审与重写。位置唯一性 (board_id, flow_id) 由 active position edge 去重。"
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Mei (winner)" }
                        span { "→ Review · HLC 01970e589d21-0004" }
                        div { class: "muted", "cx.flow.move accepted; new active position edge" }
                    }
                    div { class: "metric",
                        strong { "Alice (你)" }
                        span { "→ In Progress · superseded" }
                        div { class: "muted", "保留在 actor event chain；可创建新 cx.flow.move 重写" }
                    }
                    div { class: "metric",
                        strong { "Reducer resolve" }
                        span { "list = Review" }
                        div { class: "muted", "(board_id, flow_id) active edge dedupe" }
                    }
                }
            }

            div { class: "event", "data-testid": "schema-evolution",
                div { class: "event-head",
                    span { "Schema evolution" }
                    span { "cx.schema.{{define,update}}" }
                }
                div { class: "muted",
                    "Schema 注册和演进由 Space 内的 cx.schema.define / cx.schema.update event 维护。新增字段 SHOULD additive；遇到未知字段时客户端必须保留 raw value。"
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "cx.schema.define" }
                        span { "register" }
                        div { class: "muted", "声明新 morph_type / facet / fields shape" }
                    }
                    div { class: "metric",
                        strong { "cx.schema.update" }
                        span { "evolve" }
                        div { class: "muted", "兼容性更新；reducer profile 可能升级" }
                    }
                    div { class: "metric",
                        strong { "Reducer profile" }
                        span { "Event Envelope requirements{{}}" }
                        div { class: "muted", "schema_profile_refs / reducer_profile_ref 已合并为 requirements 对象" }
                    }
                }
            }

            div { class: "event", "data-testid": "authz-decisions",
                div { class: "event-head",
                    span { "Capability decisions" }
                    span { "accept / pending / deny" }
                }
                div { class: "muted",
                    "每次写入的 reducer 决策都附带 grant 引用与 constraint 求值结果。pending 表示叠加了 approval_constraint，仍在等待门槛达成。"
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "cx.flow.update (Mei)" }
                        span { "accept" }
                        div { class: "muted", "grant cx:grant:9a… · admin role" }
                    }
                    div { class: "metric",
                        strong { "cx.message.create (α)" }
                        span { "accept" }
                        div { class: "muted", "grant cx:grant:5b… · approval=admin_auto" }
                    }
                    div { class: "metric",
                        strong { "cx.capability.grant (α)" }
                        span { "pending 1/2" }
                        div { class: "muted", "approval_constraint=2_of_3_admin" }
                    }
                    div { class: "metric",
                        strong { "cx.capability.derived" }
                        span { "computed" }
                        div { class: "muted", "reducer 内部派生 capability set；不需要单独签名" }
                    }
                }
                div { class: "actions",
                    span { class: "muted", "Redaction events:" }
                    span { class: "badge red", "cx.redaction" }
                    span { class: "muted", "(cross-object — 比 cx.message.redact 更宽，可作用于 morph / relation / event metadata)" }
                }
            }

            div { class: "event", "data-testid": "batch-display",
                div { class: "event-head", span { "Event Audit" } span { "frontier" } }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Next Cursor" }
                        span { if next_batch().is_empty() { "not loaded" } else { "{next_batch}" } }
                    }
                    div { class: "metric",
                        strong { "Visible Events" }
                        span { "{event_count}" }
                    }
                    div { class: "metric",
                        strong { "Snapshot" }
                        span { if frontier_ref().is_empty() { "not loaded" } else { "{frontier_ref}" } }
                    }
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "refresh-audit-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let base = base.clone();
                                let api_token = token();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.backfill(DEMO_SPACE_ID).await {
                                            Ok(resp) => {
                                                event_count.set(resp.events.len());
                                                next_batch.set(
                                                    resp.next_cursor
                                                        .or(resp.prev_cursor)
                                                        .unwrap_or_else(|| "end".to_owned()),
                                                );
                                            }
                                            Err(error) => {
                                                status_msg.set(format!("events query failed: {error}"));
                                                return;
                                            }
                                        }
                                        match api.snapshot_head(DEMO_SPACE_ID).await {
                                            Ok(snapshot) => {
                                                frontier_ref.set(snapshot.snapshot_ref);
                                                status_msg.set("Audit data loaded".to_owned());
                                            }
                                            Err(error) => {
                                                status_msg.set(format!("snapshot failed: {error}"));
                                            }
                                        }
                                    }
                                });
                            }
                        },
                        "Refresh"
                    }
                }
            }

            div { class: "event", "data-testid": "event-envelope-audit",
                div { class: "event-head", span { "Event Envelope" } span { "write plane" } }
                div { class: "metric-grid",
                    div { class: "metric", strong { "actor_seq" } span { "42" } div { class: "muted", "monotonic per actor" } }
                    div { class: "metric", strong { "event_id" } span { "cx:event:preview" } div { class: "muted", "UUIDv7 event identifier" } }
                    div { class: "metric", strong { "frontier" } span { if frontier_ref().is_empty() { "not loaded" } else { "{frontier_ref}" } } div { class: "muted", "projection source" } }
                    div { class: "metric", strong { "refs" } span { "role=authorized_by" } div { class: "muted", "authorization proof references" } }
                    div { class: "metric", strong { "schema" } span { "cx.schema.core.v1" } div { class: "muted", "validated before reducer" } }
                    div { class: "metric", strong { "reducer" } span { "cx.reducer.v1" } div { class: "muted", "state hash after projection" } }
                }
                div { class: "muted",
                    "Audit links UI actions to submitted events, reducer receipts, projection hashes, authz explanation, and causal frontier metadata."
                }
            }

            div { class: "event", "data-testid": "capability-explanation",
                div { class: "event-head", span { "Capability explanation" } span { "{capability_grants().len()} grants" } }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Actor" }
                        input {
                            "data-testid": "capability-actor-input",
                            value: "{capability_actor}",
                            oninput: move |event| capability_actor.set(event.value()),
                        }
                    }
                    div { class: "metric",
                        strong { "Action" }
                        input {
                            "data-testid": "capability-action-input",
                            value: "{capability_action}",
                            oninput: move |event| capability_action.set(event.value()),
                        }
                    }
                    div { class: "metric",
                        strong { "Resource" }
                        input {
                            "data-testid": "capability-resource-input",
                            value: "{capability_resource}",
                            oninput: move |event| capability_resource.set(event.value()),
                        }
                    }
                    div { class: "metric", "data-testid": "capability-decision",
                        strong { "Decision" }
                        span { if capability_decision().is_empty() { "not checked" } else { "{capability_decision}" } }
                    }
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "load-capabilities-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let base = base.clone();
                                let api_token = token();
                                let actor = capability_actor();
                                let action = capability_action();
                                let resource = capability_resource();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.effective_grants(&actor).await {
                                            Ok(resp) => {
                                                capability_state_hash.set(resp.state_hash.clone());
                                                capability_grants.set(resp.grants);
                                            }
                                            Err(error) => capability_reason.set(format!("effective grants failed: {error}")),
                                        }
                                        match api.authz_check(&actor, &action, &resource).await {
                                            Ok(decision) => {
                                                capability_decision.set(if decision.allowed { "allowed".to_owned() } else { "denied".to_owned() });
                                                capability_reason.set(decision.reason_code.unwrap_or_else(|| "frontier current".to_owned()));
                                            }
                                            Err(error) => {
                                                capability_decision.set("error".to_owned());
                                                capability_reason.set(format!("check failed: {error}"));
                                            }
                                        }
                                    }
                                });
                            }
                        },
                        "Load Capabilities"
                    }
                }
                if let Some(state_hash) = capability_state_hash() {
                    div { class: "muted", "data-testid": "capability-frontier",
                        "state frontier {state_hash}"
                    }
                }
                if !capability_reason().is_empty() {
                    div { class: "muted", "data-testid": "capability-reason",
                        "reason {capability_reason}"
                    }
                }
                for grant in capability_grants() {
                    div { class: "event", "data-testid": "capability-grant-row",
                        div { class: "event-head",
                            span { "{json_text(&grant, \"grant_id\")}" }
                            span { "{json_text(&grant, \"issuer\")}" }
                        }
                        div { class: "muted", "data-testid": "capability-resource-selectors",
                            "selectors {json_value(&grant, &[\"resource_selectors\", \"resources\", \"resource\"])}"
                        }
                        div { class: "muted", "data-testid": "capability-constraints",
                            "constraints {json_value(&grant, &[\"constraints\", \"obligations\"])}"
                        }
                        {
                            let allowed_facets = capability_facet_allow(&grant);
                            if !allowed_facets.is_empty() {
                                let allowed_facets_label = allowed_facets.join(", ");
                                rsx! {
                                    div { class: "muted", "data-testid": "capability-allowed-facets",
                                        "facet_allow {allowed_facets_label}"
                                    }
                                }
                            } else {
                                rsx! { div {} }
                            }
                        }
                        div { class: "muted", "data-testid": "capability-delegation-chain",
                            "delegation {json_value(&grant, &[\"delegation_chain\", \"proofs\"])}"
                        }
                    }
                }
                if capability_decision() == "denied" && !capability_reason().is_empty() {
                    div { class: "muted", "data-testid": "capability-denial-class",
                        "denial {capability_denial_label(&capability_reason())}"
                    }
                }
                if capability_grants().is_empty() {
                    div { class: "muted", "No grants loaded. Click Load Capabilities." }
                }
            }

            if !status_msg().is_empty() {
                div { class: "muted", "data-testid": "audit-status", "{status_msg}" }
            }
        }
    }
}

fn json_text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_owned()
}

fn json_value(value: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| value.get(*key))
        .map(|v| v.to_string())
        .unwrap_or_else(|| "[]".to_owned())
}

fn capability_facet_allow(grant: &Value) -> Vec<String> {
    let mut facets = Vec::new();
    collect_string_array(grant.get("facet_allow"), &mut facets);

    if let Some(constraints) = grant.get("constraints").and_then(|v| v.as_array()) {
        for constraint in constraints {
            collect_string_array(constraint.get("facet_allow"), &mut facets);
            collect_string_array(
                constraint
                    .get("params")
                    .and_then(|params| params.get("facet_allow")),
                &mut facets,
            );
        }
    }

    facets
}

fn collect_string_array(value: Option<&Value>, target: &mut Vec<String>) {
    if let Some(values) = value.and_then(|v| v.as_array()) {
        for value in values {
            if let Some(text) = value.as_str() {
                let text = text.to_owned();
                if !target.contains(&text) {
                    target.push(text);
                }
            }
        }
    }
}

fn capability_denial_label(reason: &str) -> &'static str {
    let reason = reason.to_ascii_lowercase();
    if reason.contains("object type") || reason.contains("object_type") {
        "object type label mismatch"
    } else if reason.contains("facet") || reason.contains("facet_allow") {
        "facet capability missing"
    } else if reason.contains("stale") || reason.contains("frontier") {
        "stale frontier"
    } else if reason.contains("review") {
        "requires review"
    } else {
        "access denied"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn capability_explanation_helpers_extract_fallback_fields() {
        let grant = json!({
            "grant_id": "cx:grant:test",
            "resources": ["space:cx:space:test/**"],
            "constraints": [{"type": "temporal"}],
            "proofs": ["cx:grant:root"]
        });

        assert_eq!(json_text(&grant, "grant_id"), "cx:grant:test");
        assert!(
            json_value(&grant, &["resource_selectors", "resources"])
                .contains("space:cx:space:test")
        );
        assert!(json_value(&grant, &["constraints"]).contains("temporal"));
        assert!(json_value(&grant, &["delegation_chain", "proofs"]).contains("cx:grant:root"));
    }

    #[test]
    fn capability_explanation_extracts_facet_allow() {
        let grant = json!({
            "facet_allow": ["renderable"],
            "constraints": [
                {"type": "type_restriction", "params": {"facet_allow": ["stateful", "rankable"]}},
                {"type": "type_restriction", "facet_allow": ["renderable"]}
            ]
        });

        assert_eq!(
            capability_facet_allow(&grant),
            vec![
                "renderable".to_owned(),
                "stateful".to_owned(),
                "rankable".to_owned()
            ]
        );
    }

    #[test]
    fn capability_denial_label_distinguishes_type_and_facet_denials() {
        assert_eq!(
            capability_denial_label("object type flow not allowed"),
            "object type label mismatch"
        );
        assert_eq!(
            capability_denial_label("facet rankable not allowed or unavailable"),
            "facet capability missing"
        );
    }
}
