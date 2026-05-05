//! Write state badge — unified offline / optimistic / accepted / conflict states.
//!
//! Yougen 客户端在 Board / Card / Room 三处都需要展示同一个写入生命周期。
//! 当前 `views/kanban.rs` 内部定义了一个 `CardState`，这里把同一套语义抽出
//! 成共享组件供 chat / forum / timeline 复用，避免三处 drift。
//!
//! 协议依据：
//! - `sync/operations-sync.md`：offline-first 写入；Event Envelope 是 truth source。
//! - `authz/event-auth-state-resolution.md`：reducer 拒绝时落入 `state_mismatch` 或
//!   `cas_conflict`。
//! - `governance/content-moderation.md`：被 quarantine 的写入仍可见，但走审核队列。
//!
//! 状态机：
//! ```text
//! Optimistic → Queued → Submitted → Accepted | SoftFailed | CasConflict | Quarantined
//!                                                                    ↑
//!                                                         (Accepted ⇒ Synced)
//! ```

use dioxus::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteState {
    /// 已与 frontier 对齐 — 服务端 reducer 已接受。
    Synced,
    /// 本地刚乐观应用，尚未提交。
    Optimistic,
    /// 已入本地离线队列，等待网络。
    Queued,
    /// 已提交给 Principal Server，等待回执。
    Submitted,
    /// reducer accept — 与 Synced 等价，但保留以便活动流显示。
    Accepted,
    /// reducer 软失败（schema / capability 通过但 transition 不合法）。
    SoftFailed,
    /// CAS / position-edge 冲突（并发 cx.flow.move）。
    CasConflict,
    /// 通过 capability 但被 moderation policy 隔离。
    Quarantined,
}

impl WriteState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Synced => "synced",
            Self::Optimistic => "optimistic",
            Self::Queued => "queued",
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::SoftFailed => "soft failed",
            Self::CasConflict => "CAS conflict",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn class_name(self) -> &'static str {
        match self {
            Self::Synced | Self::Accepted => "badge green",
            Self::Optimistic | Self::Queued | Self::Submitted => "badge blue",
            Self::SoftFailed | Self::CasConflict => "badge red",
            Self::Quarantined => "badge amber",
        }
    }

    /// 一句话解释状态语义，方便 tooltip / inbox 摘要使用。
    pub fn explanation(self) -> &'static str {
        match self {
            Self::Synced => "已与 sync frontier 对齐；reducer 已接受。",
            Self::Optimistic => "本地乐观应用；尚未入队。",
            Self::Queued => "在本地离线队列等待网络。",
            Self::Submitted => "已提交给 Principal Server，等待回执。",
            Self::Accepted => "reducer 已接受；本地状态已合并。",
            Self::SoftFailed => "reducer 拒绝（schema 通过但 transition 非法）；可重写。",
            Self::CasConflict => "并发写入 superseded by 更晚 HLC；保留在审计链可恢复。",
            Self::Quarantined => "通过 capability 但被 moderation 隔离；进入审核队列。",
        }
    }

    /// 列出所有变体（顺序为 UI 推荐展示顺序）。
    pub fn all() -> [Self; 8] {
        [
            Self::Synced,
            Self::Optimistic,
            Self::Queued,
            Self::Submitted,
            Self::Accepted,
            Self::SoftFailed,
            Self::CasConflict,
            Self::Quarantined,
        ]
    }
}

/// 单个 pill 形式的 write state 标识，可放在 KanbanCard、Message、Flow row 上。
#[component]
pub fn WriteStatePill(state: String) -> Element {
    let parsed = parse_write_state(&state);
    let class = parsed.map(WriteState::class_name).unwrap_or("badge");
    let label = parsed.map(WriteState::label).unwrap_or(state.as_str());
    rsx! {
        span {
            class: "{class}",
            "data-testid": "write-state-pill",
            "title": "sync/operations-sync.md — write-plane state machine",
            "{label}"
        }
    }
}

/// 详细解释卡片，用于 audit / debug 抽屉。
#[component]
pub fn WriteStateExplainer(state: String) -> Element {
    let parsed = parse_write_state(&state);
    let class = parsed.map(WriteState::class_name).unwrap_or("badge");
    let label = parsed.map(WriteState::label).unwrap_or(state.as_str());
    let explanation = parsed
        .map(WriteState::explanation)
        .unwrap_or("unknown state");
    rsx! {
        div {
            class: "event",
            "data-testid": "write-state-explainer",
            div { class: "event-head", span { "Write state" } span { class: "{class}", "{label}" } }
            div { class: "muted", "{explanation}" }
        }
    }
}

fn parse_write_state(s: &str) -> Option<WriteState> {
    match s {
        "synced" => Some(WriteState::Synced),
        "optimistic" => Some(WriteState::Optimistic),
        "queued" => Some(WriteState::Queued),
        "submitted" => Some(WriteState::Submitted),
        "accepted" => Some(WriteState::Accepted),
        "soft failed" | "soft_failed" => Some(WriteState::SoftFailed),
        "CAS conflict" | "cas_conflict" => Some(WriteState::CasConflict),
        "quarantined" => Some(WriteState::Quarantined),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_state_labels_are_unique() {
        let mut labels: Vec<&str> = WriteState::all().iter().map(|s| s.label()).collect();
        labels.sort();
        labels.dedup();
        assert_eq!(labels.len(), 8, "every WriteState variant must have a unique label");
    }

    #[test]
    fn write_state_classes_partition_by_severity() {
        // green = success states
        assert_eq!(WriteState::Synced.class_name(), "badge green");
        assert_eq!(WriteState::Accepted.class_name(), "badge green");
        // blue = in-flight
        assert_eq!(WriteState::Optimistic.class_name(), "badge blue");
        assert_eq!(WriteState::Queued.class_name(), "badge blue");
        assert_eq!(WriteState::Submitted.class_name(), "badge blue");
        // red = hard reject
        assert_eq!(WriteState::SoftFailed.class_name(), "badge red");
        assert_eq!(WriteState::CasConflict.class_name(), "badge red");
        // amber = soft / requires moderation review
        assert_eq!(WriteState::Quarantined.class_name(), "badge amber");
    }

    #[test]
    fn write_state_parses_legacy_label_strings() {
        assert_eq!(parse_write_state("CAS conflict"), Some(WriteState::CasConflict));
        assert_eq!(parse_write_state("soft failed"), Some(WriteState::SoftFailed));
        assert_eq!(parse_write_state("synced"), Some(WriteState::Synced));
        assert_eq!(parse_write_state("garbage"), None);
    }
}
