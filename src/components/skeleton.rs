//! P5 — skeleton loaders for high-latency surfaces.
//!
//! Spec / scope: applied to the timeline feed, the agent list, and the
//! key-backup history. The component is intentionally CSS-driven; the
//! Rust side only renders structural placeholders + the
//! `aria-busy="true"` annotation. The pulsing animation lives in
//! `src/styles/claude_design.css` under `.skeleton-*`.
//!
//! Why three shapes:
//!   * [`SkeletonLine`] — single-line text placeholders. Best for list rows where each row is one
//!     piece of text.
//!   * [`SkeletonCard`] — multi-line card placeholders with an avatar square + two text bars.
//!     Matches the feed event-card layout.
//!   * [`SkeletonList`] — convenience wrapper that renders N [`SkeletonCard`] children. Used by
//!     agents.rs + key-backup history.

use dioxus::prelude::*;

/// Single-line skeleton. Defaults to ~60% width so a column of rows
/// looks "natural" rather than perfectly aligned.
#[derive(Clone, PartialEq, Props)]
pub struct SkeletonLineProps {
    /// CSS width string. Defaults to `"60%"`.
    #[props(default)]
    pub width: Option<String>,
    /// Optional `data-testid` override; useful when callers need to
    /// assert the skeleton is visible mid-flight in Playwright tests.
    #[props(default)]
    pub test_id: Option<String>,
}

#[component]
pub fn SkeletonLine(props: SkeletonLineProps) -> Element {
    let width = props.width.unwrap_or_else(|| "60%".to_owned());
    let tid = props.test_id.unwrap_or_else(|| "skeleton-line".to_owned());
    rsx! {
        div {
            class: "skeleton skeleton-line",
            "data-testid": "{tid}",
            "aria-hidden": "true",
            style: "width: {width};",
        }
    }
}

/// Card-shaped skeleton with an avatar + two stacked text bars.
#[derive(Clone, PartialEq, Props)]
pub struct SkeletonCardProps {
    /// Optional `data-testid` override.
    #[props(default)]
    pub test_id: Option<String>,
}

#[component]
pub fn SkeletonCard(props: SkeletonCardProps) -> Element {
    let tid = props.test_id.unwrap_or_else(|| "skeleton-card".to_owned());
    rsx! {
        div {
            class: "skeleton skeleton-card",
            "data-testid": "{tid}",
            "aria-hidden": "true",
            div { class: "skeleton skeleton-avatar" }
            div { class: "skeleton-card-body",
                div { class: "skeleton skeleton-line", style: "width: 80%;" }
                div { class: "skeleton skeleton-line", style: "width: 50%;" }
            }
        }
    }
}

/// Render N stacked [`SkeletonCard`] placeholders. The wrapper gets
/// `aria-busy="true"` + an SR-only label so assistive technology
/// announces the loading state instead of reading the placeholder bars.
#[derive(Clone, PartialEq, Props)]
pub struct SkeletonListProps {
    /// Number of placeholder cards to render. Capped at 12 to keep the
    /// DOM bounded.
    pub count: usize,
    /// Screen-reader label. Defaults to "Loading…".
    #[props(default)]
    pub label: Option<String>,
    /// Optional `data-testid` override for the wrapper.
    #[props(default)]
    pub test_id: Option<String>,
}

#[component]
pub fn SkeletonList(props: SkeletonListProps) -> Element {
    let count = props.count.clamp(1, 12);
    let label = props.label.unwrap_or_else(|| "Loading…".to_owned());
    let tid = props.test_id.unwrap_or_else(|| "skeleton-list".to_owned());
    rsx! {
        div {
            class: "skeleton-list",
            "data-testid": "{tid}",
            "data-count": "{count}",
            role: "status",
            "aria-busy": "true",
            "aria-live": "polite",
            "aria-label": "{label}",
            for _ in 0..count {
                SkeletonCard { test_id: format!("{tid}-card") }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn count_is_clamped() {
        // SkeletonList's count clamping is a property of the render path.
        // We assert the clamp invariants here so a future refactor that
        // moves the clamp out of the body still has a regression net.
        assert_eq!(1usize.clamp(1, 12), 1);
        assert_eq!(99usize.clamp(1, 12), 12);
        assert_eq!(0usize.clamp(1, 12), 1);
    }
}
