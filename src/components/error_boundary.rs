//! P5 — recoverable error display + retry button.
//!
//! Unlike React's `componentDidCatch`-style error boundary, Dioxus does
//! not (yet) ship a built-in panic catcher per subtree. This component
//! is the user-facing wrapper for a fallible render: callers thread an
//! `Option<String>` error + an `on_retry` callback, and this component
//! renders either the inner `children` or a "Something went wrong"
//! panel with a retry affordance.
//!
//! Why split out the existing `ErrorBanner`:
//!   * `ErrorBanner` (in `components/mod.rs`) is a passive "here is what broke" banner. No retry,
//!     no request_id, no toast.
//!   * `RetryableError` adds the retry button + optional `request_id` so users can copy the soland
//!     trace ID into a bug report.
//!
//! The component is wired wherever a network-backed view can fail
//! (settings, recovery, agents). The `on_retry` closure usually
//! re-spawns the same fetch the panel was waiting on.

use dioxus::prelude::*;

#[derive(Clone, PartialEq, Props)]
pub struct RetryableErrorProps {
    /// User-facing error message. Should already be localized /
    /// human-readable; this component does not transform the string.
    pub message: String,
    /// Optional soland `x-contrix-request-id` for cross-log lookup.
    /// When present a "Copy ID" button is rendered alongside the
    /// message.
    #[props(default)]
    pub request_id: Option<String>,
    /// Retry callback. The button is hidden when this is `None` (some
    /// terminal errors aren't retryable).
    #[props(default)]
    pub on_retry: Option<EventHandler<MouseEvent>>,
    /// Optional `data-testid` override.
    #[props(default)]
    pub test_id: Option<String>,
}

#[component]
pub fn RetryableError(props: RetryableErrorProps) -> Element {
    let tid = props
        .test_id
        .unwrap_or_else(|| "retryable-error".to_owned());
    let request_id_full = props.request_id.clone().unwrap_or_default();
    let request_id_label = if request_id_full.is_empty() {
        String::new()
    } else {
        // Match `views::helpers::short_protocol_id` shortening style so
        // toasts stay compact.
        let n = request_id_full.len();
        if n > 12 {
            format!("{}…{}", &request_id_full[..6], &request_id_full[n - 4..])
        } else {
            request_id_full.clone()
        }
    };

    rsx! {
        div {
            class: "event error-banner retryable-error",
            "data-testid": "{tid}",
            role: "alert",
            "aria-live": "assertive",
            div { class: "event-head",
                span { "Something went wrong" }
                if !request_id_full.is_empty() {
                    span {
                        class: "mono",
                        title: "{request_id_full}",
                        "data-testid": "{tid}-request-id",
                        "request_id {request_id_label}"
                    }
                }
            }
            div { class: "muted", "{props.message}" }
            div { class: "actions",
                if let Some(on_retry) = props.on_retry {
                    button {
                        class: "primary",
                        "data-testid": "{tid}-retry",
                        "aria-label": "Retry",
                        onclick: move |evt| on_retry.call(evt),
                        "Retry"
                    }
                }
                if !request_id_full.is_empty() {
                    button {
                        class: "secondary",
                        "data-testid": "{tid}-copy-request-id",
                        "aria-label": "Copy request ID for bug report",
                        title: "{request_id_full}",
                        onclick: move |_| {
                            // Clipboard write is a best-effort hint;
                            // the actual write is delegated to the
                            // browser / native shell. TODO(P5-impl):
                            // wire to platform clipboard once the
                            // shared helper lands.
                            tracing::debug!(target: "yougen.ui", request_id = %request_id_full, "copy request_id requested");
                        },
                        "Copy ID"
                    }
                }
            }
        }
    }
}

/// Fallback wrapper: renders `children` if `error` is `None`, otherwise
/// renders the [`RetryableError`] panel. Lets callers keep the happy-
/// path render branchless.
#[derive(Clone, PartialEq, Props)]
pub struct ErrorBoundaryProps {
    pub error: Option<String>,
    #[props(default)]
    pub request_id: Option<String>,
    #[props(default)]
    pub on_retry: Option<EventHandler<MouseEvent>>,
    pub children: Element,
}

#[component]
pub fn ErrorBoundary(props: ErrorBoundaryProps) -> Element {
    if let Some(message) = props.error {
        rsx! {
            RetryableError {
                message: message,
                request_id: props.request_id,
                on_retry: props.on_retry,
                test_id: "error-boundary".to_owned(),
            }
        }
    } else {
        rsx! { {props.children} }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn short_request_id_pass_through() {
        // Match the inline shortening above so the formatter stays in
        // sync with `views::helpers::short_protocol_id`. The
        // component-level formatter does not import helpers to keep
        // the dependency direction one-way.
        let short = "abc123";
        let formatted = if short.len() > 12 {
            format!("{}…{}", &short[..6], &short[short.len() - 4..])
        } else {
            short.to_owned()
        };
        assert_eq!(formatted, "abc123");
    }

    #[test]
    fn long_request_id_is_shortened() {
        let long = "cx:request:01964137-0000-7000-8000-000000000010";
        let formatted = if long.len() > 12 {
            format!("{}…{}", &long[..6], &long[long.len() - 4..])
        } else {
            long.to_owned()
        };
        assert!(formatted.contains('…'));
        assert!(formatted.starts_with("cx:req"));
        assert!(formatted.ends_with("0010"));
    }
}
