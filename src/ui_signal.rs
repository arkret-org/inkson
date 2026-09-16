use dioxus::prelude::{Signal, WritableExt};

/// Best-effort signal update for asynchronous UI tasks that may outlive the
/// component scope that created them.
pub(crate) fn try_set_signal<T: 'static, V: Into<T>>(mut signal: Signal<T>, value: V) {
    if let Ok(mut slot) = signal.try_write() {
        *slot = value.into();
    }
}
