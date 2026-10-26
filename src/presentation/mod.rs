//! Product presentation over Glory's owned runtime and Sapid's semantic controls.
mod context;
mod state_store;
pub mod widgets;

pub use context::{BootState, InksonContext};
pub use state_store::SharedStateStore;
pub use widgets::View;
pub mod host;
#[cfg(not(target_arch = "wasm32"))]
pub mod native_choice;
#[cfg(all(not(target_arch = "wasm32"), feature = "desktop"))]
pub(crate) mod native_images;

thread_local! {
    static CURRENT_HOST: std::cell::RefCell<std::rc::Weak<InksonContext>> = const { std::cell::RefCell::new(std::rc::Weak::new()) };
}

pub(crate) fn bind_current_host(context: &std::rc::Rc<InksonContext>) {
    CURRENT_HOST.with(|host| *host.borrow_mut() = std::rc::Rc::downgrade(context));
}

/// Capture host services before entering a domain operation. This registry does
/// not keep a window alive and never returns handles owned by a retired window.
pub(crate) fn current_context() -> Option<std::rc::Rc<InksonContext>> {
    CURRENT_HOST
        .with(|host| host.borrow().upgrade())
        .filter(|context| context.session_generation.is_alive())
}

pub(crate) fn require_current_context() -> anyhow::Result<std::rc::Rc<InksonContext>> {
    current_context().ok_or_else(|| anyhow::anyhow!("the application session owner is unavailable"))
}
