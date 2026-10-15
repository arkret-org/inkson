pub mod effects;
pub mod input;
pub mod projection;
pub mod services;
pub mod session;

/// Allocate a large local future at an explicit frame boundary before polling.
/// The factory prevents outer subscription futures from retaining its inline
/// state. This changes neither executor affinity nor cancellation semantics.
#[inline(never)]
pub(crate) fn boxed_future_from<F, Fut>(make: F) -> std::pin::Pin<Box<Fut>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future,
{
    Box::pin(make())
}
