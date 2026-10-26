//! Call work resumes only while its captured account and owner are current.
use std::future::Future;
use std::rc::Rc;
use std::task::Poll;

use crate::presentation::InksonContext;

pub(super) fn call_task(
    context: Rc<InksonContext>,
    owner: Option<glory::ui::WeakScope>,
    future: impl Future<Output = ()> + 'static,
) {
    let generation = context.session_generation.get_untracked();
    let account = context.active_account.get_untracked();
    let session = context.clone();
    let mut future = Box::pin(future);
    if let Err(error) = context.spawn(std::future::poll_fn(move |cx| {
        if !session.session_matches(generation, &account)
            || owner
                .as_ref()
                .is_some_and(|owner| owner.upgrade().is_none())
        {
            return Poll::Ready(());
        }
        future.as_mut().poll(cx)
    })) {
        tracing::warn!(%error,"call owner is unavailable");
    }
}
