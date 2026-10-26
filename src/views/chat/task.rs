//! Chat commands survive route presentation and stop at session retirement.
use std::future::{Future, poll_fn};
use std::rc::Rc;
use std::task::Poll;

pub(super) fn chat_task(
    context: Rc<crate::presentation::InksonContext>,
    future: impl Future<Output = ()> + 'static,
) {
    let Some(scope) = context.state_scope() else {
        return;
    };
    let generation = context.session_generation.get_untracked();
    let account = context.active_account.get_untracked();
    let revision = context.chat_state.revision();
    let key = crate::operation::uuid_v7();
    let finished = key.clone();
    let owner = context.clone();
    let mut future = Box::pin(future);
    if let Ok(task) = scope.spawn(poll_fn(move |cx| {
        if !owner.session_matches(generation, &account) || owner.chat_state.revision() != revision {
            owner.chat_state.finish(&finished);
            return Poll::Ready(());
        }
        match future.as_mut().poll(cx) {
            Poll::Ready(()) => {
                owner.chat_state.finish(&finished);
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    })) {
        context.chat_state.track(key, task);
    }
}

pub(super) fn dispatch(future: impl Future<Output = ()> + 'static) {
    if let Some(context) = crate::presentation::current_context() {
        chat_task(context, future);
    }
}
