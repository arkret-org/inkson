//! Retain target-owned work while an authoritative current temporarily disappears.
use std::cell::RefCell;
use std::rc::Rc;

use glory::prelude::*;

use crate::presentation::View;

pub(crate) fn retained_discussion_host(
    ready: impl Into<Lotus<bool>>,
    render: impl Fn(&Scope, Cage<bool>) -> View + 'static,
) -> View {
    let ready = ready.into();
    let render = Rc::new(render);
    Box::new(group().fill(widget(move |scope| {
        let ready = ready.clone();
        let mounted = Rc::new(RefCell::new(None::<glory::ui::Mounted>));
        let available = scope.cage(glory::core::untracked(|| ready.get()));
        let weak = scope.downgrade();
        let render = render.clone();
        scope.retain(mounted.clone())?;
        scope.effect(move || {
            let current = ready.get();
            if available.get_untracked() != current {
                available.revise(|value| *value = current);
            }
            if !current || mounted.borrow().is_some() {
                return;
            }
            let Some(scope) = weak.upgrade() else { return };
            let render = render.clone();
            match scope.mount_with(|| widget(move |child| render(child, available).build(child))) {
                Ok(child) => *mounted.borrow_mut() = Some(child),
                Err(error) => scope.report_error(error),
            }
        });
        Ok(())
    })))
}

#[cfg(test)]
mod tests {
    fn host() -> (glory::App, Rc<glory::core::executor::Executor>) {
        let executor = Rc::new(glory::core::executor::Executor::new(256));
        let app = glory::App::with_host(executor.clone(), glory::render::memory::Memory::new);
        (app, executor)
    }
    fn settle(app: &glory::App, executor: &glory::core::executor::Executor) {
        for _ in 0..64 {
            executor.poll_one();
            app.flush().unwrap();
        }
    }
    use std::cell::Cell;

    use super::*;
    struct Pending(Rc<Cell<usize>>);
    impl std::future::Future for Pending {
        type Output = ();
        fn poll(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            std::task::Poll::Pending
        }
    }
    impl Drop for Pending {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    #[test]
    fn temporary_current_gap_keeps_draft_and_pending_owner() {
        let (app, executor) = host();
        let ready = app.scope().cage(false);
        let owners = Rc::new(Cell::new(0));
        let calls = owners.clone();
        let cancelled = Rc::new(Cell::new(0));
        let pending = cancelled.clone();
        let drafts = Rc::new(RefCell::new(None));
        let observed = drafts.clone();
        app.mount(retained_discussion_host(ready, move |scope, available| {
            calls.set(calls.get() + 1);
            let draft = scope.cage("unsent draft".to_owned());
            *observed.borrow_mut() = Some(draft);
            scope.spawn(Pending(pending.clone())).unwrap();
            crate::presentation::widgets::reactive_distinct(available, move |_, visible| {
                if visible {
                    Box::new(input().value(draft.get_untracked()))
                } else {
                    crate::presentation::widgets::empty()
                }
            })
        }))
        .unwrap();
        settle(&app, &executor);
        assert_eq!(owners.get(), 0);
        ready.revise(|value| *value = true);
        settle(&app, &executor);
        assert_eq!(owners.get(), 1);
        let draft = drafts.borrow().unwrap();
        draft.revise(|value| *value = "captured private draft".into());
        ready.revise(|value| *value = false);
        settle(&app, &executor);
        assert_eq!(cancelled.get(), 0);
        assert_eq!(draft.get_untracked(), "captured private draft");
        ready.revise(|value| *value = true);
        settle(&app, &executor);
        assert_eq!(owners.get(), 1);
        app.clear().unwrap();
        assert_eq!(cancelled.get(), 1);
        assert!(!draft.is_alive());
    }
}
