use std::cell::{Cell, RefCell};

use glory::render::{self, *};

use super::*;

#[derive(Default)]
struct Wire {
    applied: u64,
    requests: Vec<QueryToken>,
    replies: Vec<Input>,
}

struct DelayedHost {
    tree: glory::render::memory::Memory,
    wire: Rc<RefCell<Wire>>,
}

impl Render for DelayedHost {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            measure: true,
            ..Default::default()
        }
    }
    fn apply(&mut self, mutations: &[Mutation]) -> std::result::Result<Receipt, render::Error> {
        let receipt = self.tree.apply(mutations)?;
        self.wire.borrow_mut().applied = receipt.applied;
        Ok(receipt)
    }
    fn request(&mut self, _: Query, token: QueryToken) -> std::result::Result<(), render::Error> {
        self.wire.borrow_mut().requests.push(token);
        Ok(())
    }
    fn drain(&mut self, inputs: &mut Vec<Input>) {
        inputs.append(&mut self.wire.borrow_mut().replies);
    }
}

fn request(state: &ImageReadState, node: NodeId, calls: Rc<Cell<usize>>) -> QueryToken {
    let revision = state.begin();
    let completion = state.clone();
    let token = state
        .owner
        .upgrade()
        .unwrap()
        .request(Query::Bounds(node), move |_| {
            if completion.is_current(revision) {
                calls.set(calls.get() + 1);
                completion.finish(revision);
            }
        })
        .unwrap();
    state.request.revise(|value| *value = Some(token));
    token
}

#[test]
fn replacement_cancel_and_owner_retirement_revoke_real_pending_replies() {
    let wire = Rc::new(RefCell::new(Wire::default()));
    let host = wire.clone();
    let app = glory::App::new(move |runtime| DelayedHost {
        tree: glory::render::memory::Memory::new(runtime),
        wire: host,
    });
    app.mount(glory::ui::view()).unwrap();
    let node = app.tree().roots()[0];
    let scope = app.scope().child().unwrap();
    let starts = Rc::new(Cell::new(0));
    let started = starts.clone();
    let state = ImageReadState::new(&scope, scope.cage(false)).on_begin(move || {
        started.set(started.get() + 1);
    });
    let old_calls = Rc::new(Cell::new(0));
    let new_calls = Rc::new(Cell::new(0));
    let first = request(&state, node, old_calls.clone());
    app.flush().unwrap();
    assert!(state.reading.get_untracked());
    let second = request(&state, node, new_calls.clone());
    app.flush().unwrap();
    let applied = wire.borrow().applied;
    let reply = |token| Input::Response {
        token,
        applied,
        result: Err(render::Error::Unsupported(
            "controlled late host completion",
        )),
    };
    wire.borrow_mut()
        .replies
        .extend([reply(first), reply(second)]);
    app.pump().unwrap();
    assert_eq!(old_calls.get(), 0);
    assert_eq!(new_calls.get(), 1);
    assert!(!state.reading.get_untracked());
    let cancelled = request(&state, node, old_calls.clone());
    app.flush().unwrap();
    state.cancel();
    assert!(!state.reading.get_untracked());
    wire.borrow_mut().replies.push(reply(cancelled));
    app.pump().unwrap();
    assert_eq!(old_calls.get(), 0);
    let retired = request(&state, node, old_calls.clone());
    app.flush().unwrap();
    drop(scope);
    app.flush().unwrap();
    wire.borrow_mut().replies.push(reply(retired));
    app.pump().unwrap();
    assert_eq!(old_calls.get(), 0);
    assert!(!state.is_current(0));
    assert_eq!(wire.borrow().requests.len(), 4);
    assert_eq!(starts.get(), 4);
}
