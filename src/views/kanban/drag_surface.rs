use std::cell::{Cell, RefCell};

use glory::render::{DragPhase, Event, NodeId, Query, QueryValue, Rect};

use super::*;
#[derive(Clone)]
pub(super) enum DragSubject {
    Board(arkret_sdk::SpaceId),
    Card(DraggedCard),
    Column(DraggedColumn),
}
#[derive(Clone)]
enum Landing {
    Board {
        id: arkret_sdk::SpaceId,
        after: bool,
    },
    Column {
        column: String,
        tail: Option<String>,
    },
    Card {
        column: String,
        previous: Option<String>,
        next: String,
    },
}
#[derive(Clone)]
struct Target {
    node: Cage<Option<NodeId>>,
    landing: Landing,
}
pub(super) struct BoardDrag {
    board: Board,
    owner: glory::ui::WeakScope,
    targets: RefCell<Vec<std::rc::Weak<Target>>>,
    rects: RefCell<Vec<(Landing, Rect)>>,
    subject: RefCell<Option<(DragSubject, Option<arkret_sdk::SpaceId>)>>,
    pub(super) board_target: Cage<Option<(arkret_sdk::SpaceId, bool)>>,
    remaining: Cell<usize>,
    ticket: Cell<u64>,
    pending_drop: Cell<Option<(f64, f64)>>,
}
impl BoardDrag {
    pub(super) fn new(scope: &Scope, board: Board) -> Rc<Self> {
        Rc::new(Self {
            board,
            owner: scope.downgrade(),
            targets: RefCell::new(vec![]),
            rects: RefCell::new(vec![]),
            subject: RefCell::new(None),
            board_target: scope.cage(None),
            remaining: Cell::new(0),
            ticket: Cell::new(0),
            pending_drop: Cell::new(None),
        })
    }
    fn register(self: &Rc<Self>, scope: &Scope, target: Target) {
        let target = Rc::new(target);
        self.targets
            .borrow_mut()
            .retain(|value| value.strong_count() > 0);
        self.targets.borrow_mut().push(Rc::downgrade(&target));
        let owner = Rc::downgrade(self);
        let _ = scope.on_cleanup(move || {
            drop(target);
            if let Some(owner) = owner.upgrade() {
                owner
                    .targets
                    .borrow_mut()
                    .retain(|value| value.strong_count() > 0);
                owner.ticket.set(owner.ticket.get().wrapping_add(1));
                owner.rects.borrow_mut().clear();
                if owner.owner.upgrade().is_some() {
                    owner.clear();
                }
            }
        });
    }
    pub(super) fn board_row(
        self: &Rc<Self>,
        scope: &Scope,
        node: Cage<Option<NodeId>>,
        id: arkret_sdk::SpaceId,
    ) {
        self.register(
            scope,
            Target {
                node,
                landing: Landing::Board { id, after: false },
            },
        );
    }
    pub(super) fn column(
        self: &Rc<Self>,
        scope: &Scope,
        node: Cage<Option<NodeId>>,
        column: &KanbanColumn,
    ) {
        self.register(
            scope,
            Target {
                node,
                landing: Landing::Column {
                    column: column.id.clone(),
                    tail: column
                        .cards
                        .iter()
                        .rfind(|card| card.lifecycle == StrandLifecycleState::Active)
                        .map(|card| card.rank.clone()),
                },
            },
        );
    }
    pub(super) fn card(
        self: &Rc<Self>,
        scope: &Scope,
        node: Cage<Option<NodeId>>,
        column: &str,
        previous: Option<String>,
        card: &KanbanCard,
    ) {
        self.register(
            scope,
            Target {
                node,
                landing: Landing::Card {
                    column: column.into(),
                    previous,
                    next: card.rank.clone(),
                },
            },
        );
    }
    fn hit(&self, x: f64, y: f64) -> Option<Landing> {
        let rects = self.rects.borrow();
        rects
            .iter()
            .filter(|(_, rect)| {
                x >= rect.x && x <= rect.x + rect.width && y >= rect.y && y <= rect.y + rect.height
            })
            .min_by_key(|(target, _)| match target {
                Landing::Board { .. } | Landing::Card { .. } => 0,
                Landing::Column { .. } => 1,
            })
            .map(|(target, rect)| match target {
                Landing::Board { id, .. } => Landing::Board {
                    id: id.clone(),
                    after: y >= rect.y + rect.height / 2.0,
                },
                other => other.clone(),
            })
    }
    fn clear(&self) {
        self.subject.borrow_mut().take();
        if self.board_target.is_alive() && self.board_target.get_untracked().is_some() {
            self.board_target.revise(|target| *target = None);
        }
        self.pending_drop.set(None);
        let c = self.board.controller;
        c.dragging_card.revise(|v| *v = None);
        c.dragging_column.revise(|v| *v = None);
        c.drop_target_column.revise(|v| *v = None);
    }
    fn finish(&self, x: f64, y: f64) {
        if self.owner.upgrade().is_none() {
            self.clear();
            return;
        }
        let Some((subject, board_id)) = self.subject.borrow_mut().take() else {
            return;
        };
        if self.board.controller.selected_board.get_untracked() != board_id {
            self.clear();
            return;
        }
        let target = self.hit(x, y);
        self.clear();
        let Some(target) = target else {
            return;
        };
        match subject {
            DragSubject::Board(id) => {
                if let Landing::Board { id: target, after } = target {
                    self.board.move_board(&id, &target, after);
                }
            }
            DragSubject::Card(card) => {
                let Some(board_id) = board_id else {
                    return;
                };
                let (column, neighbours) = match target {
                    Landing::Board { .. } => return,
                    Landing::Card {
                        column,
                        previous,
                        next,
                    } => (
                        column,
                        ColumnNeighbours {
                            prev_rank: previous,
                            next_rank: Some(next),
                        },
                    ),
                    Landing::Column { column, tail } => (
                        column,
                        ColumnNeighbours {
                            prev_rank: tail,
                            next_rank: None,
                        },
                    ),
                };
                dispatch_strand_position_move(
                    self.board.app.clone(),
                    self.board.app.base_url.get_untracked(),
                    self.board.app.token,
                    self.board.realm.clone(),
                    board_id.to_string(),
                    self.board.principal.to_string(),
                    card,
                    column,
                    neighbours,
                    self.board.app.state_store.clone(),
                    self.board.controller.board_status,
                );
            }
            DragSubject::Column(column) => {
                let target = match target {
                    Landing::Board { .. } => return,
                    Landing::Card { column, .. } | Landing::Column { column, .. } => column,
                };
                let mut columns = self.board.columns.get_untracked();
                if reorder_column_before(&mut columns, &column.column_id, &target) {
                    submit_column_order_updates(
                        self.board.app.clone(),
                        self.board.app.base_url.get_untracked(),
                        self.board.app.token,
                        self.board.realm.clone(),
                        self.board.principal.to_string(),
                        columns,
                        self.board.security.get_untracked(),
                        self.board.app.state_store.clone(),
                        self.board.controller.board_status,
                    );
                }
            }
        }
    }
    pub(super) fn event(self: &Rc<Self>, event: Event, subject: DragSubject) {
        let Event::Drag { phase, x, y, .. } = event else {
            return;
        };
        match phase {
            DragPhase::Start => {
                let Some(scope) = self.owner.upgrade() else {
                    return;
                };
                self.clear();
                self.rects.borrow_mut().clear();
                self.ticket.set(self.ticket.get().wrapping_add(1));
                let ticket = self.ticket.get();
                *self.subject.borrow_mut() = Some((
                    subject.clone(),
                    self.board.controller.selected_board.get_untracked(),
                ));
                match subject {
                    DragSubject::Board(_) => {}
                    DragSubject::Card(card) => self
                        .board
                        .controller
                        .dragging_card
                        .revise(|value| *value = Some(card)),
                    DragSubject::Column(column) => self
                        .board
                        .controller
                        .dragging_column
                        .revise(|value| *value = Some(column)),
                };
                let targets = self
                    .targets
                    .borrow()
                    .iter()
                    .filter_map(std::rc::Weak::upgrade)
                    .filter_map(|target| {
                        target
                            .node
                            .get_untracked()
                            .map(|node| (node, target.landing.clone()))
                    })
                    .collect::<Vec<_>>();
                self.remaining.set(targets.len());
                for (node, landing) in targets {
                    let state = self.clone();
                    let result = scope.request(Query::Bounds(node), move |result| {
                        if state.ticket.get() != ticket || state.owner.upgrade().is_none() {
                            return;
                        }
                        if let Ok(QueryValue::Bounds(rect)) = result {
                            state.rects.borrow_mut().push((landing.clone(), rect));
                        }
                        state.remaining.set(state.remaining.get().saturating_sub(1));
                        if state.remaining.get() == 0
                            && let Some((x, y)) = state.pending_drop.take()
                        {
                            state.finish(x, y);
                        }
                    });
                    if result.is_err() {
                        self.remaining.set(self.remaining.get().saturating_sub(1));
                    }
                }
            }
            DragPhase::Move => {
                let landing = self.hit(x, y);
                if matches!(subject, DragSubject::Board(_)) {
                    let target = landing.and_then(|landing| match landing {
                        Landing::Board { id, after } => Some((id, after)),
                        _ => None,
                    });
                    if target != self.board_target.get_untracked() {
                        self.board_target.revise(|value| *value = target);
                    }
                    return;
                }
                let column = landing.and_then(|target| match target {
                    Landing::Board { .. } => None,
                    Landing::Card { column, .. } | Landing::Column { column, .. } => Some(column),
                });
                if self.board.controller.drop_target_column.get_untracked() != column {
                    self.board
                        .controller
                        .drop_target_column
                        .revise(|value| *value = column);
                }
            }
            DragPhase::Drop => {
                if self.remaining.get() > 0 {
                    self.pending_drop.set(Some((x, y)));
                } else {
                    self.finish(x, y);
                }
            }
            DragPhase::Cancel => {
                self.ticket.set(self.ticket.get().wrapping_add(1));
                self.clear();
            }
        }
    }
}
