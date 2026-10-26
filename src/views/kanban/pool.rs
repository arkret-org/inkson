//! Typed account/realm/board state retained by the application window.
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use glory::Scope;

use super::controller::KanbanController;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct KanbanTarget {
    pub authority: arkret_sdk::AccountId,
    pub device: arkret_sdk::DeviceId,
    pub realm: arkret_sdk::RealmId,
    pub board: Option<arkret_sdk::SpaceId>,
}
pub struct KanbanStatePool {
    scope: glory::ui::WeakScope,
    boards: RefCell<BTreeMap<KanbanTarget, KanbanController>>,
    tasks: RefCell<BTreeMap<String, glory::core::TaskToken>>,
    revision: Cell<u64>,
}
impl KanbanStatePool {
    pub fn new(scope: &Scope) -> Self {
        Self {
            scope: scope.downgrade(),
            boards: RefCell::new(BTreeMap::new()),
            tasks: RefCell::new(BTreeMap::new()),
            revision: Cell::new(0),
        }
    }
    pub fn revision(&self) -> u64 {
        self.revision.get()
    }
    pub fn retire_session(&self) {
        for state in self.boards.borrow().values() {
            state.retire_session();
        }
        self.boards.borrow_mut().clear();
        self.revision.set(self.revision.get().wrapping_add(1));
        for (_, task) in std::mem::take(&mut *self.tasks.borrow_mut()) {
            task.cancel();
        }
    }
    pub(super) fn board(
        &self,
        target: KanbanTarget,
        create: impl FnOnce(&Scope) -> KanbanController,
    ) -> Option<KanbanController> {
        if let Some(state) = self.boards.borrow().get(&target).copied() {
            return Some(state);
        }
        let scope = self.scope.upgrade()?;
        let mut state = create(&scope);
        // Spaces and Strands are Realm-wide display inventory. Board/card
        // navigation may replace the page, but must retain its completed reads
        // and their rows together. Full Station/profile/session changes still
        // reset this owner through InventoryScope in mount_effects.
        if let Some(existing) = self.boards.borrow().iter().find_map(|(key, state)| {
            (key.authority == target.authority
                && key.device == target.device
                && key.realm == target.realm)
                .then_some(*state)
        }) {
            state.inventory_owner = existing.inventory_owner;
            state.lifecycle_container_projection = existing.lifecycle_container_projection;
            state.lifecycle_strand_projection = existing.lifecycle_strand_projection;
        }
        self.boards.borrow_mut().insert(target, state);
        Some(state)
    }
    pub(super) fn track(&self, key: String, task: glory::core::TaskToken) {
        if let Some(previous) = self.tasks.borrow_mut().insert(key, task) {
            previous.cancel();
        }
    }
    pub(super) fn finish(&self, key: &str) {
        self.tasks.borrow_mut().remove(key);
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::*;
    use crate::routes::Route;
    use crate::views::kanban::controller::new_kanban_controller;
    use crate::views::kanban::projection_reads::ProjectionReadSet;

    #[test]
    fn realm_inventory_survives_board_routes_but_not_session_retirement() {
        let executor = Rc::new(glory::core::executor::Executor::new(256));
        let app = glory::ui::App::with_host(executor, glory::render::memory::Memory::new);
        let pool = KanbanStatePool::new(app.scope());
        let target = KanbanTarget {
            authority: crate::test_support::authority("ak:did_core:web:alice.example"),
            device: crate::test_support::device_id(
                "ak:device:01904100-0000-7000-8000-000000000904",
            ),
            realm: arkret_sdk::RealmId::new(
                "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
            )
            .unwrap(),
            board: None,
        };
        let first = pool
            .board(target.clone(), |scope| {
                new_kanban_controller(scope, &Route::Kanban, vec![], None)
            })
            .unwrap();
        let owner = first.inventory_owner.get_untracked();
        owner.borrow_mut().set_scope(Some((
            "https://station.example".into(),
            target.realm.to_string(),
            1,
            Some((
                "alice-profile".into(),
                target.authority.clone(),
                target.device.clone(),
                url::Url::parse("https://station.example").unwrap(),
            )),
        )));
        owner.borrow_mut().cover(ProjectionReadSet::all());
        let next_target = KanbanTarget {
            board: Some(
                arkret_sdk::SpaceId::new("ak:space:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk")
                    .unwrap(),
            ),
            ..target.clone()
        };
        let second = pool
            .board(next_target.clone(), |scope| {
                new_kanban_controller(scope, &Route::Kanban, vec![], next_target.board.clone())
            })
            .unwrap();
        assert!(Rc::ptr_eq(&owner, &second.inventory_owner.get_untracked()));
        assert!(
            !second
                .inventory_owner
                .get_untracked()
                .borrow()
                .missing()
                .any()
        );
        let containers_version = second.lifecycle_container_projection.try_version().unwrap();
        let strands_version = second.lifecycle_strand_projection.try_version().unwrap();
        first.lifecycle_container_projection.revise(Vec::clear);
        first.lifecycle_strand_projection.revise(Vec::clear);
        assert_eq!(
            second.lifecycle_container_projection.try_version().unwrap(),
            containers_version + 1
        );
        assert_eq!(
            second.lifecycle_strand_projection.try_version().unwrap(),
            strands_version + 1
        );
        let foreign = KanbanTarget {
            authority: crate::test_support::authority("ak:did_core:web:bob.example"),
            ..target.clone()
        };
        let other = pool
            .board(foreign, |scope| {
                new_kanban_controller(scope, &Route::Kanban, vec![], None)
            })
            .unwrap();
        assert!(!Rc::ptr_eq(&owner, &other.inventory_owner.get_untracked()));
        assert_eq!(
            other.inventory_owner.get_untracked().borrow().missing(),
            ProjectionReadSet::all()
        );
        pool.retire_session();
        assert_eq!(owner.borrow().missing(), ProjectionReadSet::all());
        let replacement = pool
            .board(target, |scope| {
                new_kanban_controller(scope, &Route::Kanban, vec![], None)
            })
            .unwrap();
        assert!(!Rc::ptr_eq(
            &owner,
            &replacement.inventory_owner.get_untracked()
        ));
    }
}
