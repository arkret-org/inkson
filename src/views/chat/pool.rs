//! Window-owned drafts and explicitly retired session work.
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use glory::Scope;
use glory::prelude::Cage;

use super::controller::{CachedChatController, CommonTarget, ComposerState, ComposerTarget};

pub struct ChatStatePool {
    scope: glory::ui::WeakScope,
    pub(super) drafts: Cage<BTreeMap<ComposerTarget, ComposerState>>,
    pub(super) last_seen: Cage<BTreeMap<ComposerTarget, (u64, String)>>,
    pub(super) pending:
        Cage<BTreeMap<ComposerTarget, (u64, String, crate::state::E2eeCacheWriteIntent)>>,
    pub(super) running: Cage<bool>,
    pub(super) controllers: RefCell<BTreeMap<CommonTarget, CachedChatController>>,
    installed: Cell<bool>,
    tasks: RefCell<BTreeMap<String, glory::core::TaskToken>>,
    revision: Cell<u64>,
}
impl ChatStatePool {
    pub fn new(scope: &Scope) -> Self {
        Self {
            scope: scope.downgrade(),
            drafts: scope.cage(BTreeMap::new()),
            last_seen: scope.cage(BTreeMap::new()),
            pending: scope.cage(BTreeMap::new()),
            running: scope.cage(false),
            controllers: RefCell::new(BTreeMap::new()),
            installed: Cell::new(false),
            tasks: RefCell::new(BTreeMap::new()),
            revision: Cell::new(0),
        }
    }
    pub fn revision(&self) -> u64 {
        self.revision.get()
    }
    pub fn retire_session(&self) {
        self.revision.set(self.revision.get().wrapping_add(1));
        for (_, task) in std::mem::take(&mut *self.tasks.borrow_mut()) {
            task.cancel();
        }
        let controllers = self
            .controllers
            .borrow()
            .values()
            .copied()
            .collect::<Vec<_>>();
        for cached in controllers {
            cached.controller.retire_common_session();
        }
        self.pending.revise(BTreeMap::clear);
        self.running.revise(|value| *value = false);
        for state in self.drafts.get_untracked().values() {
            state
                .attachment_upload_revision
                .revise(|value| *value = value.wrapping_add(1));
            state
                .attachment_target_revision
                .revise(|value| *value = value.wrapping_add(1));
            state.compose_dragover.revise(|value| *value = false);
            state
                .moderation_report_pending
                .revise(|value| *value = false);
        }
    }
    pub(super) fn install(&self, context: &Rc<crate::presentation::InksonContext>) {
        if self.installed.replace(true) {
            return;
        }
        if let Some(scope) = self.scope.upgrade() {
            super::controller::install_composer_persistence(&scope, Rc::downgrade(context));
        }
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
