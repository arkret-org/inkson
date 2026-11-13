//! Real Glory executor and memory renderer for retained presentation tests.
use std::rc::Rc;

use glory::core::executor::Executor;

use crate::presentation::{BootState, InksonContext, SharedStateStore};
pub(super) struct NativeHarness {
    pub(super) app: glory::ui::App,
    executor: Rc<Executor>,
}
impl NativeHarness {
    pub(super) fn new() -> Self {
        let executor = Rc::new(Executor::new(256));
        let app = glory::ui::App::with_host(executor.clone(), glory::render::memory::Memory::new);
        Self { app, executor }
    }
    pub(super) fn context(&self, path: std::path::PathBuf) -> Rc<InksonContext> {
        InksonContext::new(
            self.app.scope(),
            BootState {
                config_store: crate::config::LocalConfigStore::with_path(
                    path.with_extension("config.json"),
                ),
                config: crate::config::ClientConfig::default(),
                state_store: SharedStateStore::new(crate::state::LocalStateStore::with_path(path)),
                initial_credential: String::new(),
                realm_tree_nodes: vec![],
            },
            crate::routes::Route::Dashboard,
            |_| {
                Box::pin(async {
                    crate::runtime::session::CurrentSessionRefresh::retry_later(
                        "unused fixture refresh",
                    )
                })
            },
        )
    }
    pub(super) fn flush(&self) {
        for _ in 0..16 {
            for _ in 0..256 {
                if !self.executor.poll_one() {
                    break;
                }
            }
            self.app.flush().unwrap();
        }
    }
}
