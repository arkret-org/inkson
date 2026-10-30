//! Account-store adapter for the shared checkpoint installation engine.

use garth::mls::checkpoint_port::{MlsCheckpointInstall, MlsCheckpointPort, MlsCheckpointStage};

use crate::runtime::input::StateStoreHandle;
use crate::state::{LocalStatePersistBarrier, LocalStateStore};

pub(super) struct CheckpointPort<'a, F> {
    pub state: &'a StateStoreHandle,
    pub guard: F,
}

pub(super) struct StagedCheckpoint<'a> {
    state: &'a StateStoreHandle,
    account: Option<arkret_sdk::AccountId>,
    generation: u64,
    session_epoch: u64,
    barrier: Option<LocalStatePersistBarrier>,
}

fn error(error: impl std::fmt::Display) -> garth::Error {
    garth::Error::Protocol(error.to_string())
}

impl<'a, F> MlsCheckpointPort for CheckpointPort<'a, F>
where
    F: FnOnce(&LocalStateStore) -> Result<(), String> + garth::MaybeSend,
{
    type Staged = StagedCheckpoint<'a>;

    fn stage(self, install: MlsCheckpointInstall) -> garth::Result<Self::Staged> {
        let (account, generation, session_epoch, barrier) = self
            .state
            .write(|store| {
                (self.guard)(store)?;
                let account = store.active_authority();
                let generation = store.current_generation();
                let session_epoch = crate::identity::device_directory::cache_epoch();
                let barrier = match &install.consume {
                    Some(consume) => store.install_accepted_mls_welcome(
                        &install.scope,
                        install.checkpoint,
                        &install.accepted_event_id,
                        consume,
                    ),
                    None => store.install_accepted_mls_transition(
                        &install.scope,
                        install.checkpoint,
                        &install.accepted_event_id,
                    ),
                }?;
                Ok::<_, String>((account, generation, session_epoch, barrier))
            })
            .map_err(error)?;
        Ok(StagedCheckpoint {
            state: self.state,
            account,
            generation,
            session_epoch,
            barrier: Some(barrier),
        })
    }
}

impl StagedCheckpoint<'_> {
    fn same_session(&self, store: &LocalStateStore) -> bool {
        store.active_authority() == self.account
            && store.current_generation() == self.generation
            && crate::identity::device_directory::cache_epoch() == self.session_epoch
    }
}

impl MlsCheckpointStage for StagedCheckpoint<'_> {
    async fn make_durable(&mut self) -> garth::Result<()> {
        self.barrier
            .take()
            .ok_or_else(|| error("checkpoint durability already consumed"))?
            .wait()
            .await
            .map_err(error)
    }

    fn publish(self) -> garth::Result<()> {
        self.state.write(|store| {
            if !self.same_session(store) {
                return Err(error(
                    "MLS checkpoint completion belongs to a replaced session",
                ));
            }
            Ok(())
        })
    }
}

pub(crate) async fn read_durable_checkpoint(
    state: &StateStoreHandle,
    scope: &arkret_sdk::ScopeRef,
) -> anyhow::Result<Option<garth::mls::checkpoint::MlsLocalCheckpointEnvelope>> {
    let mut read = state.read(LocalStateStore::capture_committed_account_read)?;
    for _ in 0..COMMITTED_READ_ATTEMPTS {
        let checkpoint = read.checkpoint_for_scope(scope).await;
        let changed = checkpoint
            .as_ref()
            .err()
            .is_some_and(crate::state::CommittedAccountRead::root_changed);
        if let Some(next) = next_committed_read(state, &read, changed)? {
            read = next;
            continue;
        }
        return checkpoint;
    }
    anyhow::bail!("MLS checkpoint repeatedly changed during committed read")
}

pub(crate) async fn read_durable_consumes(
    state: &StateStoreHandle,
) -> anyhow::Result<Vec<(String, arkret_sdk::KeyPackagesConsumeRequestBody)>> {
    let mut read = state.read(LocalStateStore::capture_committed_account_read)?;
    for _ in 0..COMMITTED_READ_ATTEMPTS {
        let consumes = read.pending_consumes().await;
        let changed = consumes
            .as_ref()
            .err()
            .is_some_and(crate::state::CommittedAccountRead::root_changed);
        if let Some(next) = next_committed_read(state, &read, changed)? {
            read = next;
            continue;
        }
        return consumes;
    }
    anyhow::bail!("MLS consumes repeatedly changed during committed read")
}

const COMMITTED_READ_ATTEMPTS: usize = 4;

fn next_committed_read(
    state: &StateStoreHandle,
    read: &crate::state::CommittedAccountRead,
    root_changed: bool,
) -> anyhow::Result<Option<crate::state::CommittedAccountRead>> {
    state.read(|store| {
        anyhow::ensure!(
            read.same_session(store),
            "MLS committed read belongs to a replaced session"
        );
        if !root_changed && read.matches(store) {
            // A stable-root error remains an error, including corrupt or
            // replayed records. Only a wholly superseded read is discarded.
            Ok(None)
        } else {
            Ok(Some(store.capture_committed_account_read()?))
        }
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;

// Dropping an installer does not revoke an accepted MLS transition. Its exact
// checkpoint/consume tuple stays recoverable; consumers read durable state and
// re-establish a barrier before sending an owed command.

/// Integration-test access to the production browser adapter and storage path.
#[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
pub mod wasm_harness {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    pub struct CheckpointHarness {
        state: StateStoreHandle,
    }

    impl Default for CheckpointHarness {
        fn default() -> Self {
            let store = Rc::new(RefCell::new(LocalStateStore::default()));
            let read = store.clone();
            Self {
                state: StateStoreHandle::new(
                    move |callback| callback(&read.borrow()),
                    move |callback| callback(&mut store.borrow_mut()),
                ),
            }
        }
    }

    impl CheckpointHarness {
        pub async fn install(
            &self,
            scope: &str,
            checkpoint: &str,
            accepted_event_id: &str,
        ) -> Result<(), String> {
            garth::mls::checkpoint_port::install_checkpoint(
                CheckpointPort {
                    state: &self.state,
                    guard: |_: &LocalStateStore| Ok(()),
                },
                MlsCheckpointInstall {
                    scope: serde_json::from_str(scope).map_err(|error| error.to_string())?,
                    checkpoint: serde_json::from_str(checkpoint)
                        .map_err(|error| error.to_string())?,
                    accepted_event_id: arkret_sdk::EventId::new(accepted_event_id)
                        .map_err(|error| error.to_string())?,
                    consume: None,
                },
            )
            .await
            .map_err(|error| error.to_string())
        }

        pub fn checkpoint(&self, scope: &str) -> Result<Option<String>, String> {
            let scope = serde_json::from_str(scope).map_err(|error| error.to_string())?;
            self.state
                .read(|store| store.mls_checkpoint_for_scope(&scope))
                .map(|checkpoint| {
                    serde_json::to_string(&checkpoint).map_err(|error| error.to_string())
                })
                .transpose()
        }
    }
}
