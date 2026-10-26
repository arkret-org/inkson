//! One application-owned store, independent of any rendering scope.
use std::sync::{Arc, Mutex};

use tokio::sync::watch;

use crate::state::LocalStateStore;

pub struct SharedCell<T> {
    value: Arc<Mutex<T>>,
    revision: watch::Sender<u64>,
}

impl<T> Clone for SharedCell<T> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            revision: self.revision.clone(),
        }
    }
}

impl<T> SharedCell<T> {
    pub fn new(value: T) -> Self {
        let (revision, _) = watch::channel(0);
        Self {
            value: Arc::new(Mutex::new(value)),
            revision,
        }
    }

    /// The callback cannot return a guard or keep a store reference across await.
    #[expect(
        clippy::expect_used,
        reason = "poisoned owner state must not expose a partial authority mutation"
    )]
    pub fn read<R>(&self, read: impl FnOnce(&T) -> R) -> R {
        let value = self
            .value
            .lock()
            .expect("shared owner state is not poisoned");
        read(&value)
    }

    /// Publish only after the exclusive borrow ends, so observers may read it.
    #[expect(
        clippy::expect_used,
        reason = "poisoned owner state must not accept another authority mutation"
    )]
    pub fn write<R>(&self, write: impl FnOnce(&mut T) -> R) -> R {
        let result = {
            let mut value = self
                .value
                .lock()
                .expect("shared owner state is not poisoned");
            write(&mut value)
        };
        self.revision
            .send_modify(|revision| *revision = revision.wrapping_add(1));
        result
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.revision.subscribe()
    }

    pub fn revision(&self) -> u64 {
        *self.revision.borrow()
    }

    pub async fn stage_then_commit<S, D, R, E>(
        &self,
        stage: impl FnOnce(&mut T) -> Result<S, E>,
        durable: impl FnOnce(S) -> D,
        commit: impl FnOnce(&mut T, S) -> Result<R, E>,
    ) -> Result<R, E>
    where
        D: std::future::Future<Output = Result<S, E>>,
    {
        let plan = self.write(stage)?;
        let plan = durable(plan).await?;
        self.write(|value| commit(value, plan))
    }
}

pub type SharedStateStore = SharedCell<LocalStateStore>;

impl SharedStateStore {
    pub fn handle(&self) -> crate::runtime::input::StateStoreHandle {
        let reader = self.clone();
        let writer = self.clone();
        crate::runtime::input::StateStoreHandle::new(
            move |read| reader.read(read),
            move |write| writer.write(write),
        )
    }
}

pub(crate) struct SharedLocalStateBackend(pub SharedStateStore);

impl crate::client_core::LocalStateBackend for SharedLocalStateBackend {
    fn load_cursor(
        &self,
        scope: &garth::CursorScope,
    ) -> arkret_sdk::Result<Option<garth::OpaqueCursor>> {
        self.0.read(|store| store.load_client_cursor(scope))
    }
    fn save_cursor(
        &self,
        scope: &garth::CursorScope,
        cursor: garth::OpaqueCursor,
    ) -> arkret_sdk::Result<()> {
        self.0
            .write(|store| store.save_client_cursor(scope, cursor))
    }
    fn clear_cursor(&self, scope: &garth::CursorScope) -> arkret_sdk::Result<()> {
        self.0.write(|store| store.clear_client_cursor(scope))
    }
    fn load_account_checkpoint(
        &self,
        scope: &garth::CursorScope,
    ) -> arkret_sdk::Result<Option<garth::AccountCursorCheckpoint>> {
        self.0.read(|store| store.load_account_checkpoint(scope))
    }
    fn save_account_checkpoint(
        &self,
        scope: &garth::CursorScope,
        checkpoint: garth::AccountCursorCheckpoint,
    ) -> arkret_sdk::Result<()> {
        self.0
            .write(|store| store.save_account_checkpoint(scope, checkpoint))
    }
    fn restore_account_checkpoint(
        &self,
        scope: &garth::CursorScope,
        checkpoint: Option<garth::AccountCursorCheckpoint>,
    ) -> arkret_sdk::Result<()> {
        self.0
            .write(|store| store.restore_account_checkpoint(scope, checkpoint))
    }
    fn event_seen(&self, event_id: &arkret_sdk::EventId) -> arkret_sdk::Result<bool> {
        Ok(self
            .0
            .read(|store| store.client_core_event_seen(event_id.as_str())))
    }
    fn remember_event(&self, event_id: &arkret_sdk::EventId) -> arkret_sdk::Result<()> {
        self.0
            .write(|store| store.remember_client_core_event(event_id.as_str()));
        Ok(())
    }
    fn commit_delivery(
        &self,
        scope: garth::CursorScope,
        cursor: Option<garth::OpaqueCursor>,
        events: Vec<garth::ClientEvent>,
    ) -> arkret_sdk::Result<Option<garth::DeliveryId>> {
        self.0
            .write(|store| store.commit_client_delivery(scope, cursor, events))
    }
    fn pending_deliveries(
        &self,
        limit: usize,
    ) -> arkret_sdk::Result<Vec<garth::PendingDelivery<Vec<garth::ClientEvent>>>> {
        self.0.read(|store| store.pending_client_deliveries(limit))
    }
    fn ack_delivery(&self, id: garth::DeliveryId) -> arkret_sdk::Result<bool> {
        self.0.write(|store| store.ack_client_delivery(id))
    }
    fn retry_delivery(
        &self,
        id: garth::DeliveryId,
        next_attempt_at_ms: Option<i64>,
        error_class: garth::DeliveryErrorClass,
        error: String,
    ) -> arkret_sdk::Result<bool> {
        self.0
            .write(|store| store.retry_client_delivery(id, next_attempt_at_ms, error_class, error))
    }
    fn delivery_snapshot(
        &self,
        id: garth::DeliveryId,
    ) -> arkret_sdk::Result<Option<crate::state::StoredClientDelivery>> {
        Ok(self.0.read(|store| store.client_delivery_snapshot(id)))
    }
    fn restore_delivery(
        &self,
        delivery: crate::state::StoredClientDelivery,
    ) -> arkret_sdk::Result<()> {
        self.0
            .write(|store| store.restore_client_delivery(delivery))
    }
    fn rollback_delivery_commit(
        &self,
        scope: &garth::CursorScope,
        previous_cursor: Option<garth::OpaqueCursor>,
        delivery_id: Option<garth::DeliveryId>,
    ) -> arkret_sdk::Result<()> {
        self.0.write(|store| {
            store.rollback_client_delivery_commit(scope, previous_cursor, delivery_id)
        })
    }
    fn begin_durable_flush(&self) -> arkret_sdk::Result<crate::state::LocalStatePersistBarrier> {
        self.0.read(|store| {
            store
                .begin_durable_flush()
                .map_err(|error| arkret_sdk::Error::Protocol(error.to_string()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_partial_panicking_authority_mutation_is_never_exposed() {
        let state = SharedCell::new(vec![1]);
        let mutation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            state.write(|values| {
                values.push(2);
                panic!("authority update interrupted");
            });
        }));
        assert!(mutation.is_err());
        assert_eq!(state.revision(), 0);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| state.read(Clone::clone)))
                .is_err()
        );
    }

    #[test]
    fn clones_share_mutations_and_publish_after_the_borrow_ends() {
        let store = SharedCell::new(vec![1]);
        let other = store.clone();
        let observer = store.subscribe();
        other.write(|rows| rows.push(2));
        assert_eq!(store.read(Clone::clone), [1, 2]);
        assert_eq!(*observer.borrow(), 1);
        assert!(store.value.try_lock().is_ok());
    }

    #[tokio::test]
    async fn durable_stage_releases_the_borrow_before_await_and_commit() {
        let store = SharedCell::new(Vec::<u32>::new());
        let during_durable = store.clone();
        let value = store
            .stage_then_commit(
                |rows| {
                    rows.push(1);
                    Ok::<_, ()>(2)
                },
                move |plan| async move {
                    assert!(during_durable.value.try_lock().is_ok());
                    during_durable.write(|rows| rows.push(3));
                    Ok(plan)
                },
                |rows, plan| {
                    rows.push(plan);
                    Ok(rows.len())
                },
            )
            .await;
        assert_eq!(value, Ok(3));
        assert_eq!(store.read(Clone::clone), [1, 3, 2]);
    }
}
