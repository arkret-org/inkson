use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::Notify;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum EffectOwner {
    Account(String),
    Realm { account: String, realm: String },
    Route(String),
    Session,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EffectKey {
    pub owner: EffectOwner,
    pub name: String,
    pub generation: u64,
}

#[derive(Debug)]
struct EffectState {
    cancelled: AtomicBool,
    finished: AtomicBool,
    finished_notify: Notify,
}

#[derive(Clone, Debug)]
pub struct EffectHandle {
    key: EffectKey,
    state: Arc<EffectState>,
}

impl EffectHandle {
    fn new(key: EffectKey) -> Self {
        Self {
            key,
            state: Arc::new(EffectState {
                cancelled: AtomicBool::new(false),
                finished: AtomicBool::new(false),
                finished_notify: Notify::new(),
            }),
        }
    }

    pub fn key(&self) -> &EffectKey {
        &self.key
    }

    pub fn cancel(&self) {
        self.state.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }

    pub fn finish(&self) {
        if !self.state.finished.swap(true, Ordering::AcqRel) {
            self.state.finished_notify.notify_waiters();
        }
    }

    pub async fn wait_finished(&self) {
        while !self.state.finished.load(Ordering::Acquire) {
            self.state.finished_notify.notified().await;
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct EffectRegistry {
    effects: Arc<Mutex<HashMap<EffectKey, EffectHandle>>>,
}

impl EffectRegistry {
    pub fn register(&self, key: EffectKey) -> EffectHandle {
        let mut effects = self.effects.lock().unwrap_or_else(PoisonError::into_inner);
        let replaced = effects
            .keys()
            .filter(|candidate| candidate.owner == key.owner && candidate.name == key.name)
            .cloned()
            .collect::<Vec<_>>();
        for replaced_key in replaced {
            if let Some(previous) = effects.remove(&replaced_key) {
                previous.cancel();
            }
        }
        let handle = EffectHandle::new(key.clone());
        effects.insert(key, handle.clone());
        handle
    }

    pub async fn cancel_where(&self, predicate: impl Fn(&EffectKey) -> bool) {
        let handles = {
            let mut effects = self.effects.lock().unwrap_or_else(PoisonError::into_inner);
            let keys = effects
                .keys()
                .filter(|key| predicate(key))
                .cloned()
                .collect::<Vec<_>>();
            keys.into_iter()
                .filter_map(|key| effects.remove(&key))
                .collect::<Vec<_>>()
        };
        for handle in &handles {
            handle.cancel();
        }
        for handle in handles {
            handle.wait_finished().await;
        }
    }

    pub async fn cancel_all(&self) {
        self.cancel_where(|_| true).await;
    }

    pub fn complete(&self, handle: &EffectHandle) {
        handle.finish();
        let mut effects = self.effects.lock().unwrap_or_else(PoisonError::into_inner);
        if effects
            .get(handle.key())
            .is_some_and(|registered| Arc::ptr_eq(&registered.state, &handle.state))
        {
            effects.remove(handle.key());
        }
    }

    pub fn request_cancel_all(&self) {
        let effects = self.effects.lock().unwrap_or_else(PoisonError::into_inner);
        for handle in effects.values() {
            handle.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancellation_waits_for_effect_cleanup() {
        let registry = EffectRegistry::default();
        let handle = registry.register(EffectKey {
            owner: EffectOwner::Session,
            name: "sync".to_owned(),
            generation: 1,
        });
        let worker = handle.clone();
        tokio::spawn(async move {
            while !worker.is_cancelled() {
                tokio::task::yield_now().await;
            }
            worker.finish();
        });
        registry.cancel_all().await;
        assert!(handle.is_cancelled());
    }
}
