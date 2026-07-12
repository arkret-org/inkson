use std::rc::Rc;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;

use crate::state::LocalStateStore;

#[derive(Clone)]
pub struct ValueReader<T> {
    read: Rc<dyn Fn() -> T>,
}

impl<T> ValueReader<T> {
    pub fn new(read: impl Fn() -> T + 'static) -> Self {
        Self {
            read: Rc::new(read),
        }
    }

    pub fn get(&self) -> T {
        (self.read)()
    }
}

#[derive(Clone)]
pub struct ValueCell<T> {
    read: ValueReader<T>,
    write: Rc<dyn Fn(T)>,
    update: Rc<dyn Fn(&mut dyn FnMut(&mut T))>,
}

impl<T> ValueCell<T> {
    pub fn new(
        read: impl Fn() -> T + 'static,
        write: impl Fn(T) + 'static,
        update: impl Fn(&mut dyn FnMut(&mut T)) + 'static,
    ) -> Self {
        Self {
            read: ValueReader::new(read),
            write: Rc::new(write),
            update: Rc::new(update),
        }
    }

    pub fn get(&self) -> T {
        self.read.get()
    }

    pub fn set(&self, value: T) {
        (self.write)(value);
    }

    pub fn update(&self, update: impl FnOnce(&mut T)) {
        let mut update = Some(update);
        (self.update)(&mut |value| {
            update.take().expect("value update called exactly once")(value);
        });
    }
}

#[cfg(not(target_arch = "wasm32"))]
type ReadStore = dyn Fn(&mut dyn FnMut(&LocalStateStore)) + Send + Sync;
#[cfg(target_arch = "wasm32")]
type ReadStore = dyn Fn(&mut dyn FnMut(&LocalStateStore));
#[cfg(not(target_arch = "wasm32"))]
type WriteStore = dyn Fn(&mut dyn FnMut(&mut LocalStateStore)) + Send + Sync;
#[cfg(target_arch = "wasm32")]
type WriteStore = dyn Fn(&mut dyn FnMut(&mut LocalStateStore));

#[derive(Clone)]
pub struct StateStoreHandle {
    #[cfg(not(target_arch = "wasm32"))]
    read: Arc<ReadStore>,
    #[cfg(target_arch = "wasm32")]
    read: Rc<ReadStore>,
    #[cfg(not(target_arch = "wasm32"))]
    write: Arc<WriteStore>,
    #[cfg(target_arch = "wasm32")]
    write: Rc<WriteStore>,
}

impl StateStoreHandle {
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new(
        read: impl Fn(&mut dyn FnMut(&LocalStateStore)) + Send + Sync + 'static,
        write: impl Fn(&mut dyn FnMut(&mut LocalStateStore)) + Send + Sync + 'static,
    ) -> Self {
        Self {
            read: Arc::new(read),
            write: Arc::new(write),
        }
    }

    #[cfg(target_arch = "wasm32")]
    pub fn new(
        read: impl Fn(&mut dyn FnMut(&LocalStateStore)) + 'static,
        write: impl Fn(&mut dyn FnMut(&mut LocalStateStore)) + 'static,
    ) -> Self {
        Self {
            read: Rc::new(read),
            write: Rc::new(write),
        }
    }

    pub fn read<R>(&self, read: impl FnOnce(&LocalStateStore) -> R) -> R {
        let mut read = Some(read);
        let mut result = None;
        (self.read)(&mut |store| {
            result = Some(read.take().expect("store read called exactly once")(store));
        });
        result.expect("state-store adapter must invoke its read callback")
    }

    pub fn write<R>(&self, write: impl FnOnce(&mut LocalStateStore) -> R) -> R {
        let mut write = Some(write);
        let mut result = None;
        (self.write)(&mut |store| {
            result = Some(write.take().expect("store write called exactly once")(
                store,
            ));
        });
        result.expect("state-store adapter must invoke its write callback")
    }
}
