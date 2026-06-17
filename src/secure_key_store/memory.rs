//! In-memory fallback [`SecureKeyStore`] implementation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use zeroize::{Zeroize, Zeroizing};

use super::{SecureKeyStore, SecureKeyStoreError};

/// In-memory fallback store. Wraps an `Arc<Mutex<HashMap>>` so clones
/// share state. Used on wasm32 and as the mobile fallback when a host
/// bridge has not been installed. Also useful for tests that don't
/// want to touch the real OS keychain.
///
/// **WARNING**: this store keeps secrets in plaintext in the process
/// heap. Production callers should prefer [`super::KeyringSecureKeyStore`]
/// and only fall back to this when the platform backend is
/// [`SecureKeyStoreError::Unsupported`].
///
/// **Phase A.6 #1**: secret values are stored as `Zeroizing<Vec<u8>>` so
/// the backing buffer is overwritten with zeros whenever an entry is
/// dropped, overwritten, or removed (including the implicit clear when
/// the map itself drops). Callers receive `String` clones via
/// `get_secret`; those clones still need to be zeroized by the caller
/// (they are typically wrapped in `Zeroizing<String>` at the call site,
/// e.g. session-grant / refresh-token consumers).
#[derive(Clone, Default)]
pub struct MemorySecureKeyStore {
    inner: Arc<Mutex<HashMap<String, Zeroizing<Vec<u8>>>>>,
}

impl MemorySecureKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Total entries currently held — only useful for diagnostics /
    /// tests. Production code should never iterate the store contents.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|guard| guard.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl std::fmt::Debug for MemorySecureKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NEVER include the values themselves.
        f.debug_struct("MemorySecureKeyStore")
            .field("entries", &self.len())
            .finish()
    }
}

impl SecureKeyStore for MemorySecureKeyStore {
    fn store_secret(&self, key: &str, value: &str) -> Result<(), SecureKeyStoreError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|err| SecureKeyStoreError::Backend(format!("lock poisoned: {err}")))?;
        // Insert wraps the bytes in `Zeroizing`, and the `HashMap::insert`
        // return value drops the previous entry (also `Zeroizing`) which
        // zeros it before deallocation. Overwriting an existing key
        // therefore wipes the old plaintext, not just shadows it.
        let zeroizing_value: Zeroizing<Vec<u8>> = Zeroizing::new(value.as_bytes().to_vec());
        let _previous = guard.insert(key.to_owned(), zeroizing_value);
        Ok(())
    }

    fn get_secret(&self, key: &str) -> Result<Option<String>, SecureKeyStoreError> {
        let guard = self
            .inner
            .lock()
            .map_err(|err| SecureKeyStoreError::Backend(format!("lock poisoned: {err}")))?;
        // The cloned bytes leave the zeroize protection — that is
        // unavoidable for the sync trait surface (callers need a
        // `String`). Callers handling long-lived secrets SHOULD wrap the
        // returned `String` in `zeroize::Zeroizing` so their copy is
        // also wiped on drop.
        match guard.get(key) {
            Some(bytes) => Ok(Some(String::from_utf8(bytes.to_vec()).map_err(|err| {
                SecureKeyStoreError::Backend(format!("stored secret not utf8: {err}"))
            })?)),
            None => Ok(None),
        }
    }

    fn delete_secret(&self, key: &str) -> Result<(), SecureKeyStoreError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|err| SecureKeyStoreError::Backend(format!("lock poisoned: {err}")))?;
        // `HashMap::remove` returns the value; dropping it triggers the
        // `Zeroizing<Vec<u8>>` destructor which wipes the buffer.
        let _ = guard.remove(key);
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "memory"
    }
}

/// Explicit drop wipe: when the last `Arc` clone of a
/// `MemorySecureKeyStore` is released, walk the map and zeroize every
/// remaining value. The `Zeroizing<Vec<u8>>` newtype already does this
/// per-entry on drop, but iterating explicitly here protects against
/// any future change where someone replaces the value type with a
/// plain `Vec<u8>` — the `Drop` impl makes the wipe intent
/// load-bearing.
impl Drop for MemorySecureKeyStore {
    fn drop(&mut self) {
        // Only the strong-count == 1 case actually frees the underlying
        // map. Clones share the `Arc`, so an early drop on a clone
        // would zero data still in use by other holders.
        if Arc::strong_count(&self.inner) > 1 {
            return;
        }
        if let Ok(mut guard) = self.inner.lock() {
            for (_, value) in guard.iter_mut() {
                value.zeroize();
            }
            guard.clear();
        }
    }
}
