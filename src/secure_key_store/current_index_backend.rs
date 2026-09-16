//! On-demand encrypted KV access, excluded from the synchronous secret cache.
use std::sync::Arc;

use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};

use super::{IndexedDbSecureKeyStore as Store, IndexedDbSendBoundary};

fn js(error: JsValue) -> anyhow::Error {
    anyhow::anyhow!("IndexedDB current index: {error:?}")
}

#[derive(Clone)]
pub(crate) struct Backend {
    db: IndexedDbSendBoundary<web_sys::IdbDatabase>,
    key: IndexedDbSendBoundary<JsValue>,
}

impl Backend {
    pub(crate) async fn open(
        _location: crate::state::CurrentIndexLocation,
    ) -> anyhow::Result<Self> {
        let db = Store::open_db("inkson.secret.inkson").await?;
        let key = Store::load_or_derive_wrapping_key(&db, "inkson").await?;
        Ok(Self {
            db: IndexedDbSendBoundary(send_wrapper::SendWrapper::new(Arc::new(db))),
            key: IndexedDbSendBoundary(send_wrapper::SendWrapper::new(Arc::new(key))),
        })
    }
    async fn unpack(&self, key: &str, value: JsValue) -> anyhow::Result<Vec<u8>> {
        let iv = Uint8Array::new(&Reflect::get(&value, &JsValue::from_str("iv")).map_err(js)?);
        let ct = Uint8Array::new(&Reflect::get(&value, &JsValue::from_str("ct")).map_err(js)?);
        let mut packed = iv.to_vec();
        packed.extend(ct.to_vec());
        let plain = Store::subtle_decrypt(&self.key.0, &packed).await?;
        let (bound_key, payload): (String, String) = serde_json::from_slice(&plain)?;
        anyhow::ensure!(bound_key == key, "current entry key binding differs");
        Ok(payload.into_bytes())
    }
    pub(crate) async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        match Store::idb_get_value(&self.db.0, Store::OBJECT_STORE_ENTRIES, key).await? {
            Some(value) => Ok(Some(self.unpack(key, value).await?)),
            None => Ok(None),
        }
    }
    pub(crate) async fn scan(
        &self,
        prefix: &str,
        lower: Option<&str>,
        after: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
        anyhow::ensure!((1..=100).contains(&limit), "unbounded current index scan");
        let lower = lower.unwrap_or(prefix);
        let (lower, open) = match after {
            Some(after) if after >= lower => (after, true),
            _ => (lower, false),
        };
        let range = web_sys::IdbKeyRange::bound_with_lower_open_and_upper_open(
            &JsValue::from_str(lower),
            &JsValue::from_str(&format!("{prefix}~")),
            open,
            true,
        )
        .map_err(js)?;
        let tx = self
            .db
            .0
            .transaction_with_str(Store::OBJECT_STORE_ENTRIES)
            .map_err(js)?;
        let store = tx.object_store(Store::OBJECT_STORE_ENTRIES).map_err(js)?;
        let values = store
            .get_all_with_key_and_limit(range.as_ref(), limit as u32)
            .map_err(js)?;
        let keys = store
            .get_all_keys_with_key_and_limit(range.as_ref(), limit as u32)
            .map_err(js)?;
        let (values, keys) = tokio::join!(
            Store::idb_request_result(&values),
            Store::idb_request_result(&keys)
        );
        let values: js_sys::Array = values.map_err(js)?.into();
        let keys: js_sys::Array = keys.map_err(js)?.into();
        anyhow::ensure!(
            values.length() == keys.length(),
            "current range key/value count differs"
        );
        let mut rows = Vec::new();
        for i in 0..keys.length() {
            let key = keys
                .get(i)
                .as_string()
                .ok_or_else(|| anyhow::anyhow!("current key is not a string"))?;
            rows.push((key.clone(), self.unpack(&key, values.get(i)).await?));
        }
        Ok(rows)
    }
    pub(crate) async fn keys(
        &self,
        prefix: &str,
        lower: Option<&str>,
        after: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<String>> {
        anyhow::ensure!((1..=100).contains(&limit), "unbounded current key scan");
        let lower = lower.unwrap_or(prefix);
        let (lower, open) = match after {
            Some(after) if after >= lower => (after, true),
            _ => (lower, false),
        };
        let range = web_sys::IdbKeyRange::bound_with_lower_open_and_upper_open(
            &JsValue::from_str(lower),
            &JsValue::from_str(&format!("{prefix}~")),
            open,
            true,
        )
        .map_err(js)?;
        let tx = self
            .db
            .0
            .transaction_with_str(Store::OBJECT_STORE_ENTRIES)
            .map_err(js)?;
        let store = tx.object_store(Store::OBJECT_STORE_ENTRIES).map_err(js)?;
        let request = store
            .get_all_keys_with_key_and_limit(range.as_ref(), limit as u32)
            .map_err(js)?;
        let values: js_sys::Array = Store::idb_request_result(&request)
            .await
            .map_err(js)?
            .into();
        values
            .iter()
            .map(|value| {
                value
                    .as_string()
                    .ok_or_else(|| anyhow::anyhow!("current key is not a string"))
            })
            .collect()
    }
    pub(crate) async fn apply(
        &self,
        deletes: Vec<String>,
        writes: Vec<(String, Vec<u8>)>,
    ) -> anyhow::Result<()> {
        // WebCrypto must finish before opening the IDB transaction: awaiting a
        // non-IDB promise inside it would allow the browser to auto-commit.
        let mut encrypted = Vec::with_capacity(writes.len());
        for (key, value) in writes {
            let plain = serde_json::to_vec(&(&key, String::from_utf8(value)?))?;
            let (iv, ct) = Store::subtle_encrypt(&self.key.0, &plain).await?;
            let entry = Object::new();
            Reflect::set(
                &entry,
                &JsValue::from_str("iv"),
                &Uint8Array::from(iv.as_slice()),
            )
            .map_err(js)?;
            Reflect::set(
                &entry,
                &JsValue::from_str("ct"),
                &Uint8Array::from(ct.as_slice()),
            )
            .map_err(js)?;
            encrypted.push((key, entry));
        }
        let tx = self
            .db
            .0
            .transaction_with_str_and_mode(
                Store::OBJECT_STORE_ENTRIES,
                web_sys::IdbTransactionMode::Readwrite,
            )
            .map_err(js)?;
        let (sender, receiver) = tokio::sync::oneshot::channel::<Result<(), String>>();
        let sender = std::rc::Rc::new(std::cell::RefCell::new(Some(sender)));
        let done_sender = sender.clone();
        let done = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
            if let Some(sender) = done_sender.borrow_mut().take() {
                let _ = sender.send(Ok(()));
            }
        });
        let failed = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
            if let Some(sender) = sender.borrow_mut().take() {
                let _ = sender.send(Err("current transaction aborted".into()));
            }
        });
        tx.set_oncomplete(Some(done.as_ref().unchecked_ref()));
        tx.set_onabort(Some(failed.as_ref().unchecked_ref()));
        tx.set_onerror(Some(failed.as_ref().unchecked_ref()));
        let guard = TransactionGuard {
            tx: tx.clone(),
            _done: done,
            _failed: failed,
        };
        let store = tx.object_store(Store::OBJECT_STORE_ENTRIES).map_err(js)?;
        for key in deletes {
            store.delete(&JsValue::from_str(&key)).map_err(js)?;
        }
        for (key, value) in encrypted {
            store
                .put_with_key(value.as_ref(), &JsValue::from_str(&key))
                .map_err(js)?;
        }
        let result = tokio::select! {
            result=receiver=>result.map_err(|_|anyhow::anyhow!("current transaction channel closed"))?.map_err(anyhow::Error::msg),
            _=crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(12))=>Err(anyhow::anyhow!("current transaction completion timeout")),
        };
        drop(guard);
        result
    }
}

struct TransactionGuard {
    tx: web_sys::IdbTransaction,
    _done: Closure<dyn FnMut(web_sys::Event)>,
    _failed: Closure<dyn FnMut(web_sys::Event)>,
}
impl Drop for TransactionGuard {
    fn drop(&mut self) {
        self.tx.set_oncomplete(None);
        self.tx.set_onabort(None);
        self.tx.set_onerror(None);
        let _ = self.tx.abort();
    }
}
