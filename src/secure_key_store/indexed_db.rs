//! wasm32-only IndexedDB + non-extractable SubtleCrypto
//! [`SecureKeyStore`] tier, plus the async upgrade / migration path.

#![cfg(target_arch = "wasm32")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;

use super::{
    LocalStorageSecureKeyStore, SecureKeyStore, SecureKeyStoreError,
    WASM_UPGRADED_SECURE_KEY_STORE, is_wasm_ed25519_seed_key, is_wasm_no_localstorage_mirror_key,
    unwrap_secret, wasm_localstorage_secret_downgrade_enabled,
};

/// wasm32 IndexedDB-backed secret store that upgrades the wrapping-key
/// tier from the `localStorage` byte seed to a SubtleCrypto-derived
/// **non-extractable** AES-GCM key.
///
/// ## Threat model improvement over [`LocalStorageSecureKeyStore`]
///
/// LocalStorageSecureKeyStore (H2) keeps both the wrapping seed (32
/// random bytes) AND every wrapped secret in `localStorage` under the
/// same origin. An attacker who can read the localStorage blob — via
/// a backup dump, a misconfigured browser extension, a developer-tools
/// clipboard, or a same-origin XSS — gets the seed alongside the
/// ciphertext and decrypts everything offline.
///
/// IndexedDbSecureKeyStore (H6) splits the layers:
///
///   1. The wrapping key is derived once via `SubtleCrypto.deriveKey` with `extractable: false`.
///      The derived `CryptoKey` lives in the browser's SubtleCrypto subsystem; even
///      `crypto.subtle.exportKey(...)` against it rejects.
///   2. The persisted form of the wrapping key — needed to recover across page reloads — is the
///      `CryptoKey` *object* itself, stashed in IndexedDB via structured clone. IndexedDB preserves
///      the `extractable: false` attribute on round-trip.
///   3. Encrypted entries (AES-GCM ciphertext + 12-byte IV) live in a separate IndexedDB object
///      store, keyed by `service_name`/`key`.
///
/// A disk dump now yields ciphertext + an unusable key handle.
/// Recovering plaintext requires running JS in the same origin and
/// calling `crypto.subtle.decrypt(...)`. The
/// `LocalStorageSecureKeyStore` floor stays available as a fallback
/// for browsers / contexts where IndexedDB is denied (private-mode
/// Firefox, file:// URLs, etc.).
///
/// ## Sync trait surface against async storage
///
/// SubtleCrypto and IndexedDB are Promise-based; the
/// [`SecureKeyStore`] trait is sync. The store resolves this via a
/// two-phase model:
///
///   * [`IndexedDbSecureKeyStore::new_async`] (async, called once at app startup) opens the
///     database, derives or loads the wrapping key, and decrypts every existing entry into an
///     in-process `HashMap`. This is the only async path.
///   * Sync trait methods read from / write to the cache directly. Writes additionally spawn a
///     `wasm_bindgen_futures::spawn_local` task that re-encrypts and persists the change to
///     IndexedDB. Failures are logged but do not block the caller (mirrors the `localStorage`
///     failure mode, where a quota-exceeded `setItem` also can't be reported through a sync trait).
///
/// Result: an in-flight write to IndexedDB that doesn't complete
/// before a page-unload is lost. Production callers tolerate this
/// because the data is re-derivable on next login (OIDC refresh
/// token, push registration grant, etc.).
pub struct IndexedDbSecureKeyStore {
    service_name: String,
    db_name: String,
    cache: Arc<Mutex<HashMap<String, String>>>,
    /// Non-extractable AES-GCM CryptoKey, cloned cheaply via JsValue
    /// reference counting. Used by spawn_local persistence tasks. The
    /// `IndexedDbSendBoundary` wrapper attests Send+Sync on wasm32
    /// where there is exactly one thread — `JsValue` is `!Send` by
    /// default because wasm-bindgen has to accommodate the
    /// (currently theoretical) future where multiple wasm threads can
    /// share JS values.
    crypto_key: IndexedDbSendBoundary<wasm_bindgen::JsValue>,
    /// Cached `IdbDatabase` handle reused across every persistence
    /// write/delete. The connection is opened once at `new_async` time
    /// and shared for the lifetime of the store so each `spawn_local`
    /// callback inside `store_secret` / `delete_secret` does not have to
    /// reopen IndexedDB (and re-run `onupgradeneeded` checks) on every
    /// write.
    db: IndexedDbSendBoundary<web_sys::IdbDatabase>,
}

/// wasm32-only wrapper that asserts Send + Sync on a value that is
/// only ever touched from the single wasm thread. The
/// [`SecureKeyStore`] trait requires Send + Sync; wasm32 has no real
/// thread sharing, so this is sound.
#[derive(Clone)]
struct IndexedDbSendBoundary<T>(std::sync::Arc<T>);

unsafe impl<T> Send for IndexedDbSendBoundary<T> {}
unsafe impl<T> Sync for IndexedDbSendBoundary<T> {}

impl IndexedDbSecureKeyStore {
    /// IndexedDB database version. Bump when the object-store schema
    /// changes; the `onupgradeneeded` handler will fire.
    const DB_VERSION: u32 = 1;
    const OBJECT_STORE_ENTRIES: &'static str = "entries";
    const OBJECT_STORE_KEYS: &'static str = "wrapping_keys";
    const WRAPPING_KEY_PRIMARY: &'static str = "primary";
    /// Key-derivation parameters. PBKDF2 over a stable installation
    /// salt → AES-GCM 256-bit non-extractable key. Iterations are
    /// 100k to keep init cost bounded; in-origin attackers don't
    /// benefit from raising it.
    const PBKDF2_ITERATIONS: u32 = 100_000;
    const SALT_BYTES: usize = 16;
    const OPEN_DB_TIMEOUT_MS: i32 = 12_000;

    /// Open / create the IndexedDB database, derive (or recover) the
    /// non-extractable AES-GCM wrapping key, then decrypt every
    /// existing entry into the in-process cache. Returns a fully
    /// initialised store ready for sync access via the
    /// [`SecureKeyStore`] trait.
    pub async fn new_async(service_name: &str) -> Result<Self, SecureKeyStoreError> {
        let db_name = format!("inkson.secret.{service_name}");
        tracing::debug!(target: "secure_store", db_name=%db_name, "new_async: step 1/3 open_db (awaiting IndexedDB open)…");
        let db = Self::open_db(&db_name).await?;
        tracing::debug!(target: "secure_store", "new_async: step 1/3 open_db OK; step 2/3 load_or_derive_wrapping_key (SubtleCrypto)…");
        let crypto_key = Self::load_or_derive_wrapping_key(&db, service_name).await?;
        tracing::debug!(target: "secure_store", "new_async: step 2/3 wrapping_key OK; step 3/3 load_and_decrypt_cache…");
        let cache = Self::load_and_decrypt_cache(&db, &crypto_key).await?;
        tracing::debug!(target: "secure_store", "new_async: step 3/3 cache OK; IndexedDbSecureKeyStore fully constructed");
        Ok(Self {
            service_name: service_name.to_owned(),
            db_name,
            cache: Arc::new(Mutex::new(cache)),
            crypto_key: IndexedDbSendBoundary(Arc::new(crypto_key)),
            db: IndexedDbSendBoundary(Arc::new(db)),
        })
    }

    /// Await a one-shot IndexedDB request, resolving to its `result()`
    /// or rejecting with its `error()`.
    ///
    /// The success/error closures are stored in `Rc<RefCell<Option<..>>>`
    /// bindings that outlive the `.await` and are detached + dropped only
    /// after the request has settled. The previous per-call-site code used
    /// `Closure::once_into_js` and let the returned `JsValue` handle drop at
    /// the end of the `Promise::new` executor scope. Under wasm-bindgen
    /// 0.2.120's `FinalizationRegistry`-based closure dtor (`CLOSURE_DTORS`)
    /// that frees the closure registration before the DOM invokes it, which
    /// surfaces as the runtime panic
    /// `closure invoked recursively or after being dropped`, immediately
    /// followed by a cascade of `memory access out of bounds` once the
    /// wasm-bindgen-futures executor heap is corrupted. Keeping the
    /// `Closure`s alive across the await removes the use-after-free.
    async fn idb_request_result(
        request: &web_sys::IdbRequest,
    ) -> Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue> {
        use wasm_bindgen::closure::Closure;
        use wasm_bindgen::{JsCast, JsValue};
        use wasm_bindgen_futures::JsFuture;
        type EventClosure = Closure<dyn FnMut(web_sys::Event)>;
        let on_success: std::rc::Rc<std::cell::RefCell<Option<EventClosure>>> =
            std::rc::Rc::new(std::cell::RefCell::new(None));
        let on_error: std::rc::Rc<std::cell::RefCell<Option<EventClosure>>> =
            std::rc::Rc::new(std::cell::RefCell::new(None));
        let on_success_slot = on_success.clone();
        let on_error_slot = on_error.clone();
        let settled = std::rc::Rc::new(std::cell::Cell::new(false));
        let promise = js_sys::Promise::new(&mut |resolve, reject| {
            let success_settled = settled.clone();
            let success_resolve = resolve.clone();
            let success_reject = reject.clone();
            let error_settled = settled.clone();
            let error_reject = reject.clone();
            let success = Closure::wrap(Box::new(move |event: web_sys::Event| {
                if success_settled.replace(true) {
                    return;
                }
                match event
                    .target()
                    .and_then(|t| t.dyn_into::<web_sys::IdbRequest>().ok())
                {
                    Some(req) => match req.result() {
                        Ok(value) => {
                            let _ = success_resolve.call1(&JsValue::NULL, &value);
                        }
                        Err(err) => {
                            let _ = success_reject.call1(&JsValue::NULL, &err);
                        }
                    },
                    None => {
                        let _ = success_reject.call1(
                            &JsValue::NULL,
                            &JsValue::from_str("indexedDB request: event has no IdbRequest target"),
                        );
                    }
                }
            }) as Box<dyn FnMut(web_sys::Event)>);
            let error = Closure::wrap(Box::new(move |event: web_sys::Event| {
                if error_settled.replace(true) {
                    return;
                }
                let err = event
                    .target()
                    .and_then(|t| t.dyn_into::<web_sys::IdbRequest>().ok())
                    .and_then(|req| req.error().ok().flatten())
                    .map(JsValue::from)
                    .unwrap_or_else(|| JsValue::from_str("indexedDB request error"));
                let _ = error_reject.call1(&JsValue::NULL, &err);
            }) as Box<dyn FnMut(web_sys::Event)>);
            request.set_onsuccess(Some(success.as_ref().unchecked_ref()));
            request.set_onerror(Some(error.as_ref().unchecked_ref()));
            *on_success_slot.borrow_mut() = Some(success);
            *on_error_slot.borrow_mut() = Some(error);
        });
        let settled = JsFuture::from(promise).await;
        // Detach the handlers and free the closures only after the request
        // has settled, so the DOM can never invoke a freed closure.
        request.set_onsuccess(None);
        request.set_onerror(None);
        drop(on_success);
        drop(on_error);
        settled
    }

    async fn open_db(db_name: &str) -> Result<web_sys::IdbDatabase, SecureKeyStoreError> {
        use wasm_bindgen::JsCast;
        let window = web_sys::window().ok_or_else(|| {
            SecureKeyStoreError::Unsupported("web_sys::window unavailable (non-browser host)")
        })?;
        let factory = window
            .indexed_db()
            .map_err(|err| SecureKeyStoreError::Backend(format!("indexedDB: {err:?}")))?
            .ok_or_else(|| SecureKeyStoreError::Unsupported("window.indexedDB unavailable"))?;
        let open_req = factory
            .open_with_u32(db_name, Self::DB_VERSION)
            .map_err(|err| SecureKeyStoreError::Backend(format!("indexedDB.open: {err:?}")))?;
        // onupgradeneeded synchronously creates the two object stores
        // when version bumps (first install: version goes 0 → 1).
        let on_upgrade = wasm_bindgen::closure::Closure::<dyn FnMut(web_sys::Event)>::new(
            move |event: web_sys::Event| {
                let request: web_sys::IdbOpenDbRequest = match event
                    .target()
                    .and_then(|t| t.dyn_into::<web_sys::IdbOpenDbRequest>().ok())
                {
                    Some(r) => r,
                    None => return,
                };
                let db_value = match request.result() {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let db: web_sys::IdbDatabase = match db_value.dyn_into() {
                    Ok(d) => d,
                    Err(_) => return,
                };
                let _ = db.create_object_store(Self::OBJECT_STORE_ENTRIES);
                let _ = db.create_object_store(Self::OBJECT_STORE_KEYS);
            },
        );
        open_req.set_onupgradeneeded(Some(on_upgrade.as_ref().unchecked_ref()));
        let open_result = Self::idb_open_request_result(&open_req, Self::OPEN_DB_TIMEOUT_MS).await;
        // The upgrade handler may fire before success; keep it alive until
        // the open has settled, then detach and drop it. If the open was
        // blocked / timed out, the handler must not outlive its Rust closure.
        open_req.set_onupgradeneeded(None);
        let result = open_result.map_err(|err| {
            SecureKeyStoreError::Backend(format!("indexedDB open awaited: {err:?}"))
        })?;
        let db: web_sys::IdbDatabase = result.dyn_into().map_err(|_| {
            SecureKeyStoreError::Backend("open did not return IdbDatabase".to_owned())
        })?;
        Ok(db)
    }

    async fn idb_open_request_result(
        request: &web_sys::IdbOpenDbRequest,
        timeout_ms: i32,
    ) -> Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue> {
        use wasm_bindgen::closure::Closure;
        use wasm_bindgen::{JsCast, JsValue};
        use wasm_bindgen_futures::JsFuture;
        type EventClosure = Closure<dyn FnMut(web_sys::Event)>;
        type TimerClosure = Closure<dyn FnMut()>;

        let on_success: std::rc::Rc<std::cell::RefCell<Option<EventClosure>>> =
            std::rc::Rc::new(std::cell::RefCell::new(None));
        let on_error: std::rc::Rc<std::cell::RefCell<Option<EventClosure>>> =
            std::rc::Rc::new(std::cell::RefCell::new(None));
        let on_blocked: std::rc::Rc<std::cell::RefCell<Option<EventClosure>>> =
            std::rc::Rc::new(std::cell::RefCell::new(None));
        let on_timeout: std::rc::Rc<std::cell::RefCell<Option<TimerClosure>>> =
            std::rc::Rc::new(std::cell::RefCell::new(None));
        let timer_handle = std::rc::Rc::new(std::cell::Cell::new(None::<i32>));
        let settled = std::rc::Rc::new(std::cell::Cell::new(false));
        let window = web_sys::window()
            .ok_or_else(|| JsValue::from_str("indexedDB open: browser window unavailable"))?;

        let on_success_slot = on_success.clone();
        let on_error_slot = on_error.clone();
        let on_blocked_slot = on_blocked.clone();
        let on_timeout_slot = on_timeout.clone();
        let timer_handle_slot = timer_handle.clone();
        let request_for_handlers = request.clone();
        let promise = js_sys::Promise::new(&mut |resolve, reject| {
            let success_settled = settled.clone();
            let success_resolve = resolve.clone();
            let success_reject = reject.clone();
            let success_window = window.clone();
            let success_timer_handle = timer_handle.clone();
            let success = Closure::wrap(Box::new(move |event: web_sys::Event| {
                if success_settled.replace(true) {
                    return;
                }
                if let Some(handle) = success_timer_handle.get() {
                    success_window.clear_timeout_with_handle(handle);
                }
                match event
                    .target()
                    .and_then(|t| t.dyn_into::<web_sys::IdbOpenDbRequest>().ok())
                {
                    Some(req) => match req.result() {
                        Ok(value) => {
                            let _ = success_resolve.call1(&JsValue::NULL, &value);
                        }
                        Err(err) => {
                            let _ = success_reject.call1(&JsValue::NULL, &err);
                        }
                    },
                    None => {
                        let _ = success_reject.call1(
                            &JsValue::NULL,
                            &JsValue::from_str(
                                "indexedDB open: event has no IdbOpenDbRequest target",
                            ),
                        );
                    }
                }
            }) as Box<dyn FnMut(web_sys::Event)>);

            let error_settled = settled.clone();
            let error_reject = reject.clone();
            let error_window = window.clone();
            let error_timer_handle = timer_handle.clone();
            let error = Closure::wrap(Box::new(move |event: web_sys::Event| {
                if error_settled.replace(true) {
                    return;
                }
                if let Some(handle) = error_timer_handle.get() {
                    error_window.clear_timeout_with_handle(handle);
                }
                let err = event
                    .target()
                    .and_then(|t| t.dyn_into::<web_sys::IdbOpenDbRequest>().ok())
                    .and_then(|req| req.error().ok().flatten())
                    .map(JsValue::from)
                    .unwrap_or_else(|| JsValue::from_str("indexedDB open request error"));
                let _ = error_reject.call1(&JsValue::NULL, &err);
            }) as Box<dyn FnMut(web_sys::Event)>);

            let blocked_settled = settled.clone();
            let blocked_reject = reject.clone();
            let blocked_window = window.clone();
            let blocked_timer_handle = timer_handle.clone();
            let blocked = Closure::wrap(Box::new(move |_event: web_sys::Event| {
                if blocked_settled.replace(true) {
                    return;
                }
                if let Some(handle) = blocked_timer_handle.get() {
                    blocked_window.clear_timeout_with_handle(handle);
                }
                let _ = blocked_reject.call1(
                    &JsValue::NULL,
                    &JsValue::from_str(
                        "indexedDB open blocked by another tab or stale database connection",
                    ),
                );
            }) as Box<dyn FnMut(web_sys::Event)>);

            let timeout_settled = settled.clone();
            let timeout_reject = reject.clone();
            let timeout = Closure::wrap(Box::new(move || {
                if timeout_settled.replace(true) {
                    return;
                }
                let _ = timeout_reject.call1(
                    &JsValue::NULL,
                    &JsValue::from_str(&format!("indexedDB open timed out after {timeout_ms}ms")),
                );
            }) as Box<dyn FnMut()>);

            request_for_handlers.set_onsuccess(Some(success.as_ref().unchecked_ref()));
            request_for_handlers.set_onerror(Some(error.as_ref().unchecked_ref()));
            request_for_handlers.set_onblocked(Some(blocked.as_ref().unchecked_ref()));
            match window.set_timeout_with_callback_and_timeout_and_arguments_0(
                timeout.as_ref().unchecked_ref(),
                timeout_ms,
            ) {
                Ok(handle) => timer_handle_slot.set(Some(handle)),
                Err(err) => {
                    let _ = reject.call1(&JsValue::NULL, &err);
                }
            }
            *on_success_slot.borrow_mut() = Some(success);
            *on_error_slot.borrow_mut() = Some(error);
            *on_blocked_slot.borrow_mut() = Some(blocked);
            *on_timeout_slot.borrow_mut() = Some(timeout);
        });

        let settled_result = JsFuture::from(promise).await;
        request.set_onsuccess(None);
        request.set_onerror(None);
        request.set_onblocked(None);
        if let Some(handle) = timer_handle.get() {
            window.clear_timeout_with_handle(handle);
        }
        drop(on_success);
        drop(on_error);
        drop(on_blocked);
        drop(on_timeout);
        settled_result
    }

    async fn load_or_derive_wrapping_key(
        db: &web_sys::IdbDatabase,
        service_name: &str,
    ) -> Result<wasm_bindgen::JsValue, SecureKeyStoreError> {
        // Read the existing CryptoKey if present; else generate +
        // store. IndexedDB preserves the `extractable: false`
        // attribute on round-trip via structured clone.
        if let Some(existing) =
            Self::idb_get_value(db, Self::OBJECT_STORE_KEYS, Self::WRAPPING_KEY_PRIMARY).await?
        {
            // DECISIVE DIAGNOSTIC: if the wrapping key persists across reloads we
            // hit this branch every time after first install, and encrypted
            // entries stay decryptable. If instead we keep falling through to the
            // "derived fresh" branch below on every reload, the persisted
            // `primary` CryptoKey is NOT surviving the IndexedDB round-trip — that
            // is the wrapping-key instability that orphans the MLS init key.
            tracing::debug!(target: "secure_store", "wrapping key: LOADED existing primary (stable across reloads)");
            return Ok(existing);
        }
        tracing::warn!(target: "secure_store", "wrapping key: DERIVED FRESH primary (no existing found — if this fires on EVERY reload, the key is not persisting and all prior entries are orphaned)");
        let key = Self::derive_fresh_wrapping_key(service_name).await?;
        // Atomic store-if-absent (`add`, NOT `put`). A second store that
        // initialises concurrently may have derived and persisted its own
        // random-salt wrapping key while we were deriving ours; a blind `put`
        // would OVERWRITE it, orphaning every entry that store already encrypted
        // (the next load decrypts them with the wrong key → `OperationError` →
        // the secret silently vanishes, e.g. the MLS KeyPackage init key →
        // "no local KeyPackage identity state"). `add` fails when "primary"
        // already exists, so the first writer wins and every instance converges
        // on the one wrapping key.
        match Self::idb_add_value(
            db,
            Self::OBJECT_STORE_KEYS,
            Self::WRAPPING_KEY_PRIMARY,
            &key,
        )
        .await
        {
            Ok(()) => Ok(key),
            Err(_) => Self::idb_get_value(db, Self::OBJECT_STORE_KEYS, Self::WRAPPING_KEY_PRIMARY)
                .await?
                .ok_or_else(|| {
                    SecureKeyStoreError::Backend(
                        "wrapping key add lost the race but primary is still absent".to_owned(),
                    )
                }),
        }
    }

    async fn derive_fresh_wrapping_key(
        service_name: &str,
    ) -> Result<wasm_bindgen::JsValue, SecureKeyStoreError> {
        use js_sys::{Array, Object, Reflect, Uint8Array};
        use wasm_bindgen::{JsCast, JsValue};
        use wasm_bindgen_futures::JsFuture;
        let window = web_sys::window()
            .ok_or_else(|| SecureKeyStoreError::Unsupported("web_sys::window unavailable"))?;
        let subtle = window
            .crypto()
            .map_err(|err| SecureKeyStoreError::Backend(format!("crypto: {err:?}")))?
            .subtle();
        // Step 1: import the service_name bytes as a PBKDF2 base key.
        let base_material = Uint8Array::new_with_length(service_name.len() as u32);
        base_material.copy_from(service_name.as_bytes());
        let pbkdf2_usages = Array::new();
        pbkdf2_usages.push(&JsValue::from_str("deriveKey"));
        let base_key_promise = subtle
            .import_key_with_str(
                "raw",
                base_material.as_ref(),
                "PBKDF2",
                false,
                &JsValue::from(pbkdf2_usages),
            )
            .map_err(|err| {
                SecureKeyStoreError::Backend(format!("subtle.importKey PBKDF2: {err:?}"))
            })?;
        let base_key = JsFuture::from(base_key_promise).await.map_err(|err| {
            SecureKeyStoreError::Backend(format!("subtle.importKey PBKDF2 awaited: {err:?}"))
        })?;
        // Step 2: deriveKey → AES-GCM 256, extractable=false.
        let mut salt = [0u8; Self::SALT_BYTES];
        getrandom::fill(&mut salt)
            .map_err(|err| SecureKeyStoreError::Backend(format!("getrandom salt: {err}")))?;
        let salt_array = Uint8Array::new_with_length(Self::SALT_BYTES as u32);
        salt_array.copy_from(&salt);
        let derive_algo = Object::new();
        Reflect::set(
            &derive_algo,
            &JsValue::from_str("name"),
            &JsValue::from_str("PBKDF2"),
        )
        .map_err(|err| SecureKeyStoreError::Backend(format!("derive name set: {err:?}")))?;
        Reflect::set(&derive_algo, &JsValue::from_str("salt"), &salt_array)
            .map_err(|err| SecureKeyStoreError::Backend(format!("derive salt set: {err:?}")))?;
        Reflect::set(
            &derive_algo,
            &JsValue::from_str("iterations"),
            &JsValue::from_f64(Self::PBKDF2_ITERATIONS as f64),
        )
        .map_err(|err| SecureKeyStoreError::Backend(format!("derive iter set: {err:?}")))?;
        Reflect::set(
            &derive_algo,
            &JsValue::from_str("hash"),
            &JsValue::from_str("SHA-256"),
        )
        .map_err(|err| SecureKeyStoreError::Backend(format!("derive hash set: {err:?}")))?;
        let derived_algo = Object::new();
        Reflect::set(
            &derived_algo,
            &JsValue::from_str("name"),
            &JsValue::from_str("AES-GCM"),
        )
        .map_err(|err| SecureKeyStoreError::Backend(format!("derived name set: {err:?}")))?;
        Reflect::set(
            &derived_algo,
            &JsValue::from_str("length"),
            &JsValue::from_f64(256.0),
        )
        .map_err(|err| SecureKeyStoreError::Backend(format!("derived length set: {err:?}")))?;
        let aes_usages = Array::new();
        aes_usages.push(&JsValue::from_str("encrypt"));
        aes_usages.push(&JsValue::from_str("decrypt"));
        let base_key_typed: web_sys::CryptoKey = base_key.dyn_into().map_err(|_| {
            SecureKeyStoreError::Backend("PBKDF2 importKey did not yield CryptoKey".to_owned())
        })?;
        let derive_promise = subtle
            .derive_key_with_object_and_object(
                &derive_algo,
                &base_key_typed,
                &derived_algo,
                false,
                &JsValue::from(aes_usages),
            )
            .map_err(|err| SecureKeyStoreError::Backend(format!("subtle.deriveKey: {err:?}")))?;
        let derived = JsFuture::from(derive_promise)
            .await
            .map_err(|err| SecureKeyStoreError::Backend(format!("deriveKey awaited: {err:?}")))?;
        Ok(derived)
    }

    async fn load_and_decrypt_cache(
        db: &web_sys::IdbDatabase,
        crypto_key: &wasm_bindgen::JsValue,
    ) -> Result<HashMap<String, String>, SecureKeyStoreError> {
        let entries = Self::idb_all_entries(db, Self::OBJECT_STORE_ENTRIES).await?;
        let mut out = HashMap::with_capacity(entries.len());
        let mut orphaned = Vec::new();
        for (key_name, wrapped_bytes) in entries {
            match Self::subtle_decrypt(crypto_key, &wrapped_bytes).await {
                Ok(plain) => {
                    if let Ok(s) = String::from_utf8(plain) {
                        out.insert(key_name, s);
                    }
                }
                Err(err) => {
                    tracing::warn!(?err, key=%key_name, "indexedDB entry decrypt failed");
                    orphaned.push(key_name);
                }
            }
        }
        // Self-heal. If the wrapping key decrypted at least one entry it IS the
        // valid key, so the failures are entries a transient second store
        // encrypted under a different random-salt key before this one won — now
        // permanently undecryptable ghosts. Purge them so their values
        // re-bootstrap cleanly (DPoP repaired from the signing seed, the MLS
        // KeyPackage republished with a fresh init key) instead of staying dead
        // and forcing "no local KeyPackage identity state" forever. Guard on
        // `!out.is_empty()`: if EVERYTHING failed the loaded key itself is wrong
        // (not the entries), so keep them rather than wipe the whole store.
        if !out.is_empty() && !orphaned.is_empty() {
            for key_name in &orphaned {
                let _ = Self::idb_delete_value(db, Self::OBJECT_STORE_ENTRIES, key_name).await;
            }
            tracing::warn!(
                count = orphaned.len(),
                "secure store: purged orphaned (undecryptable) entries to self-heal a past wrapping-key mismatch"
            );
        }
        Ok(out)
    }

    async fn idb_get_value(
        db: &web_sys::IdbDatabase,
        store: &str,
        key: &str,
    ) -> Result<Option<wasm_bindgen::JsValue>, SecureKeyStoreError> {
        use wasm_bindgen::JsValue;
        let tx = db
            .transaction_with_str(store)
            .map_err(|err| SecureKeyStoreError::Backend(format!("tx open: {err:?}")))?;
        let obj_store = tx
            .object_store(store)
            .map_err(|err| SecureKeyStoreError::Backend(format!("objectStore: {err:?}")))?;
        let request = obj_store
            .get(&JsValue::from_str(key))
            .map_err(|err| SecureKeyStoreError::Backend(format!("get: {err:?}")))?;
        let value = Self::idb_request_result(&request)
            .await
            .map_err(|err| SecureKeyStoreError::Backend(format!("get awaited: {err:?}")))?;
        if value.is_undefined() || value.is_null() {
            Ok(None)
        } else {
            Ok(Some(value))
        }
    }

    async fn idb_put_value(
        db: &web_sys::IdbDatabase,
        store: &str,
        key: &str,
        value: &wasm_bindgen::JsValue,
    ) -> Result<(), SecureKeyStoreError> {
        use wasm_bindgen::JsValue;
        let tx = db
            .transaction_with_str_and_mode(store, web_sys::IdbTransactionMode::Readwrite)
            .map_err(|err| SecureKeyStoreError::Backend(format!("tx open rw: {err:?}")))?;
        let obj_store = tx
            .object_store(store)
            .map_err(|err| SecureKeyStoreError::Backend(format!("objectStore: {err:?}")))?;
        let request = obj_store
            .put_with_key(value, &JsValue::from_str(key))
            .map_err(|err| SecureKeyStoreError::Backend(format!("put: {err:?}")))?;
        Self::idb_request_result(&request)
            .await
            .map_err(|err| SecureKeyStoreError::Backend(format!("put awaited: {err:?}")))?;
        Ok(())
    }

    /// `add` (insert-if-absent) variant of [`idb_put_value`]. Rejects with a
    /// `ConstraintError` when `key` already exists, which callers use for atomic
    /// first-writer-wins semantics (IndexedDB serialises the readwrite
    /// transactions, so exactly one concurrent `add` for the same key succeeds).
    async fn idb_add_value(
        db: &web_sys::IdbDatabase,
        store: &str,
        key: &str,
        value: &wasm_bindgen::JsValue,
    ) -> Result<(), SecureKeyStoreError> {
        use wasm_bindgen::JsValue;
        let tx = db
            .transaction_with_str_and_mode(store, web_sys::IdbTransactionMode::Readwrite)
            .map_err(|err| SecureKeyStoreError::Backend(format!("tx open rw: {err:?}")))?;
        let obj_store = tx
            .object_store(store)
            .map_err(|err| SecureKeyStoreError::Backend(format!("objectStore: {err:?}")))?;
        let request = obj_store
            .add_with_key(value, &JsValue::from_str(key))
            .map_err(|err| SecureKeyStoreError::Backend(format!("add: {err:?}")))?;
        Self::idb_request_result(&request)
            .await
            .map_err(|err| SecureKeyStoreError::Backend(format!("add awaited: {err:?}")))?;
        Ok(())
    }

    async fn idb_delete_value(
        db: &web_sys::IdbDatabase,
        store: &str,
        key: &str,
    ) -> Result<(), SecureKeyStoreError> {
        use wasm_bindgen::JsValue;
        let tx = db
            .transaction_with_str_and_mode(store, web_sys::IdbTransactionMode::Readwrite)
            .map_err(|err| SecureKeyStoreError::Backend(format!("tx open rw: {err:?}")))?;
        let obj_store = tx
            .object_store(store)
            .map_err(|err| SecureKeyStoreError::Backend(format!("objectStore: {err:?}")))?;
        let request = obj_store
            .delete(&JsValue::from_str(key))
            .map_err(|err| SecureKeyStoreError::Backend(format!("delete: {err:?}")))?;
        Self::idb_request_result(&request)
            .await
            .map_err(|err| SecureKeyStoreError::Backend(format!("delete awaited: {err:?}")))?;
        Ok(())
    }

    /// Read every entry in `store` as `(key, value)` via `getAll` +
    /// `getAllKeys`, each awaited through [`Self::idb_request_result`].
    async fn idb_all_entries(
        db: &web_sys::IdbDatabase,
        store: &str,
    ) -> Result<Vec<(String, Vec<u8>)>, SecureKeyStoreError> {
        use js_sys::{Object, Reflect, Uint8Array};
        use wasm_bindgen::{JsCast, JsValue};
        let tx = db
            .transaction_with_str(store)
            .map_err(|err| SecureKeyStoreError::Backend(format!("tx open: {err:?}")))?;
        let obj_store = tx
            .object_store(store)
            .map_err(|err| SecureKeyStoreError::Backend(format!("objectStore: {err:?}")))?;
        // getAll + getAllKeys is the simplest cross-browser way to
        // enumerate without cursor-callback gymnastics.
        let values_req = obj_store
            .get_all()
            .map_err(|err| SecureKeyStoreError::Backend(format!("getAll: {err:?}")))?;
        let keys_req = obj_store
            .get_all_keys()
            .map_err(|err| SecureKeyStoreError::Backend(format!("getAllKeys: {err:?}")))?;
        let values = Self::idb_request_result(&values_req)
            .await
            .map_err(|err| SecureKeyStoreError::Backend(format!("getAll awaited: {err:?}")))?;
        let keys = Self::idb_request_result(&keys_req)
            .await
            .map_err(|err| SecureKeyStoreError::Backend(format!("getAllKeys awaited: {err:?}")))?;
        let values_arr: js_sys::Array = values.into();
        let keys_arr: js_sys::Array = keys.into();
        let len = std::cmp::min(values_arr.length(), keys_arr.length()) as usize;
        let mut out = Vec::with_capacity(len);
        for i in 0..len as u32 {
            let key_value = keys_arr.get(i);
            let entry_value = values_arr.get(i);
            let Some(key_str) = key_value.as_string() else {
                continue;
            };
            // entry_value is an Object with { iv: Uint8Array, ct: Uint8Array }.
            let obj: Object = match entry_value.dyn_into() {
                Ok(o) => o,
                Err(_) => continue,
            };
            let iv = Reflect::get(&obj, &JsValue::from_str("iv"))
                .ok()
                .and_then(|v| v.dyn_into::<Uint8Array>().ok());
            let ct = Reflect::get(&obj, &JsValue::from_str("ct"))
                .ok()
                .and_then(|v| v.dyn_into::<Uint8Array>().ok());
            let (Some(iv), Some(ct)) = (iv, ct) else {
                continue;
            };
            let mut iv_bytes = vec![0u8; iv.length() as usize];
            iv.copy_to(&mut iv_bytes);
            let mut ct_bytes = vec![0u8; ct.length() as usize];
            ct.copy_to(&mut ct_bytes);
            let mut packed = Vec::with_capacity(iv_bytes.len() + ct_bytes.len());
            packed.extend_from_slice(&iv_bytes);
            packed.extend_from_slice(&ct_bytes);
            out.push((key_str, packed));
        }
        Ok(out)
    }

    /// Encrypt `plain` against the non-extractable CryptoKey via
    /// `SubtleCrypto.encrypt({ name: "AES-GCM", iv })`. Returns
    /// `[iv (12 bytes) || ciphertext]` so the on-disk record is
    /// self-contained.
    async fn subtle_encrypt(
        crypto_key: &wasm_bindgen::JsValue,
        plain: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), SecureKeyStoreError> {
        use js_sys::{Object, Reflect, Uint8Array};
        use wasm_bindgen::{JsCast, JsValue};
        use wasm_bindgen_futures::JsFuture;
        let window = web_sys::window()
            .ok_or_else(|| SecureKeyStoreError::Unsupported("web_sys::window unavailable"))?;
        let subtle = window
            .crypto()
            .map_err(|err| SecureKeyStoreError::Backend(format!("crypto: {err:?}")))?
            .subtle();
        let mut iv = [0u8; 12];
        getrandom::fill(&mut iv)
            .map_err(|err| SecureKeyStoreError::Backend(format!("getrandom iv: {err}")))?;
        let iv_array = Uint8Array::new_with_length(12);
        iv_array.copy_from(&iv);
        let algo = Object::new();
        Reflect::set(
            &algo,
            &JsValue::from_str("name"),
            &JsValue::from_str("AES-GCM"),
        )
        .map_err(|err| SecureKeyStoreError::Backend(format!("algo name: {err:?}")))?;
        Reflect::set(&algo, &JsValue::from_str("iv"), &iv_array)
            .map_err(|err| SecureKeyStoreError::Backend(format!("algo iv: {err:?}")))?;
        let plain_array = Uint8Array::new_with_length(plain.len() as u32);
        plain_array.copy_from(plain);
        let key_typed: web_sys::CryptoKey = crypto_key
            .clone()
            .dyn_into()
            .map_err(|_| SecureKeyStoreError::Backend("wrapping key not CryptoKey".to_owned()))?;
        let promise = subtle
            .encrypt_with_object_and_buffer_source(&algo, &key_typed, plain_array.as_ref())
            .map_err(|err| SecureKeyStoreError::Backend(format!("subtle.encrypt: {err:?}")))?;
        let result = JsFuture::from(promise)
            .await
            .map_err(|err| SecureKeyStoreError::Backend(format!("encrypt awaited: {err:?}")))?;
        let buf: js_sys::ArrayBuffer = result.dyn_into().map_err(|_| {
            SecureKeyStoreError::Backend("encrypt did not return ArrayBuffer".to_owned())
        })?;
        let view = Uint8Array::new(&buf);
        let mut ct = vec![0u8; view.length() as usize];
        view.copy_to(&mut ct);
        Ok((iv.to_vec(), ct))
    }

    async fn subtle_decrypt(
        crypto_key: &wasm_bindgen::JsValue,
        packed: &[u8],
    ) -> Result<Vec<u8>, SecureKeyStoreError> {
        use js_sys::{Object, Reflect, Uint8Array};
        use wasm_bindgen::{JsCast, JsValue};
        use wasm_bindgen_futures::JsFuture;
        if packed.len() < 12 {
            return Err(SecureKeyStoreError::Backend(
                "subtle_decrypt: packed too short".to_owned(),
            ));
        }
        let (iv, ct) = packed.split_at(12);
        let window = web_sys::window()
            .ok_or_else(|| SecureKeyStoreError::Unsupported("web_sys::window unavailable"))?;
        let subtle = window
            .crypto()
            .map_err(|err| SecureKeyStoreError::Backend(format!("crypto: {err:?}")))?
            .subtle();
        let iv_array = Uint8Array::new_with_length(12);
        iv_array.copy_from(iv);
        let algo = Object::new();
        Reflect::set(
            &algo,
            &JsValue::from_str("name"),
            &JsValue::from_str("AES-GCM"),
        )
        .map_err(|err| SecureKeyStoreError::Backend(format!("algo name: {err:?}")))?;
        Reflect::set(&algo, &JsValue::from_str("iv"), &iv_array)
            .map_err(|err| SecureKeyStoreError::Backend(format!("algo iv: {err:?}")))?;
        let ct_array = Uint8Array::new_with_length(ct.len() as u32);
        ct_array.copy_from(ct);
        let key_typed: web_sys::CryptoKey = crypto_key
            .clone()
            .dyn_into()
            .map_err(|_| SecureKeyStoreError::Backend("wrapping key not CryptoKey".to_owned()))?;
        let promise = subtle
            .decrypt_with_object_and_buffer_source(&algo, &key_typed, ct_array.as_ref())
            .map_err(|err| SecureKeyStoreError::Backend(format!("subtle.decrypt: {err:?}")))?;
        let result = JsFuture::from(promise)
            .await
            .map_err(|err| SecureKeyStoreError::Backend(format!("decrypt awaited: {err:?}")))?;
        let buf: js_sys::ArrayBuffer = result.dyn_into().map_err(|_| {
            SecureKeyStoreError::Backend("decrypt did not return ArrayBuffer".to_owned())
        })?;
        let view = Uint8Array::new(&buf);
        let mut out = vec![0u8; view.length() as usize];
        view.copy_to(&mut out);
        Ok(out)
    }

    /// Persist `(iv, ct)` against `key` in the entries object store.
    /// Called from sync trait paths via `spawn_local`. Takes a borrowed
    /// `IdbDatabase` so the cached connection is reused instead of
    /// re-opening per write.
    async fn persist_entry_value(
        db: &web_sys::IdbDatabase,
        crypto_key: &wasm_bindgen::JsValue,
        key: &str,
        plain: &str,
    ) -> Result<(), SecureKeyStoreError> {
        use js_sys::{Object, Reflect, Uint8Array};
        use wasm_bindgen::JsValue;
        let (iv, ct) = Self::subtle_encrypt(crypto_key, plain.as_bytes()).await?;
        let entry = Object::new();
        let iv_array = Uint8Array::new_with_length(iv.len() as u32);
        iv_array.copy_from(&iv);
        let ct_array = Uint8Array::new_with_length(ct.len() as u32);
        ct_array.copy_from(&ct);
        Reflect::set(&entry, &JsValue::from_str("iv"), &iv_array)
            .map_err(|err| SecureKeyStoreError::Backend(format!("entry iv: {err:?}")))?;
        Reflect::set(&entry, &JsValue::from_str("ct"), &ct_array)
            .map_err(|err| SecureKeyStoreError::Backend(format!("entry ct: {err:?}")))?;
        Self::idb_put_value(db, Self::OBJECT_STORE_ENTRIES, key, entry.as_ref()).await
    }
}

impl std::fmt::Debug for IndexedDbSecureKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexedDbSecureKeyStore")
            .field("service_name", &self.service_name)
            .field("db_name", &self.db_name)
            .field(
                "cache_entries",
                &self.cache.lock().map(|g| g.len()).unwrap_or(0),
            )
            .field("crypto_key", &"<non-extractable CryptoKey>")
            .finish()
    }
}

impl SecureKeyStore for IndexedDbSecureKeyStore {
    fn store_secret(&self, key: &str, value: &str) -> Result<(), SecureKeyStoreError> {
        {
            let mut guard = self
                .cache
                .lock()
                .map_err(|err| SecureKeyStoreError::Backend(format!("cache lock: {err}")))?;
            guard.insert(key.to_owned(), value.to_owned());
        }
        // YOU-02-009: the async IndexedDB put below can lose a page-unload
        // race while dependent state (e.g. the MLS snapshot this secret
        // decrypts) is persisted *synchronously* to localStorage — leaving a
        // snapshot on disk whose decryption key never landed. Close the
        // ordering gap by synchronously writing an AEAD-wrapped fallback
        // copy to localStorage first. The mirror is transient: it is
        // removed once the IndexedDB put succeeds, and the boot-time H6
        // migration sweeps any unload-race survivor back into IndexedDB.
        // Ed25519 signing seeds — and the hard-logout journal, which embeds a
        // grant-binding seed — stay IndexedDB-only (H6 fail-closed): never mirrored to
        // the localStorage unload-race copy.
        let mirrored = if is_wasm_no_localstorage_mirror_key(key) {
            false
        } else {
            // Re-open the fallback per write so its wrapping seed is
            // guaranteed to exist in localStorage at mirror time (the H6
            // migration prunes the seed after each boot sweep).
            match LocalStorageSecureKeyStore::new(&self.service_name)
                .and_then(|fallback| fallback.store_unload_race_mirror(key, value))
            {
                Ok(()) => true,
                Err(err) => {
                    tracing::warn!(?err, key=%key, "localStorage unload-race mirror failed");
                    false
                }
            }
        };
        // Fire-and-forget persistence. Failures are logged; the cache
        // already has the new value so subsequent reads succeed even
        // if the write loses out to a page-unload race (in which case
        // the localStorage mirror above is the recovery copy).
        //
        // Reuse the cached `IdbDatabase` handle instead of opening a
        // fresh one per write.
        let key_for_async = key.to_owned();
        let value_for_async = value.to_owned();
        let service_name_for_async = self.service_name.clone();
        let crypto_key = self.crypto_key.clone();
        let db = self.db.clone();
        wasm_bindgen_futures::spawn_local(async move {
            match Self::persist_entry_value(&db.0, &crypto_key.0, &key_for_async, &value_for_async)
                .await
            {
                Ok(()) => {
                    // Durable in IndexedDB — drop the transient
                    // localStorage mirror so secrets do not linger in
                    // the weaker tier (H6 threat model).
                    if mirrored
                        && let Ok(fallback) =
                            LocalStorageSecureKeyStore::new(&service_name_for_async)
                        && let Err(err) = fallback.delete_secret(&key_for_async)
                    {
                        tracing::warn!(?err, key=%key_for_async, "mirror cleanup failed");
                    }
                }
                Err(err) => {
                    tracing::warn!(?err, key=%key_for_async, "indexedDB persist failed");
                }
            }
        });
        Ok(())
    }

    fn store_secret_durable<'a>(
        &'a self,
        key: &'a str,
        value: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), SecureKeyStoreError>> + 'a>>
    {
        // Update the in-memory cache synchronously (same as `store_secret`) so
        // concurrent reads in this session observe the value immediately.
        if let Ok(mut guard) = self.cache.lock() {
            guard.insert(key.to_owned(), value.to_owned());
        }
        Box::pin(async move {
            // AWAIT the real IndexedDB put: unlike `store_secret`'s
            // fire-and-forget `spawn_local`, this resolves only after the value
            // is durably committed, closing the unload-race window. Used by
            // callers that must guarantee durability before a remote party
            // depends on the secret (e.g. the MLS KeyPackage init key before the
            // KeyPackage is advertised to the server).
            Self::persist_entry_value(&self.db.0, &self.crypto_key.0, key, value).await
        })
    }

    fn get_secret(&self, key: &str) -> Result<Option<String>, SecureKeyStoreError> {
        let guard = self
            .cache
            .lock()
            .map_err(|err| SecureKeyStoreError::Backend(format!("cache lock: {err}")))?;
        Ok(guard.get(key).cloned())
    }

    fn delete_secret(&self, key: &str) -> Result<(), SecureKeyStoreError> {
        {
            let mut guard = self
                .cache
                .lock()
                .map_err(|err| SecureKeyStoreError::Backend(format!("cache lock: {err}")))?;
            guard.remove(key);
        }
        // YOU-02-009: also drop any transient localStorage mirror left by
        // `store_secret` so a deleted secret cannot be resurrected by the
        // boot-time migration sweep.
        if let Ok(fallback) = LocalStorageSecureKeyStore::new(&self.service_name)
            && let Err(err) = fallback.delete_secret(key)
        {
            tracing::warn!(?err, key=%key, "localStorage mirror delete failed");
        }
        // Reuse the cached `IdbDatabase` handle for the spawned delete.
        let key_for_async = key.to_owned();
        let db = self.db.clone();
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(err) =
                Self::idb_delete_value(&db.0, Self::OBJECT_STORE_ENTRIES, &key_for_async).await
            {
                tracing::warn!(?err, key=%key_for_async, "indexedDB delete failed");
            }
        });
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "indexed_db_subtle_aes_gcm"
    }
}

/// wasm32-only async upgrade path.
///
/// The boot sequence on wasm32 looks like:
///
///   1. App `main` calls [`super::default_secure_key_store`] synchronously and receives a
///      [`LocalStorageSecureKeyStore`]. This unblocks first paint without waiting on
///      IndexedDB/SubtleCrypto.
///   2. App `main` then `spawn_local`s an async task that calls
///      `upgrade_wasm_secure_key_store_async(service_name).await`, which returns either:
///        * `Ok(Some(store))` — a fully-initialised [`IndexedDbSecureKeyStore`] installed as the
///          process-wide default returned by [`super::default_secure_key_store`].
///        * `Ok(None)` — IndexedDB or SubtleCrypto were unavailable (private-mode Firefox, file://
///          origin, Tor Browser hardened). Keep the LocalStorage store only for non-signing
///          secrets; signer bootstrap remains fail-closed.
///        * `Err(...)` — backend failure during init. Caller should log and keep the LocalStorage
///          store only for non-signing secrets.
///   3. The first time an entry is written through the IndexedDB store,
///      [`migrate_localstorage_entries_to_indexeddb`] (also async) can be invoked to copy any
///      pre-existing wrapped secrets across, then drop the LocalStorage seed.
///
/// Returning `Option<Arc<...>>` rather than panicking on
/// "browser doesn't support this" mirrors the rest of the secure
/// key store contract (sync `default_secure_key_store` also falls
/// back to `MemorySecureKeyStore` rather than crashing).
pub async fn upgrade_wasm_secure_key_store_async(
    service_name: &str,
) -> Result<Option<Arc<dyn SecureKeyStore>>, SecureKeyStoreError> {
    // Idempotent: if the upgraded IndexedDB store is already installed, return
    // it instead of building a SECOND one. A second `new_async` re-runs
    // `load_or_derive_wrapping_key`, and a mistimed derive would overwrite the
    // persisted `primary` wrapping key with a fresh random-salt one — orphaning
    // every entry the first store encrypted (decrypt fails with `OperationError`
    // on the next load, silently dropping secrets like the MLS KeyPackage init
    // key). `ensure_wasm_secure_key_store_ready` guards its own call site, but
    // `upgrade_*` is also invoked directly (app boot), so it must guard too.
    if let Some(store) = WASM_UPGRADED_SECURE_KEY_STORE.get() {
        return Ok(Some(store.clone()));
    }
    static UPGRADE_MUTEX: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    let _upgrade_guard = UPGRADE_MUTEX
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    if let Some(store) = WASM_UPGRADED_SECURE_KEY_STORE.get() {
        return Ok(Some(store.clone()));
    }
    // Probe for SubtleCrypto first — older browsers / file:// origins
    // expose `crypto` but not `crypto.subtle`. We can't reasonably
    // recover from a missing SubtleCrypto, so return `Ok(None)` and
    // let the caller keep the LocalStorage fallback.
    if !indexeddb_and_subtle_available() {
        tracing::info!("IndexedDB or SubtleCrypto unavailable; keeping LocalStorage store");
        return Ok(None);
    }
    let store = IndexedDbSecureKeyStore::new_async(service_name).await?;
    // One-shot migration of any pre-existing LocalStorage entries
    // into the new IndexedDB store, then prune the LocalStorage side so a future
    // disk dump can't recover the seed alongside the ciphertext.
    let migrated = migrate_localstorage_entries_to_indexeddb(service_name, &store)
        .await
        .unwrap_or_else(|err| {
            tracing::warn!(?err, "H6 LocalStorage→IndexedDB migration failed");
            0
        });
    if migrated > 0 {
        tracing::info!("H6 migration: {migrated} entry(s) migrated from LocalStorage to IndexedDB");
    }
    let store: Arc<dyn SecureKeyStore> = Arc::new(store);
    let _ = WASM_UPGRADED_SECURE_KEY_STORE.set(store.clone());
    Ok(Some(store))
}

/// Walk `localStorage` looking for keys under the
/// `inkson.secret.<service_name>.*` prefix written by
/// [`LocalStorageSecureKeyStore`], decrypt each via the
/// existing AEAD wrapping seed, re-store under the IndexedDB tier
/// via [`IndexedDbSecureKeyStore::store_secret`], then `removeItem`
/// the original localStorage key plus the wrapping seed itself.
///
/// Ed25519 signing seeds are deleted instead of migrated in the production
/// hardening path. The `wasm-localstorage-secrets-test` feature is the
/// test-only exception: first-paint fixtures may already have generated a valid
/// session-device seed in localStorage, so migration preserves it to keep later
/// recovery-policy signatures bound to the same authorized device key.
///
/// Returns the count of migrated entries. Silently skips entries
/// that fail to decrypt — they're either corrupted or written by a
/// different installation (different wrapping_seed). A
/// `Ok(_)` return means migration ran (possibly with skipped
/// entries); `Err` indicates an environmental failure like no
/// `window.localStorage` (private-mode Firefox, file:// origin).
///
/// Idempotent: a second run finds nothing to migrate and returns 0.
pub async fn migrate_localstorage_entries_to_indexeddb(
    service_name: &str,
    indexed_store: &IndexedDbSecureKeyStore,
) -> Result<usize, SecureKeyStoreError> {
    let storage = match LocalStorageSecureKeyStore::storage() {
        Ok(s) => s,
        Err(_) => return Ok(0),
    };
    // Read the H2 wrapping seed (still bytes in localStorage — that
    // is the threat model H6 is moving away from). When absent
    // there's nothing to migrate.
    let seed_key = LocalStorageSecureKeyStore::wrapping_seed_key(service_name);
    let wrapping_seed_b64 = match storage.get_item(&seed_key) {
        Ok(Some(b)) => b,
        Ok(None) => return Ok(0),
        Err(err) => {
            return Err(SecureKeyStoreError::Backend(format!(
                "migrate read seed: {err:?}"
            )));
        }
    };
    let wrapping_seed_bytes = match STANDARD_NO_PAD.decode(wrapping_seed_b64.as_bytes()) {
        Ok(b) => b,
        Err(_) => return Ok(0),
    };
    if wrapping_seed_bytes.len() != 32 {
        return Ok(0);
    }
    let mut wrapping_key = [0u8; 32];
    wrapping_key.copy_from_slice(&wrapping_seed_bytes);

    // Enumerate localStorage entries whose key matches the H2
    // prefix `inkson.secret.<service_name>.*` (excluding the
    // wrap_seed key itself).
    let prefix = format!("inkson.secret.{service_name}.");
    let length = storage
        .length()
        .map_err(|err| SecureKeyStoreError::Backend(format!("ls length: {err:?}")))?;
    let mut candidates: Vec<String> = Vec::new();
    for i in 0..length {
        let key = match storage.key(i) {
            Ok(Some(k)) => k,
            _ => continue,
        };
        if key == seed_key {
            continue;
        }
        if !key.starts_with(&prefix) {
            continue;
        }
        candidates.push(key);
    }
    let mut migrated = 0usize;
    let mut removed_sensitive = 0usize;
    for full_key in &candidates {
        let entry_name = full_key
            .strip_prefix(&prefix)
            .unwrap_or(full_key.as_str())
            .to_owned();
        if is_wasm_ed25519_seed_key(&entry_name) && !wasm_localstorage_secret_downgrade_enabled() {
            let _ = storage.remove_item(full_key);
            removed_sensitive += 1;
            tracing::warn!(
                key=%entry_name,
                "H6 migrate: removed localStorage Ed25519 seed instead of decrypting or migrating it"
            );
            continue;
        }
        let wrapped = match storage.get_item(full_key) {
            Ok(Some(v)) => v,
            _ => continue,
        };
        let Ok(Some(plain)) = unwrap_secret(&wrapped, &wrapping_key) else {
            tracing::warn!(key=%entry_name, "H6 migrate: decrypt failed; skipping");
            continue;
        };
        if let Err(err) = indexed_store.store_secret(&entry_name, &plain) {
            tracing::warn!(?err, key=%entry_name, "H6 migrate: IDB write failed");
            continue;
        }
        // Remove the LocalStorage copy only after the IDB write
        // returns Ok. The IDB persistence task is fire-and-forget
        // (see `IndexedDbSecureKeyStore::store_secret` doc-comment),
        // so we accept a small window where both sides could exist
        // — the next migration run will reconcile.
        let _ = storage.remove_item(full_key);
        migrated += 1;
    }
    // Finally drop the wrapping seed too, so a future disk dump
    // only carries the IndexedDB's non-extractable CryptoKey.
    if migrated > 0 || removed_sensitive > 0 {
        let _ = storage.remove_item(&seed_key);
    }
    if removed_sensitive > 0 {
        tracing::warn!(
            "H6 migration: removed {removed_sensitive} localStorage Ed25519 seed entry/entries"
        );
    }
    Ok(migrated)
}

fn indexeddb_and_subtle_available() -> bool {
    let Some(window) = web_sys::window() else {
        return false;
    };
    let idb_present = window.indexed_db().ok().flatten().is_some();
    // `crypto.subtle()` on web_sys returns a `SubtleCrypto` directly
    // (no `Result` / `Option`), but the underlying property access
    // panics on browsers that don't expose it. Probe by catching the
    // JS-side `undefined` via a runtime check: convert the SubtleCrypto
    // reference into a JsValue and verify it's not undefined / null.
    let subtle_present = window
        .crypto()
        .map(|c| {
            let subtle: wasm_bindgen::JsValue = c.subtle().into();
            !subtle.is_undefined() && !subtle.is_null()
        })
        .unwrap_or(false);
    if !(idb_present && subtle_present) {
        tracing::warn!(
            target: "secure_store",
            idb_present,
            subtle_present,
            "indexeddb_and_subtle_available()=false — secure store cannot upgrade to IndexedDb tier (this forces Ok(None) and breaks all account secrets)"
        );
    }
    idb_present && subtle_present
}
