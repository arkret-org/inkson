# Host-side `HostSecretBridge` reference implementations

Sprint Q1 第二十二增量 (H1) inverted the mobile FFI relationship:
inkson exposes a [`HostSecretBridge`][bridge] trait, and the host
runtime (Android shell + iOS shell that embed the Dioxus app)
implements that trait + registers it via
[`install_host_secret_bridge`][install] at startup.

Sprint Q1 第二十四增量 (H1-mobile-host) ships **reference
implementations** for the host side that drop into a Dioxus mobile
project. The inkson / arkret-rust-sdk / soland workspaces do NOT
link the JNI / Objective-C code — they can't, because the mobile
toolchain isn't wired into the regular `cargo build`. The host
project pastes these in, swaps the module path / package, then
calls `install_host_secret_bridge(Arc::new(...))` from its
`AppDelegate.didFinishLaunching` / `MainActivity.onCreate`.

The phase-3 local 1.0 milestone does not ship iOS or Android artifacts. Treat
this document as a future host-runtime contract, not a required build step for
the local desktop/web release.

[bridge]: ../src/secure_key_store/mod.rs
[install]: ../src/secure_key_store/mod.rs

---

## 1. Android Keystore via JNI

Bridge that proxies `put/get/delete` through a tiny Java helper
class that uses `java.security.KeyStore` with provider
`"AndroidKeyStore"`. AES-256-GCM is the recommended cipher; the
helper can also require biometric unlock per
`KeyGenParameterSpec.Builder::setUserAuthenticationRequired(true)`
when the host wants step-up.

### 1.1 Java helper (`SecureKeyStoreBridge.java`)

Drop in `app/src/main/java/com/arkret/inkson/SecureKeyStoreBridge.java`:

```java
package com.arkret.inkson;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Backing store for HostSecretBridge.put/get/delete on Android. */
public final class SecureKeyStoreBridge {
    private static final String PROVIDER = "AndroidKeyStore";
    private static final String AES_ALG = KeyProperties.KEY_ALGORITHM_AES;
    private static final int GCM_TAG_BITS = 128;
    private static final int IV_BYTES = 12;

    /** Returns base64-URL-safe-no-pad ciphertext (12-byte IV + ct). */
    public static String put(String serviceName, String key, String value) throws Exception {
        SecretKey aes = loadOrCreateKey(aliasFor(serviceName, key));
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aes);
        byte[] iv = cipher.getIV();
        byte[] ct = cipher.doFinal(value.getBytes("UTF-8"));
        ByteArrayOutputStream packed = new ByteArrayOutputStream(iv.length + ct.length);
        packed.write(iv);
        packed.write(ct);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(packed.toByteArray());
    }

    /** Returns null when alias absent. Throws on decryption / Keystore errors. */
    public static String get(String serviceName, String key) throws Exception {
        KeyStore ks = KeyStore.getInstance(PROVIDER);
        ks.load(null);
        String alias = aliasFor(serviceName, key);
        if (!ks.containsAlias(alias)) {
            return null;
        }
        // NOTE: This signature is simplified — production code stores
        // the IV+ciphertext blob in EncryptedSharedPreferences (or a
        // dedicated SQLite table) keyed by alias, then retrieves +
        // splits + GCM-decrypts here. The wire-up to the Rust bridge
        // is unchanged either way: `get` returns the plaintext String.
        throw new UnsupportedOperationException(
            "wire IV+ct storage backend (EncryptedSharedPreferences recommended)"
        );
    }

    public static void delete(String serviceName, String key) throws Exception {
        KeyStore ks = KeyStore.getInstance(PROVIDER);
        ks.load(null);
        String alias = aliasFor(serviceName, key);
        if (ks.containsAlias(alias)) {
            ks.deleteEntry(alias);
        }
    }

    private static String aliasFor(String serviceName, String key) {
        return serviceName + ":" + key;
    }

    private static SecretKey loadOrCreateKey(String alias) throws Exception {
        KeyStore ks = KeyStore.getInstance(PROVIDER);
        ks.load(null);
        if (ks.containsAlias(alias)) {
            return (SecretKey) ks.getKey(alias, null);
        }
        KeyGenerator kg = KeyGenerator.getInstance(AES_ALG, PROVIDER);
        kg.init(
            new KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(false)
                .build()
        );
        return kg.generateKey();
    }
}
```

### 1.2 Rust JNI bridge

```rust
use std::sync::Arc;

use jni::{JavaVM, JNIEnv, objects::JObject};
use inkson::secure_key_store::{
    HostSecretBridge, SecureKeyStoreError, install_host_secret_bridge,
};

pub struct AndroidJniSecretBridge {
    jvm: Arc<JavaVM>,
}

impl AndroidJniSecretBridge {
    pub fn new(jvm: JavaVM) -> Self {
        Self { jvm: Arc::new(jvm) }
    }

    fn with_env<R>(&self, f: impl FnOnce(&mut JNIEnv) -> Result<R, SecureKeyStoreError>) -> Result<R, SecureKeyStoreError> {
        let mut env = self
            .jvm
            .attach_current_thread()
            .map_err(|e| SecureKeyStoreError::Backend(format!("JNI attach: {e}")))?;
        f(&mut env)
    }
}

impl HostSecretBridge for AndroidJniSecretBridge {
    fn put(&self, service_name: &str, key: &str, value: &str) -> Result<(), SecureKeyStoreError> {
        self.with_env(|env| {
            let s_service: JObject = env
                .new_string(service_name)
                .map_err(|e| SecureKeyStoreError::Backend(format!("new_string service: {e}")))?
                .into();
            let s_key: JObject = env
                .new_string(key)
                .map_err(|e| SecureKeyStoreError::Backend(format!("new_string key: {e}")))?
                .into();
            let s_val: JObject = env
                .new_string(value)
                .map_err(|e| SecureKeyStoreError::Backend(format!("new_string val: {e}")))?
                .into();
            env.call_static_method(
                "com/arkret/inkson/SecureKeyStoreBridge",
                "put",
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                &[(&s_service).into(), (&s_key).into(), (&s_val).into()],
            )
            .map_err(|e| SecureKeyStoreError::Backend(format!("call put: {e}")))?;
            Ok(())
        })
    }

    fn get(&self, service_name: &str, key: &str) -> Result<Option<String>, SecureKeyStoreError> {
        self.with_env(|env| {
            let s_service: JObject = env
                .new_string(service_name)
                .map_err(|e| SecureKeyStoreError::Backend(format!("new_string service: {e}")))?
                .into();
            let s_key: JObject = env
                .new_string(key)
                .map_err(|e| SecureKeyStoreError::Backend(format!("new_string key: {e}")))?
                .into();
            let ret = env
                .call_static_method(
                    "com/arkret/inkson/SecureKeyStoreBridge",
                    "get",
                    "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                    &[(&s_service).into(), (&s_key).into()],
                )
                .map_err(|e| SecureKeyStoreError::Backend(format!("call get: {e}")))?;
            let jstr = ret
                .l()
                .map_err(|e| SecureKeyStoreError::Backend(format!("ret unwrap: {e}")))?;
            if jstr.is_null() {
                return Ok(None);
            }
            let rust_str = env
                .get_string((&jstr).into())
                .map_err(|e| SecureKeyStoreError::Backend(format!("get_string: {e}")))?;
            Ok(Some(rust_str.into()))
        })
    }

    fn delete(&self, service_name: &str, key: &str) -> Result<(), SecureKeyStoreError> {
        self.with_env(|env| {
            let s_service: JObject = env
                .new_string(service_name)
                .map_err(|e| SecureKeyStoreError::Backend(format!("new_string service: {e}")))?
                .into();
            let s_key: JObject = env
                .new_string(key)
                .map_err(|e| SecureKeyStoreError::Backend(format!("new_string key: {e}")))?
                .into();
            env.call_static_method(
                "com/arkret/inkson/SecureKeyStoreBridge",
                "delete",
                "(Ljava/lang/String;Ljava/lang/String;)V",
                &[(&s_service).into(), (&s_key).into()],
            )
            .map_err(|e| SecureKeyStoreError::Backend(format!("call delete: {e}")))?;
            Ok(())
        })
    }

    fn backend_label(&self) -> &'static str {
        "android-keystore"
    }
}

/// Call this from the JNI `JNI_OnLoad` or from
/// `MainActivity.onCreate` via a `Java_com_arkret_inkson_RustBridge_init`
/// `extern "C"` shim. Receives the `JavaVM` reference that lives for
/// the process lifetime.
pub fn register_android_keystore_bridge(jvm: JavaVM) {
    let bridge = Arc::new(AndroidJniSecretBridge::new(jvm));
    install_host_secret_bridge(bridge as Arc<dyn HostSecretBridge>);
}
```

---

## 2. iOS Keychain via Security.framework

### 2.1 Rust Obj-C FFI bridge

```rust
use std::ffi::c_void;
use std::sync::Arc;

use inkson::secure_key_store::{
    HostSecretBridge, SecureKeyStoreError, install_host_secret_bridge,
};

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecItemAdd(attributes: *const c_void, result: *mut *mut c_void) -> i32;
    fn SecItemCopyMatching(query: *const c_void, result: *mut *mut c_void) -> i32;
    fn SecItemDelete(query: *const c_void) -> i32;
}

pub struct IosKeychainBridge;

impl HostSecretBridge for IosKeychainBridge {
    fn put(&self, service_name: &str, key: &str, value: &str) -> Result<(), SecureKeyStoreError> {
        // Build a CFDictionary with:
        //   kSecClass               = kSecClassGenericPassword
        //   kSecAttrService         = service_name
        //   kSecAttrAccount         = key
        //   kSecValueData           = value.as_bytes()  (CFData)
        //   kSecAttrAccessible      = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        // The CF construction is verbose enough that production code
        // typically wraps it in an Objective-C `+ (BOOL) put:` selector
        // on a `ArkretKeychainBridge` class and dispatches through
        // `objc::msg_send!` (or via `cocoa-foundation` / `objc2`).
        let _ = (service_name, key, value);
        // The CF marshalling boilerplate omitted here — production
        // implementation uses the `keychain-services` or `security-framework`
        // crate with `SecAccessibility::AfterFirstUnlockThisDeviceOnly`.
        Err(SecureKeyStoreError::Backend(
            "wire CFDictionary build before shipping".to_owned(),
        ))
    }

    fn get(&self, service_name: &str, key: &str) -> Result<Option<String>, SecureKeyStoreError> {
        let _ = (service_name, key);
        Err(SecureKeyStoreError::Backend(
            "wire CFDictionary build before shipping".to_owned(),
        ))
    }

    fn delete(&self, service_name: &str, key: &str) -> Result<(), SecureKeyStoreError> {
        let _ = (service_name, key);
        Err(SecureKeyStoreError::Backend(
            "wire CFDictionary build before shipping".to_owned(),
        ))
    }

    fn backend_label(&self) -> &'static str {
        "ios-keychain"
    }
}

pub fn register_ios_keychain_bridge() {
    install_host_secret_bridge(Arc::new(IosKeychainBridge) as Arc<dyn HostSecretBridge>);
}
```

### 2.2 Preferred crate-backed path

For production iOS / macOS, the easier route is to depend on the
[`security-framework`](https://docs.rs/security-framework) crate
and call its high-level `SecKeychain` / `SecItem` wrappers. The
trait surface stays the same — only the body of
`IosKeychainBridge::put / get / delete` changes from raw FFI to
`security_framework::passwords::set_generic_password(...)` etc.

The crate also handles `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
through its `SecAccessibility` enum.

---

## 3. Wire-up sequence

Both platforms follow the same shape:

```
1. host app starts
2. host registers the bridge:
     register_android_keystore_bridge(vm);   // Android
     // or
     register_ios_keychain_bridge();          // iOS
3. host mounts the Dioxus app
4. Dioxus app calls `default_secure_key_store("inkson")`
     → on Android/iOS path returns AndroidKeystoreSecureKeyStore /
       IosKeychainSecureKeyStore which delegate through the
       registered bridge
5. all subsequent OIDC refresh-token reads / writes / deletes strand
   through the OS keychain
```

The `OnceLock`-based registry means a host that forgets step 2
gets `MemorySecureKeyStore` as the documented fallback (with a
`tracing::warn!` line in the logs). The "secrets in plaintext heap"
caveat applies until the host wires its bridge.

---

## 4. Test contract

The inkson crate already provides `TestHostSecretBridge` (a
`HashMap<(service, key), value>`-backed implementation) under
`#[cfg(test)]` to verify the trait surface. Hosts that ship a real
bridge should mirror the assertions in
`secure_key_store::tests::host_bridge_store_namespaces_by_service_name`
to confirm their JNI / Obj-C implementation honours service-name
scoping + backend_label propagation.

---

## 5. Sprint history

- 第二十二增量 (H1): trait + delegation pattern landed in
  `secure_key_store/mod.rs`. `unimplemented!()` stubs replaced.
- 第二十四增量 (H1-mobile-host, this document): reference Android JNI
  + iOS Obj-C example code. Host projects paste + wire.
