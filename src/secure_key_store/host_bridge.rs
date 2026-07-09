//! Mobile host-bridge delegation: [`HostSecretBridge`] trait,
//! the process-wide bridge registry, and [`HostBridgeSecureKeyStore`].

use std::sync::Arc;

use garth::{SecretBytes, SecureKeyStoreBackendInfo};

use super::{SecureKeyStore, SecureKeyStoreError};

/// Mobile **host-bridge** delegation pattern for
/// Android Keystore + iOS Keychain access.
///
/// The mobile-platform FFI surface (JNI on Android,
/// `Security.framework` on iOS) cannot be cleanly initialised from
/// inside inkson alone — the Android Keystore path needs a `JNIEnv`
/// that's only valid on the current Java thread, and iOS Keychain
/// access against `kSecClassGenericPassword` needs Objective-C
/// runtime + an app-level entitlement. Both of those are owned by
/// the host runtime (Dioxus mobile + the platform-native shell that
/// embeds it).
///
/// We solve this by inverting the relationship: instead of inkson
/// linking against a mobile FFI crate, inkson exposes a
/// [`HostSecretBridge`] trait that the host implements and registers
/// via [`install_host_secret_bridge`]. When
/// [`super::default_secure_key_store`] runs on `target_os = "android"` or
/// `"ios"`, it constructs a [`HostBridgeSecureKeyStore`] that delegates
/// every store/get/delete through the installed bridge. The bridge
/// implementation lives in the host runtime where it has access to
/// `JNIEnv` / Security.framework.
///
/// Hosts that don't install a bridge get
/// [`super::MemorySecureKeyStore`] as the fallback (matches existing
/// "secrets in plaintext heap" caveat), so the API is forwards-
/// safe by default: a binary that never wires a bridge keeps working,
/// it just loses the OS-keychain tier.
///
/// The host implementation contract:
///
/// * **Android** — bridge methods call into a Java class (`com.arkret.inkson.SecureKeyStoreBridge`
///   or similar) via JNI. That class proxies to `java.security.KeyStore` with provider
///   `"AndroidKeyStore"`, aliasing entries as `"<service_name>:<key>"`. AES-256-GCM is the
///   recommended cipher; the platform Keystore can be configured to require user authentication /
///   biometrics before the key is unsealed.
/// * **iOS** — bridge methods call into Objective-C / Swift code that invokes `SecItemAdd`,
///   `SecItemCopyMatching`, and `SecItemDelete` against `kSecClassGenericPassword` keychain items.
///   `kSecAttrService` is set to `service_name`, `kSecAttrAccount` is set to the entry key.
///   `kSecAttrAccessible` defaults to `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` so secrets
///   do NOT propagate through iCloud Keychain.
///
/// Both bridges MUST be safe to call from arbitrary threads
/// (the trait demands `Send + Sync`). On Android that means each
/// call attaches the current thread to the JavaVM before issuing
/// JNI calls; on iOS Keychain Services is already thread-safe.
pub trait HostSecretBridge: Send + Sync {
    /// Persist `value` under `(service_name, key)` in the platform
    /// secure store. Overwrites silently when the alias already
    /// exists.
    fn put(&self, service_name: &str, key: &str, value: &str) -> Result<(), SecureKeyStoreError>;

    /// Load the secret under `(service_name, key)`. Returns `Ok(None)`
    /// when the alias is absent.
    fn get(&self, service_name: &str, key: &str) -> Result<Option<String>, SecureKeyStoreError>;

    /// Remove the secret. Idempotent — deleting an absent alias
    /// returns `Ok(())`.
    fn delete(&self, service_name: &str, key: &str) -> Result<(), SecureKeyStoreError>;

    /// Optional human-readable label surfaced via
    /// [`SecureKeyStore::backend_name`]. Default is
    /// `"host-bridge"`; hosts override to e.g. `"android-keystore"`
    /// or `"ios-keychain"` so diagnostic UI can distinguish them.
    fn backend_label(&self) -> &'static str {
        "host-bridge"
    }

    /// Phase A.6 #5: iOS Keychain `kSecAttrAccessGroup` identifier.
    ///
    /// On iOS, Keychain items default to the calling app's private
    /// access group (the `application-identifier` entitlement). When
    /// inkson ships extensions (Notification Service Extension for
    /// silent-push key unwrap, share extension, etc.) the extension and
    /// the main app need to share Keychain entries; the OS enforces
    /// that via a matching `kSecAttrAccessGroup` value on both sides
    /// of the boundary.
    ///
    /// The host runtime is the only place that knows the app-bundle's
    /// access-group identifier (it's a `$(AppIdentifierPrefix).<group>`
    /// string burned into the entitlements plist). Bridges return
    /// `Some(group)` to opt in, or `None` to keep the
    /// per-app-private default. Implementations that don't carry an
    /// access group (Android, desktop fallbacks, test stubs) should
    /// return `None`.
    ///
    /// The trait's default is `None` so existing implementations
    /// compile unchanged — they keep the private-access-group default
    /// which is the safe choice when no entitlement is configured.
    fn access_group_identifier(&self) -> Option<&str> {
        None
    }

    /// True when the bridge has been asked (typically by the user via a
    /// host-side setting toggle) to require a biometric / device-credential
    /// challenge before [`HostBridgeSecureKeyStore::store_secret`] and
    /// [`HostBridgeSecureKeyStore::get_secret`] succeed. The default is
    /// `false` so existing bridges compile unchanged — they retain the
    /// no-prompt behaviour that matches the pre-biometric contract.
    ///
    /// On Android the bridge typically maps this to
    /// `setUserAuthenticationRequired(true)` on the AndroidKeystore alias;
    /// on iOS it maps to a `SecAccessControl` with the
    /// `kSecAccessControlBiometryCurrentSet` / `kSecAccessControlUserPresence`
    /// flag. Both surfaces translate a failed prompt to
    /// [`SecureKeyStoreError::Backend`] with a "biometric" substring so
    /// the UI can detect "user cancelled" vs a real backend failure.
    fn biometric_challenge_required(&self) -> bool {
        false
    }

    /// Prompt the host runtime to perform a biometric (or device-credential
    /// fallback) authentication challenge. Returns `Ok(true)` when the user
    /// satisfied the prompt, `Ok(false)` when the user declined or cancelled,
    /// and `Err(...)` when the prompt could not be displayed (e.g. no
    /// enrolled biometrics, hardware unavailable). `reason` is a short
    /// human-readable string the host shows in the system biometric sheet.
    ///
    /// The default implementation returns `Ok(true)` so non-biometric
    /// bridges (desktop test stubs, the in-process unit-test bridge) keep
    /// compiling and behave as if the challenge always succeeds. Real
    /// Android / iOS bridges override this method to invoke
    /// `BiometricPrompt` / `LAContext.evaluatePolicy` respectively.
    fn biometric_authenticate(&self, _reason: &str) -> Result<bool, SecureKeyStoreError> {
        Ok(true)
    }
}

static HOST_SECRET_BRIDGE: std::sync::OnceLock<Arc<dyn HostSecretBridge>> =
    std::sync::OnceLock::new();

/// Register a [`HostSecretBridge`] implementation. Idempotent — the
/// first call wins; subsequent calls are no-ops and return `false`.
/// Hosts MUST call this **before** any secure-store consumer runs
/// (typically in the platform glue's `init()` hook before mounting
/// the Dioxus app).
///
/// Returns `true` on first install, `false` if a bridge was already
/// registered. The "first-write-wins" semantics match how the
/// Android `JavaVM` reference works: there is exactly one host
/// runtime per process, and re-registering would race against
/// in-flight secret reads.
pub fn install_host_secret_bridge(bridge: Arc<dyn HostSecretBridge>) -> bool {
    HOST_SECRET_BRIDGE.set(bridge).is_ok()
}

/// Test/diagnostic helper: did the host install a secret bridge?
pub fn host_secret_bridge_installed() -> bool {
    HOST_SECRET_BRIDGE.get().is_some()
}

/// [`SecureKeyStore`] implementation that delegates every operation
/// through the installed [`HostSecretBridge`]. Constructed by
/// [`super::default_secure_key_store`] on `target_os = "android"` and
/// `"ios"` when a bridge is registered; falls back to
/// [`super::MemorySecureKeyStore`] otherwise.
#[derive(Clone)]
pub struct HostBridgeSecureKeyStore {
    service_name: String,
    bridge: Arc<dyn HostSecretBridge>,
}

impl HostBridgeSecureKeyStore {
    /// Build a store that funnels calls through the supplied bridge.
    /// Use [`HostBridgeSecureKeyStore::from_installed`] when the
    /// bridge has been registered via
    /// [`install_host_secret_bridge`].
    pub fn new(service_name: impl Into<String>, bridge: Arc<dyn HostSecretBridge>) -> Self {
        Self {
            service_name: service_name.into(),
            bridge,
        }
    }

    /// Build a store backed by the currently-installed host bridge.
    /// Returns `None` when no bridge has been registered yet.
    pub fn from_installed(service_name: impl Into<String>) -> Option<Self> {
        let bridge = HOST_SECRET_BRIDGE.get()?.clone();
        Some(Self {
            service_name: service_name.into(),
            bridge,
        })
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }
}

impl std::fmt::Debug for HostBridgeSecureKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostBridgeSecureKeyStore")
            .field("service_name", &self.service_name)
            .field("bridge", &self.bridge.backend_label())
            .finish()
    }
}

impl HostBridgeSecureKeyStore {
    /// If the bridge has biometric protection enabled, prompt the user
    /// for a biometric/device-credential challenge and require an
    /// affirmative response. Returns `Err(Backend("biometric..."))` on
    /// user cancel so callers can distinguish "user declined" from a
    /// hardware failure via the `biometric` substring.
    fn require_biometric(&self, reason: &str) -> Result<(), SecureKeyStoreError> {
        if !self.bridge.biometric_challenge_required() {
            return Ok(());
        }
        match self.bridge.biometric_authenticate(reason)? {
            true => Ok(()),
            false => Err(SecureKeyStoreError::Backend(
                "biometric challenge declined or cancelled".to_owned(),
            )),
        }
    }
}

impl SecureKeyStore for HostBridgeSecureKeyStore {
    fn store_secret_bytes(&self, key: &str, value: &[u8]) -> Result<(), SecureKeyStoreError> {
        // The host bridge FFI (Android Keystore / iOS Keychain) exchanges string
        // secrets; every inkson caller stores UTF-8 and garth's default
        // `store_secret(&str)` routes here as valid UTF-8.
        let value = std::str::from_utf8(value).map_err(|err| {
            SecureKeyStoreError::Backend(format!("host-bridge secret not utf8: {err}"))
        })?;
        self.require_biometric("Authenticate to store secret")?;
        self.bridge.put(&self.service_name, key, value)
    }

    fn get_secret_bytes(&self, key: &str) -> Result<Option<SecretBytes>, SecureKeyStoreError> {
        self.require_biometric("Authenticate to access secret")?;
        Ok(self
            .bridge
            .get(&self.service_name, key)?
            .map(|value| SecretBytes::new(value.into_bytes())))
    }

    fn delete_secret(&self, key: &str) -> Result<(), SecureKeyStoreError> {
        // Deletion is intentionally NOT biometric-gated — letting users
        // remove an entry without re-auth lets them recover from a lost
        // biometric (e.g. enrolled fingerprint removed) without being
        // permanently locked out of overwriting the key.
        self.bridge.delete(&self.service_name, key)
    }

    fn list_secret_keys(&self, _prefix: Option<&str>) -> Result<Vec<String>, SecureKeyStoreError> {
        // The `HostSecretBridge` FFI contract exposes only put/get/delete, so the
        // platform keystore behind it cannot be enumerated from here.
        Err(SecureKeyStoreError::Unsupported(
            "host-bridge backend does not support secret key enumeration",
        ))
    }

    fn backend_info(&self) -> SecureKeyStoreBackendInfo {
        SecureKeyStoreBackendInfo {
            // Preserved verbatim: strands from the bridge label so diagnostic UI
            // can distinguish Android Keystore vs iOS Keychain.
            name: self.bridge.backend_label(),
            // Android Keystore / iOS Keychain are hardware-backed, non-exportable.
            hardware_backed: true,
            exportable: false,
        }
    }
}
