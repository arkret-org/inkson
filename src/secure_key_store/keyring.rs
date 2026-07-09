//! Desktop OS-keychain backed [`SecureKeyStore`] (macOS / Linux / Windows).

#![cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]

use garth::{SecretBytes, SecureKeyStoreBackendInfo};

use super::{SecureKeyStore, SecureKeyStoreError};

/// Desktop OS-keychain backend. Uses the `keyring` crate which routes
/// to:
///
/// * **macOS** — Security framework Keychain Services.
/// * **Linux** — freedesktop Secret Service (`libsecret` / GNOME Keyring / KWallet).
/// * **Windows** — Windows Credential Manager (`wincred`).
///
/// The store is keyed by a constant `service_name` (typically
/// `"inkson"` or `"inkson.test"`) plus the per-secret `key` as the
/// "username" slot. That two-level naming matches `cmdkey /list`,
/// `Keychain Access.app`, and `seahorse` UX.
#[derive(Clone, Debug)]
pub struct KeyringSecureKeyStore {
    service_name: String,
    /// Phase A.6 #4: snapshot of the service name captured at
    /// construction. `entry()` asserts that the current `service_name`
    /// matches this expected value before handing off to
    /// `keyring::Entry::new`, so any future code path that accidentally
    /// mutates `service_name` (or constructs an Entry against a
    /// different service) trips a panic instead of silently writing
    /// secrets under the wrong keychain bucket. The field is `Box<str>`
    /// (immutable) to make accidental mutation harder.
    expected_service: Box<str>,
}

impl KeyringSecureKeyStore {
    /// Construct a store whose entries land under
    /// `service_name`. Conventional value: `"inkson"`.
    pub fn new(service_name: impl Into<String>) -> Self {
        let service_name = service_name.into();
        let expected_service = service_name.clone().into_boxed_str();
        Self {
            service_name,
            expected_service,
        }
    }

    /// Service name passed to the `keyring` crate. Returned for
    /// diagnostic UI / test introspection.
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Phase A.6 #4: invariant check. The expected service name was
    /// captured at construction; verify that any caller / external
    /// reflection has not mutated `self.service_name` before we
    /// create the keychain Entry. If this fires, secrets would land
    /// under the wrong service bucket and become irretrievable from
    /// the legitimate `service_name()`-keyed path.
    fn assert_service_invariant(&self) -> Result<(), SecureKeyStoreError> {
        if self.service_name.as_str() != &*self.expected_service {
            return Err(SecureKeyStoreError::Backend(format!(
                "keyring service name drifted: current `{}` != expected `{}`",
                self.service_name, self.expected_service
            )));
        }
        Ok(())
    }

    fn entry(&self, key: &str) -> Result<keyring::Entry, SecureKeyStoreError> {
        self.assert_service_invariant()?;
        keyring::Entry::new(&self.service_name, key)
            .map_err(|err| SecureKeyStoreError::Backend(format!("entry init: {err}")))
    }
}

impl SecureKeyStore for KeyringSecureKeyStore {
    fn store_secret_bytes(&self, key: &str, value: &[u8]) -> Result<(), SecureKeyStoreError> {
        // The OS keychain slot is a "password" string; every inkson caller stores
        // UTF-8 (base64/JSON) and garth's default `store_secret(&str)` routes here
        // as valid UTF-8. Reject non-UTF-8 rather than changing the stored form.
        let value = std::str::from_utf8(value).map_err(|err| {
            SecureKeyStoreError::Backend(format!("keyring secret not utf8: {err}"))
        })?;
        let entry = self.entry(key)?;
        entry
            .set_password(value)
            .map_err(|err| SecureKeyStoreError::Backend(format!("set_password: {err}")))
    }

    fn get_secret_bytes(&self, key: &str) -> Result<Option<SecretBytes>, SecureKeyStoreError> {
        let entry = self.entry(key)?;
        match entry.get_password() {
            Ok(value) => Ok(Some(SecretBytes::new(value.into_bytes()))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(SecureKeyStoreError::Backend(format!("get_password: {err}"))),
        }
    }

    fn delete_secret(&self, key: &str) -> Result<(), SecureKeyStoreError> {
        let entry = self.entry(key)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(SecureKeyStoreError::Backend(format!(
                "delete_credential: {err}"
            ))),
        }
    }

    fn list_secret_keys(&self, _prefix: Option<&str>) -> Result<Vec<String>, SecureKeyStoreError> {
        // The `keyring` crate exposes no per-service enumeration (Secret Service /
        // Credential Manager / Keychain each need a platform-specific search that
        // the crate does not surface), so enumeration is genuinely unsupported on
        // this backend rather than silently empty.
        Err(SecureKeyStoreError::Unsupported(
            "keyring backend does not support secret key enumeration",
        ))
    }

    fn backend_info(&self) -> SecureKeyStoreBackendInfo {
        SecureKeyStoreBackendInfo {
            // Preserved verbatim (diagnostics + `default_secure_key_store` test).
            name: "keyring",
            // OS keychain: guarded by the platform credential store, not
            // guaranteed hardware-backed, and not plainly exportable via this API.
            hardware_backed: false,
            exportable: false,
        }
    }
}
