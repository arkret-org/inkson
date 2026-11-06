use base64::Engine as _;

use super::*;
use crate::config::{AccountProfile, LocalConfigStore, MultiProfileConfig};
use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStoreError};

struct Fixture {
    _directory: tempfile::TempDir,
    accounts: Vec<ActiveAccountContext>,
    config: LocalConfigStore,
    keys: MemorySecureKeyStore,
}

async fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let principal = format!(
        "ak:did_core:web:session-menu.example:{}",
        crate::operation::uuid_v7()
    );
    let mut config = LocalConfigStore::with_path(directory.path().join("config.json"));
    let mut profiles = MultiProfileConfig::default();
    let keys = MemorySecureKeyStore::new();
    let mut accounts = Vec::new();
    for (index, name) in ["a", "b", "c"].iter().enumerate() {
        let account = crate::test_support::AccountFixture::new(&principal)
            .station(&format!("ak:did_core:web:session-{name}.example"))
            .server_url(&format!("https://session-{name}.example"))
            .profile_id(format!("session-{name}"))
            .build();
        let user =
            UserLocalStore::new(account.authority.clone(), account.device_id.clone()).unwrap();
        user.save_signing_seed(&keys, &[0x40 + index as u8; 32])
            .unwrap();
        user.save_grant_binding_seed_b64url_durable(
            &keys,
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1 + index as u8; 32]),
        )
        .await
        .unwrap();
        let grant = PersistedSessionGrant {
            grant_jwt: format!("grant-{name}"),
            session_private_key_pem: String::new(),
            grant_id: format!("grant-id-{name}"),
            audience_id: account.authority.station_id.clone(),
            granted_scope: vec![],
            account_id: account.authority.clone(),
            device_id: account.device_id.clone(),
            station_url: account.server_url.clone(),
            grant_expires_at: None,
            stored_at: chrono::Utc::now(),
        };
        user.save_secret(
            &keys,
            LocalStateStore::SECURE_SESSION_GRANT_KEY,
            &serde_json::to_string(&grant).unwrap(),
        )
        .unwrap();
        user.save_secret(&keys, LocalStateStore::SECURE_DPOP_DEVICE_KEY, "{}")
            .unwrap();
        profiles
            .upsert_and_activate(AccountProfile::new(
                account.clone(),
                format!("credential-{name}"),
            ))
            .unwrap();
        accounts.push(account);
    }
    config.save_profiles(&profiles).unwrap();
    Fixture {
        _directory: directory,
        accounts,
        config,
        keys,
    }
}

fn user(account: &ActiveAccountContext) -> UserLocalStore {
    UserLocalStore::new(account.authority.clone(), account.device_id.clone()).unwrap()
}

#[tokio::test]
async fn bulk_logout_journals_each_holder_and_preserves_identity_and_unselected_account() {
    let f = fixture().await;
    let selected = &f.accounts[..2];
    let records = journal_accounts(selected, &f.accounts[0], None, &f.keys)
        .await
        .unwrap();
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(PendingLogout::has_coauth_revoke));
    assert_ne!(records[0].authority, records[1].authority);
    assert_ne!(records[0].device_jkt, records[1].device_jkt);
    clear_account_sessions(selected, &f.keys).await.unwrap();
    for account in selected {
        let user = user(account);
        assert!(
            user.load_secret(&f.keys, LocalStateStore::SECURE_SESSION_GRANT_KEY)
                .unwrap()
                .is_none()
        );
        assert!(user.load_grant_binding_seed(&f.keys).unwrap().is_none());
        assert!(user.load_signing_seed(&f.keys).unwrap().is_some());
    }
    assert!(
        user(&f.accounts[2])
            .load_grant_binding_seed(&f.keys)
            .unwrap()
            .is_some()
    );
    let profiles = f.config.load_profiles();
    assert!(profiles.profiles[0].session_credential.is_empty());
    assert!(profiles.profiles[1].session_credential.is_empty());
    assert_eq!(profiles.profiles[2].session_credential, "credential-c");
    assert_eq!(
        crate::pending_logout::restore_pending_logouts(&f.keys)
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn current_logout_does_not_clear_the_other_saved_sessions() {
    let f = fixture().await;
    journal_accounts(&f.accounts[..1], &f.accounts[0], None, &f.keys)
        .await
        .unwrap();
    clear_account_sessions(&f.accounts[..1], &f.keys)
        .await
        .unwrap();
    for account in &f.accounts[1..] {
        assert!(
            user(account)
                .load_secret(&f.keys, LocalStateStore::SECURE_SESSION_GRANT_KEY)
                .unwrap()
                .is_some()
        );
        assert!(
            user(account)
                .load_grant_binding_seed(&f.keys)
                .unwrap()
                .is_some()
        );
    }
    assert_eq!(
        f.config.load_profiles().profiles[1].session_credential,
        "credential-b"
    );
}

struct FailingStore {
    inner: MemorySecureKeyStore,
    journal: bool,
    delete: Option<String>,
}
impl SecureKeyStore for FailingStore {
    fn store_secret_bytes(&self, key: &str, value: &[u8]) -> Result<(), SecureKeyStoreError> {
        if self.journal
            && key.starts_with(crate::secure_key_store::PENDING_LOGOUT_SECRET_KEY_PREFIX)
        {
            return Err(SecureKeyStoreError::Backend("journal unavailable".into()));
        }
        self.inner.store_secret_bytes(key, value)
    }
    fn get_secret_bytes(
        &self,
        key: &str,
    ) -> Result<Option<arkret_sdk::KeyBytes>, SecureKeyStoreError> {
        self.inner.get_secret_bytes(key)
    }
    fn delete_secret(&self, key: &str) -> Result<(), SecureKeyStoreError> {
        if self.delete.as_deref() == Some(key) {
            return Err(SecureKeyStoreError::Backend("delete unavailable".into()));
        }
        self.inner.delete_secret(key)
    }
    fn list_secret_keys(&self, prefix: Option<&str>) -> Result<Vec<String>, SecureKeyStoreError> {
        self.inner.list_secret_keys(prefix)
    }
    fn backend_info(&self) -> garth::SecureKeyStoreBackendInfo {
        self.inner.backend_info()
    }
}

#[tokio::test]
async fn journal_failure_keeps_live_credentials_and_no_wrong_account_holder_is_accepted() {
    let f = fixture().await;
    let keys = FailingStore {
        inner: f.keys,
        journal: true,
        delete: None,
    };
    assert!(
        journal_accounts(&f.accounts[..2], &f.accounts[0], None, &keys)
            .await
            .is_err()
    );
    assert!(
        user(&f.accounts[0])
            .load_grant_binding_seed(&keys)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        f.config.load_profiles().profiles[0].session_credential,
        "credential-a"
    );
    let wrong = user(&f.accounts[0])
        .load_secret(&keys, LocalStateStore::SECURE_SESSION_GRANT_KEY)
        .unwrap()
        .unwrap();
    user(&f.accounts[1])
        .save_secret(&keys, LocalStateStore::SECURE_SESSION_GRANT_KEY, &wrong)
        .unwrap();
    let keys = FailingStore {
        inner: keys.inner,
        journal: false,
        delete: None,
    };
    assert!(
        journal_accounts(&f.accounts[1..2], &f.accounts[0], None, &keys)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn delete_failure_still_clears_other_selected_accounts_and_keeps_the_journals() {
    let f = fixture().await;
    let failed = user(&f.accounts[0]).secret_key(LocalStateStore::SECURE_SESSION_GRANT_KEY);
    let keys = FailingStore {
        inner: f.keys,
        journal: false,
        delete: Some(failed),
    };
    journal_accounts(&f.accounts[..2], &f.accounts[0], None, &keys)
        .await
        .unwrap();
    assert!(
        clear_account_sessions(&f.accounts[..2], &keys)
            .await
            .is_err()
    );
    assert!(
        user(&f.accounts[1])
            .load_secret(&keys, LocalStateStore::SECURE_SESSION_GRANT_KEY)
            .unwrap()
            .is_none()
    );
    assert!(
        user(&f.accounts[0])
            .load_signing_seed(&keys)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        crate::pending_logout::restore_pending_logouts(&keys)
            .unwrap()
            .len(),
        2
    );
}
