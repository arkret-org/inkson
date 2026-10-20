//! Private account/device journal for exact Contact confirmation retries.

use std::sync::{Arc, LazyLock, Mutex, Weak};

use arkret_sdk::contact_operations::{
    ContactCommitRequestBody, ContactContinuityCheckpointOutcome,
    ContactContinuityCheckpointRequestBody, ContactContinuityCheckpointStatus,
    ContactOperationOutcome, ContactPeer,
};
use serde::{Deserialize, Serialize};

use super::{AuthoringSessionFence, ContactCommitContext};
use crate::secure_key_store::{SecureKeyStore, UserLocalStore};

pub(crate) const SECRET_KEY: &str = "contact.pending_commit";
static OPERATIONS: LazyLock<
    Mutex<std::collections::BTreeMap<String, Weak<tokio::sync::Mutex<()>>>>,
> = LazyLock::new(|| Mutex::new(std::collections::BTreeMap::new()));

fn operation_lock(scope: &UserLocalStore) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks = OPERATIONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    locks.retain(|_, lock| lock.strong_count() > 0);
    let key = scope.secret_key(SECRET_KEY);
    if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    lock
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingRecord {
    authority: arkret_sdk::AccountId,
    device_id: arkret_sdk::DeviceId,
    verification_method: String,
    signer_key: String,
    intent_digest: String,
    request: PendingRequest,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum PendingRequest {
    Commit(Box<ContactCommitRequestBody>),
    Checkpoint {
        request: ContactContinuityCheckpointRequestBody,
        checkpoint_digest: Option<arkret_sdk::Hash>,
    },
}

impl PendingRecord {
    fn validate(
        &self,
        scope: &UserLocalStore,
        signer: &crate::event_signer::InksonEventSigner,
        intent_digest: Option<&String>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.authority == *scope.authority()
                && self.device_id == *scope.device_id()
                && self.verification_method == signer.verification_method()
                && signer.public_key_base64url().as_ref() == Some(&self.signer_key),
            "Contact journal belongs to another account/device signer"
        );
        match &self.request {
            PendingRequest::Commit(commit) => {
                anyhow::ensure!(
                    commit.signed_event.actor_id
                        == arkret_sdk::ActorId::account(self.authority.clone()),
                    "Contact journal changed its full account actor"
                );
                commit
                    .signed_event
                    .verify_event_id_matches_content_with_digest_suite(
                        commit
                            .signed_event
                            .event_id
                            .digest_suite_code()
                            .digest_suite(),
                    )?;
            }
            PendingRequest::Checkpoint { request, .. } => {
                anyhow::ensure!(
                    request.peer.contact_actor_id()
                        != arkret_sdk::ActorId::account(self.authority.clone()),
                    "checkpoint peer equals holder"
                );
            }
        }
        if let Some(expected) = intent_digest {
            anyhow::ensure!(
                &self.intent_digest == expected,
                "another Contact operation is awaiting confirmation; resume it before creating a new intent"
            );
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct Journal {
    scope: UserLocalStore,
    store: Arc<dyn SecureKeyStore + Send + Sync>,
    record: Arc<Mutex<PendingRecord>>,
}

impl Journal {
    fn snapshot(&self) -> PendingRecord {
        self.record
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    async fn save(&self) -> anyhow::Result<()> {
        let bytes = serde_json::to_string(&self.snapshot())?;
        self.scope
            .save_secret_durable(self.store.as_ref(), SECRET_KEY, &bytes)
            .await?;
        Ok(())
    }

    async fn accept_checkpoint_result(
        &self,
        outcome: &ContactContinuityCheckpointOutcome,
    ) -> anyhow::Result<()> {
        let record = self.snapshot();
        let PendingRequest::Checkpoint {
            request,
            checkpoint_digest,
        } = &record.request
        else {
            anyhow::bail!("journal is not a checkpoint request");
        };
        outcome.validate_for_request(&record.authority, request)?;
        anyhow::ensure!(
            checkpoint_digest
                .as_ref()
                .is_none_or(|digest| digest == &outcome.checkpoint_digest),
            "checkpoint retry changed its frozen digest"
        );
        match outcome.status {
            ContactContinuityCheckpointStatus::Committed => self.clear().await?,
            ContactContinuityCheckpointStatus::Pending => {
                {
                    let mut record = self
                        .record
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let PendingRequest::Checkpoint {
                        checkpoint_digest, ..
                    } = &mut record.request
                    else {
                        unreachable!()
                    };
                    *checkpoint_digest = Some(outcome.checkpoint_digest.clone());
                }
                self.save().await?;
            }
        }
        Ok(())
    }

    pub(super) async fn clear(&self) -> anyhow::Result<()> {
        self.store
            .delete_secret_durable(&self.scope.secret_key(SECRET_KEY))
            .await?;
        Ok(())
    }
}

/// Holds the process lock across loading, preparation and all durable updates.
/// Persistent identity uses the complete account/device, never this run's epoch.
pub(crate) struct PendingOperation {
    _lock: tokio::sync::OwnedMutexGuard<()>,
    pub(super) fence: AuthoringSessionFence,
    scope: UserLocalStore,
    store: Arc<dyn SecureKeyStore + Send + Sync>,
    intent_digest: Option<String>,
    pending: Option<Journal>,
}

impl PendingOperation {
    pub(crate) async fn begin(intent: Option<serde_json::Value>) -> anyhow::Result<Self> {
        let fence = AuthoringSessionFence::capture()?;
        let scope = crate::secure_key_store::active_device_seed_scope().ok_or_else(|| {
            anyhow::anyhow!("Contact recovery requires an active account/device scope")
        })?;
        let scope = UserLocalStore::new(scope.authority, scope.device_id)?;
        let _lock = operation_lock(&scope).lock_owned().await;
        fence.check()?;
        anyhow::ensure!(
            fence.signer.device_id() == Some(scope.device_id().as_str()),
            "Contact journal device differs from the active signer"
        );
        let store = crate::secure_key_store::default_secure_key_store("inkson");
        let intent_digest = intent
            .map(|intent| arkret_sdk::canonical::canonical_sha256(&intent))
            .transpose()?;
        let pending = scope
            .load_secret(store.as_ref(), SECRET_KEY)?
            .map(|raw| -> anyhow::Result<Journal> {
                let record: PendingRecord = serde_json::from_str(&raw)?;
                record.validate(&scope, &fence.signer, intent_digest.as_ref())?;
                Ok(Journal {
                    scope: scope.clone(),
                    store: store.clone(),
                    record: Arc::new(Mutex::new(record)),
                })
            })
            .transpose()?;
        Ok(Self {
            _lock,
            fence,
            scope,
            store,
            intent_digest,
            pending,
        })
    }

    pub(crate) async fn resume(
        &self,
        http: &arkret_sdk::http_client::Client,
    ) -> anyhow::Result<Option<ContactOperationOutcome>> {
        let Some(journal) = &self.pending else {
            return Ok(None);
        };
        let record = journal.snapshot();
        let PendingRequest::Commit(commit) = &record.request else {
            anyhow::bail!("a Contact history request is awaiting confirmation; resume it first");
        };
        let context = ContactCommitContext {
            actor_id: commit.signed_event.actor_id.clone(),
            control_realm: commit.signed_event.realm_id.clone(),
            fence: self.fence.clone(),
            journal: Some(journal.clone()),
        };
        let outcome = super::run_contact_commit(http, context, commit).await?;
        self.fence.check()?;
        journal.clear().await?;
        Ok(Some(outcome))
    }

    pub(super) async fn stage(
        &self,
        context: &mut ContactCommitContext,
        commit: &ContactCommitRequestBody,
    ) -> anyhow::Result<Journal> {
        self.fence.check()?;
        anyhow::ensure!(
            commit.signed_event.actor_id
                == arkret_sdk::ActorId::account(self.scope.authority().clone()),
            "Contact commit actor differs from the active full account"
        );
        let journal = self
            .stage_request(PendingRequest::Commit(Box::new(commit.clone())))
            .await?;
        context.journal = Some(journal.clone());
        Ok(journal)
    }
    async fn stage_request(&self, request: PendingRequest) -> anyhow::Result<Journal> {
        let journal =
            Journal {
                scope: self.scope.clone(),
                store: self.store.clone(),
                record: Arc::new(Mutex::new(PendingRecord {
                    authority: self.scope.authority().clone(),
                    device_id: self.scope.device_id().clone(),
                    verification_method: self.fence.signer.verification_method().to_owned(),
                    signer_key: self.fence.signer.public_key_base64url().ok_or_else(|| {
                        anyhow::anyhow!("Contact journal requires signer public key")
                    })?,
                    intent_digest: self
                        .intent_digest
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("new Contact request omitted intent"))?,
                    request,
                })),
            };
        journal.snapshot().validate(
            &self.scope,
            &self.fence.signer,
            self.intent_digest.as_ref(),
        )?;
        journal.save().await?;
        self.fence.check()?;
        Ok(journal)
    }

    async fn checkpoint(
        &self,
        http: &arkret_sdk::http_client::Client,
        journal: &Journal,
    ) -> anyhow::Result<ContactContinuityCheckpointOutcome> {
        self.fence.check()?;
        let record = journal.snapshot();
        let PendingRequest::Checkpoint { request, .. } = &record.request else {
            anyhow::bail!("a signed Contact write is awaiting confirmation; resume it first");
        };
        let result = http.contacts_checkpoint(&record.authority, request).await;
        self.fence.check()?;
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(error) => {
                // A definitive client rejection accepts no checkpoint. Transport,
                // rate-limit and server failures retain the exact durable request.
                if matches!(
                    error.error_code(),
                    Some(
                        arkret_sdk::ErrorCode::ParamInvalid
                            | arkret_sdk::ErrorCode::FailedPrecondition
                    )
                ) {
                    journal.clear().await?;
                }
                return Err(error.into());
            }
        };
        journal.accept_checkpoint_result(&outcome).await?;
        self.fence.check()?;
        Ok(outcome)
    }
}

pub(crate) async fn resume_pending_contact(
    http: &arkret_sdk::http_client::Client,
) -> anyhow::Result<()> {
    let pending = PendingOperation::begin(None).await?;
    if let Some(journal) = &pending.pending
        && matches!(
            journal.snapshot().request,
            PendingRequest::Checkpoint { .. }
        )
    {
        pending.checkpoint(http, journal).await?;
    } else {
        pending.resume(http).await?;
    }
    Ok(())
}

/// Resume one exact command after a crash, or durably freeze it before first I/O.
pub(crate) async fn compact_contact_history(
    http: &arkret_sdk::http_client::Client,
    peer: ContactPeer,
) -> anyhow::Result<ContactContinuityCheckpointOutcome> {
    let pending = PendingOperation::begin(Some(serde_json::json!(["checkpoint", peer]))).await?;
    let journal = match &pending.pending {
        Some(journal) => journal.clone(),
        None => {
            let (_, idempotency_key) = super::new_contact_operation_binding()?;
            pending
                .stage_request(PendingRequest::Checkpoint {
                    request: ContactContinuityCheckpointRequestBody {
                        idempotency_key,
                        peer,
                    },
                    checkpoint_digest: None,
                })
                .await?
        }
    };
    pending.checkpoint(http, &journal).await
}

// The crate intentionally disables its inline unit-test tree on WASM. Reuse
// the journal probe only through the existing conformance integration lane.
#[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
pub async fn checkpoint_journal_browser_recovery() {
    crate::secure_key_store::ensure_wasm_secure_key_store_ready("inkson")
        .await
        .unwrap();
    let (mut journal, signer) = tests::checkpoint_fixture();
    journal.store = crate::secure_key_store::default_secure_key_store("inkson");
    tests::assert_checkpoint_restart(journal, signer).await;
}

#[cfg(any(test, all(target_arch = "wasm32", feature = "spec-conformance")))]
mod tests {
    use super::*;

    #[cfg(not(target_arch = "wasm32"))]
    fn fixture() -> (Journal, crate::event_signer::InksonEventSigner) {
        let event = super::super::tests::event(arkret_wire::event_kind_str::CONTACT_REQUESTED);
        let authority = event.actor_id.as_account_id().unwrap().clone();
        let device_id =
            arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-0000000000a1").unwrap();
        let signer = crate::event_signer::build_ed25519_device_signer(
            [17; 32],
            "did:web:alice.example",
            device_id.as_str(),
        );
        let scope = UserLocalStore::new(authority.clone(), device_id.clone()).unwrap();
        let record = PendingRecord {
            authority,
            device_id,
            verification_method: signer.verification_method().to_owned(),
            signer_key: signer.public_key_base64url().unwrap(),
            intent_digest: "original-user-intent".into(),
            request: PendingRequest::Commit(Box::new(ContactCommitRequestBody {
                phase: arkret_sdk::contact_operations::ContactCommitPhase::Commit,
                operation_id: super::super::tests::operation_id(),
                idempotency_key: arkret_sdk::IdempotencyKey::new("same-exact-attempt").unwrap(),
                reservation_handle: arkret_sdk::ReservationHandle::new("opaque-reservation")
                    .unwrap(),
                signed_event: event,
            })),
        };
        (
            Journal {
                scope,
                store: Arc::new(crate::secure_key_store::MemorySecureKeyStore::new()),
                record: Arc::new(Mutex::new(record)),
            },
            signer,
        )
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn journal_restart_preserves_exact_contact_commit() {
        let (journal, signer) = fixture();
        let original = journal.snapshot();
        journal.save().await.unwrap();
        let restored: PendingRecord = serde_json::from_str(
            &journal
                .scope
                .load_secret(journal.store.as_ref(), SECRET_KEY)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        restored
            .validate(&journal.scope, &signer, Some(&original.intent_digest))
            .unwrap();
        assert_eq!(
            serde_json::to_value(&restored.request).unwrap(),
            serde_json::to_value(&original.request).unwrap()
        );
        journal.clear().await.unwrap();
        assert!(
            journal
                .scope
                .load_secret(journal.store.as_ref(), SECRET_KEY)
                .unwrap()
                .is_none()
        );
    }

    pub(super) fn checkpoint_fixture() -> (Journal, crate::event_signer::InksonEventSigner) {
        let authority = arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        );
        let device_id =
            arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-0000000000a1").unwrap();
        let signer = crate::event_signer::build_ed25519_device_signer(
            [17; 32],
            "did:web:alice.example",
            device_id.as_str(),
        );
        let request = PendingRequest::Checkpoint {
            request: ContactContinuityCheckpointRequestBody {
                idempotency_key: arkret_sdk::IdempotencyKey::new("frozen-checkpoint-attempt")
                    .unwrap(),
                peer: ContactPeer::Human {
                    account_id: arkret_sdk::AccountId::new(
                        arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
                        arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                    ),
                },
            },
            checkpoint_digest: None,
        };
        let journal = Journal {
            scope: UserLocalStore::new(authority.clone(), device_id.clone()).unwrap(),
            store: Arc::new(crate::secure_key_store::MemorySecureKeyStore::new()),
            record: Arc::new(Mutex::new(PendingRecord {
                authority,
                device_id,
                verification_method: signer.verification_method().to_owned(),
                signer_key: signer.public_key_base64url().unwrap(),
                intent_digest: "original-checkpoint-intent".into(),
                request,
            })),
        };
        (journal, signer)
    }

    pub(super) async fn assert_checkpoint_restart(
        journal: Journal,
        signer: crate::event_signer::InksonEventSigner,
    ) {
        journal.save().await.unwrap();
        let original = journal.snapshot();
        let pending = ContactContinuityCheckpointOutcome {
            status: ContactContinuityCheckpointStatus::Pending,
            checkpoint_digest: arkret_sdk::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            continuity_evidence: None,
        };
        journal.accept_checkpoint_result(&pending).await.unwrap();
        #[cfg(target_arch = "wasm32")]
        let cold_store: Arc<dyn SecureKeyStore + Send + Sync> = Arc::new(
            crate::secure_key_store::IndexedDbSecureKeyStore::new_async("inkson")
                .await
                .unwrap(),
        );
        #[cfg(not(target_arch = "wasm32"))]
        let cold_store = journal.store.clone();
        let restored: PendingRecord = serde_json::from_str(
            &journal
                .scope
                .load_secret(cold_store.as_ref(), SECRET_KEY)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        restored
            .validate(&journal.scope, &signer, Some(&original.intent_digest))
            .unwrap();
        let PendingRequest::Checkpoint {
            request,
            checkpoint_digest,
        } = &restored.request
        else {
            panic!("checkpoint request changed kind");
        };
        let PendingRequest::Checkpoint {
            request: initial, ..
        } = &original.request
        else {
            unreachable!()
        };
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            serde_json::to_value(initial).unwrap()
        );
        assert_eq!(checkpoint_digest.as_ref(), Some(&pending.checkpoint_digest));
        let reopened = Journal {
            scope: journal.scope.clone(),
            store: cold_store,
            record: Arc::new(Mutex::new(restored)),
        };
        let mut wrong = pending.clone();
        wrong.checkpoint_digest =
            arkret_sdk::Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap();
        assert!(reopened.accept_checkpoint_result(&wrong).await.is_err());
        let raw = reopened
            .scope
            .load_secret(reopened.store.as_ref(), SECRET_KEY)
            .unwrap()
            .unwrap();
        assert!(raw.contains("frozen-checkpoint-attempt"));
        let other_scope = UserLocalStore::new(
            arkret_sdk::AccountId::new(
                original.authority.principal_id.clone(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
            ),
            original.device_id.clone(),
        )
        .unwrap();
        assert!(
            other_scope
                .load_secret(reopened.store.as_ref(), SECRET_KEY)
                .unwrap()
                .is_none()
        );
        reopened.clear().await.unwrap();
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn checkpoint_journal_restart_preserves_request_and_digest_with_account_isolation() {
        let (journal, signer) = checkpoint_fixture();
        assert_checkpoint_restart(journal, signer).await;
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn recovery_rejects_same_principal_other_station_device_key_or_intent() {
        let (journal, signer) = fixture();
        let record = journal.snapshot();
        record.validate(&journal.scope, &signer, None).unwrap();
        let other_account = crate::test_support::authority_at_station(
            "did:web:alice.example",
            "did:web:other.example",
        );
        let other_scope = UserLocalStore::new(other_account, record.device_id.clone()).unwrap();
        assert!(record.validate(&other_scope, &signer, None).is_err());
        let other_device = UserLocalStore::new(
            record.authority.clone(),
            arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-0000000000a2").unwrap(),
        )
        .unwrap();
        assert!(record.validate(&other_device, &signer, None).is_err());
        let changed_key = crate::event_signer::build_ed25519_device_signer(
            [18; 32],
            "did:web:alice.example",
            record.device_id.as_str(),
        );
        assert!(record.validate(&journal.scope, &changed_key, None).is_err());
        assert!(
            record
                .validate(
                    &journal.scope,
                    &signer,
                    Some(&"different-intent".to_owned())
                )
                .is_err()
        );
        assert!(
            crate::secure_key_store::is_wasm_indexeddb_required_secret_key(
                &journal.scope.secret_key(SECRET_KEY)
            )
        );
        assert_ne!(
            journal.scope.secret_key(SECRET_KEY),
            other_scope.secret_key(SECRET_KEY)
        );
        let first_lock = operation_lock(&journal.scope);
        assert!(Arc::ptr_eq(&first_lock, &operation_lock(&journal.scope)));
        assert!(!Arc::ptr_eq(&first_lock, &operation_lock(&other_scope)));
    }
}
