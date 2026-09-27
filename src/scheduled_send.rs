//! Scheduled-send plan dispatch driver (spec `models/personal-productivity.md` §4).
//!
//! A plan lives as encrypted `ak.scheduled_send.v1:<scheduled_send_id>`
//! account data until its `send_at` passes. This module is the expiry
//! trigger: it scans the locally staged plan entries, and for every due plan
//! drives the durable dispatch boundary
//! [`crate::event_submit::EventSubmitter::submit_scheduled_send_event`], which
//! freezes the complete canonical signed Event bytes before the first network
//! submit and replays them verbatim on any retry. A plan is retired (its
//! account-data entry deleted through the CAS binding) only after the durable
//! queue reports the frozen Event as sent; until then the plan stays so a
//! crash or an offline interval cannot lose it.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::event_submit::EventSubmitter;
use crate::state::LocalStateStore;

/// How often the session shell scans staged plans for `send_at` expiry.
pub(crate) const DISPATCH_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// One decrypted, validated, due scheduled-send plan plus its account-data key.
#[derive(Clone, Debug)]
pub(crate) struct DueScheduledSendPlan {
    pub account_data_key: String,
    pub value: arkret_sdk::ScheduledSendValue,
}

pub(crate) fn scheduled_send_plan_is_due(
    value: &arkret_sdk::ScheduledSendValue,
    now: DateTime<Utc>,
) -> anyhow::Result<bool> {
    let send_at = DateTime::parse_from_rfc3339(&value.send_at)
        .map_err(|error| anyhow::anyhow!("scheduled_send send_at is not RFC 3339: {error}"))?;
    Ok(send_at.with_timezone(&Utc) <= now)
}

/// Everything a writer needs to stage and push one plan: the validated value
/// (fresh `scheduled_send_id` on create, unchanged id on modify), its
/// account-data key, and the encrypted entry content for the local staging.
pub(crate) struct PreparedScheduledSendPlan {
    pub account_data_key: String,
    pub value: arkret_sdk::ScheduledSendValue,
    pub encrypted_entry: Value,
}

pub(crate) fn prepare_scheduled_send_plan(
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    existing_scheduled_send_id: Option<&str>,
    send_at: &str,
    message_payload: arkret_sdk::MessageCreatePayload,
) -> anyhow::Result<PreparedScheduledSendPlan> {
    let scheduled_send_id = match existing_scheduled_send_id {
        Some(existing) => arkret_identifiers::ScheduledSendId::new(existing.to_owned())
            .map_err(|error| anyhow::anyhow!(error.to_string()))?,
        None => arkret_identifiers::ScheduledSendId::new_v7_at(crate::clock::now_unix_ms()),
    };
    let hlc = crate::signing_stamp::issue_account_data_hlc(
        authority.principal_id.as_str(),
        device_id.as_str(),
    )?;
    let value = crate::account_data::build_scheduled_send_value(
        scheduled_send_id.as_str(),
        send_at,
        message_payload,
        hlc.as_str(),
    )?;
    let account_data_key =
        crate::account_data::scheduled_send_account_data_key(scheduled_send_id.as_str())?;
    let encrypted_entry = crate::account_data::encrypt_account_data_value(
        authority,
        &account_data_key,
        &crate::account_data::scheduled_send_account_data_value(&value)?,
    )?;
    Ok(PreparedScheduledSendPlan {
        account_data_key,
        value,
        encrypted_entry,
    })
}

/// Decrypt and validate every staged plan entry, ordered by `send_at`
/// ascending. Entries that do not decrypt, do not validate, or do not bind
/// their own account-data key are skipped: a foreign or corrupt plan must
/// never be dispatched, edited, or deleted by this client.
pub(crate) fn staged_scheduled_send_plans(
    authority: &arkret_sdk::AccountId,
    state_store: &LocalStateStore,
) -> Vec<DueScheduledSendPlan> {
    let state = state_store.load();
    let mut plans = Vec::new();
    for (account_data_key, content) in &state.scheduled_send_account_data {
        let plan =
            crate::account_data::decrypt_account_data_value(authority, account_data_key, content)
                .and_then(|plaintext| {
                    crate::account_data::scheduled_send_value_from_account_data(&plaintext)
                })
                .and_then(|value| {
                    let value_key = crate::account_data::scheduled_send_account_data_key(
                        value.scheduled_send_id.as_str(),
                    )?;
                    if value_key != *account_data_key {
                        anyhow::bail!(
                            "scheduled_send account-data value does not bind its own key"
                        );
                    }
                    Ok(value)
                });
        match plan {
            Ok(value) => plans.push(DueScheduledSendPlan {
                account_data_key: account_data_key.clone(),
                value,
            }),
            Err(error) => {
                tracing::warn!(
                    key = %account_data_key,
                    error = %format!("{error:#}"),
                    "skipping undecryptable or invalid scheduled-send plan"
                );
            }
        }
    }
    plans.sort_by(|left, right| left.value.send_at.cmp(&right.value.send_at));
    plans
}

/// The subset of [`staged_scheduled_send_plans`] whose `send_at` has passed.
pub(crate) fn due_scheduled_send_plans(
    authority: &arkret_sdk::AccountId,
    state_store: &LocalStateStore,
    now: DateTime<Utc>,
) -> Vec<DueScheduledSendPlan> {
    staged_scheduled_send_plans(authority, state_store)
        .into_iter()
        .filter(|plan| match scheduled_send_plan_is_due(&plan.value, now) {
            Ok(due) => due,
            Err(error) => {
                tracing::warn!(
                    key = %plan.account_data_key,
                    error = %format!("{error:#}"),
                    "skipping scheduled-send plan with unparsable send_at"
                );
                false
            }
        })
        .collect()
}

/// Resolve the authoring Realm for the plan's target Strand. The spec plan
/// value carries no `realm_id`, so creation records the Strand's home Realm in
/// a local index; a fresh device falls back to scanning the synced Realm
/// projections for the Strand listing.
fn scheduled_send_target_realm(
    state: &crate::state::ClientLocalState,
    value: &arkret_sdk::ScheduledSendValue,
) -> Option<String> {
    let scheduled_send_id = value.scheduled_send_id.as_str();
    if let Some(realm_id) = state.scheduled_send_target_realms.get(scheduled_send_id) {
        return Some(realm_id.clone());
    }
    realm_id_for_strand_from_projections(
        &state.realm_tree_projections,
        value.message_payload.strand_id.as_str(),
    )
}

fn realm_id_for_strand_from_projections(
    projections: &BTreeMap<String, Value>,
    strand_id: &str,
) -> Option<String> {
    if let Some(body) = projections.get(strand_id)
        && let Some(realm_id) = body.get("realm_id").and_then(Value::as_str)
    {
        return Some(realm_id.to_owned());
    }
    for (key, body) in projections {
        if !key.starts_with("ak:realm:") {
            continue;
        }
        let listed = [
            body.pointer("/summary/strands"),
            body.get("strands"),
            body.pointer("/summary/strand"),
        ]
        .into_iter()
        .flatten()
        .any(|entry| {
            entry.as_str() == Some(strand_id)
                || entry.get("strand_id").and_then(Value::as_str) == Some(strand_id)
                || entry.as_array().is_some_and(|entries| {
                    entries.iter().any(|item| {
                        item.as_str() == Some(strand_id)
                            || item.get("strand_id").and_then(Value::as_str) == Some(strand_id)
                    })
                })
        });
        if listed {
            return Some(key.clone());
        }
    }
    None
}

/// Retire a dispatched plan: delete the account-data entry through the CAS
/// binding and drop the local staging. Spec §4 makes the plan
/// principal-private state, so retirement is the account-data delete.
async fn retire_scheduled_send_plan(
    submitter: &EventSubmitter,
    state_store: &crate::runtime::input::StateStoreHandle,
    account_data_key: &str,
    scheduled_send_id: &str,
) -> anyhow::Result<()> {
    crate::transport::account::cancel_scheduled_send_plan(submitter, scheduled_send_id).await?;
    state_store.write(|store| store.remove_scheduled_send_account_data_entry(account_data_key));
    Ok(())
}

/// Dispatch every due plan through the durable freeze boundary. Returns the
/// number of plans whose frozen Event is confirmed sent (and whose account-
/// data entry was retired).
pub(crate) async fn dispatch_due_scheduled_sends(
    submitter: &EventSubmitter,
    authority: &arkret_sdk::AccountId,
    state_store: &crate::runtime::input::StateStoreHandle,
) -> anyhow::Result<usize> {
    if submitter.authority()? != authority {
        anyhow::bail!(
            "scheduled-send authority changed while constructing the durable Event submitter"
        );
    }
    let actor_id = authority.principal_id.as_str();
    // Spec §4: an uncertain or interrupted submit MUST be retried with the
    // persisted canonical signed bytes, never re-authored from the plan. The
    // durable outbound queue owns those bytes.  The account long-poll can end
    // without a committed heartbeat (for example a browser fetch abort at its
    // timeout), so this bounded account-scoped tick is also an independent
    // retry clock for every ordinary durable Event, not only scheduled-send
    // records.  Fresh scheduled-send authoring below still only runs for plans
    // with no dispatch record yet.
    if let Err(error) = submitter.drain_outbound().await {
        tracing::debug!(
            error = %format!("{error:#}"),
            "scheduled-send dispatch: durable outbound drain deferred"
        );
    }
    let due = state_store
        .read(|store| due_scheduled_send_plans(authority, store, crate::clock::now_utc()));
    if due.is_empty() {
        return Ok(0);
    }
    let mut dispatched = 0usize;
    for plan in due {
        match dispatch_due_plan(submitter, authority, actor_id, state_store, &plan).await {
            Ok(true) => dispatched += 1,
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(
                    scheduled_send_id = %plan.value.scheduled_send_id,
                    error = %format!("{error:#}"),
                    "scheduled-send dispatch failed; plan stays for the next tick"
                );
            }
        }
    }
    Ok(dispatched)
}

async fn dispatch_due_plan(
    submitter: &EventSubmitter,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    state_store: &crate::runtime::input::StateStoreHandle,
    plan: &DueScheduledSendPlan,
) -> anyhow::Result<bool> {
    let scheduled_send_id = plan.value.scheduled_send_id.clone();
    // Serialize dispatch authoring in this holder runtime. The durable store
    // also atomically arbitrates a binding before any network I/O.
    static DISPATCH_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    let _dispatch_guard = DISPATCH_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let outbound = garth::OutboundEngine::new(
        crate::outbound_store::InksonOutboundStore::open(
            authority,
            crate::outbound_store::OutboundLane::Standard,
        )?,
        crate::event_submit::InksonHostClock,
    );
    let existing = outbound
        .store()
        .scheduled_dispatch(&scheduled_send_id)
        .await?;
    if let Some(existing) = existing {
        if existing.status == garth::SendQueueStatus::Committed {
            retire_scheduled_send_plan(
                submitter,
                state_store,
                &plan.account_data_key,
                scheduled_send_id.as_str(),
            )
            .await?;
            return Ok(true);
        }
        if matches!(
            &existing.submission.state,
            garth::SubmissionState::Rejected {
                status: arkret_wire::AuthorityRejectionStatus::RetryableUnavailable,
                ..
            }
        ) {
            // A retryable Station answer reopens the same binding; it never
            // sends this tick's possibly edited plan to the authoring engine.
            if submitter
                .submit_scheduled_send_event(scheduled_send_id.clone(), existing.submission)
                .await
                .is_ok()
            {
                retire_scheduled_send_plan(
                    submitter,
                    state_store,
                    &plan.account_data_key,
                    scheduled_send_id.as_str(),
                )
                .await?;
                return Ok(true);
            }
            return Ok(false);
        }
        if existing.status.is_terminal() {
            tracing::warn!(
                scheduled_send_id = %scheduled_send_id,
                status = ?existing.status,
                "scheduled-send dispatch reached a terminal non-committed state"
            );
            return Ok(false);
        }
        // The frozen dispatch record is still in flight; the drain above owns
        // its byte-exact retry.
        return Ok(false);
    }

    let state = state_store.read(|store| store.load());
    let Some(realm_id) = scheduled_send_target_realm(&state, &plan.value) else {
        tracing::warn!(scheduled_send_id = %scheduled_send_id, "scheduled-send target Realm is not resolved");
        return Ok(false);
    };
    let operation = scheduled_send_operation(&plan.value, &realm_id, actor_id)?;
    let submission = outbound
        .store()
        .resolve_scheduled_dispatch(scheduled_send_id.clone(), || async {
            let signed = submitter
                .author_for_direct_submission(&operation)
                .await
                .map_err(|error| garth::Error::Protocol(error.to_string()))?;
            crate::event_submit::event_submission(&signed)
                .map_err(|error| garth::Error::Protocol(error.to_string()))
        })
        .await?;
    match submitter
        .submit_scheduled_send_event(scheduled_send_id.clone(), submission)
        .await
    {
        Ok(_) => {
            retire_scheduled_send_plan(
                submitter,
                state_store,
                &plan.account_data_key,
                scheduled_send_id.as_str(),
            )
            .await?;
            Ok(true)
        }
        Err(error) => {
            // `DurablyQueuedError` means the signed bytes are frozen in the
            // durable queue and the authority result is pending; the plan stays
            // so the next tick can observe the queue item reaching `Committed`.
            tracing::debug!(
                scheduled_send_id = %scheduled_send_id,
                error = %format!("{error:#}"),
                "scheduled-send dispatch is durably queued"
            );
            Ok(false)
        }
    }
}

/// Build the dispatch write for one plan, pinned to the plan's own `send_at`.
fn scheduled_send_operation(
    value: &arkret_sdk::ScheduledSendValue,
    realm_id: &str,
    actor_id: &str,
) -> anyhow::Result<crate::operation::LocalOperation> {
    let send_at = DateTime::parse_from_rfc3339(&value.send_at)
        .map_err(|error| anyhow::anyhow!("scheduled_send send_at is not RFC 3339: {error}"))?
        .with_timezone(&Utc);
    let operation = crate::operation::TypedOperationBuilder::new::<
        arkret_sdk::event_spec::MessageCreate,
    >(realm_id, actor_id, value.message_payload.clone())
    .target_ref(value.message_payload.strand_id.as_str())
    .build_sdk_event("inkson")?;
    let local_operation_id = operation.local_operation_id().clone();
    Ok(
        crate::operation::LocalOperation::new(operation.into_intent().with_created_at(send_at))
            .with_local_operation_id(local_operation_id),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(send_at: &str) -> arkret_sdk::ScheduledSendValue {
        let payload = arkret_sdk::MessageCreatePayload::with_content(
            arkret_sdk::StrandId::from_event_id(&arkret_sdk::EventId::from_digest(
                arkret_sdk::canonical::DigestSuite::Sha256,
                [0x22; 32],
            )),
            "discussion",
            arkret_sdk::ContentBlock::text("scheduled hello"),
        );
        crate::account_data::build_scheduled_send_value(
            "ak:scheduled_send:01904100-0000-7000-8000-000000000003",
            send_at,
            payload,
            "01970e589d21-0000-a13f9c2e",
        )
        .expect("plan")
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn edited_plan_after_restart_reuses_the_atomic_frozen_dispatch_without_authoring() {
        use garth::OutboundQueueStore as _;
        let directory = std::env::temp_dir().join(format!(
            "inkson-scheduled-binding-{}",
            crate::operation::uuid_v7()
        ));
        let path = directory.join("standard.json");
        let original = plan("2026-08-19T00:00:00.000Z");
        let id = original.scheduled_send_id.clone();
        let operation = scheduled_send_operation(
            &original,
            "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "did:web:alice.example",
        )
        .unwrap();
        let store = crate::outbound_store::InksonOutboundStore::for_test_path(path.clone());
        let mut author_calls = 0;
        let first = store
            .resolve_scheduled_dispatch(id.clone(), || async {
                author_calls += 1;
                Ok(crate::event_submit::queue_message_operation_for_test(
                    &operation,
                ))
            })
            .await
            .unwrap();
        let expected = arkret_sdk::canonical::canonical_json_bytes(&first.request).unwrap();
        let mut edited = plan("2026-08-20T00:00:00.000Z");
        edited.message_payload.content =
            Some(arkret_sdk::ContentBlock::text("edited after dispatch"));
        let edited_operation = scheduled_send_operation(
            &edited,
            "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "did:web:alice.example",
        )
        .unwrap();
        assert_ne!(operation.payload(), edited_operation.payload());
        let resumed = crate::outbound_store::InksonOutboundStore::for_test_path(path.clone());
        let after_crash = resumed
            .resolve_scheduled_dispatch(id.clone(), || async {
                author_calls += 1;
                Ok(crate::event_submit::queue_message_operation_for_test(
                    &edited_operation,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            author_calls, 1,
            "recovery must not reach signing or encryption/authoring"
        );
        assert_eq!(first.event_id, after_crash.event_id);
        assert_eq!(
            expected,
            arkret_sdk::canonical::canonical_json_bytes(&after_crash.request).unwrap()
        );
        assert_eq!(
            resumed
                .scheduled_dispatch(&id)
                .await
                .unwrap()
                .unwrap()
                .event_id(),
            &first.event_id
        );
        // Compaction must not turn a frozen plan back into an unbound plan.
        let durable = std::fs::read(&path).unwrap();
        assert!(
            resumed
                .mutate_outbound(|queue| {
                    *queue = garth::SendQueue::default();
                    Ok(())
                })
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), durable);
        assert_eq!(
            resumed
                .scheduled_dispatch(&id)
                .await
                .unwrap()
                .unwrap()
                .event_id(),
            &first.event_id
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn concurrent_scheduled_dispatches_author_and_sign_once() {
        let directory = std::env::temp_dir().join(format!(
            "inkson-scheduled-race-{}",
            crate::operation::uuid_v7()
        ));
        let store = crate::outbound_store::InksonOutboundStore::for_test_path(
            directory.join("standard.json"),
        );
        let value = plan("2026-08-19T00:00:00.000Z");
        let operation = scheduled_send_operation(
            &value,
            "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "did:web:alice.example",
        )
        .unwrap();
        let calls = std::cell::Cell::new(0);
        let first = store.resolve_scheduled_dispatch(value.scheduled_send_id.clone(), || async {
            calls.set(calls.get() + 1);
            tokio::task::yield_now().await;
            Ok(crate::event_submit::queue_message_operation_for_test(
                &operation,
            ))
        });
        let second = store.resolve_scheduled_dispatch(value.scheduled_send_id.clone(), || async {
            calls.set(calls.get() + 1);
            Ok(crate::event_submit::queue_message_operation_for_test(
                &operation,
            ))
        });
        let (first, second) = tokio::join!(first, second);
        assert_eq!(calls.get(), 1);
        assert_eq!(first.unwrap().request, second.unwrap().request);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn scheduled_message_dispatch_enters_the_shared_proof_and_durable_queue_seam() {
        let operation = scheduled_send_operation(
            &plan("2026-08-19T00:00:00.000Z"),
            "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "did:web:alice.example",
        )
        .unwrap();
        crate::event_submit::queue_message_operation_for_test(&operation);
    }

    #[test]
    fn due_check_compares_canonical_send_at_against_now() {
        let now = DateTime::parse_from_rfc3339("2026-08-19T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(scheduled_send_plan_is_due(&plan("2026-08-18T23:59:59.999Z"), now).unwrap());
        assert!(scheduled_send_plan_is_due(&plan("2026-08-19T00:00:00.000Z"), now).unwrap());
        assert!(!scheduled_send_plan_is_due(&plan("2026-08-19T00:00:00.001Z"), now).unwrap());
    }

    #[test]
    fn projection_scan_finds_strand_listed_in_realm_summary() {
        let strand_id = "ak:strand:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j";
        let realm_id = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
        let mut projections = BTreeMap::new();
        projections.insert(
            realm_id.to_owned(),
            serde_json::json!({
                "summary": {"strands": [{"strand_id": strand_id}]}
            }),
        );
        assert_eq!(
            realm_id_for_strand_from_projections(&projections, strand_id).as_deref(),
            Some(realm_id)
        );
        assert_eq!(
            realm_id_for_strand_from_projections(
                &projections,
                "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
            ),
            None
        );
    }
}
