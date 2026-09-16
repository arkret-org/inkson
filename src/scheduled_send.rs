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
    let outbound = garth::OutboundEngine::new(crate::outbound_store::InksonOutboundStore::open(
        authority,
        crate::outbound_store::OutboundLane::Standard,
    )?);
    let existing = outbound
        .snapshot()
        .await?
        .items
        .into_iter()
        .find(|item| item.transaction_id == scheduled_send_id.as_str());
    if let Some(existing) = existing {
        if existing.status == garth::SendQueueStatus::Sent {
            retire_scheduled_send_plan(
                submitter,
                state_store,
                &plan.account_data_key,
                scheduled_send_id.as_str(),
            )
            .await?;
            return Ok(true);
        }
        // The frozen dispatch record is still in flight; the drain above owns
        // its byte-exact retry. Re-authoring here would trip the queue's
        // immutable-intent guard, which is the spec-required failure mode for
        // diverging retry bytes.
        return Ok(false);
    }

    let state = state_store.read(|store| store.load());
    let Some(realm_id) = scheduled_send_target_realm(&state, &plan.value) else {
        tracing::warn!(
            scheduled_send_id = %scheduled_send_id,
            strand_id = %plan.value.message_payload.strand_id,
            "scheduled-send dispatch cannot resolve the target Strand's home Realm yet"
        );
        return Ok(false);
    };
    let event =
        crate::operation::TypedOperationBuilder::new::<arkret_sdk::event_spec::MessageCreate>(
            realm_id,
            actor_id,
            plan.value.message_payload.clone(),
        )
        .target_ref(plan.value.message_payload.strand_id.as_str())
        .build_sdk_event("inkson")?;
    // Authoring completes every producer-signed envelope field (actor frontier,
    // HLC, CBS basis) and derives the one content-bound EventId — only now do
    // the final Event / Message identities exist (spec §4).
    // `submit_scheduled_send_event` then freezes and persists the exact
    // canonical signed bytes before the first network submit.
    let signed = submitter.author_for_direct_submission(&event).await?;
    let authoring_generation =
        crate::identity::authoring_generation::resolve_event_authoring_generation(
            submitter.http(),
            &crate::identity::authoring_generation::EventAuthorityFacts::from_intent(
                event.intent(),
            ),
        )
        .await?;
    match submitter
        .submit_scheduled_send_event(scheduled_send_id.clone(), signed, authoring_generation)
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
            // durable queue and the network result is pending; the plan stays
            // so the next tick can observe the queue item reaching `Sent`.
            tracing::debug!(
                scheduled_send_id = %scheduled_send_id,
                error = %format!("{error:#}"),
                "scheduled-send dispatch is durably queued"
            );
            Ok(false)
        }
    }
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
