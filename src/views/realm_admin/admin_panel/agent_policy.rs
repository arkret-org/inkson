//! Normal Realm administration of an exact Agent management Policy.
use std::rc::Rc;

use arkret_models_collaboration::governance::operation_wire::{
    Policy, PolicySetStatePayload, PolicySetValue,
};
use arkret_sdk::exact_current_state::{
    ExactCurrentState, ExactCurrentStateReadRequestBody, ExactCurrentStateReadResponseBody,
    ExactCurrentStateSelector, PolicyExactCurrentSelector, PolicyExactCurrentSelectorKind,
};
use arkret_sdk::{AccountId, CommitStreamRef, CurrentRevision, PolicyId, RealmId, ScopeRef};
use glory::{Cage, Scope};

use crate::presentation::{InksonContext, View};
use crate::views::settings::widgets::*;

mod model;
use model::{Draft, ResourceDraft, RuleDraft, supported_by_current_backend};

#[derive(Clone)]
struct LoadedPolicy {
    account: AccountId,
    session_generation: u64,
    realm: RealmId,
    id: PolicyId,
    policy: Option<Policy>,
    revision: Option<CurrentRevision>,
    scope: ScopeRef,
}
fn check_session(
    context: &InksonContext,
    account: &AccountId,
    generation: u64,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        context.session_generation.get() == generation
            && context.active_account.get().as_ref().map(|a| &a.authority) == Some(account),
        "The Account or Device session changed; read current again"
    );
    Ok(())
}
async fn read_policy(
    context: Rc<InksonContext>,
    http: &arkret_sdk::http_client::Client,
    realm: &RealmId,
    id: &PolicyId,
) -> anyhow::Result<LoadedPolicy> {
    let generation = context.session_generation.get();
    let account = context
        .active_account
        .get()
        .ok_or_else(|| anyhow::anyhow!("No active Account"))?
        .authority;
    let client = crate::transport::own_station_results::client_for_http(http).await?;
    let before = client.snapshot_head(realm).await?;
    garth::own_station_results::consume_bound_snapshot(&before, realm)?;
    let request = ExactCurrentStateReadRequestBody {
        realm_id: realm.clone(),
        selector: ExactCurrentStateSelector::Policy(PolicyExactCurrentSelector {
            kind: PolicyExactCurrentSelectorKind::Policy,
            policy_id: id.clone(),
        }),
    };
    let result = client
        .exact_current_state(&request, before.value()?.governance_generation)
        .await?;
    let after = client.snapshot_head(realm).await?;
    garth::own_station_results::consume_bound_snapshot(&after, realm)?;
    result
        .value()?
        .validate_for_request(&request, before.value()?.governance_generation)?;
    let (result_head, result_generation) = match result.value()? {
        ExactCurrentStateReadResponseBody::Present {
            effective_stream_head,
            governance_generation,
            ..
        }
        | ExactCurrentStateReadResponseBody::NeverWritten {
            effective_stream_head,
            governance_generation,
            ..
        } => (effective_stream_head, *governance_generation),
    };
    anyhow::ensure!(
        before.session() == after.session()
            && before.value()?.governance_generation == result_generation
            && after.value()?.governance_generation == result_generation
            && before
                .value()?
                .visible_stream_heads
                .iter()
                .find(|h| h.stream_ref == result_head.stream_ref)
                == Some(result_head)
            && after
                .value()?
                .visible_stream_heads
                .iter()
                .find(|h| h.stream_ref == result_head.stream_ref)
                == Some(result_head),
        "The Policy read crossed a governance cut; read current again"
    );
    check_session(&context, &account, generation)?;
    let (policy, revision, scope) = match result.into_value()? {
        ExactCurrentStateReadResponseBody::NeverWritten { .. } => (
            None,
            None,
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
        ),
        ExactCurrentStateReadResponseBody::Present {
            current_state: ExactCurrentState::Policy(row),
            ..
        } => {
            let PolicySetValue::Governance(policy) = row.value else {
                anyhow::bail!("This Policy id belongs to another policy family")
            };
            anyhow::ensure!(
                policy.policy_kind == arkret_sdk::PolicyKind::Agent
                    && policy.id == *id
                    && policy.realm_id.as_ref() == Some(realm),
                "The exact result is not this Realm's Agent Policy"
            );
            let scope = match row.source_stream_ref {
                CommitStreamRef::Realm { realm_id } => ScopeRef::Realm { realm_id },
                CommitStreamRef::Circle {
                    realm_id,
                    circle_id,
                } => ScopeRef::Circle {
                    realm_id,
                    circle_id,
                },
                _ => anyhow::bail!("This Policy has an unsupported source scope"),
            };
            (Some(*policy), Some(row.revision), scope)
        }
        _ => anyhow::bail!("The exact result is not a Policy; absence is not established"),
    };
    Ok(LoadedPolicy {
        account,
        session_generation: generation,
        realm: realm.clone(),
        id: id.clone(),
        policy,
        revision,
        scope,
    })
}
fn prepare_write(
    context: &InksonContext,
    form: &Draft,
    current: &LoadedPolicy,
) -> anyhow::Result<(PolicySetStatePayload, ScopeRef)> {
    check_session(context, &current.account, current.session_generation)?;
    anyhow::ensure!(
        form.policy_id.trim() == current.id.as_str(),
        "Policy id changed; read the exact id first"
    );
    let scope = form.scope(&current.realm)?;
    ensure_editor_scope(current.policy.is_some(), &current.scope, &scope)?;
    let payload = form.build(
        &current.realm,
        &current.account,
        current.policy.as_ref(),
        current.revision.clone(),
    )?;
    anyhow::ensure!(
        supported_by_current_backend(&payload, &scope),
        "This configuration is not enabled by the current Station admission matrix"
    );
    Ok((payload, scope))
}

fn ensure_editor_scope(
    present: bool,
    original: &ScopeRef,
    requested: &ScopeRef,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !present || original == requested,
        "This editor preserves the accepted source scope; scope migration is not enabled here"
    );
    Ok(())
}

#[derive(Clone)]
struct PendingPolicyWrite {
    current: LoadedPolicy,
    payload: PolicySetStatePayload,
    scope: ScopeRef,
    operation: crate::operation::LocalOperation,
    signed: Option<arkret_sdk::AuthoredEvent>,
}

async fn author_policy_once<F, Fut>(
    signed: &mut Option<arkret_sdk::AuthoredEvent>,
    author: F,
) -> anyhow::Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<arkret_sdk::AuthoredEvent>>,
{
    if signed.is_none() {
        *signed = Some(author().await?);
    }
    Ok(())
}

fn submit_pending(
    owner: glory::ui::WeakScope,
    context: Rc<InksonContext>,
    mut write: PendingPolicyWrite,
    token: Cage<String>,
    busy: Cage<bool>,
    awaiting: Cage<Option<PendingPolicyWrite>>,
    loaded: Cage<Option<LoadedPolicy>>,
    message: Cage<String>,
) {
    busy.revise(|value| {
        *value = true;
    });
    let original_account = write.current.account.clone();
    let original_generation = write.current.session_generation;
    if let Some(scope) = owner.upgrade() {
        crate::views::settings::widgets::spawn(&scope, async move {
            let base = context.base_url.get();
            let result =
                crate::transport::auth::with_authed_sdk_client(&base, token.get(), |http| {
                    let context = context.clone();
                    async move {
                        check_session(
                            &context,
                            &write.current.account,
                            write.current.session_generation,
                        )?;
                        let submitter = crate::app::runtime_adapter::event_submitter(http.clone());
                        if write.signed.is_none() {
                            // No queue/network submission exists before this one-shot authoring
                            // completes.
                            awaiting.revise(|value| {
                                *value = None;
                            });
                            author_policy_once(&mut write.signed, || {
                                submitter.author_for_direct_submission(&write.operation)
                            })
                            .await?;
                            check_session(
                                &context,
                                &write.current.account,
                                write.current.session_generation,
                            )?;
                            // Freeze the proof as well as the Event identity before any network
                            // submission.
                            awaiting.revise(|value| {
                                *value = Some(write.clone());
                            });
                        }
                        let accepted = submitter
                            .submit_signed_sdk_events_in_order(std::slice::from_ref(
                                write.signed.as_ref().ok_or_else(|| {
                                    anyhow::anyhow!(
                                        "Policy authoring did not produce a signed event"
                                    )
                                })?,
                            ))
                            .await;
                        check_session(
                            &context,
                            &write.current.account,
                            write.current.session_generation,
                        )?;
                        let accepted = match accepted {
                            Ok(mut results) => results.pop().ok_or_else(|| {
                                anyhow::anyhow!("Submission omits its final result")
                            })?,
                            Err(error) if definitive_policy_refusal(&error) => {
                                awaiting.revise(|value| {
                                    *value = None;
                                });
                                return Ok(None);
                            }
                            Err(error) => return Err(error),
                        };
                        anyhow::ensure!(
                            accepted.is_committed(),
                            "The original Policy is still pending"
                        );
                        awaiting.revise(|value| {
                            *value = None;
                        });
                        let reread = read_policy(
                            context.clone(),
                            &http,
                            &write.current.realm,
                            &write.current.id,
                        )
                        .await?;
                        check_session(
                            &context,
                            &write.current.account,
                            write.current.session_generation,
                        )?;
                        let commit = accepted
                            .commit
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("Committed Policy omits its Commit"))?;
                        anyhow::ensure!(
                            reread
                                .revision
                                .as_ref()
                                .is_some_and(|r| r.commit_id == commit.commit_id
                                    && r.stream_position == commit.stream_position)
                                && reread.scope == write.scope
                                && serde_json::to_value(reread.policy.as_ref())?
                                    == serde_json::to_value(match &write.payload.value {
                                        PolicySetValue::Governance(p) => Some(p),
                                        _ => None,
                                    })?,
                            "The exact current does not yet confirm this accepted Policy"
                        );
                        Ok(Some(reread))
                    }
                })
                .await;
            if check_session(&context, &original_account, original_generation).is_err() {
                return;
            }
            match result {
                Ok(Some(current)) => {
                    loaded.revise(|value| {
                        *value = Some(current);
                    });
                    awaiting.revise(|value| {
                        *value = None;
                    });
                    message.revise(|value|{*value="Policy committed and exact current confirmed. Business actions still require their own current checks.".into();});
                }
                Ok(None) => {
                    loaded.revise(|value| {
                        *value = None;
                    });
                    awaiting.revise(|value| {
                        *value = None;
                    });
                    message.revise(|value|{*value="The original Policy was rejected. Read current and confirm a new edit; no automatic overwrite occurred.".into();});
                }
                Err(error) => {
                    loaded.revise(|value| {
                        *value = None;
                    });
                    let state = if awaiting.get().is_some() {
                        "Final outcome remains unknown; new authoring is blocked. Retry the original pending Policy."
                    } else {
                        "No pending signed submission remains. Read exact current before editing again; success has not been confirmed."
                    };
                    message.revise(|value| {
                        *value = format!("{} {}", state, error.display());
                    });
                }
            }
            busy.revise(|value| {
                *value = false;
            });
        });
    };
}

fn definitive_policy_refusal(error: &anyhow::Error) -> bool {
    if crate::ephemeral::authority_rejection_reason(error).is_some() {
        return true;
    }
    error.chain().any(|cause| {
        let Some(arkret_sdk::http_client::Error::Api { status, error }) =
            cause.downcast_ref::<arkret_sdk::http_client::Error>()
        else {
            return false;
        };
        use arkret_sdk::ErrorCode as Code;
        matches!(
            (*status, error.error_code().map(|code| code.as_str())),
            (409, Some(Code::FAILED_PRECONDITION))
                | (403, Some(Code::CAPABILITY_DENIED | Code::POLICY_VIOLATION))
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scopes() -> (ScopeRef, ScopeRef) {
        let realm_id = RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [11; 32],
        ));
        let circle_id = arkret_sdk::CircleId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [14; 32],
        ));
        (
            ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            ScopeRef::Circle {
                realm_id,
                circle_id,
            },
        )
    }

    fn signed_policy() -> arkret_sdk::AuthoredEvent {
        let (scope, _) = scopes();
        let ScopeRef::Realm { realm_id } = &scope else {
            unreachable!()
        };
        let account = AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:admin.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:home.example").unwrap(),
        );
        let payload = Draft::default()
            .build(realm_id, &account, None, None)
            .unwrap();
        let operation = crate::operation::TypedOperationBuilder::new_for_station::<
            arkret_sdk::event_spec::PolicySet,
        >(
            realm_id.as_str(),
            account.principal_id.as_str(),
            account.station_id.clone(),
            payload,
        )
        .effective_scope(scope)
        .build_sdk_event("inkson")
        .unwrap();
        let mut event = operation
            .intent()
            .clone()
            .author_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
            .unwrap();
        crate::event_signer::build_ed25519_device_signer(
            [73; 32],
            "did:web:admin.example",
            "ak:device:01904100-0000-7000-8000-000000000001",
        )
        .sign_sdk_event_with_context(
            &mut event,
            crate::event_signer::ProducerProofContext::new()
                .with_digest_suite(arkret_sdk::DigestSuite::Sha256),
        )
        .unwrap();
        event
    }

    #[test]
    fn explicit_policy_cas_refusal_is_terminal_but_unavailability_is_unknown() {
        for (status, code, expected) in [
            (409, "failed_precondition", true),
            (403, "capability_denied", true),
            (503, "policy_unavailable", false),
        ] {
            let error = anyhow::Error::new(arkret_sdk::http_client::Error::Api {
                status,
                error: Box::new(arkret_sdk::Problem::new(code, status, "test refusal")),
            })
            .context("original signed Policy request");
            assert_eq!(definitive_policy_refusal(&error), expected);
        }
        assert!(!definitive_policy_refusal(&anyhow::anyhow!(
            "failed_precondition"
        )));
    }

    #[test]
    fn present_circle_cannot_be_resaved_as_realm_by_clearing_form_scope() {
        let (realm, circle) = scopes();
        assert!(ensure_editor_scope(true, &circle, &realm).is_err());
        assert!(ensure_editor_scope(true, &circle, &circle).is_ok());
        assert!(ensure_editor_scope(false, &realm, &circle).is_ok());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn pending_retry_preserves_original_proof_and_restored_queue_request() {
        let original = signed_policy();
        let mut retained = None;
        author_policy_once(&mut retained, || async { Ok(original.clone()) })
            .await
            .unwrap();
        let frozen = crate::event_submit::event_submission(retained.as_ref().unwrap()).unwrap();
        let mut queue = garth::SendQueue::default();
        queue
            .enqueue(frozen.clone(), crate::clock::now_utc())
            .unwrap();
        let restored = garth::SendQueue::from_snapshot(
            serde_json::from_value(serde_json::to_value(queue.snapshot()).unwrap()).unwrap(),
        );
        // A retry author would issue a fresh proof; the production gate must never call it.
        author_policy_once(&mut retained, || async {
            anyhow::bail!("retry attempted to re-sign")
        })
        .await
        .unwrap();
        let retry = crate::event_submit::event_submission(retained.as_ref().unwrap()).unwrap();
        assert_eq!(retry.request, frozen.request);
        assert_eq!(restored.items()[0].request(), &retry.request);
        assert_eq!(retained.unwrap(), original);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn failed_initial_authoring_never_creates_a_pending_signed_submission() {
        let mut retained = None;
        assert!(
            author_policy_once(&mut retained, || async {
                anyhow::bail!("pre-authoring failure")
            })
            .await
            .is_err()
        );
        assert!(retained.is_none());
        author_policy_once(&mut retained, || async { Ok(signed_policy()) })
            .await
            .unwrap();
        assert!(retained.is_some());
    }
}

fn effects() -> Vec<String> {
    ["allow", "deny", "quarantine", "require_review"]
        .map(str::to_owned)
        .into()
}

#[derive(Clone)]
struct PolicyPage {
    context: Rc<InksonContext>,
    owner: glory::ui::WeakScope,
    realm: String,
    form: Cage<Draft>,
    loaded: Cage<Option<LoadedPolicy>>,
    pending: Cage<bool>,
    awaiting: Cage<Option<PendingPolicyWrite>>,
    message: Cage<String>,
    structure: Cage<u64>,
}
impl PolicyPage {
    fn load(&self) {
        if self.pending.get_untracked() {
            return;
        }
        let context = self.context.clone();
        let form = self.form;
        let loaded = self.loaded;
        let pending = self.pending;
        let message = self.message;
        let structure = self.structure;
        let Some(account) = context.active_account.get().map(|value| value.authority) else {
            return;
        };
        let generation = context.session_generation.get();
        let realm = self.realm.clone();
        let id = form.get().policy_id;
        let token = context.token.get();
        let base = context.base_url.get();
        let task_context = context.clone();
        let Some(scope) = self.owner.upgrade() else {
            return;
        };
        pending.revise(|value| {
            *value = true;
        });
        loaded.revise(|value| {
            *value = None;
        });
        spawn(&scope, async move {
            let result =
                crate::transport::auth::with_authed_sdk_client(&base, token, |http| async move {
                    check_session(&task_context, &account, generation)?;
                    read_policy(
                        task_context,
                        &http,
                        &RealmId::new(realm)?,
                        &PolicyId::new(id.trim())?,
                    )
                    .await
                })
                .await;
            if context.session_generation.get() != generation {
                return;
            }
            match result {
                Ok(current) => {
                    if let Some(policy) = &current.policy {
                        match Draft::from_policy(policy, &current.scope) {
                            Ok(draft) => {
                                form.revise(|value| {
                                    *value = draft;
                                });
                                structure.revise(|value| *value += 1);
                            }
                            Err(error) => {
                                message.revise(|value| {
                                    *value = error.to_string();
                                });
                                pending.revise(|value| {
                                    *value = false;
                                });
                                return;
                            }
                        }
                        let Some(revision) = current.revision.as_ref() else {
                            message.revise(|value|{*value="Accepted policy has no current revision; editing remains blocked.".into();});
                            pending.revise(|value| {
                                *value = false;
                            });
                            return;
                        };
                        message.revise(|value|{*value=format!("Accepted current {} at {}. Editing does not change the accepted value.",current.id,revision.commit_id);});
                    } else {
                        message.revise(|value|{*value="Authoritative never_written: this exact id can be created with null expected_revision.".into();});
                    }
                    loaded.revise(|value| {
                        *value = Some(current);
                    });
                }
                Err(error) => message.revise(|value| {
                    *value = format!(
                        "Current is unavailable or hidden; creation remains blocked: {}",
                        error.display()
                    );
                }),
            }
            pending.revise(|value| {
                *value = false;
            });
        });
    }
    fn save(&self) {
        if self.pending.get_untracked() || self.awaiting.get_untracked().is_some() {
            return;
        }
        let Some(current) = self.loaded.get() else {
            return;
        };
        let (payload, scope) = match prepare_write(&self.context, &self.form.get(), &current) {
            Ok(value) => value,
            Err(error) => {
                self.message.revise(|value| {
                    *value = error.to_string();
                });
                return;
            }
        };
        let operation = crate::operation::TypedOperationBuilder::new_for_station::<
            arkret_sdk::event_spec::PolicySet,
        >(
            current.realm.as_str(),
            current.account.principal_id.as_str(),
            current.account.station_id.clone(),
            payload.clone(),
        )
        .effective_scope(scope.clone())
        .build_sdk_event("inkson");
        let operation = match operation {
            Ok(value) => value,
            Err(error) => {
                self.message.revise(|value| {
                    *value = error.to_string();
                });
                return;
            }
        };
        let write = PendingPolicyWrite {
            current,
            payload,
            scope,
            operation,
            signed: None,
        };
        self.awaiting.revise(|value| {
            *value = Some(write.clone());
        });
        submit_pending(
            self.owner.clone(),
            self.context.clone(),
            write,
            self.context.token,
            self.pending,
            self.awaiting,
            self.loaded,
            self.message,
        );
    }
    fn retry(&self) {
        if self.pending.get_untracked() {
            return;
        }
        if let Some(write) = self.awaiting.get() {
            submit_pending(
                self.owner.clone(),
                self.context.clone(),
                write,
                self.context.token,
                self.pending,
                self.awaiting,
                self.loaded,
                self.message,
            );
        }
    }
}

fn draft_field(
    scope: &Scope,
    _context: Rc<InksonContext>,
    key: String,
    label: &str,
    form: Cage<Draft>,
    enabled: glory::Bond<bool>,
    multiline: bool,
    read: impl Fn(&Draft) -> String + 'static,
    write: impl Fn(&mut Draft, String) + 'static,
) -> View {
    let read = Rc::new(read);
    let write = Rc::new(write);
    let value = scope.bond(move || read(&form.get()));
    Box::new(
        sapid::field(key)
            .unstyled()
            .class("field")
            .label(label.to_owned())
            .control(move |field| {
                let write = write.clone();
                sapid::text_field()
                    .unstyled()
                    .field(field)
                    .value(value)
                    .enabled(enabled)
                    .multiline(multiline)
                    .on_value_change(move |next| form.revise(|draft| write(draft, next)))
            }),
    )
}
fn draft_choice(
    scope: &Scope,
    key: String,
    label: &str,
    form: Cage<Draft>,
    structure: Cage<u64>,
    enabled: glory::Bond<bool>,
    options: Vec<String>,
    read: impl Fn(&Draft) -> String + 'static,
    write: impl Fn(&mut Draft, String) + 'static,
) -> View {
    let read = Rc::new(read);
    let write = Rc::new(write);
    #[cfg(not(target_arch = "wasm32"))]
    {
        use crate::presentation::native_choice::{
            NativeChoiceOption, NativeChoiceProps, native_choice,
        };
        let value = scope.bond(move || Some(read(&form.get())));
        native_choice(
            scope,
            NativeChoiceProps::new(
                key,
                label.to_owned(),
                value,
                options
                    .into_iter()
                    .map(|value| NativeChoiceOption::new(value.clone(), value))
                    .collect(),
                move |next| {
                    if let Some(next) = next {
                        form.revise(|draft| write(draft, next));
                        structure.revise(|value| *value += 1);
                    }
                },
            )
            .class("select")
            .enabled(enabled),
        )
    }
    #[cfg(target_arch = "wasm32")]
    {
        let options: Vec<_> = options
            .into_iter()
            .map(|label| (label.clone(), label))
            .collect();
        let selection = options.clone();
        let value = scope.bond(move || {
            crate::views::settings::widgets::select_key(&selection, &read(&form.get()))
        });
        let callback_options = options.clone();
        Box::new(
            sapid::select(key)
                .unstyled()
                .class("select")
                .label(label.to_owned())
                .value(value)
                .enabled(enabled)
                .options(
                    options.into_iter().enumerate().map(|(index, (_, label))| {
                        sapid::select_option(format!("opt-{index}"), label)
                    }),
                )
                .on_value_change(move |next| {
                    if let Some(next) = next.and_then(|key| {
                        crate::views::settings::widgets::select_value(&callback_options, &key)
                    }) {
                        form.revise(|draft| write(draft, next));
                        structure.revise(|value| *value += 1);
                    }
                }),
        )
    }
}

fn operations(
    scope: &Scope,
    form: Cage<Draft>,
    enabled: glory::Bond<bool>,
    index: Option<usize>,
    review_only: bool,
) -> View {
    let mut children = Vec::new();
    for op in [
        "join",
        "authorize",
        "execute",
        "read",
        "deliver",
        "publish",
        "serve",
    ] {
        if review_only && !matches!(op, "join" | "publish") {
            continue;
        }
        let checked = scope.bond(move || {
            let draft = form.get();
            let values = if let Some(index) = index {
                &draft.rules[index].operations
            } else {
                &draft.default_operations
            };
            values.iter().any(|value| value == op)
        });
        children.push(Box::new(
            sapid::checkbox()
                .unstyled()
                .label(op)
                .checked(checked)
                .enabled(enabled)
                .on_checked_change(move |checked| {
                    form.revise(|draft| {
                        let values = if let Some(index) = index {
                            &mut draft.rules[index].operations
                        } else {
                            &mut draft.default_operations
                        };
                        values.retain(|value| value != op);
                        if checked {
                            values.push(op.into());
                        }
                    })
                }),
        ) as View);
    }
    line("actions", children)
}
pub(super) fn page(scope: &Scope, context: Rc<InksonContext>, realm: String) -> View {
    let state=PolicyPage{context:context.clone(),owner:scope.downgrade(),realm,form:scope.cage(Draft::default()),
  loaded:scope.cage(None),pending:scope.cage(false),awaiting:scope.cage(None),
  message:scope.cage("Read an exact Policy id before saving. Hidden or unavailable results do not prove absence.".into()),structure:scope.cage(0)};
    let session_state = state.clone();
    scope.effect(move || {
        let _ = session_state.context.session_generation.get();
        session_state.loaded.revise(|value| {
            *value = None;
        });
        session_state.awaiting.revise(|value| {
            *value = None;
        });
        session_state.pending.revise(|value| {
            *value = false;
        });
    });
    let form = state.form;
    let pending = state.pending;
    let loaded = state.loaded;
    let awaiting = state.awaiting;
    let structure = state.structure;
    let enabled = scope.bond(move || !pending.get());
    let read_state = state.clone();
    let save_state = state.clone();
    let retry_state = state.clone();
    let support_context = context.clone();
    let supported = scope.bond(move || {
        !pending.get()
            && awaiting.get().is_none()
            && loaded.get().as_ref().is_some_and(|current| {
                prepare_write(&support_context, &form.get(), current).is_ok()
            })
    });
    let editor_context = context.clone();
    let dynamic = reactive(structure, move |scope, _| {
        let context = editor_context.clone();
        let draft = form.get_untracked();
        let mut fields = Vec::new();
        if draft.default_effect == "require_review" {
            fields.push(operations(scope, form, enabled, None, true));
            fields.push(draft_field(
                scope,
                context.clone(),
                "policy-default-approvers".into(),
                "Default approvers: complete SDK ActorId array",
                form,
                enabled,
                true,
                |draft| draft.default_approvers.clone(),
                |draft, value| draft.default_approvers = value,
            ));
            fields.push(draft_field(
                scope,
                context.clone(),
                "policy-default-threshold".into(),
                "Default approval threshold",
                form,
                enabled,
                false,
                |draft| draft.default_threshold.clone(),
                |draft, value| draft.default_threshold = value,
            ));
            fields.push(draft_field(
                scope,
                context.clone(),
                "policy-default-max-age".into(),
                "Default approval lifetime seconds (1–86400)",
                form,
                enabled,
                false,
                |draft| draft.default_max_age.clone(),
                |draft, value| draft.default_max_age = value,
            ));
        }
        for (index, rule) in draft.rules.iter().enumerate() {
            let mut children = vec![
                draft_field(
                    scope,
                    context.clone(),
                    format!("rule-{index}-id"),
                    "Stable rule id",
                    form,
                    enabled,
                    false,
                    move |draft| draft.rules[index].id.clone(),
                    move |draft, value| draft.rules[index].id = value,
                ),
                draft_field(
                    scope,
                    context.clone(),
                    format!("rule-{index}-priority"),
                    "Rule priority",
                    form,
                    enabled,
                    false,
                    move |draft| draft.rules[index].priority.clone(),
                    move |draft, value| draft.rules[index].priority = value,
                ),
                draft_choice(
                    scope,
                    format!("rule-{index}-effect"),
                    "Effect",
                    form,
                    structure,
                    enabled,
                    effects(),
                    move |draft| draft.rules[index].effect.clone(),
                    move |draft, value| draft.rules[index].effect = value,
                ),
                draft_choice(
                    scope,
                    format!("rule-{index}-target"),
                    "Agent selector",
                    form,
                    structure,
                    enabled,
                    ["all", "controller", "agent"].map(str::to_owned).into(),
                    move |draft| draft.rules[index].target.clone(),
                    move |draft, value| draft.rules[index].target = value,
                ),
            ];
            if rule.target != "all" {
                children.push(draft_field(
                    scope,
                    context.clone(),
                    format!("rule-{index}-principal"),
                    "Complete Account: principal_id",
                    form,
                    enabled,
                    false,
                    move |draft| draft.rules[index].principal.clone(),
                    move |draft, value| draft.rules[index].principal = value,
                ));
                children.push(draft_field(
                    scope,
                    context.clone(),
                    format!("rule-{index}-station"),
                    "Complete Account: station_id",
                    form,
                    enabled,
                    false,
                    move |draft| draft.rules[index].station.clone(),
                    move |draft, value| draft.rules[index].station = value,
                ));
            }
            children.push(operations(scope, form, enabled, Some(index), false));
            children.push(draft_field(
                scope,
                context.clone(),
                format!("rule-{index}-actions"),
                "Registered action ids (optional, whitespace separated)",
                form,
                enabled,
                true,
                move |draft| draft.rules[index].actions.clone(),
                move |draft, value| draft.rules[index].actions = value,
            ));
            for resource_index in 0..rule.resources.len() {
                children.push(stack(
                    "policy-resource-editor",
                    vec![
                        draft_choice(
                            scope,
                            format!("rule-{index}-resource-{resource_index}-kind"),
                            "Resource kind",
                            form,
                            structure,
                            enabled,
                            ["realm", "strand", "space", "object", "service"]
                                .map(str::to_owned)
                                .into(),
                            move |draft| draft.rules[index].resources[resource_index].kind.clone(),
                            move |draft, value| {
                                draft.rules[index].resources[resource_index].kind = value
                            },
                        ),
                        draft_field(
                            scope,
                            context.clone(),
                            format!("rule-{index}-resource-{resource_index}-realm"),
                            "Resource Realm (optional)",
                            form,
                            enabled,
                            false,
                            move |draft| draft.rules[index].resources[resource_index].realm.clone(),
                            move |draft, value| {
                                draft.rules[index].resources[resource_index].realm = value
                            },
                        ),
                        draft_field(
                            scope,
                            context.clone(),
                            format!("rule-{index}-resource-{resource_index}-reference"),
                            "Exact resource reference (optional)",
                            form,
                            enabled,
                            false,
                            move |draft| {
                                draft.rules[index].resources[resource_index]
                                    .reference
                                    .clone()
                            },
                            move |draft, value| {
                                draft.rules[index].resources[resource_index].reference = value
                            },
                        ),
                        action(
                            scope,
                            context.clone(),
                            "policy-remove-resource",
                            "Remove resource",
                            "secondary",
                            enabled,
                            move || {
                                form.revise(|draft| {
                                    draft.rules[index].resources.remove(resource_index);
                                });
                                structure.revise(|value| *value += 1);
                            },
                        ),
                    ],
                ));
            }
            children.push(action(
                scope,
                context.clone(),
                "policy-add-resource",
                "Add resource",
                "secondary",
                enabled,
                move || {
                    form.revise(|draft| {
                        draft.rules[index].resources.push(ResourceDraft {
                            kind: "realm".into(),
                            ..ResourceDraft::default()
                        })
                    });
                    structure.revise(|value| *value += 1);
                },
            ));
            if rule.effect == "require_review" {
                children.push(draft_field(
                    scope,
                    context.clone(),
                    format!("rule-{index}-approvers"),
                    "Approvers: complete SDK ActorId array",
                    form,
                    enabled,
                    true,
                    move |draft| draft.rules[index].approvers.clone(),
                    move |draft, value| draft.rules[index].approvers = value,
                ));
                children.push(draft_field(
                    scope,
                    context.clone(),
                    format!("rule-{index}-threshold"),
                    "Approval threshold",
                    form,
                    enabled,
                    false,
                    move |draft| draft.rules[index].threshold.clone(),
                    move |draft, value| draft.rules[index].threshold = value,
                ));
                children.push(draft_field(
                    scope,
                    context.clone(),
                    format!("rule-{index}-max-age"),
                    "Approval lifetime seconds (1–86400)",
                    form,
                    enabled,
                    false,
                    move |draft| draft.rules[index].max_age.clone(),
                    move |draft, value| draft.rules[index].max_age = value,
                ));
            }
            children.push(action(
                scope,
                context.clone(),
                "policy-remove-rule",
                "Remove rule",
                "secondary",
                enabled,
                move || {
                    form.revise(|draft| {
                        draft.rules.remove(index);
                    });
                    structure.revise(|value| *value += 1);
                },
            ));
            fields.push(card(
                scope,
                context.clone(),
                &format!("Rule {index}"),
                children,
            ));
        }
        stack("agent-policy-rules", fields)
    });
    card(
        scope,
        context.clone(),
        "Agent management Policy",
        vec![
            paragraph(
                "",
                "Management limits are separate from Realm joining, member consent and Agent capability grants. A controller selector applies to that complete Account's current and future Agents.",
            ),
            draft_field(
                scope,
                context.clone(),
                "agent-policy-id".into(),
                "Exact Policy id",
                form,
                enabled,
                false,
                |draft| draft.policy_id.clone(),
                move |draft, value| {
                    draft.policy_id = value;
                    loaded.revise(|value| {
                        *value = None;
                    });
                },
            ),
            action(
                scope,
                context.clone(),
                "agent-policy-read-current",
                "Read current",
                "secondary",
                enabled,
                move || read_state.load(),
            ),
            draft_field(
                scope,
                context.clone(),
                "agent-policy-circle".into(),
                "Scope Circle id (blank means this Realm)",
                form,
                enabled,
                false,
                |draft| draft.circle.clone(),
                |draft, value| draft.circle = value,
            ),
            draft_choice(
                scope,
                "policy-default-effect".into(),
                "Default effect",
                form,
                structure,
                enabled,
                effects(),
                |draft| draft.default_effect.clone(),
                |draft, value| draft.default_effect = value,
            ),
            draft_field(
                scope,
                context.clone(),
                "agent-policy-priority".into(),
                "Policy priority (optional)",
                form,
                enabled,
                false,
                |draft| draft.priority.clone(),
                |draft, value| draft.priority = value,
            ),
            draft_field(
                scope,
                context.clone(),
                "agent-policy-not-before".into(),
                "Not before (RFC 3339, optional)",
                form,
                enabled,
                false,
                |draft| draft.not_before.clone(),
                |draft, value| draft.not_before = value,
            ),
            draft_field(
                scope,
                context.clone(),
                "agent-policy-expires".into(),
                "Expires at (RFC 3339, optional)",
                form,
                enabled,
                false,
                |draft| draft.expires_at.clone(),
                |draft, value| draft.expires_at = value,
            ),
            dynamic,
            action(
                scope,
                context.clone(),
                "policy-add-rule",
                "Add rule",
                "secondary",
                enabled,
                move || {
                    form.revise(|draft| draft.rules.push(RuleDraft::default()));
                    structure.revise(|value| *value += 1);
                },
            ),
            paragraph(
                "muted",
                "Realm and Circle policies support the registered Agent operations and allow, deny or quarantine effects. Realm Join and Publish can require review; Circle review is unavailable. Saving a policy does not confirm runtime authorization.",
            ),
            action(
                scope,
                context.clone(),
                "agent-policy-retry-pending",
                "Retry original pending Policy",
                "secondary",
                scope.bond(move || !pending.get() && awaiting.get().is_some()),
                move || retry_state.retry(),
            ),
            action(
                scope,
                context.clone(),
                "agent-policy-save",
                "Save Agent Policy",
                "primary",
                supported,
                move || save_state.save(),
            ),
            status(state.message),
        ],
    )
}
