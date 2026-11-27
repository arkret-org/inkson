use arkret_sdk::{
    ActorId, CallId, CallRecordingId, CurrentSelector, CurrentState, DidCoreId, GrantId, RealmId,
    RecordingCaptureKind, ScopeRef,
};

use crate::event_submit::EventSubmitter;
use crate::models::{
    EventSubmissionProgress, MediaIceConfigurationRequestBody, MediaIceConfigurationResponseBody,
};

/// Local selection from a current disclosure. The server still decides the
/// complete permission, approvals, quota and current global refusals.
pub(crate) struct CallCaptureSource {
    scope: ScopeRef,
    recorder: DidCoreId,
    key_ref: Option<arkret_sdk::EncryptedAttachmentKeyRef>,
    digest: arkret_sdk::Hash,
}

impl CallCaptureSource {
    fn require_unchanged(&self, next: &Self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.digest == next.digest
                && self.scope == next.scope
                && self.recorder == next.recorder
                && self.key_ref == next.key_ref,
            "Call capture sources changed during Grant selection; reload current state"
        );
        Ok(())
    }
}

fn current_entry<'a>(
    entries: &'a [CurrentState],
    selector: &CurrentSelector,
) -> anyhow::Result<&'a CurrentState> {
    let mut rows = entries.iter().filter(
        |row| matches!(row, CurrentState::Value { selector: found, .. } if found == selector),
    );
    let row = rows
        .next()
        .ok_or_else(|| anyhow::anyhow!("Call current source is unavailable"))?;
    anyhow::ensure!(rows.next().is_none(), "Call current repeats a selector");
    Ok(row)
}

fn call_scope(
    realm: &RealmId,
    call: &CallId,
    entries: &[CurrentState],
) -> anyhow::Result<ScopeRef> {
    let CurrentState::Value {
        source_stream_ref, ..
    } = current_entry(
        entries,
        &CurrentSelector::CallState {
            call_id: call.clone(),
        },
    )?;
    anyhow::ensure!(
        source_stream_ref.realm_id() == realm,
        "Call current belongs to another Realm"
    );
    anyhow::ensure!(
        matches!(
            source_stream_ref,
            arkret_sdk::CommitStreamRef::Realm { .. }
        ),
        "Call current has an unsupported source stream"
    );
    Ok(source_stream_ref.scope_ref())
}

pub(crate) fn call_capture_source(
    realm: &RealmId,
    call: &CallId,
    entries: &[CurrentState],
    kind: RecordingCaptureKind,
) -> anyhow::Result<CallCaptureSource> {
    let scope = call_scope(realm, call, entries)?;
    let state = current_entry(
        entries,
        &CurrentSelector::CallState {
            call_id: call.clone(),
        },
    )?;
    let CurrentState::Value { value, .. } = state;
    let lifecycle: arkret_sdk::CallStateCurrentValue =
        garth::current_ingest::closed_current_value(value, "call_state")?;
    lifecycle.validate().map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        lifecycle.to == arkret_sdk::CallLifecycleState::Active,
        "Capture requires a committed active Call"
    );
    let focus = current_entry(
        entries,
        &CurrentSelector::CallFocus {
            call_id: call.clone(),
        },
    )?;
    let CurrentState::Value {
        source_stream_ref,
        value,
        ..
    } = focus;
    anyhow::ensure!(
        source_stream_ref.scope_ref() == scope,
        "Call focus belongs to another stream"
    );
    let selected: arkret_sdk::CallFocus =
        garth::current_ingest::closed_current_value(value, "call_focus")?;
    let media = current_entry(entries, &CurrentSelector::RealmMediaService)?;
    let CurrentState::Value {
        source_stream_ref,
        value,
        ..
    } = media;
    anyhow::ensure!(
        *source_stream_ref
            == arkret_sdk::CommitStreamRef::Realm {
                realm_id: realm.clone()
            },
        "Media descriptor belongs to another stream"
    );
    let descriptor: arkret_models_collaboration::events_payloads::RealmMediaServiceValue =
        garth::current_ingest::closed_current_value(value, "realm_media_service")?;
    descriptor.validate()?;
    anyhow::ensure!(
        selected
            .session_focus
            .as_ref()
            .is_some_and(|focus| descriptor.foci.iter().any(|row| &row.focus_id == focus)),
        "Capture requires the committed focus in the current media descriptor"
    );
    let mut sources = vec![state, focus, media];
    let key_ref = if kind == RecordingCaptureKind::Recording {
        anyhow::ensure!(
            descriptor.recording_supported == Some(true),
            "Current media service does not support recording"
        );
        let mls = current_entry(
            entries,
            &CurrentSelector::MlsGroup {
                scope_ref: scope.clone(),
            },
        )?;
        let CurrentState::Value {
            source_stream_ref,
            value,
            ..
        } = mls;
        anyhow::ensure!(
            source_stream_ref.scope_ref() == scope,
            "Recording MLS current belongs to another stream"
        );
        let current: arkret_sdk::MlsGroupValue =
            garth::current_ingest::closed_current_value(value, "mls_group")?;
        anyhow::ensure!(
            current.effective_scope == scope,
            "Recording MLS value belongs to another effective scope"
        );
        anyhow::ensure!(
            current.current_key_access_revision == current.covered_key_access_revision,
            "Recording requires a winning MLS epoch that covers current key access"
        );
        anyhow::ensure!(
            arkret_sdk::MLS_CIPHERSUITES
                .iter()
                .any(|suite| suite.status == "active"
                    && suite.canonical_id == current.cipher_suite.as_str()),
            "Recording MLS current names an unsupported ciphersuite"
        );
        anyhow::ensure!(
            (current.epoch == 0)
                == (current.current_mls_commit_event_ref == current.genesis_event_ref),
            "Recording MLS current has inconsistent Genesis/epoch coordinates"
        );
        sources.push(mls);
        Some(arkret_sdk::EncryptedAttachmentKeyRef {
            algorithm: arkret_sdk::EncryptedAttachmentKeyAlgorithm::Mls,
            group_state_ref: arkret_sdk::EncryptedAttachmentGroupStateRef::Event(
                current.current_mls_commit_event_ref,
            ),
        })
    } else {
        None
    };
    Ok(CallCaptureSource {
        scope,
        recorder: descriptor.service_id,
        key_ref,
        digest: arkret_sdk::Hash::new(arkret_sdk::canonical::canonical_sha256(&sources)?)?,
    })
}

fn capture_action(kind: RecordingCaptureKind) -> arkret_sdk::CapabilityActionId {
    match kind {
        RecordingCaptureKind::Recording => arkret_sdk::CapabilityActionId::CallRecord,
        RecordingCaptureKind::Transcript => arkret_sdk::CapabilityActionId::CallTranscribe,
    }
}

fn select_capture_grant(
    rows: &arkret_sdk::EffectiveGrantSnapshot,
    actor: &ActorId,
    scope: &ScopeRef,
    kind: RecordingCaptureKind,
) -> anyhow::Result<GrantId> {
    let target = match scope {
        ScopeRef::Realm { realm_id } => arkret_sdk::WireResourceSelector::realm(realm_id.clone()),
        _ => anyhow::bail!("Capture requires its Call's Realm scope"),
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut candidates = Vec::new();
    for row in &rows.grants {
        let grant = &row.grant;
        grant.validate_authority_shape()?;
        anyhow::ensure!(
            seen.insert(grant.id.clone()),
            "Current grant response repeats a GrantId"
        );
        if grant.realm_id.as_ref() == Some(scope.realm_id())
            && grant.status == arkret_sdk::CapabilityGrantStatus::Active
            && matches!(&grant.subject, arkret_sdk::CapabilitySubject::Actor(subject) if subject == actor)
            && grant
                .actions
                .iter()
                .any(|action| action == capture_action(kind).as_str())
            && grant.resources.iter().any(|resource| {
                arkret_policy::grant_evaluation::resource_selector_covers(resource, &target)
            })
        {
            candidates.push(grant.id.clone());
        }
    }
    candidates.sort();
    candidates.into_iter().next().ok_or_else(|| {
        anyhow::anyhow!("No current Grant names this complete actor, capture action and Call scope")
    })
}

pub(crate) fn active_capture_segments(
    realm: &RealmId,
    call: &CallId,
    entries: &[CurrentState],
    kind: RecordingCaptureKind,
) -> anyhow::Result<Vec<CallRecordingId>> {
    let scope = call_scope(realm, call, entries)?;
    let mut active = Vec::new();
    for row in entries {
        let CurrentState::Value {
            selector,
            source_stream_ref,
            ..
        } = row;
        let id = match (kind, selector) {
            (
                RecordingCaptureKind::Recording,
                CurrentSelector::CallRecordingState {
                    call_id,
                    recording_id,
                },
            ) if call_id == call => recording_id,
            (
                RecordingCaptureKind::Transcript,
                CurrentSelector::CallTranscriptState {
                    call_id,
                    recording_id,
                },
            ) if call_id == call => recording_id,
            _ => continue,
        };
        anyhow::ensure!(
            source_stream_ref.scope_ref() == scope,
            "Capture current belongs to another Call stream"
        );
        let is_active = capture_state_is_active(row)?;
        if is_active {
            active.push(id.clone());
        }
    }
    active.sort();
    anyhow::ensure!(
        active.windows(2).all(|pair| pair[0] != pair[1]),
        "Capture current repeats a segment"
    );
    Ok(active)
}

pub(crate) fn capture_segment_is_stopped(
    realm: &RealmId,
    call: &CallId,
    entries: &[CurrentState],
    segment: &CallRecordingId,
    kind: RecordingCaptureKind,
) -> anyhow::Result<bool> {
    let scope = call_scope(realm, call, entries)?;
    let selector = match kind {
        RecordingCaptureKind::Recording => CurrentSelector::CallRecordingState {
            call_id: call.clone(),
            recording_id: segment.clone(),
        },
        RecordingCaptureKind::Transcript => CurrentSelector::CallTranscriptState {
            call_id: call.clone(),
            recording_id: segment.clone(),
        },
    };
    let row = current_entry(entries, &selector)?;
    let CurrentState::Value {
        source_stream_ref, ..
    } = row;
    anyhow::ensure!(
        source_stream_ref.scope_ref() == scope,
        "Capture Stop source belongs to another stream"
    );
    Ok(!capture_state_is_active(row)?)
}

fn capture_state_is_active(row: &CurrentState) -> anyhow::Result<bool> {
    let CurrentState::Value {
        selector, value, ..
    } = row;
    match selector {
        CurrentSelector::CallRecordingState { .. } => {
            match serde_json::from_value::<arkret_sdk::CallRecordingState>(value.clone())? {
                arkret_sdk::CallRecordingState::Recording => Ok(true),
                arkret_sdk::CallRecordingState::Stopped => Ok(false),
                _ => anyhow::bail!(
                    "Artifact status cannot replace the native recording permission state"
                ),
            }
        }
        CurrentSelector::CallTranscriptState { .. } => {
            match serde_json::from_value::<arkret_sdk::CallTranscriptState>(value.clone())? {
                arkret_sdk::CallTranscriptState::Transcribing => Ok(true),
                arkret_sdk::CallTranscriptState::Stopped => Ok(false),
                _ => anyhow::bail!(
                    "Artifact status cannot replace the native transcript permission state"
                ),
            }
        }
        _ => anyhow::bail!("Not a capture permission current selector"),
    }
}

pub(crate) enum CallCaptureStopOutcome {
    ObservedStopped,
    Submitted(Box<EventSubmissionProgress>),
}

pub(crate) fn capture_progress_is_committed(progress: &EventSubmissionProgress) -> bool {
    progress.is_committed()
        && progress
            .commit
            .as_ref()
            .is_some_and(|commit| commit.event_ref.as_str() == progress.event_id.as_str())
}

impl CallCaptureStopOutcome {
    pub(crate) fn is_stopped(&self) -> bool {
        matches!(self, Self::ObservedStopped)
            || matches!(self, Self::Submitted(progress) if capture_progress_is_committed(progress))
    }
}

pub struct MediaEndpoints<'a> {
    transport: &'a super::TransportClient,
}

impl<'a> MediaEndpoints<'a> {
    pub(crate) fn new(transport: &'a super::TransportClient) -> Self {
        Self { transport }
    }

    pub async fn ice_config(
        &self,
        request: &MediaIceConfigurationRequestBody,
    ) -> anyhow::Result<MediaIceConfigurationResponseBody> {
        self.transport
            .http()
            .media_ice_config(request)
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn token_exchange(
        &self,
        request: &arkret_sdk::CallMediaTokenExchangeRequestBody,
    ) -> anyhow::Result<arkret_sdk::CallMediaTokenExchangeResponseBody> {
        self.transport
            .http()
            .media_token_exchange(request)
            .await
            .map_err(anyhow::Error::from)
    }
}

pub async fn submit_call_recording_start(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &ActorId,
    call_id: &str,
    recording_id: &CallRecordingId,
    mode: arkret_sdk::RecordingMode,
) -> anyhow::Result<EventSubmissionProgress> {
    submit_call_capture_start(
        submitter,
        realm_id,
        actor_id,
        call_id,
        recording_id,
        arkret_sdk::RecordingCaptureKind::Recording,
        mode,
    )
    .await
}

pub async fn submit_call_transcription_start(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &ActorId,
    call_id: &str,
    transcript_id: &CallRecordingId,
    mode: arkret_sdk::RecordingMode,
) -> anyhow::Result<EventSubmissionProgress> {
    submit_call_capture_start(
        submitter,
        realm_id,
        actor_id,
        call_id,
        transcript_id,
        arkret_sdk::RecordingCaptureKind::Transcript,
        mode,
    )
    .await
}

async fn submit_call_capture_start(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &ActorId,
    call_id: &str,
    recording_id: &CallRecordingId,
    capture_kind: arkret_sdk::RecordingCaptureKind,
    mode: arkret_sdk::RecordingMode,
) -> anyhow::Result<EventSubmissionProgress> {
    let realm = RealmId::new(realm_id.to_owned())?;
    let call = CallId::new(call_id.to_owned())?;
    let own = super::own_station_results::client_for_http(submitter.http()).await?;
    anyhow::ensure!(
        actor_id.as_account_id() == Some(submitter.authority()?)
            && actor_id.as_account_id() == Some(own.session()?.account_id()),
        "Capture author differs from the captured complete Account"
    );
    let before = own.snapshot_head(&realm).await?;
    garth::own_station_results::consume_bound_snapshot(&before, &realm)?;
    let snapshot = before.value()?;
    let source = call_capture_source(&realm, &call, &snapshot.current_state_entries, capture_kind)?;
    anyhow::ensure!(
        active_capture_segments(&realm, &call, &snapshot.current_state_entries, capture_kind)?
            .is_empty(),
        "A native capture segment is already active; stop that segment first"
    );
    let grants = super::realm_read::effective_grants(submitter.http(), &realm, actor_id).await?;
    before.value()?;
    let grant = select_capture_grant(&grants, actor_id, &source.scope, capture_kind)?;
    let after = own.snapshot_head(&realm).await?;
    garth::own_station_results::consume_bound_snapshot(&after, &realm)?;
    let current = after.value()?;
    let next = call_capture_source(&realm, &call, &current.current_state_entries, capture_kind)?;
    source.require_unchanged(&next)?;
    anyhow::ensure!(
        active_capture_segments(&realm, &call, &current.current_state_entries, capture_kind)?
            .is_empty(),
        "A native capture segment became active during Grant selection; reload current state"
    );
    let event = crate::webrtc::build_call_recording_start(
        &source.scope,
        actor_id,
        &call,
        recording_id,
        &grant,
        &source.recorder,
        source.key_ref.as_ref(),
        capture_kind,
        mode,
        true,
    )?
    .build_sdk_event("inkson")?;
    before.value()?;
    after.value()?;
    own.check_session()?;
    submitter.submit_sdk_event(&event).await
}

pub(crate) async fn submit_call_capture_stop(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor: &ActorId,
    call_id: &str,
    recording_id: Option<&CallRecordingId>,
    kind: RecordingCaptureKind,
) -> anyhow::Result<CallCaptureStopOutcome> {
    let realm = RealmId::new(realm_id.to_owned())?;
    let call = CallId::new(call_id.to_owned())?;
    let own = super::own_station_results::client_for_http(submitter.http()).await?;
    anyhow::ensure!(
        actor.as_account_id() == Some(submitter.authority()?)
            && actor.as_account_id() == Some(own.session()?.account_id()),
        "Capture Stop author differs from the captured complete Account"
    );
    let response = own.snapshot_head(&realm).await?;
    garth::own_station_results::consume_bound_snapshot(&response, &realm)?;
    let snapshot = response.value()?;
    let scope = call_scope(&realm, &call, &snapshot.current_state_entries)?;
    let segment = match recording_id {
        Some(id) => id.clone(),
        None => {
            let active =
                active_capture_segments(&realm, &call, &snapshot.current_state_entries, kind)?;
            let [segment] = active.as_slice() else {
                anyhow::bail!(
                    "Capture Stop requires one proven native segment; select its current source first"
                )
            };
            segment.clone()
        }
    };
    if capture_segment_is_stopped(
        &realm,
        &call,
        &snapshot.current_state_entries,
        &segment,
        kind,
    )? {
        response.value()?;
        return Ok(CallCaptureStopOutcome::ObservedStopped);
    }
    let event = crate::webrtc::build_call_capture_stop(&scope, actor, &call, &segment, kind)?
        .build_sdk_event("inkson")?;
    response.value()?;
    own.check_session()?;
    Ok(CallCaptureStopOutcome::Submitted(Box::new(
        submitter.submit_sdk_event(&event).await?,
    )))
}

#[cfg(test)]
mod tests;
