use super::*;

#[derive(Clone)]
pub struct ChatPanelProps {
    pub selected_realm_id: String,
    pub initial_strand_id: String,
    pub embedded: bool,
    pub source_suspended: Lotus<bool>,
    pub direct_mode: bool,
    pub direct_peer_id: String,
    pub sidecar_session: Option<crate::sidecar::HostedSidecarState>,
    pub focus_message_id: String,
    pub mention_insert_request: Option<Cage<Option<MentionInsertRequest>>>,
}

fn probe_default_strand(
    scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,
    realm: String,
) {
    let attempted = scope.cage(false);
    scope.effect(move||{
        let _=context.realm_live_epoch.get();let _=context.state_revision.get();
        let feature=crate::conformance::StationFeature::Discussion;
        let credential=context.token.get();
        let missing=context.state_store.read(|store|store.load().realm_tree_projections.get(&realm).and_then(default_discussion_strand_id).is_none());
        if attempted.get_untracked()||!missing||realm.is_empty()||credential.trim().is_empty()||!feature.ready(context.server_description.get().as_ref()){return;}
        attempted.revise(|value|*value=true);
        let context=context.clone();let worker=context.clone();let realm=realm.clone();let base=context.base_url.get_untracked();let generation=context.session_generation.get_untracked();let account=context.active_account.get_untracked();
        super::task::chat_task(context,async move {
            for attempt in 0..20u32 {
                if !worker.session_matches(generation,&account){return;}
                let result=crate::transport::auth::with_authed_sdk_client(&base,credential.clone(),|http|{let realm=realm.clone();async move {crate::transport::realm_read::list_realm_strands(&http,&realm).await}}).await;
                if !worker.session_matches(generation,&account){return;}
                let default=match result {Ok(strands)=>strands.iter().find(|strand|strand.is_default).map(|strand|strand.strand_id.to_string()),Err(error)=>{tracing::warn!(realm_id=%realm,attempt,error=%error.display_diagnostic(),"default Strand projection hydration failed");None}};
                if let Some(default)=default {
                    let changed=worker.state_store.write(|store|{
                        let mut projection=store.load().realm_tree_projections.get(&realm).and_then(Value::as_object).cloned().unwrap_or_default();
                        if projection.get("default_strand_id").and_then(Value::as_str)==Some(default.as_str()){return false;}
                        projection.insert("default_strand_id".into(),Value::String(default));store.save_realm_tree_projection(realm.clone(),Value::Object(projection));true
                    });
                    if changed {worker.realm_live_epoch.revise(|value|*value=value.wrapping_add(1));}return;
                }
                if attempt<19 {crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(250u64.saturating_mul(1u64<<attempt.min(3)))).await;}
            }
            tracing::warn!(realm_id=%realm,"default Strand projection hydration exhausted retries");
        });
    });
}

pub fn page(scope: &Scope, context: Rc<crate::presentation::InksonContext>, route: Route) -> View {
    let (realm, strand, message, direct) = match route {
        Route::Chat { realm_id, message } => (realm_id, None, message, false),
        Route::DirectConversation {
            realm_id,
            strand_id,
        } => (realm_id, Some(strand_id), String::new(), true),
        _ => (
            context.selected_realm_id.get_untracked(),
            None,
            String::new(),
            false,
        ),
    };
    context
        .selected_realm_id
        .revise(|selected| *selected = realm.clone());
    if !direct {
        probe_default_strand(scope, context.clone(), realm.clone());
    }
    let current = context.clone();
    let selected_realm = realm.clone();
    let phase = scope.bond(move || {
        let _ = current.state_revision.get();
        let _ = current.realm_live_epoch.get();
        let description = current.server_description.get();
        let feature = crate::conformance::StationFeature::Discussion;
        let ready = feature.ready(description.as_ref());
        let missing = feature.missing_requirements(description.as_ref());
        let strand = strand
            .clone()
            .or_else(|| {
                current.state_store.read(|store| {
                    store
                        .load()
                        .realm_tree_projections
                        .get(&selected_realm)
                        .and_then(default_discussion_strand_id)
                })
            })
            .unwrap_or_default();
        (ready, description.is_none(), missing, strand)
    });
    crate::presentation::widgets::reactive_distinct(
        phase,
        move |scope, (ready, pending, missing, strand)| {
            if !ready {
                return crate::app::feature_gate_notice(
                    scope,
                    context.clone(),
                    crate::conformance::StationFeature::Discussion,
                    missing,
                    pending,
                );
            }
            let direct_peer_id = if direct {
                crate::app::direct_conversation_peer_id(
                    &context.contact_rows.get(),
                    &realm,
                    &strand,
                )
            } else {
                String::new()
            };
            chat_panel(
                scope,
                context.clone(),
                ChatPanelProps {
                    selected_realm_id: realm.clone(),
                    initial_strand_id: strand,
                    embedded: false,
                    source_suspended: false.into(),
                    direct_mode: direct,
                    direct_peer_id,
                    sidecar_session: None,
                    focus_message_id: message.clone(),
                    mention_insert_request: None,
                },
            )
        },
    )
}

pub fn chat_panel(
    scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,
    props: ChatPanelProps,
) -> View {
    let suspended = props.source_suspended.clone();
    let available = scope.bond(move || !suspended.get());
    retained_discussion_host(available, move |scope, available| {
        let Some(account) = context.active_account.get_untracked() else {
            return crate::presentation::widgets::empty();
        };
        let controller = match controller::chat_controller(
            scope,
            context.clone(),
            &props.selected_realm_id,
            &props.initial_strand_id,
            &account.authority,
            &account.device_id,
        ) {
            Ok(controller) => controller,
            Err(error) => {
                scope.report_error(error);
                return crate::presentation::widgets::empty();
            }
        };
        let target = controller.selected_channel;
        let context = context.clone();
        let props = props.clone();
        crate::presentation::widgets::reactive_distinct(target, move |scope, strand| {
            let controller = match controller.for_strand(
                &context,
                &account.authority,
                &account.device_id,
                &props.selected_realm_id,
                &strand,
            ) {
                Ok(controller) => controller,
                Err(error) => {
                    scope.report_error(error);
                    return crate::presentation::widgets::empty();
                }
            };
            super::panel::target(
                scope,
                context.clone(),
                props.clone(),
                account.clone(),
                controller,
                available,
            )
        })
    })
}
