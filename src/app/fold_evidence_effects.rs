use std::rc::Rc;

use glory::Scope;

use crate::presentation::InksonContext;

#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
const SIDECAR_FOLD_EVIDENCE_HOOK: &str = "__inkson_sidecar_fold_evidence_v1";

/// Read-only test-controller evidence. Production builds expose no JS hooks.
pub(super) fn install(scope: &Scope, context: Rc<InksonContext>) {
    #[cfg(not(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test")))]
    let _ = (scope, context);
    #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
    install_test_hooks(scope, context);
}

#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
fn install_test_hooks(scope: &Scope, context: Rc<InksonContext>) {
    use wasm_bindgen::prelude::Closure;
    let Some(window) = web_sys::window() else {
        return;
    };
    let principal_id = context.principal_id;
    let active_account = context.active_account;
    let session_generation = context.session_generation;
    let fold_context = context.clone();
    let hook = Closure::<dyn Fn(String) -> String>::new(move |source_realm_id: String| {
        if !fold_context.session_generation.is_alive() {
            return serde_json::json!({"error":"owner retired"}).to_string();
        }
        let Some(controller_principal_id) = principal_id.get_untracked() else {
            return serde_json::json!({"error":"no signed-in controller"}).to_string();
        };
        let Some(controller_account_id) = active_account
            .get_untracked()
            .map(|account| account.authority)
        else {
            return serde_json::json!({"error":"no signed-in controller account"}).to_string();
        };
        if controller_account_id.principal_id != controller_principal_id {
            return serde_json::json!({"error":"signed-in controller account changed"}).to_string();
        }
        fold_context.state_store.read(|store| {
            crate::sidecar::sidecar_fold_evidence_canonical_json(
                store,
                &controller_account_id,
                &source_realm_id,
            )
            .unwrap_or_else(|error| serde_json::json!({"error":error.to_string()}).to_string())
        })
    });
    let sender_scope = scope.downgrade();
    let sender_context = context.clone();
    let sender = Closure::<dyn Fn(String, String, bool) -> js_sys::Promise>::new(
        move |realm_text: String, strand_text: String, typing: bool| {
            let (reply, received) = tokio::sync::oneshot::channel();
            if let Some(scope) = sender_scope.upgrade() {
                let context = sender_context.clone();
                let state_store = context.state_store.clone();
                let account = active_account.get_untracked();
                let generation = session_generation.get_untracked();
                if let Err(error) = crate::runtime_helpers::spawn_owned(&scope, async move {
                    let result: anyhow::Result<serde_json::Value> = async {
                            let account =
                                account.ok_or_else(|| anyhow::anyhow!("account absent"))?;
                            let fence = crate::transport::auth::AuthoringSessionFence::capture()?;
                            let realm = arkret_sdk::RealmId::new(realm_text)?;
                            let strand = arkret_sdk::StrandId::new(strand_text)?;
                            let scope = arkret_sdk::ScopeRef::Realm {
                                realm_id: realm.clone(),
                            };
                            let material = state_store.read(|store| crate::signal::key_material_for_scope(store, realm.as_str(), None))?;
                            let store =
                                state_store.handle();
                            let session = store
                                .read(|store| store.session_grant())
                                .ok_or_else(|| anyhow::anyhow!("session absent"))?;
                            anyhow::ensure!(
                                session.account_id == account.authority
                                    && session.device_id == account.device_id,
                                "session does not belong to the active Device"
                            );
                            let group_id = scope.canonical_mls_group_id()?;
                            let epoch = material.epoch;
                            fence.check()?;
                            anyhow::ensure!(
                                session_generation.get_untracked() == generation
                                    && active_account.get_untracked().as_ref().is_some_and(
                                        |current| current.authority == account.authority
                                            && current.device_id == account.device_id
                                            && current.server_url == account.server_url
                                            && current.profile_id == account.profile_id
                                    ),
                                "session replaced"
                            );
                            let base_url = account.server_url.to_string();
                            let authority = account.authority.clone();
                            let device = account.device_id.clone();
                            let outcome = crate::transport::auth::with_event_submitter(
                                &base_url,
                                session.grant_jwt,
                                |submitter| async move {
                                    submitter
                                        .send_scope_signal(
                                            scope,
                                            &authority,
                                            &device,
                                            &material,
                                            &crate::signal::SignalPayload::Typing {
                                                strand_id: strand,
                                                typing,
                                            },
                                            &store,
                                        )
                                        .await
                                },
                            )
                            .await
                            .map_err(|_| anyhow::anyhow!("Signal send failed"))?;
                            fence.check()?;
                            anyhow::ensure!(
                                session_generation.get_untracked() == generation
                                    && active_account.get_untracked().as_ref().is_some_and(
                                        |current| current.authority == account.authority
                                            && current.device_id == account.device_id
                                            && current.server_url == account.server_url
                                            && current.profile_id == account.profile_id
                                    ),
                                "session replaced"
                            );
                            Ok(serde_json::json!({"accepted": outcome.accepted,
                                "dispatched_recipient_count": outcome.dispatched_recipient_count,
                                "envelope_digest": outcome.envelope_digest,
                                "group_id": group_id, "epoch": epoch,
                                "sender_actor_id": arkret_sdk::ActorId::account(account.authority.clone()),
                                "sender_device_id": account.device_id}))
                        }
                        .await;
                    // Never return arbitrary transport errors or any body/key bytes.
                    let safe = result.unwrap_or_else(
                        |_| serde_json::json!({"error": "real_signal_send_unavailable"}),
                    );
                    let _ = reply.send(safe.to_string());
                }) {
                    scope.report_error(error);
                }
            }
            wasm_bindgen_futures::future_to_promise(async move {
                let safe = received.await.unwrap_or_else(|_| {
                    serde_json::json!({"error":"real_signal_send_unavailable"}).to_string()
                });
                Ok(wasm_bindgen::JsValue::from_str(&safe))
            })
        },
    );
    let receiver_context = context;
    let receiver = Closure::<dyn Fn(String) -> String>::new(move |command: String| {
        if !receiver_context.session_generation.is_alive() {
            return "[]".to_owned();
        }
        let Some(principal) = principal_id.get_untracked() else {
            return "[]".to_owned();
        };
        crate::signal_receive_engine::signal_receiver_evidence(
            principal.as_str(),
            command == "clear",
        )
    });
    for (name, function) in [
        (SIDECAR_FOLD_EVIDENCE_HOOK, hook.as_ref()),
        ("__inkson_signal_sender_evidence", sender.as_ref()),
        ("__inkson_signal_receiver_evidence", receiver.as_ref()),
    ] {
        if js_sys::Reflect::set(&window, &wasm_bindgen::JsValue::from_str(name), function).is_err()
        {
            tracing::warn!(name, "could not install controller evidence hook");
        }
    }
    // Keep closures alive exactly as long as the account owner. Do not leak
    // a process-global function that can access a retired account's store.
    if let Err(error) = scope.on_cleanup(move || {
        for (name, function) in [
            (SIDECAR_FOLD_EVIDENCE_HOOK, hook.as_ref()),
            ("__inkson_signal_sender_evidence", sender.as_ref()),
            ("__inkson_signal_receiver_evidence", receiver.as_ref()),
        ] {
            let key = wasm_bindgen::JsValue::from_str(name);
            if js_sys::Reflect::get(&window, &key).is_ok_and(|current| current == *function) {
                let _ = js_sys::Reflect::delete_property(window.as_ref(), &key);
            }
        }
    }) {
        scope.report_error(error);
    }
}
