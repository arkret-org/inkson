use super::*;

/// Global name the joint harness calls to read this device's Sidecar fold
/// cache. Versioned so a shape change is a rename, not a silent reinterpretation
/// of the same handle.
#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
const SIDECAR_FOLD_EVIDENCE_HOOK: &str = "__inkson_sidecar_fold_evidence_v1";

#[derive(Clone, Copy, PartialEq)]
pub(super) struct SidecarFoldEvidenceEffectState {
    pub principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
}

/// Install the controller-only, read-only fold-cache evidence surface.
///
/// The whole component collapses to an empty element unless the build is both
/// wasm and explicitly compiled with `wasm-localstorage-secrets-test`, so a
/// production bundle carries neither the hook nor the serializer behind it. The
/// surface is a callable handle rather than anything rendered, logged, or put
/// in a URL: only a driver that already controls the page can reach it, and it
/// returns nothing the signed-in controller does not already hold locally.
#[component]
pub(super) fn SidecarFoldEvidenceEffects(state: SidecarFoldEvidenceEffectState) -> Element {
    #[cfg(not(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test")))]
    let _ = state;

    #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
    {
        use wasm_bindgen::JsCast as _;
        use wasm_bindgen::prelude::Closure;

        let SidecarFoldEvidenceEffectState { principal_id } = state;
        let SessionContext {
            state_store,
            active_account,
            session_generation,
            ..
        } = SessionContext::get();
        use_hook(move || {
            let Some(window) = web_sys::window() else {
                return;
            };
            let hook = Closure::<dyn Fn(String) -> String>::new(move |source_realm_id: String| {
                let Some(controller_principal_id) = principal_id.peek().clone() else {
                    return serde_json::json!({"error": "no signed-in controller"}).to_string();
                };
                let Some(controller_account_id) = active_account
                    .peek()
                    .clone()
                    .map(|account| account.authority)
                else {
                    return serde_json::json!({"error": "no signed-in controller account"})
                        .to_string();
                };
                if controller_account_id.principal_id != controller_principal_id {
                    return serde_json::json!({"error": "signed-in controller account changed"})
                        .to_string();
                }
                let store = state_store.peek();
                match crate::sidecar::sidecar_fold_evidence_canonical_json(
                    &store,
                    &controller_account_id,
                    &source_realm_id,
                ) {
                    Ok(evidence) => evidence,
                    // A shape failure must be visible to the caller rather than
                    // silently becoming an empty exchange list, which would read
                    // as "the fold caches agree".
                    Err(error) => serde_json::json!({"error": error.to_string()}).to_string(),
                }
            });
            let installed = js_sys::Reflect::set(
                &window,
                &wasm_bindgen::JsValue::from_str(SIDECAR_FOLD_EVIDENCE_HOOK),
                hook.as_ref().unchecked_ref(),
            );
            if installed.is_err() {
                tracing::warn!("could not install the Sidecar fold evidence surface");
                return;
            }
            // The handle must outlive this hook: the harness calls it at
            // arbitrary points in the scenario, not during a render.
            hook.forget();

            // Test feature only: invoke the SAME sender as the real composer.
            // Secret group state, Device keys and the nonce ledger never leave Rust.
            let sender = Closure::<dyn Fn(String, String, bool) -> js_sys::Promise>::new(
                move |realm_text: String, strand_text: String, typing: bool| {
                    let account = active_account.peek().clone();
                    let generation = *session_generation.peek();
                    wasm_bindgen_futures::future_to_promise(async move {
                        let result: anyhow::Result<serde_json::Value> = async {
                            let account =
                                account.ok_or_else(|| anyhow::anyhow!("account absent"))?;
                            let fence = crate::transport::auth::AuthoringSessionFence::capture()?;
                            let realm = arkret_sdk::RealmId::new(realm_text)?;
                            let strand = arkret_sdk::StrandId::new(strand_text)?;
                            let scope = arkret_sdk::ScopeRef::Realm {
                                realm_id: realm.clone(),
                            };
                            let material = crate::signal::key_material_for_scope(
                                &state_store.peek(),
                                realm.as_str(),
                                None,
                            )?;
                            let store =
                                crate::app::runtime_adapter::state_store_handle(state_store);
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
                                *session_generation.peek() == generation
                                    && active_account.peek().as_ref().is_some_and(
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
                                *session_generation.peek() == generation
                                    && active_account.peek().as_ref().is_some_and(
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
                        Ok(wasm_bindgen::JsValue::from_str(&safe.to_string()))
                    })
                },
            );
            if js_sys::Reflect::set(
                &window,
                &wasm_bindgen::JsValue::from_str("__inkson_signal_sender_evidence"),
                sender.as_ref().unchecked_ref(),
            )
            .is_ok()
            {
                sender.forget();
            }
            let receiver = Closure::<dyn Fn(String) -> String>::new(move |command: String| {
                let Some(principal) = principal_id.peek().clone() else {
                    return "[]".to_owned();
                };
                crate::signal_receive_engine::signal_receiver_evidence(
                    principal.as_str(),
                    command == "clear",
                )
            });
            if js_sys::Reflect::set(
                &window,
                &wasm_bindgen::JsValue::from_str("__inkson_signal_receiver_evidence"),
                receiver.as_ref().unchecked_ref(),
            )
            .is_ok()
            {
                receiver.forget();
            }
        });
    }

    rsx! {}
}
