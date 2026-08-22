use super::*;

/// Global name the joint harness calls to read this device's Sidecar fold
/// cache. Versioned so a shape change is a rename, not a silent reinterpretation
/// of the same handle.
#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
const SIDECAR_FOLD_EVIDENCE_HOOK: &str = "__inkson_sidecar_fold_evidence_v1";

#[derive(Clone, Copy, PartialEq)]
pub(super) struct SidecarFoldEvidenceEffectState {
    pub principal_id: Signal<String>,
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
        let SessionContext { state_store, .. } = SessionContext::get();
        use_hook(move || {
            let Some(window) = web_sys::window() else {
                return;
            };
            let hook = Closure::<dyn Fn(String) -> String>::new(move |source_realm_id: String| {
                let controller_id = principal_id.peek().clone();
                if controller_id.is_empty() {
                    return serde_json::json!({"error": "no signed-in controller"}).to_string();
                }
                let store = state_store.peek();
                match crate::sidecar::sidecar_fold_evidence_canonical_json(
                    &store,
                    &controller_id,
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
        });
    }

    rsx! {}
}
