//! Browser WebAuthn PRF bridge for local Recovery Key quick unlock.
//!
//! This module intentionally does not register a new Cokret key-backup
//! recipient method. The PRF output wraps the user's existing 24-word Recovery
//! Key for the current browser/RP context only; fresh-device recovery remains
//! the recovery-policy + key-backup strand.

use anyhow::{Result, anyhow};
#[cfg(target_arch = "wasm32")]
use base64::Engine as _;
#[cfg(target_arch = "wasm32")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

use crate::recovery_crypto::{PASSKEY_PRF_OUTPUT_LEN, PASSKEY_WRAP_SALT_LEN};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyPrfMaterial {
    pub credential_id_b64: String,
    pub prf_output: [u8; PASSKEY_PRF_OUTPUT_LEN],
}

#[cfg(not(target_arch = "wasm32"))]
pub fn default_rp_id() -> Option<String> {
    None
}

#[cfg(target_arch = "wasm32")]
pub fn default_rp_id() -> Option<String> {
    use wasm_bindgen::JsValue;

    let window = web_sys::window()?;
    let location = js_sys::Reflect::get(window.as_ref(), &JsValue::from_str("location")).ok()?;
    let hostname = js_sys::Reflect::get(&location, &JsValue::from_str("hostname"))
        .ok()?
        .as_string()?;
    let host = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host == "127.0.0.1"
        || host == "::1"
        || host.parse::<std::net::IpAddr>().is_ok()
    {
        return Some("origin-default".to_owned());
    }
    Some(host)
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn create_recovery_passkey_prf(
    _label: &str,
    _account_did: &str,
    _rp_id: &str,
    _salt: &[u8; PASSKEY_WRAP_SALT_LEN],
) -> Result<PasskeyPrfMaterial> {
    Err(anyhow!(
        "Passkey PRF quick unlock is available only in the browser build."
    ))
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn evaluate_recovery_passkey_prf(
    _credential_id_b64: &str,
    _rp_id: &str,
    _salt_b64: &str,
) -> Result<PasskeyPrfMaterial> {
    Err(anyhow!(
        "Passkey PRF quick unlock is available only in the browser build."
    ))
}

#[cfg(target_arch = "wasm32")]
pub async fn create_recovery_passkey_prf(
    label: &str,
    account_did: &str,
    rp_id: &str,
    salt: &[u8; PASSKEY_WRAP_SALT_LEN],
) -> Result<PasskeyPrfMaterial> {
    use getrandom::fill;
    use js_sys::{Array, Function, Object, Promise, Reflect};
    use sha2::{Digest, Sha256};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    let credentials = browser_credentials_container()?;

    let mut challenge = [0u8; 32];
    fill(&mut challenge).map_err(|err| anyhow!("passkey challenge rng: {err}"))?;
    let user_digest = Sha256::digest(account_did.as_bytes());

    let public_key = Object::new();
    set(&public_key, "challenge", bytes_js(&challenge).as_ref())?;

    let rp = Object::new();
    set(&rp, "name", &JsValue::from_str("Cokret"))?;
    if explicit_rp_id(rp_id) {
        set(&rp, "id", &JsValue::from_str(rp_id))?;
    }
    set(&public_key, "rp", rp.as_ref())?;

    let user = Object::new();
    set(&user, "id", bytes_js(&user_digest).as_ref())?;
    set(&user, "name", &JsValue::from_str(account_did))?;
    let display_name = label.trim();
    set(
        &user,
        "displayName",
        &JsValue::from_str(if display_name.is_empty() {
            account_did
        } else {
            display_name
        }),
    )?;
    set(&public_key, "user", user.as_ref())?;

    let params = Array::new();
    params.push(&pub_key_param(-7.0)?);
    params.push(&pub_key_param(-257.0)?);
    set(&public_key, "pubKeyCredParams", params.as_ref())?;

    let selection = Object::new();
    set(&selection, "residentKey", &JsValue::from_str("preferred"))?;
    set(
        &selection,
        "userVerification",
        &JsValue::from_str("required"),
    )?;
    set(&public_key, "authenticatorSelection", selection.as_ref())?;
    set(&public_key, "attestation", &JsValue::from_str("none"))?;
    set(&public_key, "timeout", &JsValue::from_f64(60_000.0))?;
    set(
        &public_key,
        "extensions",
        prf_create_extensions(salt)?.as_ref(),
    )?;

    let options = Object::new();
    set(&options, "publicKey", public_key.as_ref())?;

    let create_fn: Function = Reflect::get(&credentials, &JsValue::from_str("create"))
        .map_err(|err| anyhow!("navigator.credentials.create unavailable: {err:?}"))?
        .dyn_into()
        .map_err(|_| anyhow!("navigator.credentials.create is not a function"))?;
    let promise: Promise = create_fn
        .call1(&credentials, options.as_ref())
        .map_err(|err| anyhow!("passkey create call failed: {err:?}"))?
        .dyn_into()
        .map_err(|_| anyhow!("passkey create did not return a Promise"))?;
    let credential = JsFuture::from(promise)
        .await
        .map_err(|err| anyhow!("passkey create rejected: {err:?}"))?;

    let raw_id = Reflect::get(&credential, &JsValue::from_str("rawId"))
        .map_err(|err| anyhow!("passkey rawId missing: {err:?}"))?;
    let credential_id_b64 = B64.encode(array_buffer_bytes(&raw_id)?);

    match prf_first_output(&credential) {
        Ok(prf_output) => Ok(PasskeyPrfMaterial {
            credential_id_b64,
            prf_output,
        }),
        Err(_) => evaluate_recovery_passkey_prf_with_salt(&credential_id_b64, rp_id, salt).await,
    }
}

#[cfg(target_arch = "wasm32")]
pub async fn evaluate_recovery_passkey_prf(
    credential_id_b64: &str,
    rp_id: &str,
    salt_b64: &str,
) -> Result<PasskeyPrfMaterial> {
    let salt_bytes = B64
        .decode(salt_b64.trim_end_matches('='))
        .map_err(|err| anyhow!("passkey salt base64: {err}"))?;
    let salt: [u8; PASSKEY_WRAP_SALT_LEN] = salt_bytes
        .try_into()
        .map_err(|_| anyhow!("passkey salt must be {PASSKEY_WRAP_SALT_LEN} bytes"))?;
    evaluate_recovery_passkey_prf_with_salt(credential_id_b64, rp_id, &salt).await
}

#[cfg(target_arch = "wasm32")]
async fn evaluate_recovery_passkey_prf_with_salt(
    credential_id_b64: &str,
    rp_id: &str,
    salt: &[u8; PASSKEY_WRAP_SALT_LEN],
) -> Result<PasskeyPrfMaterial> {
    use getrandom::fill;
    use js_sys::{Array, Function, Object, Promise, Reflect};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    let credential_id = B64
        .decode(credential_id_b64.trim_end_matches('='))
        .map_err(|err| anyhow!("passkey credential id base64: {err}"))?;
    let credentials = browser_credentials_container()?;

    let mut challenge = [0u8; 32];
    fill(&mut challenge).map_err(|err| anyhow!("passkey challenge rng: {err}"))?;
    let public_key = Object::new();
    set(&public_key, "challenge", bytes_js(&challenge).as_ref())?;
    if explicit_rp_id(rp_id) {
        set(&public_key, "rpId", &JsValue::from_str(rp_id))?;
    }
    set(
        &public_key,
        "userVerification",
        &JsValue::from_str("required"),
    )?;
    set(&public_key, "timeout", &JsValue::from_f64(60_000.0))?;

    let allow_credential = Object::new();
    set(&allow_credential, "type", &JsValue::from_str("public-key"))?;
    set(&allow_credential, "id", bytes_js(&credential_id).as_ref())?;
    let allow_credentials = Array::new();
    allow_credentials.push(allow_credential.as_ref());
    set(&public_key, "allowCredentials", allow_credentials.as_ref())?;
    set(
        &public_key,
        "extensions",
        prf_get_extensions(credential_id_b64, salt)?.as_ref(),
    )?;

    let options = Object::new();
    set(&options, "publicKey", public_key.as_ref())?;

    let get_fn: Function = Reflect::get(&credentials, &JsValue::from_str("get"))
        .map_err(|err| anyhow!("navigator.credentials.get unavailable: {err:?}"))?
        .dyn_into()
        .map_err(|_| anyhow!("navigator.credentials.get is not a function"))?;
    let promise: Promise = get_fn
        .call1(&credentials, options.as_ref())
        .map_err(|err| anyhow!("passkey get call failed: {err:?}"))?
        .dyn_into()
        .map_err(|_| anyhow!("passkey get did not return a Promise"))?;
    let credential = JsFuture::from(promise)
        .await
        .map_err(|err| anyhow!("passkey get rejected: {err:?}"))?;
    let prf_output = prf_first_output(&credential)?;
    Ok(PasskeyPrfMaterial {
        credential_id_b64: credential_id_b64.to_owned(),
        prf_output,
    })
}

#[cfg(target_arch = "wasm32")]
fn browser_credentials_container() -> Result<wasm_bindgen::JsValue> {
    use wasm_bindgen::JsValue;

    let window = web_sys::window().ok_or_else(|| anyhow!("browser window is not available"))?;
    let navigator = js_sys::Reflect::get(window.as_ref(), &JsValue::from_str("navigator"))
        .map_err(|err| anyhow!("window.navigator unavailable: {err:?}"))?;
    let credentials = js_sys::Reflect::get(&navigator, &JsValue::from_str("credentials"))
        .map_err(|err| anyhow!("navigator.credentials unavailable: {err:?}"))?;
    if credentials.is_undefined() || credentials.is_null() {
        return Err(anyhow!("navigator.credentials is not available"));
    }
    Ok(credentials)
}

#[cfg(target_arch = "wasm32")]
fn explicit_rp_id(rp_id: &str) -> bool {
    let trimmed = rp_id.trim();
    !trimmed.is_empty() && trimmed != "origin-default"
}

#[cfg(target_arch = "wasm32")]
fn set(obj: &js_sys::Object, key: &str, value: &wasm_bindgen::JsValue) -> Result<()> {
    js_sys::Reflect::set(obj.as_ref(), &wasm_bindgen::JsValue::from_str(key), value)
        .map_err(|err| anyhow!("set {key}: {err:?}"))?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn bytes_js(bytes: &[u8]) -> js_sys::Uint8Array {
    let out = js_sys::Uint8Array::new_with_length(bytes.len() as u32);
    out.copy_from(bytes);
    out
}

#[cfg(target_arch = "wasm32")]
fn pub_key_param(alg: f64) -> Result<wasm_bindgen::JsValue> {
    let param = js_sys::Object::new();
    set(
        &param,
        "type",
        &wasm_bindgen::JsValue::from_str("public-key"),
    )?;
    set(&param, "alg", &wasm_bindgen::JsValue::from_f64(alg))?;
    Ok(param.into())
}

#[cfg(target_arch = "wasm32")]
fn prf_create_extensions(salt: &[u8; PASSKEY_WRAP_SALT_LEN]) -> Result<js_sys::Object> {
    let first = js_sys::Object::new();
    set(&first, "first", bytes_js(salt).as_ref())?;

    let prf = js_sys::Object::new();
    set(&prf, "eval", first.as_ref())?;

    let extensions = js_sys::Object::new();
    set(&extensions, "prf", prf.as_ref())?;
    Ok(extensions)
}

#[cfg(target_arch = "wasm32")]
fn prf_get_extensions(
    credential_id_b64: &str,
    salt: &[u8; PASSKEY_WRAP_SALT_LEN],
) -> Result<js_sys::Object> {
    let first = js_sys::Object::new();
    set(&first, "first", bytes_js(salt).as_ref())?;

    let eval_by_credential = js_sys::Object::new();
    set(&eval_by_credential, credential_id_b64, first.as_ref())?;

    let prf = js_sys::Object::new();
    set(&prf, "evalByCredential", eval_by_credential.as_ref())?;

    let extensions = js_sys::Object::new();
    set(&extensions, "prf", prf.as_ref())?;
    Ok(extensions)
}

#[cfg(target_arch = "wasm32")]
fn prf_first_output(credential: &wasm_bindgen::JsValue) -> Result<[u8; PASSKEY_PRF_OUTPUT_LEN]> {
    use js_sys::{Function, Reflect};
    use wasm_bindgen::{JsCast, JsValue};

    let ext_fn: Function =
        Reflect::get(credential, &JsValue::from_str("getClientExtensionResults"))
            .map_err(|err| anyhow!("getClientExtensionResults unavailable: {err:?}"))?
            .dyn_into()
            .map_err(|_| anyhow!("getClientExtensionResults is not a function"))?;
    let extensions = ext_fn
        .call0(credential)
        .map_err(|err| anyhow!("getClientExtensionResults failed: {err:?}"))?;
    let prf = Reflect::get(&extensions, &JsValue::from_str("prf"))
        .map_err(|err| anyhow!("prf extension result missing: {err:?}"))?;
    if prf.is_undefined() || prf.is_null() {
        return Err(anyhow!(
            "Passkey PRF is not supported by this browser/authenticator."
        ));
    }
    let results = Reflect::get(&prf, &JsValue::from_str("results"))
        .map_err(|err| anyhow!("prf results missing: {err:?}"))?;
    if results.is_undefined() || results.is_null() {
        return Err(anyhow!(
            "Passkey PRF did not return output; keep the 24-word Recovery Key."
        ));
    }
    let first = Reflect::get(&results, &JsValue::from_str("first"))
        .map_err(|err| anyhow!("prf first output missing: {err:?}"))?;
    let bytes = array_buffer_bytes(&first)?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("passkey PRF output must be {PASSKEY_PRF_OUTPUT_LEN} bytes"))
}

#[cfg(target_arch = "wasm32")]
fn array_buffer_bytes(value: &wasm_bindgen::JsValue) -> Result<Vec<u8>> {
    let view = js_sys::Uint8Array::new(value);
    let mut out = vec![0u8; view.length() as usize];
    view.copy_to(&mut out);
    if out.is_empty() {
        return Err(anyhow!("expected non-empty ArrayBuffer"));
    }
    Ok(out)
}
