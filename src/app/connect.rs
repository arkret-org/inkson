use super::*;

pub(super) fn oidc_refresh_error_invalidates_grant(error: &anyhow::Error) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("invalid_grant")
        || (message.contains("refresh endpoint returned 400")
            && (message.contains("expired")
                || message.contains("revoked")
                || message.contains("provided access grant is invalid")
                || (message.contains("refresh") && message.contains("invalid"))))
}

pub(super) async fn reissue_development_session(
    principal_server_url: &str,
    actor_id: &str,
    device_id: &str,
) -> Option<crate::models::SessionLoginOutcome> {
    if !can_attempt_development_session_reissue(principal_server_url, actor_id, device_id) {
        return None;
    }
    let api = CokretApi::new(principal_server_url).ok()?;
    let description = api.describe().await.ok()?;
    if !description.development_mode {
        return None;
    }
    api.dev_login(actor_id.trim(), device_id.trim()).await.ok()
}

/// The single source of truth for re-minting the principal bearer.
///
/// Registered once at the app root and reached everywhere through
/// [`crate::session::refresh_current_bearer`]. Reads the live
/// base/actor/device from their signals (so it always targets the active
/// session), tries the OIDC `refresh_token` path first, then the
/// session-grant exchange. On success it writes the fresh bearer into the
/// `token` signal and persisted config and returns it; on definitive
/// failure it returns `None` and the caller routes to login.
///
/// Concurrency is handled by `crate::session`: callers coalesce onto one
/// in-flight invocation, so this never runs twice in parallel for a single
/// rollover.
pub(super) async fn remint_principal_bearer(
    base_url: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    mut state_store: Signal<LocalStateStore>,
    mut token: Signal<String>,
    config_store: Signal<LocalConfigStore>,
    session_generation: Signal<u64>,
) -> Option<String> {
    let base = base_url();
    let actor = account_did();
    let device = device_id();
    let generation = session_generation();

    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    let oidc_bundle = {
        let store = state_store.read();
        store.load_oidc_tokens_with_secure_store(&actor, secure_store.as_ref())
    };
    if let Some(bundle) = oidc_bundle
        && crate::oidc::lifecycle::has_refresh_token(&bundle)
    {
        match refresh_oidc_bearer_for_server(&base, &actor, &device, &bundle).await {
            Ok(next) => {
                // Abandon if the user switched servers while the refresh was in
                // flight, or if a logout invalidated this refresh generation.
                // Committing here would resurrect stale credentials over the
                // freshly selected or logged-out session.
                if !same_server_url(&base, &base_url()) || session_generation() != generation {
                    return None;
                }
                let access_token = next.access_token.clone();
                state_store.write().set_oidc_tokens_with_secure_store(
                    Some(next),
                    &actor,
                    secure_store.as_ref(),
                );
                token.set(access_token.clone());
                persist_config(
                    config_store,
                    base.clone(),
                    actor.clone(),
                    device.clone(),
                    access_token.clone(),
                );
                return Some(access_token);
            }
            Err(error) if oidc_refresh_error_invalidates_grant(&error) => {
                if !same_server_url(&base, &base_url()) || session_generation() != generation {
                    return None;
                }
                tracing::warn!(
                    ?error,
                    actor = %actor,
                    "OIDC refresh_token was rejected permanently; clearing persisted OIDC bundle before fallback",
                );
                state_store.write().set_oidc_tokens_with_secure_store(
                    None,
                    &actor,
                    secure_store.as_ref(),
                );
            }
            Err(error) => {
                tracing::warn!(
                    ?error,
                    actor = %actor,
                    "OIDC refresh attempt failed without invalidating the stored refresh_token",
                );
            }
        }
    }

    // ②(A+②): multi-day sliding session. The held credential is the grant
    // itself; when it is near its own expiry the refresh path rotates it (DPoP
    // holder proof signed by the durable device key bound into `cnf.jkt`) onto a
    // fresh grant, and the rotated grant JWT becomes the live credential. There
    // is no longer a grant→bearer exchange. `prepare_refresh_for_server_after_unauthorized`
    // forces a rotation attempt even when the local expiry metadata looks fresh
    // (the server may have rotated/revoked the grant early).
    let prepared = {
        let mut store = state_store.write();
        crate::session_refresh::prepare_refresh_for_server_after_unauthorized(&mut store, &base)
    };
    let outcome = match prepared {
        crate::session_refresh::RefreshPrepared::Done(outcome) => outcome,
        crate::session_refresh::RefreshPrepared::Ready {
            grant,
            device_handle,
        } => {
            let result = crate::session_refresh::exchange_refresh(&grant, &device_handle).await;
            // Same server-switch guard as the OIDC path: don't write the
            // old server's grant outcome onto a session that just moved or
            // logged out.
            if !same_server_url(&base, &base_url()) || session_generation() != generation {
                return None;
            }
            let mut store = state_store.write();
            crate::session_refresh::commit_refresh(&mut store, result)
        }
    };
    match outcome {
        crate::session_refresh::RefreshOutcome::Refreshed { access_token, .. } => {
            if session_generation() != generation {
                return None;
            }
            token.set(access_token.clone());
            persist_config(
                config_store,
                base.clone(),
                actor.clone(),
                device.clone(),
                access_token.clone(),
            );
            Some(access_token)
        }
        crate::session_refresh::RefreshOutcome::LoginRequired { reason } => {
            crate::session::invalidate_current_session(reason);
            None
        }
        _ => {
            let can_reissue_development_session = {
                let store = state_store.read();
                let state = store.load();
                can_bootstrap_with_development_session_reissue(&state, &base, &actor, &device)
            };
            if !can_reissue_development_session {
                return None;
            }
            if let Some(session) = reissue_development_session(&base, &actor, &device).await {
                if !same_server_url(&base, &base_url()) || session_generation() != generation {
                    return None;
                }
                let access_token = session.access_token.clone();
                let actor = if session.actor.as_str().trim().is_empty() {
                    actor
                } else {
                    session.actor.as_str().to_owned()
                };
                let device = if session.device_id.as_str().trim().is_empty() {
                    device
                } else {
                    session.device_id.as_str().to_owned()
                };
                token.set(access_token.clone());
                persist_config(config_store, base, actor, device, access_token.clone());
                return Some(access_token);
            }
            None
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct ConnectContext {
    pub(super) status: Signal<String>,
    pub(super) sync_cursor: Signal<String>,
    pub(super) token: Signal<String>,
    pub(super) account_did: Signal<String>,
    pub(super) selected_realm_id: Signal<String>,
    pub(super) realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
    pub(super) timeline: Signal<Vec<TimelineEvent>>,
    pub(super) device_queue: Signal<usize>,
    pub(super) frontier_state: Signal<String>,
    pub(super) crypto_state: Signal<String>,
    pub(super) config_store: Signal<LocalConfigStore>,
    pub(super) state_store: Signal<LocalStateStore>,
    pub(super) network_state: Signal<String>,
    pub(super) last_error: Signal<Option<String>>,
    pub(super) server_description: Signal<Option<ServerDescription>>,
    pub(super) server_probe_status: Signal<String>,
    pub(super) personal_handles: Signal<Vec<String>>,
    pub(super) personal_handles_status: Signal<String>,
    /// A4a: shared UI theme signal so `/sync` can hydrate the theme
    /// from the remote `client.ui` account-data payload right after
    /// session bootstrap. Stub field — wire-up is tracked under A4a.
    pub(super) theme: Signal<String>,
    /// SyncEngine generation counter. Bumped when `connect()` detects
    /// the canonical actor has changed since the last persisted run
    /// (account swap on the same device) so any in-flight engine for
    /// the previous account exits before applying its response.
    pub(super) sync_generation: Signal<u64>,
    pub(super) needs_device_authorization: Signal<bool>,
    pub(super) device_authorization_check_complete: Signal<bool>,
    pub(super) account_has_other_devices: Signal<bool>,
    /// Set when the explicit bootstrap/manual connect attempt has completed.
    /// The background SyncEngine waits for this so it does not race the
    /// first full account-subscribe snapshot on the same render.
    pub(super) sync_bootstrap_complete: Signal<bool>,
    pub(super) session_boot_state: Signal<SessionBootState>,
    pub(super) navigator: Navigator,
    /// Receive-side call-signaling hub. The full boot sync routes inbound
    /// `ck.call.signal` envelopes into it (dedup → incoming ring / per-call
    /// inbox); `CallPanel` drains it. See `crate::views::call_signals`.
    pub(super) call_signal_hub: crate::views::call_signals::CallSignalHub,
    /// Session DID-resolution cache handle. The boot sync's Tier-2 device-key
    /// chain verification (`device-lifecycle.md` §8.3) anchors the published
    /// PSK against the actor's DID document through a resolver backed by a
    /// snapshot of this cache; back-fills are written back. Shared with the
    /// SyncEngine's `did_cache` so both receive paths reuse resolved documents.
    pub(super) did_cache: Signal<crate::did_resolver::DidResolutionCache>,
}

pub(super) fn redirect_to_login(navigator: Navigator) {
    let _ = navigator.push(Route::Login);
}

/// ②(A+②) — build a `/_cokret/self/*`-ready client: the credential
/// (`ck.session.grant` JWT) as the bearer plus the device DPoP holder key so
/// each request carries a per-request `DPoP` proof (api-conventions.md §3.3).
/// Used by standalone (non-`connect`) self-path call sites that build their own
/// `CokretApi`. Best-effort on the DPoP key: if it cannot be loaded the bearer
/// is still attached (dev-login / OAuth-introspection inbound paths).
pub(super) fn self_authed_api(
    base: &str,
    grant_or_bearer: impl Into<String>,
) -> anyhow::Result<CokretApi> {
    let api = CokretApi::new(base)?.with_bearer(grant_or_bearer);
    Ok(crate::views::helpers::attach_device_dpop(api))
}

pub(super) fn adopt_live_token_for_api(
    api: &CokretApi,
    live_token: Signal<String>,
    session_token: &mut String,
    authed: &mut CokretApi,
) {
    let latest = live_token();
    if !latest.trim().is_empty() && latest != *session_token {
        *session_token = latest;
        *authed = api.clone().with_bearer(session_token.clone());
    }
}

/// Enroll the current session `device` through the delegated account authority
/// (decision 0002 §5.4). Resolves the gate base from the Principal Server's
/// describe, derives this device's `device_public_key` from the persisted
/// signing seed, reads the next `actor_seq` from the principal control stream,
/// asks coauth to mint a signed `service_attested` `ck.device.authorize`, and
/// submits it via `principal_api` (`POST /_cokret/self/events`).
async fn enroll_current_session_device(
    base: &str,
    actor: &str,
    device: &str,
    principal_api: &CokretApi,
    mut state_store: Signal<crate::local_state::LocalStateStore>,
) -> anyhow::Result<()> {
    let actor = actor.trim();
    if actor.is_empty() {
        anyhow::bail!("device enrollment requires a known account DID");
    }
    let grant = state_store
        .read()
        .session_grant()
        .ok_or_else(|| anyhow::anyhow!("device enrollment requires an active session grant"))?;

    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    let material = crate::secure_key_store::ensure_signing_seed(secure_store.as_ref())
        .map_err(|error| anyhow::anyhow!("ensure device signing seed: {error}"))?;
    let device_public_key = crate::device_enrollment::device_public_key_multibase(&material);

    let gate_account_base = crate::coauth::resolve_principal_auth_server_url(base)
        .await
        .map_err(|error| anyhow::anyhow!("resolve account authority: {error}"))?;
    let coauth = crate::coauth::CoauthApi::new(&gate_account_base)?;

    let device_key = {
        let mut store = state_store.write();
        crate::auth_dpop::ensure_device_key(&mut store)
            .map_err(|error| anyhow::anyhow!("load device holder key: {error}"))?
    };
    let htu = coauth.endpoint_url("device-authorize")?;
    let dpop_proof = device_key
        .mint_proof("POST", &htu, Some(&grant.grant_jwt))
        .map_err(|error| anyhow::anyhow!("mint device-authorize DPoP proof: {error}"))?;

    // Next control-stream sequence for this principal = highest accepted + 1.
    // `actor_seq` is 1-indexed on the Principal Server (soland rejects 0 with
    // `actor_seq must be greater than zero`), so an empty stream (no frontier
    // yet) enrolls at seq 1, not 0.
    let actor_seq = match principal_api.events_frontier_actor(actor).await {
        Ok(view) => view.actor_seq.saturating_add(1),
        Err(error) => {
            tracing::debug!(?error, "no actor frontier yet; enrolling at seq 1");
            1
        }
    };

    let request = crate::device_enrollment::DeviceEnrollmentRequest {
        grant_jwt: grant.grant_jwt,
        dpop_proof,
        device_id: device.to_owned(),
        device_public_key,
        actor_seq,
        not_before: None,
    };
    crate::device_enrollment::enroll_current_device(&coauth, principal_api, &request, device).await
}

pub(super) fn connect(base: String, actor: String, device: String, ctx: ConnectContext) {
    let device = normalize_device_id(&device);
    spawn(async move {
        let mut sync_bootstrap_complete = ctx.sync_bootstrap_complete;
        let mut status = ctx.status;
        let mut sync_cursor = ctx.sync_cursor;
        let mut token = ctx.token;
        let mut account_did = ctx.account_did;
        let mut selected_realm_id = ctx.selected_realm_id;
        let mut realm_tree_nodes = ctx.realm_tree_nodes;
        let mut timeline = ctx.timeline;
        let mut device_queue = ctx.device_queue;
        let mut frontier_state = ctx.frontier_state;
        let mut crypto_state = ctx.crypto_state;
        let config_store = ctx.config_store;
        let mut state_store = ctx.state_store;
        let mut network_state = ctx.network_state;
        let mut last_error = ctx.last_error;
        let mut server_description = ctx.server_description;
        let mut server_probe_status = ctx.server_probe_status;
        let mut personal_handles = ctx.personal_handles;
        let mut personal_handles_status = ctx.personal_handles_status;
        let mut theme = ctx.theme;
        let navigator = ctx.navigator;
        let mut session_boot_state = ctx.session_boot_state;
        let mut needs_device_authorization = ctx.needs_device_authorization;
        let mut device_authorization_check_complete = ctx.device_authorization_check_complete;
        let mut account_has_other_devices = ctx.account_has_other_devices;

        needs_device_authorization.set(false);
        device_authorization_check_complete.set(false);
        account_has_other_devices.set(false);
        session_boot_state.set(if token().trim().is_empty() {
            SessionBootState::Restoring
        } else {
            SessionBootState::Checking
        });
        status.set(ConnectionState::Loading.label().to_owned());
        network_state.set("reconnecting".to_owned());
        last_error.set(None);
        match CokretApi::new(&base) {
            Ok(api) => {
                // ②(A+②) — bind the device DPoP holder key so every clone of
                // this base client attaches a per-request `DPoP` proof to
                // `/_cokret/self/*` requests (api-conventions.md §3.3). The grant
                // (set later via `with_bearer`) is the credential; the DPoP key
                // sender-constrains it. `with_bearer` preserves this field, so all
                // `api.clone().with_bearer(grant)` sites below inherit the DPoP
                // device. Falls back to bearer-only if no device key is available.
                let device_handle = crate::auth_dpop::load_device_key(&state_store.read())
                    .ok()
                    .flatten();
                let persisted_grant = state_store.read().session_grant();
                let api = match device_handle {
                    Some(handle) => {
                        let mut api = api.with_dpop_device(handle.clone());
                        // Attach the session-grant holder proof (minted from the
                        // persisted grant + device key) so the Principal Server's
                        // grant introspection passes on cache-miss / restore, not
                        // just within the ≤120s introspection cache window seeded
                        // by the initial login.
                        if let Some(grant) = persisted_grant
                            && let Ok(proof) = handle.mint_session_grant_introspection_proof(
                                &grant.grant_id,
                                &grant.grant_jwt,
                                &grant.audience,
                            )
                        {
                            api = api.with_session_grant_proof(proof);
                        }
                        api
                    }
                    None => api,
                };
                // Probe `/server/describe` for status text, but treat failure
                // as non-fatal: a transient describe error (CORS preflight,
                // server warming up, brief 5xx) must not block the sync below
                // — otherwise an existing session with cached/server-side
                // the Realm tree silently renders "No Realm tree loaded" until the user
                // manually retries.
                let description = match api.describe().await {
                    Ok(description) => {
                        let missing = description.missing_v1_principal_server_requirements();
                        if !missing.is_empty() {
                            let message =
                                format!("server describe rejected: missing {}", missing.join(", "));
                            status.set(format!("{}: {message}", ConnectionState::Error.label()));
                            network_state.set("offline".to_owned());
                            last_error.set(Some(message.clone()));
                            server_probe_status.set(message);
                            server_description.set(None);
                            session_boot_state.set(if token().trim().is_empty() {
                                SessionBootState::Unauthenticated
                            } else {
                                SessionBootState::Authenticated
                            });
                            sync_bootstrap_complete.set(true);
                            return;
                        }
                        status.set(format!(
                            "{}: {} / {}",
                            ConnectionState::Online.label(),
                            description.service_type,
                            description.protocol_version
                        ));
                        network_state.set("online".to_owned());
                        server_probe_status.set(format!(
                            "server describe loaded: {} / {}",
                            description.service_type, description.protocol_version
                        ));
                        // Round 4 — cache the advertised trust_domain so
                        // downstream signing strands (cross_signing.publish,
                        // S2S transcripts) can pull a canonical
                        // value off local state without an extra round
                        // trip. Cleared when describe fails so a stale
                        // domain can't leak into the next strand.
                        {
                            let mut store = state_store.write();
                            let mut snapshot = store.load();
                            // `TypedTrustDomainId` enforces a non-empty
                            // `ck:trust_domain:<scope>` shape at deserialize
                            // time, so the previous "is_empty" guard is
                            // structurally impossible. Always cache.
                            snapshot.server_trust_domain =
                                Some(description.trust_domain.as_str().to_owned());
                            store.save(snapshot);
                        }
                        server_description.set(Some(description.clone()));
                        Some(description)
                    }
                    Err(error) => {
                        status.set(format!(
                            "{}: describe failed: {error}; trying sync",
                            ConnectionState::Reconnecting.label()
                        ));
                        network_state.set("reconnecting".to_owned());
                        last_error.set(Some(format!("describe: {error}")));
                        server_probe_status.set(format!("server describe failed: {error}"));
                        server_description.set(None);
                        None
                    }
                };

                let mut session_token = token();
                if !session_token.trim().is_empty()
                    && let Some(refreshed) = crate::session::refresh_current_bearer().await
                {
                    session_token = refreshed;
                    session_boot_state.set(SessionBootState::Checking);
                }
                if session_token.trim().is_empty() {
                    if let Some(refreshed) = crate::session::refresh_current_bearer().await {
                        session_token = refreshed;
                        session_boot_state.set(SessionBootState::Checking);
                    } else {
                        let probe_label = description
                            .as_ref()
                            .map(|d| format!("{} / {}", d.service_type, d.protocol_version))
                            .unwrap_or_else(|| "server probe unavailable".to_owned());
                        status.set(format!("Refreshed: {probe_label}; sign-in required"));
                        network_state.set("online".to_owned());
                        sync_cursor.set("-".to_owned());
                        realm_tree_nodes.set(Vec::new());
                        timeline.set(Vec::new());
                        device_queue.set(0);
                        crypto_state.set("No authenticated session".to_owned());
                        persist_config(
                            config_store,
                            base.clone(),
                            actor.clone(),
                            device.clone(),
                            String::new(),
                        );
                        needs_device_authorization.set(false);
                        device_authorization_check_complete.set(true);
                        session_boot_state.set(SessionBootState::Unauthenticated);
                        sync_bootstrap_complete.set(true);
                        return;
                    }
                }

                let mut authed = api.clone().with_bearer(session_token.clone());
                adopt_live_token_for_api(&api, token, &mut session_token, &mut authed);
                // Resolve the canonical actor DID from the account viewer. Three
                // outcomes:
                //   1. Ok with non-empty DID -> use it as canonical_actor.
                //   2. Err that looks like auth expiry -> wipe session, bounce to login. The
                //      session is provably dead.
                //   3. Anything else (Ok with empty DID, transient 5xx, parse error, network
                //      failure) -> fall back to the locally stored actor, log a diagnostic to
                //      last_error so the sidebar/status surface can show it, and keep going so sync
                //      still has a chance to populate realm_tree_nodes.
                let mut account_personal_handle = None::<String>;
                let canonical_actor = match authed.account_me().await {
                    Ok(account) if !account.did.trim().is_empty() => {
                        account_personal_handle =
                            personal_handle_from_account_handle(&account.handle, &base);
                        account.did
                    }
                    Ok(_) => {
                        last_error.set(Some(
                            "account_me: server returned empty actor DID; reusing local actor"
                                .to_owned(),
                        ));
                        actor.clone()
                    }
                    Err(error) if is_auth_expired_error(&error) => {
                        if let Some(refreshed) = crate::session::refresh_current_bearer().await {
                            session_token = refreshed;
                            authed = api.clone().with_bearer(session_token.clone());
                            match authed.account_me().await {
                                Ok(account) if !account.did.trim().is_empty() => {
                                    account_personal_handle =
                                        personal_handle_from_account_handle(&account.handle, &base);
                                    account.did
                                }
                                Ok(_) => {
                                    last_error.set(Some(
                                        "account_me: refreshed session returned empty actor DID; reusing local actor"
                                            .to_owned(),
                                    ));
                                    actor.clone()
                                }
                                Err(retry_error) if !is_auth_expired_error(&retry_error) => {
                                    last_error.set(Some(format!("account_me: {retry_error}")));
                                    actor.clone()
                                }
                                Err(_) => {
                                    token.set(String::new());
                                    persist_config(
                                        config_store,
                                        base.clone(),
                                        actor.clone(),
                                        device.clone(),
                                        String::new(),
                                    );
                                    sync_cursor.set("-".to_owned());
                                    selected_realm_id.set(String::new());
                                    realm_tree_nodes.set(Vec::new());
                                    timeline.set(Vec::new());
                                    device_queue.set(0);
                                    crypto_state.set("Session expired".to_owned());
                                    status.set("Session expired; sign in again".to_owned());
                                    network_state.set("online".to_owned());
                                    last_error
                                        .set(Some("auth_expired: session expired".to_owned()));
                                    needs_device_authorization.set(false);
                                    device_authorization_check_complete.set(true);
                                    session_boot_state.set(SessionBootState::Unauthenticated);
                                    redirect_to_login(navigator);
                                    sync_bootstrap_complete.set(true);
                                    return;
                                }
                            }
                        } else {
                            token.set(String::new());
                            persist_config(
                                config_store,
                                base.clone(),
                                actor.clone(),
                                device.clone(),
                                String::new(),
                            );
                            sync_cursor.set("-".to_owned());
                            selected_realm_id.set(String::new());
                            realm_tree_nodes.set(Vec::new());
                            timeline.set(Vec::new());
                            device_queue.set(0);
                            crypto_state.set("Session expired".to_owned());
                            status.set("Session expired; sign in again".to_owned());
                            network_state.set("online".to_owned());
                            last_error.set(Some("auth_expired: session expired".to_owned()));
                            needs_device_authorization.set(false);
                            device_authorization_check_complete.set(true);
                            session_boot_state.set(SessionBootState::Unauthenticated);
                            redirect_to_login(navigator);
                            sync_bootstrap_complete.set(true);
                            return;
                        }
                    }
                    Err(error) => {
                        last_error.set(Some(format!("account_me: {error}")));
                        actor.clone()
                    }
                };
                if let Some(personal_handle) = account_personal_handle {
                    personal_handles.set(vec![personal_handle]);
                    personal_handles_status.set("1 handle".to_owned());
                } else if personal_handles().is_empty() {
                    personal_handles_status.set("Not published".to_owned());
                }
                if canonical_actor != actor {
                    // Account changed since the last persisted run (the
                    // server's account viewer disagrees with our cached
                    // actor). When the previous actor was non-empty this
                    // means a different human is signing in on the same
                    // device — every account-scoped record (projections,
                    // drafts, seal views, read markers, remarks, and the
                    // previous identity's session grant + OIDC bundle) is
                    // someone else's data and must be wiped before the sync
                    // below repopulates the store. `adopt_account_scope`
                    // performs the wipe and stamps the new owner so a later
                    // login recognises the scope. Device-level state
                    // (local_identity, push_registration, DPoP key) is
                    // preserved.
                    if !actor.trim().is_empty() {
                        let mut store = state_store.write();
                        store.adopt_account_scope(&canonical_actor);
                        // Also wipe the in-memory UI signals so the
                        // sidebar can't paint the previous actor's
                        // Realm tree updates between this point and the sync that's
                        // about to run.
                        drop(store);
                        realm_tree_nodes.set(Vec::new());
                        timeline.set(Vec::new());
                        selected_realm_id.set(String::new());
                        sync_cursor.set("-".to_owned());
                        device_queue.set(0);
                        // Retire the previous-account SyncEngine so its
                        // in-flight long-poll doesn't write back into
                        // the freshly-wiped state.
                        let mut sync_generation = ctx.sync_generation;
                        sync_generation.set(sync_generation() + 1);
                    } else {
                        // No previous identity to displace — just record
                        // who the scope now belongs to (don't wipe: a
                        // just-established grant could be dropped).
                        state_store
                            .write()
                            .stamp_account_scope_owner(&canonical_actor);
                    }
                    account_did.set(canonical_actor.clone());
                } else {
                    // Actor unchanged — record the scope owner so a later
                    // login for a different identity is recognised and the
                    // stale scope is reset.
                    state_store
                        .write()
                        .stamp_account_scope_owner(&canonical_actor);
                }
                adopt_live_token_for_api(&api, token, &mut session_token, &mut authed);
                match authed.list_devices().await {
                    Ok(viewer) => {
                        account_has_other_devices.set(
                            account_has_other_active_devices_from_account_viewer(&viewer, &device),
                        );
                        needs_device_authorization.set(
                            device_authorization_required_from_account_viewer(&viewer, &device),
                        );
                        device_authorization_check_complete.set(true);
                    }
                    Err(error) if is_auth_expired_error(&error) => {
                        if let Some(refreshed) = crate::session::refresh_current_bearer().await {
                            session_token = refreshed;
                            authed = api.clone().with_bearer(session_token.clone());
                            match authed.list_devices().await {
                                Ok(viewer) => {
                                    account_has_other_devices.set(
                                        account_has_other_active_devices_from_account_viewer(
                                            &viewer, &device,
                                        ),
                                    );
                                    needs_device_authorization.set(
                                        device_authorization_required_from_account_viewer(
                                            &viewer, &device,
                                        ),
                                    );
                                }
                                Err(retry_error) => {
                                    tracing::warn!(
                                        ?retry_error,
                                        "device authorization check failed after refresh"
                                    );
                                    needs_device_authorization.set(true);
                                }
                            }
                        } else {
                            needs_device_authorization.set(true);
                        }
                        device_authorization_check_complete.set(true);
                    }
                    Err(error) => {
                        tracing::warn!(?error, "device authorization check failed");
                        needs_device_authorization.set(true);
                        device_authorization_check_complete.set(true);
                    }
                }
                // Decision 0002 §5.4 — when the Principal Server reports this
                // session device is not yet authorized, enroll it through the
                // delegated account authority: coauth signs a `service_attested`
                // `ck.device.authorize` and we submit it to `/_cokret/self/events`,
                // which gives the device row a `device_public_key` so recovery
                // genesis stops failing with `recovery_policy_device_not_authorized`.
                // Idempotent: skipped when already authorized, and a no-op-on-retry
                // because the submit is a CAS on `actor_seq`.
                if needs_device_authorization() {
                    adopt_live_token_for_api(&api, token, &mut session_token, &mut authed);
                    match enroll_current_session_device(
                        &base,
                        &canonical_actor,
                        &device,
                        &authed,
                        state_store,
                    )
                    .await
                    {
                        Ok(()) => {
                            if let Ok(viewer) = authed.list_devices().await {
                                needs_device_authorization.set(
                                    device_authorization_required_from_account_viewer(
                                        &viewer, &device,
                                    ),
                                );
                            } else {
                                needs_device_authorization.set(false);
                            }
                        }
                        Err(error) => {
                            tracing::warn!(?error, "device enrollment failed");
                        }
                    }
                }
                persist_config(
                    config_store,
                    base.clone(),
                    canonical_actor.clone(),
                    device.clone(),
                    session_token.clone(),
                );
                crypto_state.set("Session active".to_owned());

                // `connect()` always issues a full sync (`since=None`) —
                // it's invoked on app boot, the mobile Refresh button,
                // and server switches, all of which represent
                // "re-establish the world from scratch". The SyncEngine
                // (see crate::sync_engine) owns the long-poll loop that
                // threads the cursor for incremental deltas.
                adopt_live_token_for_api(&api, token, &mut session_token, &mut authed);
                let sync_result = match authed.account_subscribe_snapshot(None).await {
                    Ok(sync) => Ok(sync),
                    Err(error) if is_auth_expired_error(&error) => {
                        if let Some(refreshed) = crate::session::refresh_current_bearer().await {
                            session_token = refreshed;
                            authed = api.clone().with_bearer(session_token.clone());
                            authed.account_subscribe_snapshot(None).await
                        } else {
                            Err(error)
                        }
                    }
                    Err(error) => Err(error),
                };
                match sync_result {
                    Ok(sync) => {
                        adopt_live_token_for_api(&api, token, &mut session_token, &mut authed);
                        let invite_notifications = match authed.invites().await {
                            Ok(response) => Some(response.invites),
                            Err(error) if is_auth_expired_error(&error) => {
                                if let Some(refreshed) =
                                    crate::session::refresh_current_bearer().await
                                {
                                    session_token = refreshed;
                                    authed = api.clone().with_bearer(session_token.clone());
                                    authed.invites().await.ok().map(|response| response.invites)
                                } else {
                                    None
                                }
                            }
                            Err(error) => {
                                tracing::debug!(
                                    ?error,
                                    "background sync could not refresh invite notifications"
                                );
                                None
                            }
                        };
                        {
                            let mut store = state_store.write();
                            store.save_sync_cursor(sync.cursor.clone());
                            // Server-authoritative reconcile for top-level
                            // Realm membership. Nested Space containers are
                            // not always returned as top-level sync entries,
                            // so keep local container projections while their
                            // home Realm is still present.
                            let server_set: BTreeSet<String> =
                                sync.realms.keys().cloned().collect();
                            let keep_set = full_sync_projection_keep_set(
                                &server_set,
                                &store.load().realm_tree_projections,
                            );
                            let pruned =
                                store.retain_realm_tree_projections(|id| keep_set.contains(id));
                            if !pruned.is_empty() {
                                tracing::info!(
                                    pruned_count = pruned.len(),
                                    "full sync pruned stale realm-tree projections",
                                );
                            }
                            // Explicit `left_realms` deltas — soland emits
                            // these on incremental syncs too; for full sync
                            // they're redundant with `retain_realm_tree_projections`
                            // above but cheap to apply when soland evolves
                            // to send them on full sync.
                            for left_id in &sync.left_realms {
                                store.forget_realm_tree_projection(left_id);
                            }
                            let realm_title_hints = invite_notifications
                                .as_deref()
                                .map(crate::views::notifications::realm_title_hints_from_values)
                                .unwrap_or_default();
                            for (id, body) in &sync.realms {
                                let projection = crate::realm_tree::projection_with_title_hint(
                                    id,
                                    body,
                                    realm_title_hints.get(id).map(String::as_str),
                                );
                                store.save_realm_tree_projection(id.clone(), projection);
                                // Thread the per-Realm Seal view (frontier /
                                // leaves / state_root / bottom cells) into the
                                // local store so Move builders + UI can read
                                // it. Bodies without an `seal_view` field
                                // produce a Default view (empty frontier =
                                // sentinel) so we still record presence.
                                let view = crate::local_state::LocalSealView::from_sync_body(body);
                                store.set_realm_seal_view(id.clone(), view);
                                store.ingest_move_event_states(id, body);
                            }
                            // Keep notification projection current even when
                            // invites live on `authz/invites` rather than the
                            // normal account subscribe notification stream.
                            let projection_from_sync =
                                crate::views::notifications::notification_items_from_value(
                                    &sync.notifications,
                                );
                            let account_notification_projection = sync
                                .account_data
                                .iter()
                                .filter(|entry| {
                                    crate::views::notifications::is_notification_account_data(entry)
                                })
                                .cloned()
                                .collect::<Vec<_>>();
                            let should_save_notification_projection = projection_from_sync
                                .is_some()
                                || !account_notification_projection.is_empty()
                                || invite_notifications.is_some();
                            let mut notification_projection =
                                projection_from_sync.unwrap_or_else(|| {
                                    if account_notification_projection.is_empty() {
                                        store.notification_projection()
                                    } else {
                                        account_notification_projection
                                    }
                                });
                            if let Some(invites) = invite_notifications {
                                crate::views::notifications::merge_invite_notifications(
                                    &mut notification_projection,
                                    invites,
                                    &server_set,
                                );
                            }
                            if should_save_notification_projection {
                                store.save_notification_projection(notification_projection);
                            }
                            store.save_presence_projection(sync.presence.clone());
                            for entry in &sync.account_data {
                                let Some(data_type) =
                                    entry.get("data_type").and_then(serde_json::Value::as_str)
                                else {
                                    continue;
                                };
                                // A4a — hydrate `client.ui` theme from
                                // the remote payload. Cross-device wins:
                                // when remote carries a valid theme that
                                // differs from the local cached value
                                // we update the UI Signal +
                                // LocalConfigStore synchronously.
                                if data_type == "client.ui" {
                                    if let Some(content) = entry.get("content") {
                                        let local_theme = theme();
                                        if let Some(remote_theme) =
                                            crate::account_data::merge_client_ui_theme(
                                                &local_theme,
                                                content,
                                            )
                                        {
                                            theme.set(remote_theme.clone());
                                            store.save_private_data(
                                                &account_did(),
                                                "theme",
                                                remote_theme,
                                            );
                                        }
                                        if let Some(avatar_blob_ref) =
                                            crate::account_data::avatar_blob_ref_from_client_ui(
                                                content,
                                            )
                                        {
                                            store.save_private_data(
                                                &account_did(),
                                                "avatar_blob_ref",
                                                avatar_blob_ref,
                                            );
                                        } else if crate::account_data::avatar_blob_ref_tombstoned_from_client_ui(content) {
                                            store.save_private_data(
                                                &account_did(),
                                                "avatar_blob_ref",
                                                "",
                                            );
                                        }
                                    }
                                    continue;
                                }
                                if data_type == "ck.account.blocklist" {
                                    let Some(content) = entry.get("content") else {
                                        continue;
                                    };
                                    match crate::account_data::blocklist_entries_from_account_data(
                                        content,
                                    ) {
                                        Ok(entries) => {
                                            store.set_client_blocklist(entries);
                                        }
                                        Err(error) => {
                                            tracing::warn!(
                                                "ignoring malformed ck.account.blocklist account_data: {error}"
                                            );
                                        }
                                    }
                                    continue;
                                }
                                if let Some(actor_id) =
                                    crate::account_data::actor_id_from_contact_remark_key(data_type)
                                {
                                    let Some(content) = entry.get("content") else {
                                        continue;
                                    };
                                    match serde_json::from_value::<crate::account_data::ContactRemark>(
                                        content.clone(),
                                    ) {
                                        Ok(remark) => {
                                            store.set_contact_remark(actor_id.to_owned(), remark);
                                        }
                                        Err(error) => {
                                            tracing::warn!(
                                                "ignoring malformed Contact remark for {actor_id}: {error}"
                                            );
                                        }
                                    }
                                    continue;
                                }
                                let Some(realm_id) =
                                    crate::account_data::realm_id_from_realm_remark_key(data_type)
                                else {
                                    continue;
                                };
                                let Some(content) = entry.get("content") else {
                                    continue;
                                };
                                match serde_json::from_value::<crate::account_data::RealmRemark>(
                                    content.clone(),
                                ) {
                                    Ok(remark) => {
                                        store.set_realm_remark(realm_id.to_owned(), remark);
                                    }
                                    Err(error) => {
                                        tracing::warn!(
                                            "ignoring malformed Realm remark for {realm_id}: {error}"
                                        );
                                    }
                                }
                            }
                            // Force a synchronous flush so that if the user
                            // refreshes the tab immediately after a successful
                            // sync the next mount's `initial_state_store.load()`
                            // sees the new projections + cursor. Without this
                            // we rely on the per-call `flush()` inside each
                            // setter (which is best-effort on wasm) and on the
                            // WriteGuard's Drop, neither of which is guaranteed
                            // before the browser tears down the page.
                            if let Err(error) = store.flush() {
                                last_error.set(Some(format!("state_store flush failed: {error}")));
                            }
                            // YOU-02-002/003: surface a latched persistence
                            // failure from the fire-and-forget setters (quota
                            // exceeded, atomic write error, corrupt boot read)
                            // so the user learns their changes are not being
                            // saved instead of silently diverging from disk.
                            if let Some(message) = store.persist_error() {
                                last_error.set(Some(format!("local state not saved: {message}")));
                            }
                        }
                        // Receive side of `ck.call.signal`: route every realm
                        // body's inbound call-signal envelopes into the hub
                        // (dedup → incoming ring / per-call inbox). Done after
                        // the `store` write guard above is dropped so the hub
                        // Signal writes don't nest inside the store borrow.
                        //
                        // Receiver proof verification (`webrtc-signaling.md`
                        // §5.1, fail-closed): each inbound envelope's `proof` is
                        // verified against the sender's authoritative directory
                        // verify key (resolved via `device_directory`) before any
                        // ring / inbox side effect. The routing is async because
                        // a directory cache miss resolves through `keys/query`.
                        {
                            let mut hub = ctx.call_signal_hub;
                            // Tier-2 (device-lifecycle.md §8.3): resolver-backed
                            // DID anchor over a snapshot of the session DID
                            // cache, so the receiver verifies the sender device
                            // key's full cross-signing chain (not just soland's
                            // assertion). Cache back-fills are written back.
                            let mut did_cache = ctx.did_cache;
                            let anchor = crate::did_resolver::ResolverDidAnchor::from_profile(
                                crate::did_resolver::DeploymentProfile::PersonalNode,
                                did_cache.read().clone(),
                            );
                            for (id, body) in &sync.realms {
                                crate::views::call_signals::route_realm_call_signals(
                                    &mut hub,
                                    id,
                                    body,
                                    &canonical_actor,
                                    Some(&api),
                                    &anchor,
                                )
                                .await;
                            }
                            *did_cache.write() = anchor.into_cache();
                        }
                        let synced_timeline = {
                            // Merge encrypted bodies on read (author sidecar →
                            // remote decrypt-on-read). The `store` write guard
                            // above is out of scope here; take a fresh read
                            // guard scoped to this call.
                            let store_guard = state_store.read();
                            crate::views::timeline::timeline_events_from_sync_realms(
                                &sync.realms,
                                Some(&store_guard),
                                Some((&canonical_actor, &device)),
                            )
                        };
                        // `realm_tree_nodes` is derived from `state_store.realm_tree_projections`
                        // by a use_effect in `RouterView` — we don't set it
                        // here. Read a reconciled snapshot for status text
                        // and selected_realm_id bookkeeping only.
                        let reconciled = realm_tree_nodes_from_sync_realms(
                            &state_store.read().load().realm_tree_projections,
                        );
                        if reconciled.is_empty() {
                            status.set(ConnectionState::Empty.label().to_owned());
                        } else {
                            status.set(format!(
                                "{}: synced {} space(s)",
                                ConnectionState::Online.label(),
                                reconciled.len()
                            ));
                        }
                        let first_realm = reconciled
                            .iter()
                            .find(|node| node.kind == RealmTreeNodeKind::Realm)
                            .map(|node| node.id.clone());
                        let current = selected_realm_id();
                        let trimmed = current.trim();
                        let needs_reset =
                            trimmed.is_empty() || !reconciled.iter().any(|s| s.id == trimmed);
                        if needs_reset {
                            selected_realm_id.set(first_realm.unwrap_or_default());
                        }
                        timeline.set(synced_timeline);
                        device_queue.set(sync.to_device.len());
                        sync_cursor.set(sync.cursor);
                    }
                    Err(error) if is_auth_expired_error(&error) => {
                        token.set(String::new());
                        persist_config(
                            config_store,
                            base.clone(),
                            canonical_actor.clone(),
                            device.clone(),
                            String::new(),
                        );
                        sync_cursor.set("-".to_owned());
                        selected_realm_id.set(String::new());
                        realm_tree_nodes.set(Vec::new());
                        timeline.set(Vec::new());
                        device_queue.set(0);
                        crypto_state.set("Session expired".to_owned());
                        status.set("Session expired; sign in again".to_owned());
                        network_state.set("online".to_owned());
                        last_error.set(Some("auth_expired: session expired".to_owned()));
                        session_boot_state.set(SessionBootState::Unauthenticated);
                        redirect_to_login(navigator);
                        sync_bootstrap_complete.set(true);
                        return;
                    }
                    Err(error) => {
                        // Sync failed — the `realm_tree_nodes` Signal already
                        // reflects what's in the local store via the
                        // derive effect; just refresh status text and
                        // make sure selected_realm_id points at something
                        // still in scope.
                        let fallback = realm_tree_nodes_from_sync_realms(
                            &state_store.read().load().realm_tree_projections,
                        );
                        if fallback.is_empty() {
                            status.set(format!(
                                "{}: sync failed: {error}",
                                ConnectionState::Reconnecting.label()
                            ));
                        } else {
                            status.set(
                                "Refreshed: sync unavailable, showing cached/local Space list"
                                    .to_owned(),
                            );
                        }
                        let first_realm = fallback
                            .iter()
                            .find(|node| node.kind == RealmTreeNodeKind::Realm)
                            .map(|node| node.id.clone());
                        let current = selected_realm_id();
                        let trimmed = current.trim();
                        let needs_reset =
                            trimmed.is_empty() || !fallback.iter().any(|s| s.id == trimmed);
                        if needs_reset {
                            selected_realm_id.set(first_realm.unwrap_or_default());
                        }
                        last_error.set(Some(format!("sync: {error}")));
                    }
                }
                adopt_live_token_for_api(&api, token, &mut session_token, &mut authed);
                let events_result = match authed.events_describe().await {
                    Ok(events) => Ok(events),
                    Err(error) if is_auth_expired_error(&error) => {
                        if let Some(refreshed) = crate::session::refresh_current_bearer().await {
                            session_token = refreshed;
                            authed = api.clone().with_bearer(session_token.clone());
                            authed.events_describe().await
                        } else {
                            Err(error)
                        }
                    }
                    Err(error) => Err(error),
                };
                match events_result {
                    Ok(events) => {
                        // Spec `ServiceDescribe.frontier` is a typed
                        // EventId list; surface the first head.
                        if let Some(frontier) = events.frontier.first() {
                            frontier_state.set(frontier.to_string());
                        }
                    }
                    Err(error) if is_auth_expired_error(&error) => {
                        // Same definitive-session-loss handling as the sync 401
                        // branch above. Without this, an expired token that
                        // passed sync (because sync was served from a cache or
                        // a misrouted path) could silently leave the user with
                        // a stale frontier and no session-expiry redirect.
                        token.set(String::new());
                        persist_config(
                            config_store,
                            base.clone(),
                            canonical_actor.clone(),
                            device.clone(),
                            String::new(),
                        );
                        sync_cursor.set("-".to_owned());
                        selected_realm_id.set(String::new());
                        realm_tree_nodes.set(Vec::new());
                        timeline.set(Vec::new());
                        device_queue.set(0);
                        crypto_state.set("Session expired".to_owned());
                        status.set("Session expired; sign in again".to_owned());
                        network_state.set("online".to_owned());
                        last_error.set(Some("auth_expired: session expired".to_owned()));
                        session_boot_state.set(SessionBootState::Unauthenticated);
                        redirect_to_login(navigator);
                        sync_bootstrap_complete.set(true);
                        return;
                    }
                    Err(error) => {
                        last_error.set(Some(format!("events_describe: {error}")));
                    }
                }
            }
            Err(error) => {
                status.set(format!(
                    "{}: invalid URL: {error}",
                    ConnectionState::Error.label()
                ));
                network_state.set("offline".to_owned());
                last_error.set(Some(format!("invalid URL: {error}")));
                server_probe_status.set(format!("server describe skipped: invalid URL: {error}"));
                server_description.set(None);
            }
        }
        session_boot_state.set(if token().trim().is_empty() {
            SessionBootState::Unauthenticated
        } else {
            SessionBootState::Authenticated
        });
        sync_bootstrap_complete.set(true);
    });
}
