use super::*;
use crate::api::is_terminal_session_grant_error;

/// The single source of truth for restoring or rotating the current session credential.
///
/// Registered once at the app root and reached everywhere through
/// [`crate::session::refresh_current_session`]. Reads the live
/// base/actor/device from their signals (so it always targets the active
/// session), then either adopts the current grant JWT or rotates the grant.
/// On success it writes the current credential into the `token` signal and
/// persisted config and returns it. Only a terminal refresh-endpoint grant
/// error invalidates the active session; missing local refresh material is
/// reported without clearing the token.
///
/// Concurrency is handled by `crate::session`: callers coalesce onto one
/// in-flight invocation, so this never runs twice in parallel for a single
/// rollover.
pub(super) async fn refresh_session_credential_for_active_context(
    base_url: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    mut state_store: Signal<LocalStateStore>,
    mut token: Signal<String>,
    config_store: Signal<LocalConfigStore>,
    session_generation: Signal<u64>,
) -> crate::session::CurrentSessionRefresh {
    let base = base_url();
    let actor = account_did();
    let device = device_id();
    let generation = session_generation();

    if token().trim().is_empty() {
        let live_grant = {
            let store = state_store.read();
            store.session_grant().and_then(|grant| {
                (crate::session_refresh::grant_matches_principal_server(&grant, &base)
                    && !crate::session_refresh::grant_is_dead(&grant))
                .then_some(grant)
            })
        };
        if let Some(grant) = live_grant {
            let session_credential = grant.grant_jwt.clone();
            token.set(session_credential.clone());
            persist_config(
                config_store,
                base.clone(),
                actor.clone(),
                device.clone(),
                session_credential.clone(),
            );
            return crate::session::CurrentSessionRefresh::Credential(session_credential);
        }
    }

    // ②(A+②): multi-day sliding session. The held credential is the grant
    // itself; when it is near its own expiry the refresh path rotates it (DPoP
    // holder proof signed by the durable device key bound into `cnf.jkt`) onto a
    // fresh grant, and the rotated grant JWT becomes the live credential.
    // `prepare_refresh_for_server_after_unauthorized` forces a rotation attempt
    // even when the local expiry metadata looks fresh (the server may have
    // rotated/revoked the grant early).
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
            // Server-switch guard: don't write the old server's grant outcome
            // onto a session that just moved or logged out.
            if !same_server_url(&base, &base_url()) || session_generation() != generation {
                return crate::session::CurrentSessionRefresh::retry_later(
                    "session changed while refresh was in flight",
                );
            }
            let mut store = state_store.write();
            crate::session_refresh::commit_refresh(&mut store, result)
        }
    };
    match outcome {
        crate::session_refresh::RefreshOutcome::Refreshed { session_credential } => {
            if session_generation() != generation {
                return crate::session::CurrentSessionRefresh::retry_later(
                    "session changed while refresh was in flight",
                );
            }
            token.set(session_credential.clone());
            persist_config(
                config_store,
                base.clone(),
                actor.clone(),
                device.clone(),
                session_credential.clone(),
            );
            crate::session::CurrentSessionRefresh::Credential(session_credential)
        }
        crate::session_refresh::RefreshOutcome::LoginRequired { reason } => {
            crate::session::invalidate_current_session(reason.clone());
            crate::session::CurrentSessionRefresh::LoginRequired { reason }
        }
        crate::session_refresh::RefreshOutcome::NoGrant => {
            let reason = "no session grant is available".to_owned();
            crate::session::CurrentSessionRefresh::SignInRequired { reason }
        }
        crate::session_refresh::RefreshOutcome::Transient { reason } => {
            crate::session::CurrentSessionRefresh::RetryLater { reason }
        }
        crate::session_refresh::RefreshOutcome::Fresh => {
            let current = token();
            if current.trim().is_empty() {
                crate::session::CurrentSessionRefresh::retry_later(
                    "session grant is fresh but no live credential is loaded",
                )
            } else {
                crate::session::CurrentSessionRefresh::Credential(current)
            }
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
    pub(super) projection_events: Signal<Vec<ProjectionEvent>>,
    pub(super) device_queue: Signal<usize>,
    pub(super) frontier_state: Signal<String>,
    pub(super) crypto_state: Signal<String>,
    pub(super) config_store: Signal<LocalConfigStore>,
    pub(super) state_store: Signal<LocalStateStore>,
    pub(super) network_state: Signal<String>,
    pub(super) last_error: Signal<Option<String>>,
    pub(super) server_description: Signal<Option<ServerDescription>>,
    pub(super) server_probe_status: Signal<String>,
    pub(super) account_primary_handle: Signal<String>,
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
    /// App-shell DID resolution health banner state. The root identity
    /// describe probe updates this on every connect/manual refresh; authority
    /// resolution remains fail-closed in `did_resolver`.
    pub(super) did_resolution_health: Signal<crate::components::DidResolutionHealth>,
}

pub(super) fn redirect_to_login(navigator: Navigator) {
    let _ = navigator.push(Route::Login);
}

fn attach_current_session_material(
    api: CokretApi,
    store: &crate::local_state::LocalStateStore,
) -> CokretApi {
    let Some(handle) = crate::auth_dpop::load_device_key(store).ok().flatten() else {
        return api;
    };
    api.with_dpop_device(handle)
}

fn current_base_api(base: &str, state_store: Signal<LocalStateStore>) -> anyhow::Result<CokretApi> {
    let api = CokretApi::new(base)?;
    let store = state_store.read();
    Ok(attach_current_session_material(api, &store))
}

fn current_authed_api(
    base: &str,
    session_credential: &str,
    state_store: Signal<LocalStateStore>,
) -> anyhow::Result<CokretApi> {
    let api = CokretApi::new(base)?.with_bearer(session_credential.to_owned());
    let store = state_store.read();
    Ok(attach_current_session_material(api, &store))
}

/// ②(A+②) — build a `/_cokret/self/*`-ready client: the credential
/// (`ck.session.grant` JWT) in the HTTP Bearer authorization slot plus the
/// device DPoP holder key so each request carries a per-request `DPoP` proof
/// (api-conventions.md §3.3).
/// Used by standalone (non-`connect`) self-path call sites that build their own
/// `CokretApi`. Best-effort on the DPoP key: if it cannot be loaded the
/// credential is still attached for compatibility inbound paths.
pub(super) fn self_authed_api(
    base: &str,
    session_credential: impl Into<String>,
) -> anyhow::Result<CokretApi> {
    let api = CokretApi::new(base)?.with_bearer(session_credential);
    let store = crate::local_state::LocalStateStore::default();
    Ok(attach_current_session_material(api, &store))
}

pub(super) fn adopt_live_token_for_api(
    base: &str,
    state_store: Signal<LocalStateStore>,
    live_token: Signal<String>,
    session_credential: &mut String,
    authed: &mut CokretApi,
) {
    let latest = live_token();
    if !latest.trim().is_empty() && latest != *session_credential {
        *session_credential = latest.clone();
        if let Ok(api) = current_authed_api(base, &latest, state_store) {
            *authed = api;
        } else {
            *authed = authed.clone().with_bearer(latest);
        }
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

    let signer = match crate::event_signer::active_signer() {
        Some(signer) => signer,
        None => crate::event_signer::bootstrap_default_signer("yougen")
            .map_err(|error| anyhow::anyhow!("bootstrap device signer: {error}"))?,
    };
    let device_public_key = signer.public_key_multibase().ok_or_else(|| {
        anyhow::anyhow!("device enrollment requires a local Ed25519 active signer")
    })?;

    let gate_account_base = crate::coauth::resolve_principal_gate_account_base(base)
        .await
        .map_err(|error| anyhow::anyhow!("resolve account authority: {error}"))?;
    let coauth = crate::coauth::CoauthApi::new(&gate_account_base)?;

    let device_key = {
        let mut store = state_store.write();
        crate::auth_dpop::ensure_device_key(&mut store)
            .map_err(|error| anyhow::anyhow!("load device holder key: {error}"))?
    };
    let htu = coauth.endpoint_url("device-enroll")?;
    let dpop_proof = device_key
        .mint_proof("POST", &htu, Some(&grant.grant_jwt))
        .map_err(|error| anyhow::anyhow!("mint device-enroll DPoP proof: {error}"))?;

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

async fn probe_device_authorization_with_auto_enroll(
    base: &str,
    actor: &str,
    device: &str,
    principal_api: &CokretApi,
    state_store: Signal<crate::local_state::LocalStateStore>,
) -> anyhow::Result<(bool, bool)> {
    let viewer = principal_api.list_devices().await?;
    let mut has_other = account_has_other_active_devices_from_account_viewer(&viewer, device);
    let mut needs_authorization =
        device_authorization_required_from_account_viewer(&viewer, device);

    if needs_authorization {
        match enroll_current_session_device(base, actor, device, principal_api, state_store).await {
            Ok(()) => match principal_api.list_devices().await {
                Ok(viewer) => {
                    has_other =
                        account_has_other_active_devices_from_account_viewer(&viewer, device);
                    needs_authorization =
                        device_authorization_required_from_account_viewer(&viewer, device);
                }
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        "device authorization re-check failed after enrollment"
                    );
                    needs_authorization = false;
                }
            },
            Err(error) => {
                tracing::warn!(?error, "device enrollment failed");
            }
        }
    }

    Ok((needs_authorization, has_other))
}

pub(super) fn connect(base: String, actor: String, device: String, ctx: ConnectContext) {
    let device = normalize_device_id(&device);
    spawn(async move {
        let mut sync_bootstrap_complete = ctx.sync_bootstrap_complete;
        let mut status = ctx.status;
        let mut sync_cursor = ctx.sync_cursor;
        let token = ctx.token;
        let mut account_did = ctx.account_did;
        let mut selected_realm_id = ctx.selected_realm_id;
        let mut realm_tree_nodes = ctx.realm_tree_nodes;
        let mut projection_events = ctx.projection_events;
        let mut device_queue = ctx.device_queue;
        let mut frontier_state = ctx.frontier_state;
        let mut crypto_state = ctx.crypto_state;
        let config_store = ctx.config_store;
        let mut state_store = ctx.state_store;
        let mut network_state = ctx.network_state;
        let mut last_error = ctx.last_error;
        let mut server_description = ctx.server_description;
        let mut server_probe_status = ctx.server_probe_status;
        let mut account_primary_handle = ctx.account_primary_handle;
        let mut personal_handles = ctx.personal_handles;
        let mut personal_handles_status = ctx.personal_handles_status;
        let mut theme = ctx.theme;
        let mut session_boot_state = ctx.session_boot_state;
        let mut needs_device_authorization = ctx.needs_device_authorization;
        let mut device_authorization_check_complete = ctx.device_authorization_check_complete;
        let mut account_has_other_devices = ctx.account_has_other_devices;
        let mut did_resolution_health = ctx.did_resolution_health;

        did_resolution_health.set(crate::components::DidResolutionHealth::healthy());
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
        match current_base_api(&base, state_store) {
            Ok(mut api) => {
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
                            did_resolution_health.set(
                                crate::components::DidResolutionHealth::unsupported_principal_server(),
                            );
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

                let identity_health = match api.identity_describe().await {
                    Ok(identity) => {
                        crate::components::DidResolutionHealth::from_identity_description(&identity)
                    }
                    Err(error) => {
                        tracing::warn!(?error, "identity describe probe failed");
                        let cache = ctx.did_cache.read();
                        crate::components::DidResolutionHealth::from_identity_probe_failure(
                            &cache,
                            chrono::Utc::now(),
                        )
                    }
                };
                did_resolution_health.set(identity_health);

                let mut session_credential = token();
                if session_credential.trim().is_empty() {
                    match crate::session::refresh_current_session().await {
                        crate::session::CurrentSessionRefresh::Credential(refreshed) => {
                            session_credential = refreshed;
                            if let Ok(rebound) = current_base_api(&base, state_store) {
                                api = rebound;
                            }
                            session_boot_state.set(SessionBootState::Checking);
                        }
                        crate::session::CurrentSessionRefresh::SignInRequired { reason }
                        | crate::session::CurrentSessionRefresh::LoginRequired { reason } => {
                            let probe_label = description
                                .as_ref()
                                .map(|d| format!("{} / {}", d.service_type, d.protocol_version))
                                .unwrap_or_else(|| "server probe unavailable".to_owned());
                            status.set(format!("Refreshed: {probe_label}; sign-in required"));
                            network_state.set("online".to_owned());
                            crypto_state.set("No authenticated session".to_owned());
                            last_error.set(Some(reason));
                            needs_device_authorization.set(false);
                            device_authorization_check_complete.set(true);
                            session_boot_state.set(SessionBootState::Unauthenticated);
                            sync_bootstrap_complete.set(true);
                            return;
                        }
                        crate::session::CurrentSessionRefresh::RetryLater { reason } => {
                            status.set("Session refresh pending; retrying".to_owned());
                            network_state.set("reconnecting".to_owned());
                            last_error.set(Some(format!(
                                "session credential restore pending: {reason}"
                            )));
                            session_boot_state.set(SessionBootState::Restoring);
                            sync_bootstrap_complete.set(true);
                            return;
                        }
                    }
                }

                let mut authed = current_authed_api(&base, &session_credential, state_store)
                    .unwrap_or_else(|_| api.clone().with_bearer(session_credential.clone()));
                adopt_live_token_for_api(
                    &base,
                    state_store,
                    token,
                    &mut session_credential,
                    &mut authed,
                );
                // Resolve the canonical actor DID from the account viewer. Three
                // outcomes:
                //   1. Ok with non-empty DID -> use it as canonical_actor.
                //   2. Err that looks like auth expiry -> try the shared session refresh path. Only
                //      terminal refresh/grant errors invalidate the active session.
                //   3. Anything else (Ok with empty DID, transient 5xx, parse error, network
                //      failure) -> fall back to the locally stored actor, log a diagnostic to
                //      last_error so the sidebar/status surface can show it, and keep going so sync
                //      still has a chance to populate realm_tree_nodes.
                let mut account_personal_handle = None::<String>;
                let canonical_actor = match authed.account_me().await {
                    Ok(account) if !account.did.trim().is_empty() => {
                        account_personal_handle =
                            personal_handle_from_account_handle(&account.handle);
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
                        match crate::session::refresh_current_session().await {
                            crate::session::CurrentSessionRefresh::Credential(refreshed) => {
                                session_credential = refreshed;
                                if let Ok(rebound) = current_base_api(&base, state_store) {
                                    api = rebound;
                                }
                                authed =
                                    current_authed_api(&base, &session_credential, state_store)
                                        .unwrap_or_else(|_| {
                                            api.clone().with_bearer(session_credential.clone())
                                        });
                                match authed.account_me().await {
                                    Ok(account) if !account.did.trim().is_empty() => {
                                        account_personal_handle =
                                            personal_handle_from_account_handle(&account.handle);
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
                                    Err(retry_error)
                                        if is_terminal_session_grant_error(&retry_error) =>
                                    {
                                        crate::session::invalidate_current_session(
                                            "session grant is no longer active",
                                        );
                                        sync_bootstrap_complete.set(true);
                                        return;
                                    }
                                    Err(retry_error) => {
                                        status.set("Session refresh pending; retrying".to_owned());
                                        network_state.set("reconnecting".to_owned());
                                        last_error.set(Some(format!(
                                            "account_me after session refresh: {retry_error}"
                                        )));
                                        actor.clone()
                                    }
                                }
                            }
                            crate::session::CurrentSessionRefresh::SignInRequired { reason }
                            | crate::session::CurrentSessionRefresh::LoginRequired { reason } => {
                                last_error.set(Some(reason));
                                sync_bootstrap_complete.set(true);
                                return;
                            }
                            crate::session::CurrentSessionRefresh::RetryLater { reason } => {
                                status.set("Session refresh pending; retrying".to_owned());
                                network_state.set("reconnecting".to_owned());
                                last_error.set(Some(format!(
                                    "auth_expired: session refresh pending: {reason}; account_me: {error}"
                                )));
                                actor.clone()
                            }
                        }
                    }
                    Err(error) => {
                        last_error.set(Some(format!("account_me: {error}")));
                        actor.clone()
                    }
                };
                if canonical_actor != actor {
                    account_primary_handle.set(String::new());
                    personal_handles.set(Vec::new());
                    personal_handles_status.set("Not published".to_owned());
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
                        projection_events.set(Vec::new());
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
                if let Some(personal_handle) = account_personal_handle {
                    account_primary_handle.set(personal_handle.clone());
                    let handles = merge_personal_handles(&personal_handles(), [personal_handle]);
                    personal_handles_status.set(personal_handles_status_for(&handles));
                    personal_handles.set(handles);
                } else {
                    account_primary_handle.set(String::new());
                    if personal_handles().is_empty() {
                        personal_handles_status.set("Not published".to_owned());
                    }
                }
                adopt_live_token_for_api(
                    &base,
                    state_store,
                    token,
                    &mut session_credential,
                    &mut authed,
                );
                match probe_device_authorization_with_auto_enroll(
                    &base,
                    &canonical_actor,
                    &device,
                    &authed,
                    state_store,
                )
                .await
                {
                    Ok((needs_authorization, has_other)) => {
                        account_has_other_devices.set(has_other);
                        needs_device_authorization.set(needs_authorization);
                        device_authorization_check_complete.set(true);
                    }
                    Err(error) if is_auth_expired_error(&error) => {
                        match crate::session::refresh_current_session().await {
                            crate::session::CurrentSessionRefresh::Credential(refreshed) => {
                                session_credential = refreshed;
                                if let Ok(rebound) = current_base_api(&base, state_store) {
                                    api = rebound;
                                }
                                authed =
                                    current_authed_api(&base, &session_credential, state_store)
                                        .unwrap_or_else(|_| {
                                            api.clone().with_bearer(session_credential.clone())
                                        });
                                match probe_device_authorization_with_auto_enroll(
                                    &base,
                                    &canonical_actor,
                                    &device,
                                    &authed,
                                    state_store,
                                )
                                .await
                                {
                                    Ok((needs_authorization, has_other)) => {
                                        account_has_other_devices.set(has_other);
                                        needs_device_authorization.set(needs_authorization);
                                    }
                                    Err(retry_error) => {
                                        tracing::warn!(
                                            ?retry_error,
                                            "device authorization check failed after refresh"
                                        );
                                        needs_device_authorization.set(true);
                                    }
                                }
                            }
                            crate::session::CurrentSessionRefresh::SignInRequired { reason }
                            | crate::session::CurrentSessionRefresh::LoginRequired { reason } => {
                                tracing::warn!(
                                    %reason,
                                    "device authorization check ended because session refresh requires login"
                                );
                                needs_device_authorization.set(false);
                            }
                            crate::session::CurrentSessionRefresh::RetryLater { reason } => {
                                tracing::warn!(
                                    %reason,
                                    "device authorization check deferred while session refresh is pending"
                                );
                                needs_device_authorization.set(true);
                            }
                        }
                        device_authorization_check_complete.set(true);
                    }
                    Err(error) => {
                        tracing::warn!(?error, "device authorization check failed");
                        needs_device_authorization.set(true);
                        device_authorization_check_complete.set(true);
                    }
                }
                persist_config(
                    config_store,
                    base.clone(),
                    canonical_actor.clone(),
                    device.clone(),
                    session_credential.clone(),
                );
                crypto_state.set("Session active".to_owned());

                // `connect()` always issues a full sync (`since=None`) —
                // it's invoked on app boot, the mobile Refresh button,
                // and server switches, all of which represent
                // "re-establish the world from scratch". The SyncEngine
                // (see crate::sync_engine) owns the long-poll loop that
                // threads the cursor for incremental deltas.
                adopt_live_token_for_api(
                    &base,
                    state_store,
                    token,
                    &mut session_credential,
                    &mut authed,
                );
                let sync_result = match authed.account_subscribe_snapshot(None).await {
                    Ok(sync) => Ok(sync),
                    Err(error) if is_auth_expired_error(&error) => {
                        match crate::session::refresh_current_session().await {
                            crate::session::CurrentSessionRefresh::Credential(refreshed) => {
                                session_credential = refreshed;
                                if let Ok(rebound) = current_base_api(&base, state_store) {
                                    api = rebound;
                                }
                                authed =
                                    current_authed_api(&base, &session_credential, state_store)
                                        .unwrap_or_else(|_| {
                                            api.clone().with_bearer(session_credential.clone())
                                        });
                                authed.account_subscribe_snapshot(None).await
                            }
                            crate::session::CurrentSessionRefresh::SignInRequired { reason } => {
                                Err(anyhow::anyhow!(
                                    "session refresh cannot continue locally: {reason}; sync: {error}"
                                ))
                            }
                            crate::session::CurrentSessionRefresh::LoginRequired { reason } => {
                                Err(anyhow::anyhow!(
                                    "session refresh requires login: {reason}; sync: {error}"
                                ))
                            }
                            crate::session::CurrentSessionRefresh::RetryLater { reason } => {
                                Err(anyhow::anyhow!(
                                    "auth_expired: session refresh pending: {reason}; sync: {error}"
                                ))
                            }
                        }
                    }
                    Err(error) => Err(error),
                };
                match sync_result {
                    Ok(sync) => {
                        adopt_live_token_for_api(
                            &base,
                            state_store,
                            token,
                            &mut session_credential,
                            &mut authed,
                        );
                        let invite_notifications = match authed.invites().await {
                            Ok(response) => Some(response.invites),
                            Err(error) if is_auth_expired_error(&error) => {
                                match crate::session::refresh_current_session().await {
                                    crate::session::CurrentSessionRefresh::Credential(
                                        refreshed,
                                    ) => {
                                        session_credential = refreshed;
                                        if let Ok(rebound) = current_base_api(&base, state_store) {
                                            api = rebound;
                                        }
                                        authed = current_authed_api(
                                            &base,
                                            &session_credential,
                                            state_store,
                                        )
                                        .unwrap_or_else(|_| {
                                            api.clone().with_bearer(session_credential.clone())
                                        });
                                        authed.invites().await.ok().map(|response| response.invites)
                                    }
                                    crate::session::CurrentSessionRefresh::SignInRequired {
                                        ..
                                    }
                                    | crate::session::CurrentSessionRefresh::LoginRequired {
                                        ..
                                    }
                                    | crate::session::CurrentSessionRefresh::RetryLater {
                                        ..
                                    } => None,
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
                            crate::disappearing::shred_expired_message_plaintext_from_sync_realms(
                                &mut store,
                                &sync.realms,
                            );
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
                                if data_type == "ck.presence.visibility" {
                                    let Some(visibility) = entry
                                        .get("content")
                                        .and_then(|content| content.get("presence_visibility"))
                                        .and_then(serde_json::Value::as_str)
                                        .and_then(
                                            crate::local_state::PresenceVisibility::try_from_wire,
                                        )
                                    else {
                                        tracing::warn!(
                                            "ignoring malformed ck.presence.visibility account_data"
                                        );
                                        continue;
                                    };
                                    store.set_presence_visibility(visibility);
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
                                if crate::account_data::private_account_data_key_prefix(data_type)
                                    == Some(cokret_sdk::ACCOUNT_DATA_TYPE_SAVED)
                                {
                                    if let Some(content) = entry
                                        .get("content")
                                        .or_else(|| entry.get("encrypted_payload"))
                                        .cloned()
                                    {
                                        store.stage_saved_account_data_entry(data_type, content);
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
                        let synced_projection_events = {
                            {
                                let mut store = state_store.write();
                                crate::disappearing::shred_expired_message_plaintext_from_sync_realms(
                                    &mut store,
                                    &sync.realms,
                                );
                            }
                            // Merge encrypted bodies on read (author sidecar →
                            // remote decrypt-on-read). The `store` write guard
                            // above is out of scope here; take a fresh read
                            // guard scoped to this call.
                            let store_guard = state_store.read();
                            crate::views::account_projection::projection_events_from_sync_realms(
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
                        projection_events.set(synced_projection_events);
                        device_queue.set(sync.to_device.len());
                        sync_cursor.set(sync.cursor);
                    }
                    Err(error) if is_terminal_session_grant_error(&error) => {
                        crate::session::invalidate_current_session(
                            "session grant is no longer active",
                        );
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
                adopt_live_token_for_api(
                    &base,
                    state_store,
                    token,
                    &mut session_credential,
                    &mut authed,
                );
                let events_result = match authed.events_describe().await {
                    Ok(events) => Ok(events),
                    Err(error) if is_auth_expired_error(&error) => {
                        match crate::session::refresh_current_session().await {
                            crate::session::CurrentSessionRefresh::Credential(refreshed) => {
                                session_credential = refreshed;
                                if let Ok(rebound) = current_base_api(&base, state_store) {
                                    api = rebound;
                                }
                                authed =
                                    current_authed_api(&base, &session_credential, state_store)
                                        .unwrap_or_else(|_| {
                                            api.clone().with_bearer(session_credential.clone())
                                        });
                                authed.events_describe().await
                            }
                            crate::session::CurrentSessionRefresh::SignInRequired { reason } => {
                                Err(anyhow::anyhow!(
                                    "session refresh cannot continue locally: {reason}; events_describe: {error}"
                                ))
                            }
                            crate::session::CurrentSessionRefresh::LoginRequired { reason } => {
                                Err(anyhow::anyhow!(
                                    "session refresh requires login: {reason}; events_describe: {error}"
                                ))
                            }
                            crate::session::CurrentSessionRefresh::RetryLater { reason } => {
                                Err(anyhow::anyhow!(
                                    "auth_expired: session refresh pending: {reason}; events_describe: {error}"
                                ))
                            }
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
                    Err(error) if is_terminal_session_grant_error(&error) => {
                        crate::session::invalidate_current_session(
                            "session grant is no longer active",
                        );
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
                let cache = ctx.did_cache.read();
                did_resolution_health.set(
                    crate::components::DidResolutionHealth::from_identity_probe_failure(
                        &cache,
                        chrono::Utc::now(),
                    ),
                );
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
