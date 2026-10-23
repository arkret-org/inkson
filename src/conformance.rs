//! Feature-local runtime checks. Client conformance profiles are build claims,
//! not a list of operations every connected Station must provide.

use arkret_wire::{BindingKind, ServiceKind, ServiceOperationId, operation_bundle_descriptor};

use crate::models::ServiceDescribe;

#[cfg(all(not(target_arch = "wasm32"), feature = "spec-conformance"))]
mod message_send;
#[cfg(all(not(target_arch = "wasm32"), feature = "spec-conformance"))]
pub use message_send::*;

/// Inspect the ordinary Account frame's admitted own-Station pages. Audit
/// proof pages remain separate; every row access retains the live session fence.
#[cfg(all(not(target_arch = "wasm32"), feature = "spec-conformance"))]
pub fn own_station_account_pages(
    frame: &crate::realm_events_engine::VerifiedAccountFrame,
) -> garth::Result<&[garth::own_station_results::OwnStationScanPage]> {
    frame.check_session()?;
    Ok(frame.own_pages())
}

/// Inspect the ordinary durable current index without installing fixture rows.
#[cfg(all(not(target_arch = "wasm32"), feature = "spec-conformance"))]
pub async fn retained_realm_current(
    store: &crate::LocalStateStore,
    account: &arkret_sdk::AccountId,
    realm: &arkret_sdk::RealmId,
) -> anyhow::Result<serde_json::Value> {
    anyhow::ensure!(
        store.active_authority().as_ref() == Some(account),
        "current readback account mismatch"
    );
    let index =
        crate::state::CurrentIndex::open_committed(account, store.current_index_location(), || {
            Ok(store.load().current_generation)
        })
        .await?;
    let mut entries = Vec::new();
    let mut after = None;
    loop {
        let page = index
            .read_realm_page(realm.as_str(), after.as_deref(), 100)
            .await?;
        entries.extend(page.entries);
        after = page.next_cursor;
        if after.is_none() {
            break;
        }
    }
    Ok(serde_json::json!({
        "progress": index.read_progress(realm.as_str()).await?,
        "entries": entries,
    }))
}

/// Inspect only the complete admitted private cut used by the product fold.
#[cfg(all(not(target_arch = "wasm32"), feature = "spec-conformance"))]
pub fn retained_sidecar_cut(
    store: &crate::LocalStateStore,
    scope: &arkret_sdk::ScopeRef,
) -> anyhow::Result<(
    arkret_sdk::RealmStateSnapshot,
    Vec<arkret_sdk::CommittedEventFullView>,
)> {
    let arkret_sdk::ScopeRef::Sidecar {
        realm_id,
        sidecar_id,
    } = scope
    else {
        anyhow::bail!("private cut inspection requires a Sidecar scope");
    };
    let (snapshot, histories) = store.verified_sidecar_inputs(realm_id.as_str())?;
    let history = histories
        .get(sidecar_id.as_str())
        .ok_or_else(|| anyhow::anyhow!("the admitted cut does not cover this Sidecar"))?;
    Ok((snapshot, history.clone()))
}

/// A native conformance login uses the ordinary durable grant provider and
/// active holder fence. Dropping the fixture invalidates all captured results.
#[cfg(all(not(target_arch = "wasm32"), feature = "spec-conformance"))]
pub struct NativeAccountSession {
    client: arkret_sdk::http_client::Client,
    previous: Option<crate::secure_key_store::ActiveDeviceSeedScope>,
    previous_pending: Option<arkret_sdk::DeviceId>,
    previous_signer: Option<std::sync::Arc<crate::event_signer::InksonEventSigner>>,
    previous_mode: crate::operation::ProofMode,
}

#[cfg(all(not(target_arch = "wasm32"), feature = "spec-conformance"))]
impl NativeAccountSession {
    pub fn client(&self) -> arkret_sdk::http_client::Client {
        self.client.clone()
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "spec-conformance"))]
impl Drop for NativeAccountSession {
    fn drop(&mut self) {
        crate::identity::session_refresh::reset_session_grant_runtime();
        crate::secure_key_store::set_active_device_seed_scope(
            self.previous
                .as_ref()
                .map(|scope| (&scope.authority, &scope.device_id)),
        );
        crate::secure_key_store::set_pending_login_device_id(self.previous_pending.as_ref());
        crate::event_signer::replace_active_signer(self.previous_signer.take());
        crate::operation::set_proof_mode(self.previous_mode);
    }
}

/// Restore an issuer-backed fixture through the same discovery, secure
/// persistence and transport restoration used after an accepted login.
#[cfg(all(not(target_arch = "wasm32"), feature = "spec-conformance"))]
pub async fn restore_native_account_session(
    outcome: &arkret_sdk::SessionGrantOutcome,
    station_url: &str,
    holder_seed_b64url: &str,
    principal: &arkret_sdk::Did,
    identity_seed: &[u8; 32],
) -> anyhow::Result<NativeAccountSession> {
    anyhow::ensure!(
        outcome.account_id.station_id == outcome.audience_id,
        "fixture grant audience differs from its Account"
    );
    anyhow::ensure!(
        outcome.expires_at > chrono::Utc::now(),
        "fixture grant is not live"
    );
    anyhow::ensure!(
        arkret_sdk::project_did_to_core_id(principal)? == outcome.account_id.principal_id,
        "fixture identity signer belongs to another principal"
    );
    let record = crate::identity::account_auth::grant_dpop::dpop_device_key_record_from_seed(
        holder_seed_b64url,
    )?;
    let holder = crate::identity::account_auth::grant_dpop::device_handle_from_seed(
        holder_seed_b64url,
        &record.jkt,
    )?;
    anyhow::ensure!(
        holder.canonical_session_public_jwk()? == outcome.session_public_key,
        "fixture grant names another session public key"
    );
    let grant = crate::state::PersistedSessionGrant {
        grant_jwt: outcome.session_grant.clone(),
        session_private_key_pem: holder.session_signing_key_pkcs8_pem()?.to_string(),
        grant_id: outcome.session_grant_id.to_string(),
        audience_id: outcome.audience_id.clone(),
        granted_scope: outcome.granted_scope.clone(),
        account_id: outcome.account_id.clone(),
        device_id: outcome
            .device_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("native fixture requires a human Device"))?,
        station_url: crate::config::validate_server_url(station_url)?,
        grant_expires_at: Some(outcome.expires_at),
        stored_at: chrono::Utc::now(),
    };
    let description = crate::station_connection::discover(grant.station_url.as_str()).await?;
    anyhow::ensure!(
        description.service_id == grant.audience_id,
        "fixture grant names another Station"
    );
    let user = crate::secure_key_store::UserLocalStore::new(
        grant.account_id.clone(),
        grant.device_id.clone(),
    )?;
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    user.save_grant_binding_seed_b64url_durable(secure.as_ref(), holder_seed_b64url)
        .await?;
    user.save_signing_seed_durable(secure.as_ref(), identity_seed)
        .await?;
    crate::state::store_session_grant_in_user_secure_store_durable(&user, secure.as_ref(), &grant)
        .await?;
    let mut session = NativeAccountSession {
        client: arkret_sdk::http_client::Client::new(grant.station_url.clone())?,
        previous: crate::secure_key_store::active_device_seed_scope(),
        previous_pending: crate::secure_key_store::pending_login_device_id(),
        previous_signer: crate::event_signer::replace_active_signer(Some(std::sync::Arc::new(
            crate::event_signer::build_ed25519_device_signer(
                *identity_seed,
                principal.as_str(),
                grant.device_id.as_str(),
            ),
        ))),
        previous_mode: crate::operation::current_proof_mode(),
    };
    crate::operation::set_proof_mode(crate::operation::ProofMode::RealEd25519);
    crate::identity::session_refresh::reset_session_grant_runtime();
    user.activate();
    session.client = crate::identity::session_refresh::provide_authenticated_sdk_client(
        grant.station_url.as_str(),
    )
    .await?;
    Ok(session)
}

/// Retain the independently registered PCR for an actual native fixture host.
/// This does not select an account or derive a pin from a Consent response.
#[cfg(all(not(target_arch = "wasm32"), feature = "spec-conformance"))]
pub fn persist_native_registration_pin(
    host: &crate::sync_engine::NativeAccountHost,
    expected_account: &arkret_sdk::AccountId,
    expected_device: &arkret_sdk::DeviceId,
    registered_pcr: &arkret_sdk::RealmId,
) -> anyhow::Result<()> {
    let root = std::path::PathBuf::from(
        std::env::var_os("COTEST_NATIVE_CLIENT_CONFIG_ROOT").ok_or_else(|| {
            anyhow::anyhow!("native registration requires the isolated test runner")
        })?,
    );
    anyhow::ensure!(
        root.is_absolute()
            && root.is_dir()
            && std::env::var_os("INKSON_CONFIG_PATH").map(std::path::PathBuf::from)
                == Some(root.join("inkson").join("config.json")),
        "native registration configuration scope is inconsistent"
    );
    #[cfg(target_os = "windows")]
    anyhow::ensure!(
        matches!(root.canonicalize()?.components().next(),
            Some(std::path::Component::Prefix(prefix))
                if matches!(prefix.kind(), std::path::Prefix::Disk(drive)
                    | std::path::Prefix::VerbatimDisk(drive) if drive.to_ascii_uppercase() == b'D')),
        "native registration test configuration must stay on D"
    );
    let mut account = host.active_account_context();
    anyhow::ensure!(
        &account.authority == expected_account
            && &account.device_id == expected_device
            && &account.principal_control_realm_id == registered_pcr
            && account.server_url.origin() == host.call_http_client().base_url().origin(),
        "native host differs from the independently accepted registration"
    );
    let mut config = crate::config::LocalConfigStore::default();
    let mut profiles = config.load_profile_metadata()?;
    // Native hosts share a factory label, whereas durable profiles require a
    // distinct local id for each complete Account. Preserve an existing id.
    account.profile_id = match profiles
        .profiles
        .iter()
        .find(|profile| profile.account.authority == account.authority)
    {
        Some(profile) => profile.account.profile_id.clone(),
        None => format!(
            "native-accepted:{}",
            arkret_sdk::canonical::canonical_sha256(&account.authority)?
        ),
    };
    let selected = profiles.active_profile_id.clone();
    profiles.upsert_and_activate(crate::config::AccountProfile::new(account, String::new()))?;
    profiles.active_profile_id = selected;
    config.save_profiles(&profiles)?;
    anyhow::ensure!(
        crate::config::LocalConfigStore::default()
            .known_account_context(expected_account)
            .is_some_and(
                |account| account.principal_control_realm_id == *registered_pcr
                    && account.device_id == *expected_device
            ),
        "native registration PCR pin was not durable"
    );
    Ok(())
}

/// Baseline operations for a view or background task. Optional actions (media,
/// encrypted authoring, recovery, etc.) keep their own operation/feature checks.
/// These are local product requirements, not new wire profiles or features.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StationFeature {
    Discussion,
    Board,
    CreateRealm,
    CreateSpace,
    Circles,
    PublishKeyPackage,
    MlsAdmission,
    WelcomeBootstrap,
}

impl StationFeature {
    pub fn label_key(self) -> &'static str {
        match self {
            Self::Discussion => "route.chat",
            Self::Board => "route.board",
            Self::CreateRealm => "route.setup_realms",
            Self::CreateSpace => "route.setup_new_space",
            Self::Circles => "route.circles",
            Self::PublishKeyPackage | Self::MlsAdmission | Self::WelcomeBootstrap => {
                "route.devices"
            }
        }
    }

    /// HTTP/JSON operations actually consumed by the baseline workflow. Do not
    /// expand a client profile here or add unrelated optional-action operations.
    pub fn operations(self) -> &'static [ServiceOperationId] {
        use ServiceOperationId::*;
        match self {
            Self::Discussion => &[
                SelfCommittedEventReadScanV1,
                SelfCommittedEventResourceGetV1,
                SelfCommittedEventStreamSubscribeV1,
            ],
            Self::Board => &[
                SelfCommittedEventReadScanV1,
                SelfCommittedEventResourceGetV1,
                SelfCommittedEventStreamSubscribeV1,
                SelfSpaceReadListV1,
                SelfStrandReadListV1,
            ],
            Self::CreateRealm => &[
                ServerReadDescribeV1,
                SelfEventsCommandSubmitV1,
                SelfCommittedEventReadScanV1,
                OpenServiceReadResolutionV1,
                SelfSignerKeysReadResolveV1,
            ],
            Self::CreateSpace => &[SelfEventsCommandSubmitV1, SelfCommittedEventReadScanV1],
            Self::Circles => &[SelfCircleReadListV1],
            Self::PublishKeyPackage => &[
                SelfKeysKeypackagesUploadCreateV1,
                SelfKeysKeypackagesCommandRevokeV1,
            ],
            Self::MlsAdmission => &[
                SelfKeysKeypackagesCommandClaimV1,
                SelfKeysKeypackagesCommandConsumeV1,
                SelfEventsCommandSubmitV1,
                SelfCommittedEventReadScanV1,
            ],
            Self::WelcomeBootstrap => &[
                SelfDeviceMessagesReadListV1,
                SelfDeviceMessagesCommandAckV1,
                SelfKeysKeypackagesCommandConsumeV1,
                SelfCommittedEventReadScanV1,
            ],
        }
    }

    pub fn ready(self, server: Option<&ServiceDescribe>) -> bool {
        self.missing_requirements(server).is_empty()
    }

    /// Report exact missing operations and discovery prerequisites for diagnostics.
    pub fn missing_requirements(self, server: Option<&ServiceDescribe>) -> Vec<String> {
        let Some(server) = server else {
            return vec!["ServiceDescribe".to_owned()];
        };
        if server.service_kind != ServiceKind::Station {
            return vec!["service_kind=station".to_owned()];
        }
        if server.protocol_version.as_str() != arkret_sdk::PROTOCOL_VERSION {
            return vec!["protocol_version=1.0".to_owned()];
        }
        // The normal discovery decoder validates the description. Also fail
        // closed here for unknown/wrong-role bundles supplied by local callers.
        if server.supported_operation_bundles.iter().any(|id| {
            operation_bundle_descriptor(id)
                .is_none_or(|bundle| bundle.service_kind != server.service_kind)
        }) {
            return vec!["supported_operation_bundles".to_owned()];
        }
        self.operations()
            .iter()
            .filter(|operation| {
                server
                    .select_transport_binding(**operation, &[BindingKind::HttpJson])
                    .is_none()
            })
            .map(|operation| format!("{} (http_json)", operation.as_str()))
            .collect()
    }
}

/// Native projection inspection for the same retained store and exact actor
/// visibility selector consumed by the production chat timeline. The booleans
/// describe holder visibility; the canonical body remains in local history.
pub fn retained_blocklist_message_projection(
    store: &crate::state::LocalStateStore,
) -> Vec<(String, String, bool)> {
    let messages = crate::views::chat::model::chat_messages_from_local_state_with_sidecar(
        &store.load(),
        Some(store),
        None,
    );
    let blocked = crate::account_data::blocked_message_actor_ids(&store.client_blocklist());
    messages
        .into_iter()
        .map(|message| {
            let hidden = message.actor_id.as_ref().is_some_and(|actor| {
                crate::account_data::message_actor_is_blocked(actor, &blocked)
            });
            (message.id, message.body, hidden)
        })
        .collect()
}

/// Inspect encrypted retained history through the production decrypt-on-read
/// path using the actual receiving endpoint's identity and MLS checkpoint.
pub fn retained_blocklist_message_projection_for_account(
    store: &crate::LocalStateStore,
    account: &arkret_sdk::AccountId,
    actor: &str,
    device: &arkret_sdk::DeviceId,
) -> Vec<(String, String, bool)> {
    let messages = crate::views::chat::model::chat_messages_from_local_state_with_sidecar(
        &store.load(),
        Some(store),
        Some((account, actor, device)),
    );
    let blocked = crate::account_data::blocked_message_actor_ids(&store.client_blocklist());
    messages
        .into_iter()
        .map(|message| {
            let hidden = message.actor_id.as_ref().is_some_and(|actor| {
                crate::account_data::message_actor_is_blocked(actor, &blocked)
            });
            (message.id, message.body, hidden)
        })
        .collect()
}

/// Read the production automatic-receipt selector without initiating transport.
pub fn retained_blocklist_receipt_candidate(
    store: &crate::state::LocalStateStore,
    realm: &str,
    strand: &str,
) -> Option<String> {
    let messages = crate::views::chat::model::chat_messages_from_local_state_with_sidecar(
        &store.load(),
        Some(store),
        None,
    );
    let blocked = crate::account_data::blocked_message_actor_ids(&store.client_blocklist());
    crate::views::chat::model::visible_read_receipt_event(&messages, realm, strand, &blocked)
}

/// Observe the Native host's actual automatic-receipt production path through
/// an instrumented transport. The ordinary Signal sender remains unchanged.
#[cfg(not(target_arch = "wasm32"))]
pub async fn send_native_automatic_read_receipt(
    host: &crate::sync_engine::NativeAccountHost,
    http: arkret_sdk::http_client::Client,
    realm: &str,
    strand: &str,
    latest_cursor: &str,
) -> anyhow::Result<Option<arkret_sdk::SignalSubmitOutcome>> {
    host.send_automatic_read_receipt_using(
        &crate::event_submit::EventSubmitter::new(http),
        realm,
        strand,
        latest_cursor,
    )
    .await
}

/// Feed a genuinely admitted Signal through the production product router.
#[cfg(not(target_arch = "wasm32"))]
pub async fn observe_native_call_projection(
    host: &crate::sync_engine::NativeAccountHost,
    outcome: garth::signal::SignalReceiveOutcome,
) -> anyhow::Result<usize> {
    observe_call_projection_with_account(
        host.state_store_handle(),
        outcome,
        Some(host.active_account_context()),
        Some(host.call_http_client()),
    )
    .await
}

#[cfg(not(target_arch = "wasm32"))]
async fn observe_call_projection_with_account(
    state_store: crate::runtime::input::StateStoreHandle,
    outcome: garth::signal::SignalReceiveOutcome,
    account: Option<crate::config::ActiveAccountContext>,
    http: Option<arkret_sdk::http_client::Client>,
) -> anyhow::Result<usize> {
    use std::cell::Cell;
    use std::rc::Rc;

    use crate::runtime::projection::{AdmittedSignal, SignalProductRouter, SignalProductSink};
    struct Calls(Cell<usize>);
    impl SignalProductSink for Calls {
        fn call_signal<'a>(
            &'a self,
            _: &'a AdmittedSignal,
            _: serde_json::Value,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>> {
            self.0.set(self.0.get() + 1);
            Box::pin(async {})
        }
        fn message_stream<'a>(
            &'a self,
            _: &'a AdmittedSignal,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>> {
            Box::pin(async {})
        }
        fn read_receipt(&self, _: &AdmittedSignal, _: &arkret_sdk::ReadReceiptPolicy) {}
        fn advance_clock(&self, _: chrono::DateTime<chrono::Utc>) {}
    }
    let calls = Rc::new(Calls(Cell::new(0)));
    let products = SignalProductRouter::default();
    products.install(calls.clone());
    let sink = crate::signal_receive_engine::InksonSignalSink {
        call_account: account,
        call_http: http,
        state_store,
        products,
        live: std::sync::Mutex::new(Default::default()),
    };
    sink.handle(outcome).await?;
    Ok(calls.0.get())
}

/// Exercise the ordinary native send ratchet and authored plaintext retention.
/// The checkpoint must already represent an actually accepted Sidecar transition.
#[cfg(all(not(target_arch = "wasm32"), feature = "spec-conformance"))]
pub fn encrypt_private_sidecar_request(
    store: &mut crate::LocalStateStore,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
    scope: &arkret_sdk::ScopeRef,
    group_state_ref: arkret_sdk::EventId,
    content: &[u8],
    metadata: &[u8],
) -> anyhow::Result<(arkret_sdk::EncryptedPayload, arkret_sdk::EncryptedPayload)> {
    let arkret_sdk::ScopeRef::Sidecar {
        realm_id,
        sidecar_id,
    } = scope
    else {
        anyhow::bail!("native Sidecar required");
    };
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    let encrypted = crate::mls::runtime::encrypt_message_with_device_snapshot(
        store,
        secure.as_ref(),
        realm_id.as_str(),
        account,
        device,
        "application/vnd.arkret.message+json",
        arkret_sdk::EventKind::MessageCreate.as_str(),
        group_state_ref,
        content,
        Some(arkret_sdk::MESSAGE_METADATA_MLS_CONTENT_TYPE),
        Some(metadata),
        None,
        None,
        Some(sidecar_id),
    )
    .map_err(|error| anyhow::anyhow!("native Sidecar encryption: {error:?}"))?;
    Ok((
        encrypted.content,
        encrypted
            .metadata
            .ok_or_else(|| anyhow::anyhow!("metadata missing"))?,
    ))
}

/// Commit the actual application's captured private cache through the ordinary
/// secure-store barrier, including authored echoes and receive ratchets.
#[cfg(all(not(target_arch = "wasm32"), feature = "spec-conformance"))]
pub async fn persist_native_private_cache(store: &crate::LocalStateStore) -> anyhow::Result<()> {
    let write = store
        .capture_e2ee_plaintext_cache_secure_write()?
        .ok_or_else(|| anyhow::anyhow!("active private cache namespace unavailable"))?;
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    crate::LocalStateStore::persist_captured_e2ee_cache_write_durable(secure.as_ref(), write).await
}

/// Restore the application's encrypted private cache during native startup.
/// No expected plaintext or fixture projection is supplied to this operation.
#[cfg(all(not(target_arch = "wasm32"), feature = "spec-conformance"))]
pub fn hydrate_native_private_cache(store: &mut crate::LocalStateStore) -> anyhow::Result<()> {
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    store.hydrate_e2ee_plaintext_cache_with_secure_store(secure.as_ref())?;
    Ok(())
}

/// Exercise the post-accept production reader without starting any live rail.
/// The native host must already hold its real session and MLS private state.
#[cfg(all(not(target_arch = "wasm32"), feature = "spec-conformance"))]
pub async fn read_back_native_accepted_sidecar(
    http: &arkret_sdk::http_client::Client,
    account: &arkret_sdk::AccountId,
    scope: &arkret_sdk::ScopeRef,
    event: &arkret_sdk::EventId,
    store: crate::runtime::input::StateStoreHandle,
) -> anyhow::Result<()> {
    let arkret_sdk::ScopeRef::Sidecar {
        realm_id,
        sidecar_id,
    } = scope
    else {
        anyhow::bail!("accepted private readback requires a Sidecar scope");
    };
    crate::realm_events_engine::refresh_accepted_sidecar(
        http,
        account,
        crate::identity::device_directory::session_cache_epoch(),
        realm_id,
        sidecar_id,
        event,
        store,
        || true,
    )
    .await?;
    Ok(())
}

/// Read an admitted response through the product fold, signer gate and receive
/// ratchet. No fixture plaintext or projection is installed by this inspector.
#[cfg(all(not(target_arch = "wasm32"), feature = "spec-conformance"))]
pub fn private_sidecar_response_plaintext(
    store: &crate::LocalStateStore,
    account: &arkret_sdk::AccountId,
    scope: &arkret_sdk::ScopeRef,
    event_id: &arkret_sdk::EventId,
) -> anyhow::Result<Vec<u8>> {
    let realm = scope.realm_id();
    let projections =
        crate::sidecar::cached_sidecar_exchange_projections(store, account, realm.as_str())?;
    anyhow::ensure!(
        projections
            .iter()
            .any(|p| p.user_facing_response_event_ids.contains(event_id)),
        "response has no authenticated user-facing exchange projection"
    );
    let (_, history) = retained_sidecar_cut(store, scope)?;
    let event = history
        .iter()
        .find(|row| &row.event.event_id == event_id)
        .ok_or_else(|| anyhow::anyhow!("response absent from durable private history"))?
        .event
        .clone();
    let envelope: arkret_sdk::EncryptedEnvelope =
        serde_json::from_value(event.payload["encrypted_content"].clone())?;
    let sender = arkret_sdk::mls_basic_credential_identity(event.actual_signer())?;
    let payload = crate::mls::runtime::encrypted_payload_from_verified_event_context(
        store,
        &envelope,
        scope,
        event.kind.as_str(),
        &sender,
        None,
    )
    .ok_or_else(|| anyhow::anyhow!("response lacks its accepted MLS context"))?;
    let device = store
        .load()
        .device_authoring_authority
        .ok_or_else(|| anyhow::anyhow!("authorized device absent"))?;
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    crate::mls::runtime::decrypt_application_payload_for_scope_from_verified_sender(
        store,
        secure.as_ref(),
        realm.as_str(),
        account,
        &device.device_id,
        &payload,
        scope,
        &sender,
    )
    .ok_or_else(|| anyhow::anyhow!("user-facing response cannot be authenticated and decrypted"))
}

/// Consume a genuine holder read through the same persistent installation as ringing.
#[cfg(not(target_arch = "wasm32"))]
pub async fn consume_native_consent_current(
    host: &crate::sync_engine::NativeAccountHost,
    consent_scope: arkret_sdk::ConsentScope,
    response: &arkret_sdk::http_client::own_station_results::BoundOwnStationResponse<
        arkret_sdk::ConsentCurrentReadRequestBody,
        arkret_sdk::ConsentCurrentReadOutcome,
    >,
) -> anyhow::Result<bool> {
    let account = host.active_account_context();
    let store = host.state_store_handle();
    let epoch = crate::identity::device_directory::session_cache_epoch();
    let guard = || -> anyhow::Result<()> {
        anyhow::ensure!(
            store.read(|s| s.active_authority()) == Some(account.authority.clone())
                && !store.read(|s| s.current_reset_required())
                && crate::identity::device_directory::session_cache_epoch() == epoch,
            "native Consent attempt changed its session"
        );
        Ok(())
    };
    crate::signal_receive_engine::install_call_consent_current(
        &store,
        &account,
        response,
        consent_scope,
        epoch,
        &guard,
    )
    .await
}

/// Read genuine holder material using the active Native host's bound transport.
#[cfg(not(target_arch = "wasm32"))]
pub async fn read_native_consent_current(
    host: &crate::sync_engine::NativeAccountHost,
    peer: arkret_sdk::ActorId,
) -> anyhow::Result<
    arkret_sdk::http_client::own_station_results::BoundOwnStationResponse<
        arkret_sdk::ConsentCurrentReadRequestBody,
        arkret_sdk::ConsentCurrentReadOutcome,
    >,
> {
    let account = host.active_account_context();
    let http = host.call_http_client();
    let client = crate::transport::own_station_results::client_for_http(&http).await?;
    let authority = crate::transport::own_station_results::consent_current_authority(
        &http,
        &client,
        &account.authority,
        &account.principal_control_realm_id,
    )
    .await?;
    Ok(client
        .consent_current(
            &arkret_sdk::ConsentCurrentReadRequestBody {
                holder_account_id: account.authority.clone(),
                peer: arkret_sdk::ConsentPeer::Actor { actor_id: peer },
                audience_actor_id: arkret_sdk::ActorId::service(account.authority.station_id),
                nonce: crate::random::base64url_token(32, "Consent read nonce unavailable")?,
            },
            &account.principal_control_realm_id,
            &authority,
        )
        .await?)
}

/// Exercise the product's current/checkpoint, own-Station binding and RTC join path.
#[cfg(all(not(target_arch = "wasm32"), feature = "spec-conformance"))]
pub async fn join_native_call_media(
    host: &crate::sync_engine::NativeAccountHost,
    http: arkret_sdk::http_client::Client,
    request: &arkret_sdk::CallMediaTokenExchangeRequestBody,
    issuer: &arkret_sdk::DidCoreId,
) -> anyhow::Result<crate::media::rtc::JoinedMediaSession> {
    let account = request
        .actor_id
        .as_account_id()
        .ok_or_else(|| anyhow::anyhow!("media subject is not an Account"))?;
    let store = host.state_store();
    let evidence = crate::media::rtc::current_media_governance_evidence(
        &store,
        request.realm_id.as_str(),
        request.device_id.as_str(),
        false,
    )
    .ok_or_else(|| {
        anyhow::anyhow!("complete current and authenticated checkpoint do not cover media join")
    })?;
    let binding =
        crate::media::service_route::binding_for_http(&http, &request.realm_id, issuer).await?;
    let checkpoint = store.mls_checkpoint_for(request.realm_id.as_str());
    let secure = crate::secure_key_store::default_secure_key_store("inkson");
    let exporter = crate::media::rtc::RealmMlsExporter::for_realm(
        checkpoint,
        secure.as_ref(),
        account,
        &request.device_id,
    )
    .map_err(|e| anyhow::anyhow!("actual MLS exporter: {e:?}"))?;
    let desired = request
        .desired_media
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("media selection missing"))?;
    let join = crate::media::rtc::MediaJoinRequest {
        account_id: account.clone(),
        join_context: request.join_context.clone(),
        realm_id: request.realm_id.to_string(),
        call_id: request.call_id.to_string(),
        actor_id: account.principal_id.to_string(),
        device_id: request.device_id.to_string(),
        focus_id: request.focus_id.clone(),
        epoch_id: exporter.epoch(),
        desired_media: crate::media::rtc::DesiredMedia {
            audio: desired.audio.unwrap_or(false),
            video: desired.video.unwrap_or(false),
            screen: desired.screen.unwrap_or(false),
        },
        media_service_ids: vec![issuer.to_string()],
        verified_media_bindings: vec![binding],
        governance_evidence: Some(evidence),
        media_service_decryption_requested: false,
    };
    let api = crate::transport::TransportClient::from_http(
        http,
        crate::transport::RequestContext::new(""),
    );
    crate::media::rtc::join_call_media(&api, &join, &exporter)
        .await
        .map_err(|e| anyhow::anyhow!("production native RTC join: {e:?}"))
}

/// Capture an actual bound holder read for delayed-consumption regressions.
#[cfg(not(target_arch = "wasm32"))]
pub async fn read_native_call_consent(
    host: &crate::sync_engine::NativeAccountHost,
    invitation: &arkret_sdk::CallInvitationEnvelope,
) -> anyhow::Result<garth::call_invitation::HolderCallConsent> {
    let account = host.active_account_context();
    let http = host.call_http_client();
    let client = crate::transport::own_station_results::client_for_http(&http).await?;
    let authority = crate::transport::own_station_results::consent_current_authority(
        &http,
        &client,
        &account.authority,
        &account.principal_control_realm_id,
    )
    .await?;
    Ok(garth::call_invitation::read_holder_call_consent(
        &client,
        &account.authority,
        &account.principal_control_realm_id,
        &authority,
        invitation,
        crate::random::base64url_token(32, "Consent read nonce unavailable")?,
        garth::call_invitation::HolderConsentKnownCut {
            governance_generation: None,
            stream_heads: &[],
        },
    )
    .await?)
}

#[cfg(test)]
mod tests {
    use arkret_models_discovery::TransportBinding;
    use arkret_wire::{Did, ProfileId, TrustDomainId};

    use super::*;

    fn station(bundles: &[&str]) -> ServiceDescribe {
        ServiceDescribe::development(
            Did::new("did:web:coland.example".to_owned()).unwrap(),
            TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            ServiceKind::Station,
            bundles.iter().map(|id| (*id).to_owned()).collect(),
            vec![TransportBinding::HttpJson {
                base_url: "https://coland.example/".to_owned(),
                extension_profile_required: (),
            }],
        )
    }

    #[test]
    fn realm_creation_does_not_require_identity_resolver_or_upload_transport() {
        let description = station(&[
            "ak.operation_bundle.station.describe.v1",
            "ak.operation_bundle.station.http_core_current.v1",
        ]);
        assert!(!description.supports_operation(ServiceOperationId::RootIdentityReadResolveV1));
        assert!(StationFeature::CreateRealm.ready(Some(&description)));
        assert!(StationFeature::CreateSpace.ready(Some(&description)));
        assert!(StationFeature::Board.ready(Some(&description)));
    }

    #[test]
    fn missing_describe_bundle_blocks_creation_but_not_reading_or_key_publication() {
        let description = station(&["ak.operation_bundle.station.http_core_current.v1"]);
        assert_eq!(
            StationFeature::CreateRealm.missing_requirements(Some(&description)),
            vec!["ak.server.read.describe.v1 (http_json)"]
        );
        assert!(StationFeature::Discussion.ready(Some(&description)));
        assert!(StationFeature::PublishKeyPackage.ready(Some(&description)));
    }

    #[test]
    fn every_baseline_operation_is_a_live_registry_operation() {
        for feature in [
            StationFeature::Discussion,
            StationFeature::Board,
            StationFeature::CreateRealm,
            StationFeature::CreateSpace,
            StationFeature::Circles,
            StationFeature::PublishKeyPackage,
            StationFeature::MlsAdmission,
            StationFeature::WelcomeBootstrap,
        ] {
            for operation in feature.operations() {
                assert_eq!(
                    ServiceOperationId::from_wire(operation.as_str()),
                    Some(*operation)
                );
            }
        }
    }

    #[test]
    fn discovery_and_transport_are_required_and_profile_claims_cannot_supply_operations() {
        assert!(!StationFeature::CreateRealm.ready(None));
        let mut description = station(&[]);
        description
            .supported_profiles
            .push(ProfileId::FULL_CLIENT_V1.to_owned());
        assert!(!StationFeature::CreateRealm.ready(Some(&description)));
        description = station(&["ak.operation_bundle.station.http_core_current.v1"]);
        description.transport_bindings.clear();
        assert!(!StationFeature::Discussion.ready(Some(&description)));
        description = station(&["ak.operation_bundle.station.http_core_current.v1"]);
        description.service_kind = ServiceKind::IdentityRegistry;
        assert!(!StationFeature::Discussion.ready(Some(&description)));
        description = station(&["ak.operation_bundle.station.unknown.v1"]);
        assert!(!StationFeature::Discussion.ready(Some(&description)));
    }
}
