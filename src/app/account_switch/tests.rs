use super::*;
use crate::app::initial_session_credential_from_state;
use crate::config::{AccountProfile, ClientConfig};
use crate::presentation::{BootState, InksonContext, SharedStateStore};

struct Fixture {
    directory: tempfile::TempDir,
    dom: glory::ui::App,
    root: AccountSessionRoot,
    a: ActiveAccountContext,
    b: ActiveAccountContext,
    _signer: crate::event_signer::ActiveSignerTestGuard,
    _scope: crate::secure_key_store::DeviceSeedScopeTestGuard,
}

fn grant(account: &ActiveAccountContext, token: &str) -> PersistedSessionGrant {
    PersistedSessionGrant {
        grant_jwt: token.into(),
        session_private_key_pem: String::new(),
        grant_id: "ak:session_grant:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7".into(),
        audience_id: account.authority.station_id.clone(),
        granted_scope: vec![],
        account_id: account.authority.clone(),
        device_id: account.device_id.clone(),
        station_url: account.server_url.clone(),
        grant_expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        stored_at: chrono::Utc::now(),
    }
}

fn fixture() -> Fixture {
    let scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
    let signer = crate::event_signer::ActiveSignerTestGuard::replace(None);
    let directory = tempfile::tempdir().unwrap();
    let principal = format!(
        "ak:did_core:web:warm.example:{}",
        crate::operation::uuid_v7()
    );
    let a = crate::test_support::AccountFixture::new(&principal)
        .station("ak:did_core:web:warm-a.example")
        .server_url("https://warm-a.example")
        .profile_id("warm-a".into())
        .build();
    let b = crate::test_support::AccountFixture::new(&principal)
        .station("ak:did_core:web:warm-b.example")
        .server_url("https://warm-b.example")
        .profile_id("warm-b".into())
        .build();
    let mut store = LocalStateStore::with_path(directory.path().join("state.json"));
    store.switch_active_account(&a).unwrap();
    store.set_primary_handle("private-a");
    store.set_session_grant(Some(grant(&a, "grant-a")));
    store.switch_saved_account(&b).unwrap();
    store.set_primary_handle("private-b");
    store.set_session_grant(Some(grant(&b, "grant-b")));
    store.switch_saved_account(&a).unwrap();
    let mut config = LocalConfigStore::with_path(directory.path().join("config.json"));
    let mut profiles = MultiProfileConfig::default();
    profiles
        .upsert_and_activate(AccountProfile::new(a.clone(), "credential-a".into()))
        .unwrap();
    profiles
        .upsert_and_activate(AccountProfile::new(b.clone(), "credential-b".into()))
        .unwrap();
    profiles.activate(&a.profile_id);
    config.save_profiles(&profiles).unwrap();
    config.save(ClientConfig::authenticated(
        a.clone(),
        "credential-a".into(),
    ));
    config.flush().unwrap();
    let dom = glory::ui::App::memory();
    let configuration = config.load();
    let initial_credential = initial_session_credential_from_state(
        &store.load(),
        &configuration,
        chrono::Utc::now().timestamp(),
    );
    let context = InksonContext::new(
        dom.scope(),
        BootState {
            config_store: config,
            config: configuration,
            state_store: SharedStateStore::new(store),
            initial_credential,
            realm_tree_nodes: Vec::new(),
        },
        Route::Dashboard,
        |_| {
            Box::pin(async {
                crate::runtime::session::CurrentSessionRefresh::retry_later("unused")
            })
        },
    );
    let root = AccountSessionRoot::from_context(context);
    Fixture {
        directory,
        dom,
        root,
        a,
        b,
        _signer: signer,
        _scope: scope,
    }
}

async fn select(fixture: &Fixture, id: &str) -> anyhow::Result<()> {
    let mut future = Box::pin(fixture.root.clone().select_profile(id.to_owned()));
    std::future::poll_fn(|cx| {
        fixture
            .dom
            .scope()
            .owner()
            .enter(|| future.as_mut().poll(cx))
    })
    .await
}

#[tokio::test]
async fn warm_switch_same_principal_different_stations_retains_grants_and_rejects_old_work() {
    let f = fixture();
    let old_store = f.root.store.read(|store| store.clone());
    let connection = crate::transport::websocket_rail::SharedConnection::new();
    connection.set_ready(true);
    f.root.services.websocket_rail.attach(connection);
    assert!(f.root.services.websocket_rail.is_live());
    let keys = crate::secure_key_store::MemorySecureKeyStore::new();
    for (account, seed) in [(&f.a, [0xa; 32]), (&f.b, [0xb; 32])] {
        crate::secure_key_store::UserLocalStore::new(
            account.authority.clone(),
            account.device_id.clone(),
        )
        .unwrap()
        .save_signing_seed(&keys, &seed)
        .unwrap();
    }

    let generation = f.root.services.session.generation();
    let abandoned = f
        .root
        .services
        .effects
        .register(crate::runtime::effects::EffectKey {
            owner: crate::runtime::effects::EffectOwner::Account(f.a.profile_id.clone()),
            name: "component-scoped-request".into(),
            generation,
        });
    select(&f, &f.b.profile_id).await.unwrap();
    assert!(abandoned.is_cancelled());
    // Its old component was dropped before it could report completion. A later
    // logout must not wait forever for that retired component's future.
    use futures_util::FutureExt;
    assert!(
        f.root
            .services
            .effects
            .cancel_all()
            .now_or_never()
            .is_some()
    );
    assert!(!f.root.account_view_retired());
    assert_eq!(
        f.root.account.get_untracked().as_ref().unwrap().authority,
        f.b.authority
    );
    assert_eq!(
        f.root.store.read(|store| store.load()).primary_handle,
        "private-b"
    );
    assert!(f.root.services.websocket_rail.connection().is_none());
    let scope = crate::secure_key_store::active_device_seed_scope().unwrap();
    assert_eq!(scope.authority, f.b.authority);
    let selected_keys =
        crate::secure_key_store::UserLocalStore::new(scope.authority, scope.device_id).unwrap();
    assert_eq!(
        selected_keys
            .load_signing_seed(&keys)
            .unwrap()
            .unwrap()
            .seed,
        [0xb; 32]
    );
    assert_eq!(
        f.root
            .store
            .read(|store| store.session_grant())
            .unwrap()
            .grant_jwt,
        "grant-b"
    );
    assert!(old_store.flush().is_err());
    assert!(
        !f.root
            .services
            .session
            .invalidate_if_generation(generation, "late A denial")
    );
    assert_eq!(
        f.root.account.get_untracked().as_ref().unwrap().authority,
        f.b.authority
    );
    select(&f, &f.a.profile_id).await.unwrap();
    assert_eq!(
        f.root.store.read(|store| store.load()).primary_handle,
        "private-a"
    );
    assert_eq!(
        f.root
            .store
            .read(|store| store.session_grant())
            .unwrap()
            .grant_jwt,
        "grant-a"
    );
    let profiles = f.root.config.with(|store| store.load_profiles());
    assert_eq!(profiles.profiles[0].session_credential, "credential-a");
    assert_eq!(profiles.profiles[1].session_credential, "credential-b");
    assert!(
        !std::fs::read_to_string(f.directory.path().join("profiles.json"))
            .unwrap()
            .contains("credential-")
    );
    let cold = LocalConfigStore::with_path(f.directory.path().join("config.json")).load();
    assert_eq!(cold.active_account.unwrap().authority, f.a.authority);
}

#[tokio::test]
async fn warm_switch_never_promotes_another_accounts_unfinished_login() {
    let f = fixture();
    let store = f.root.store.clone();
    store.write(|store| store.begin_pending_login(&f.b.device_id, None));
    store.write(|store| store.set_session_grant(Some(grant(&f.b, "pending-b"))));
    store.write(|store| store.set_primary_handle("pending-b-private"));
    select(&f, &f.a.profile_id).await.unwrap();
    assert_eq!(
        store.read(|store| store.active_authority()).unwrap(),
        f.a.authority
    );
    assert_eq!(store.read(|store| store.load()).primary_handle, "private-a");
    assert_eq!(
        store.read(|store| store.session_grant()).unwrap().grant_jwt,
        "grant-a"
    );
    assert!(store.read(|store| store.pending_login()).is_none());
}

#[tokio::test]
async fn warm_switch_config_failure_keeps_old_account_and_metadata() {
    let f = fixture();
    let path = f.directory.path().join("config.json");
    std::fs::rename(&path, path.with_extension("backup")).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(select(&f, &f.b.profile_id).await.is_err());
    assert_eq!(
        f.root.account.get_untracked().as_ref().unwrap().authority,
        f.a.authority
    );
    assert_eq!(
        f.root.store.read(|store| store.active_authority()).unwrap(),
        f.a.authority
    );
    assert_eq!(
        f.root
            .config
            .with(|store| store.load_profile_metadata())
            .unwrap()
            .active_profile_id,
        Some(f.a.profile_id.clone())
    );
    assert!(!f.root.blocked());
    assert_eq!(
        f.root.config.with(|store| store.load_profiles()).profiles[1].session_credential,
        "credential-b"
    );
}

#[tokio::test]
async fn warm_switch_unknown_and_duplicate_profile_ids_have_no_fallback() {
    let f = fixture();
    let generation = f.root.generation.get_untracked();
    assert!(select(&f, "missing").await.is_err());
    assert_eq!(f.root.generation.get_untracked(), generation);
    let mut profiles = f
        .root
        .config
        .with(|store| store.load_profile_metadata())
        .unwrap();
    profiles.profiles.push(profiles.profiles[0].clone());
    std::fs::write(
        f.directory.path().join("profiles.json"),
        serde_json::to_vec(&profiles).unwrap(),
    )
    .unwrap();
    assert!(select(&f, &f.b.profile_id).await.is_err());
    assert_eq!(f.root.generation.get_untracked(), generation);
    assert_eq!(
        f.root.account.get_untracked().as_ref().unwrap().authority,
        f.a.authority
    );
}

#[tokio::test]
async fn warm_switch_add_account_preserves_previous_session_and_can_return() {
    let f = fixture();
    let mut future = Box::pin(f.root.clone().add_account());
    std::future::poll_fn(|cx| f.dom.scope().owner().enter(|| future.as_mut().poll(cx)))
        .await
        .unwrap();
    assert!(f.root.account.get_untracked().is_none());
    assert!(f.root.store.read(|store| store.pending_login()).is_some());
    assert!(
        f.root
            .store
            .read(|store| store.load())
            .primary_handle
            .is_empty()
    );
    select(&f, &f.a.profile_id).await.unwrap();
    assert_eq!(
        f.root
            .store
            .read(|store| store.session_grant())
            .unwrap()
            .grant_jwt,
        "grant-a"
    );
    assert_eq!(
        f.root.config.with(|store| store.load_profiles()).profiles[0].session_credential,
        "credential-a"
    );
}

#[tokio::test]
async fn warm_switch_failed_durable_account_write_preserves_unsaved_source_for_retry() {
    let f = fixture();
    let store = f.root.store.clone();
    store
        .read(|store| store.conformance_fail_account_commit(true))
        .unwrap();
    store.write(|store| store.set_primary_handle("edited-before-switch"));
    assert!(select(&f, &f.b.profile_id).await.is_err());
    assert_eq!(
        store.read(|store| store.active_authority()).unwrap(),
        f.a.authority
    );
    assert_eq!(
        store.read(|store| store.load()).primary_handle,
        "edited-before-switch"
    );
    assert_eq!(
        f.root.account.get_untracked().as_ref().unwrap().authority,
        f.a.authority
    );
    store
        .read(|store| store.conformance_fail_account_commit(false))
        .unwrap();
    select(&f, &f.b.profile_id).await.unwrap();
    select(&f, &f.a.profile_id).await.unwrap();
    assert_eq!(
        store.read(|store| store.load()).primary_handle,
        "edited-before-switch"
    );
}

#[tokio::test]
async fn warm_switch_expired_or_missing_grant_never_adopts_a_saved_bearer_string() {
    let f = fixture();
    let store = f.root.store.clone();
    store
        .write(|store| store.switch_saved_account(&f.b))
        .unwrap();
    let mut expired = grant(&f.b, "expired-grant");
    expired.grant_expires_at = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
    store.write(|store| store.set_session_grant(Some(expired)));
    store
        .write(|store| store.switch_saved_account(&f.a))
        .unwrap();
    select(&f, &f.b.profile_id).await.unwrap();
    let mut config = f.root.config.with(|store| store.load());
    // An interrupted older rotation can leave a bearer mirror without valid grant metadata.
    config.session_credential = "stale-bearer-string".into();
    assert!(
        initial_session_credential_from_state(
            &store.read(|store| store.load()),
            &config,
            chrono::Utc::now().timestamp()
        )
        .is_empty()
    );
    store.write(|store| store.set_session_grant(None));
    assert!(
        initial_session_credential_from_state(
            &store.read(|store| store.load()),
            &config,
            chrono::Utc::now().timestamp()
        )
        .is_empty()
    );
}

#[tokio::test]
async fn warm_switch_can_repair_an_interrupted_selection_of_the_same_account() {
    let mut f = fixture();
    let mut profiles = f
        .root
        .config
        .with(|store| store.load_profile_metadata())
        .unwrap();
    profiles.activate(&f.b.profile_id);
    f.root
        .config
        .revise(|store| store.save_account_selection(Some(f.b.clone()), &profiles))
        .unwrap();
    f.root.check_selection_coherence();
    assert!(f.root.blocked());
    select(&f, &f.a.profile_id).await.unwrap();
    assert!(!f.root.blocked());
    assert_eq!(
        f.root.config.with(|store| store.selected_authority()),
        Some(f.a.authority)
    );
    assert_eq!(
        f.root.store.read(|store| store.load()).primary_handle,
        "private-a"
    );
}

#[tokio::test]
async fn warm_switch_add_account_root_write_failure_retains_source_for_retry() {
    let f = fixture();
    let temporary_root = f.directory.path().join("state.json.tmp");
    std::fs::create_dir(&temporary_root).unwrap();
    let mut future = Box::pin(f.root.clone().add_account());
    let outcome =
        std::future::poll_fn(|cx| f.dom.scope().owner().enter(|| future.as_mut().poll(cx))).await;
    assert!(outcome.is_err());
    assert_eq!(
        f.root.store.read(|store| store.active_authority()),
        Some(f.a.authority.clone())
    );
    assert_eq!(
        f.root.config.with(|store| store.selected_authority()),
        Some(f.a.authority.clone())
    );
    assert_eq!(
        f.root.store.read(|store| store.load()).primary_handle,
        "private-a"
    );
    assert!(f.root.store.read(|store| store.pending_login()).is_none());
    assert!(!f.root.blocked());
    std::fs::remove_dir(&temporary_root).unwrap();
    select(&f, &f.b.profile_id).await.unwrap();
    select(&f, &f.a.profile_id).await.unwrap();
    assert_eq!(
        f.root.store.read(|store| store.load()).primary_handle,
        "private-a"
    );
}
