use std::cell::{Cell, RefCell};
use std::rc::Rc;

use super::*;

struct PendingRefresh {
    menu: glory::ui::Mounted,
    owner: Rc<RefCell<Option<glory::ui::WeakScope>>>,
    release: tokio::sync::oneshot::Sender<()>,
    entered: Rc<Cell<bool>>,
}

fn context(
    app: &glory::ui::App,
    directory: &std::path::Path,
) -> Rc<crate::presentation::InksonContext> {
    crate::presentation::InksonContext::new(
        app.scope(),
        crate::presentation::BootState {
            config_store: LocalConfigStore::with_path(directory.join("config.json")),
            config: ClientConfig::default(),
            state_store: crate::presentation::SharedStateStore::new(LocalStateStore::with_path(
                directory.join("state.json"),
            )),
            initial_credential: "fixture-session".into(),
            realm_tree_nodes: vec![],
        },
        Route::Dashboard,
        |_| Box::pin(std::future::pending()),
    )
}

fn stage(app: &glory::ui::App, context: Rc<crate::presentation::InksonContext>) -> PendingRefresh {
    let (release, response) = tokio::sync::oneshot::channel();
    let mut response = Some(response);
    let entered = Rc::new(Cell::new(false));
    let observed = entered.clone();
    let owner = Rc::new(RefCell::new(None));
    let captured_owner = owner.clone();
    let menu = app
        .scope()
        .mount_with(|| {
            glory::ui::widget(move |scope| {
                *captured_owner.borrow_mut() = Some(scope.downgrade());
                let response = response.take().unwrap();
                let observed = observed.clone();
                let transient_id = scope.id();
                let app_owner = context.state_scope().unwrap();
                let ctx = ConnectContext::for_application(&app_owner, context.clone());
                let owner = ctx.owner.upgrade().unwrap();
                assert_ne!(
                    owner.id(),
                    transient_id,
                    "the menu must not own the account bootstrap"
                );
                let completed = ctx.sync_bootstrap_complete;
                let session = ctx.session.clone();
                spawn_bootstrap(&owner, session.clone(), move |epoch| async move {
                    observed.set(true);
                    let result = session_scoped_bootstrap_request(
                        "controlled refresh",
                        &session,
                        epoch,
                        async move {
                            response
                                .await
                                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                            Ok(())
                        },
                    )
                    .await;
                    if matches!(result, Some(Ok(()))) {
                        completed.revise(|value| *value = true);
                    }
                })
                .unwrap();
                Ok(())
            })
        })
        .unwrap();
    PendingRefresh {
        menu,
        owner,
        release,
        entered,
    }
}

fn settle(app: &glory::ui::App, executor: &glory::core::executor::Executor) {
    for _ in 0..32 {
        executor.poll_one();
        app.flush().unwrap();
    }
}

#[test]
fn refresh_finishes_after_the_actual_menu_scope_closes() {
    let directory = tempfile::tempdir().unwrap();
    let executor = Rc::new(glory::core::executor::Executor::new(64));
    let app = glory::ui::App::with_host(executor.clone(), glory::render::memory::Memory::new);
    let context = context(&app, directory.path());
    let pending = stage(&app, context.clone());
    settle(&app, &executor);
    assert!(pending.entered.get());
    assert!(!context.sync_bootstrap_complete.get_untracked());
    drop(pending.menu);
    app.flush().unwrap();
    assert!(pending.owner.borrow().as_ref().unwrap().upgrade().is_none());
    pending.release.send(()).unwrap();
    settle(&app, &executor);
    assert!(context.sync_bootstrap_complete.get_untracked());
}

#[test]
fn an_account_epoch_change_rejects_a_held_refresh_completion() {
    let directory = tempfile::tempdir().unwrap();
    let executor = Rc::new(glory::core::executor::Executor::new(64));
    let app = glory::ui::App::with_host(executor.clone(), glory::render::memory::Memory::new);
    let context = context(&app, directory.path());
    let pending = stage(&app, context.clone());
    settle(&app, &executor);
    assert!(pending.entered.get());
    drop(pending.menu);
    context.services.session.suspend();
    pending.release.send(()).unwrap();
    settle(&app, &executor);
    assert!(
        !context.sync_bootstrap_complete.get_untracked(),
        "the retired account cannot publish completion into the new session"
    );
}

#[test]
fn refresh_captures_the_epoch_before_its_first_executor_poll() {
    let directory = tempfile::tempdir().unwrap();
    let executor = Rc::new(glory::core::executor::Executor::new(64));
    let app = glory::ui::App::with_host(executor.clone(), glory::render::memory::Memory::new);
    let context = context(&app, directory.path());
    let pending = stage(&app, context.clone());
    assert!(!pending.entered.get());
    context.services.session.suspend();
    drop(pending.menu);
    settle(&app, &executor);
    assert!(
        !pending.entered.get(),
        "an old task must not adopt the replacement epoch on first poll"
    );
    assert!(!context.sync_bootstrap_complete.get_untracked());
}

#[tokio::test]
async fn delayed_retry_follows_session_state_after_an_unrelated_error() {
    let directory = tempfile::tempdir().unwrap();
    let executor = Rc::new(glory::core::executor::Executor::new(64));
    let app = glory::ui::App::with_host(executor.clone(), glory::render::memory::Memory::new);
    let cases = [
        context(&app, directory.path()),
        context(&app, directory.path()),
        context(&app, directory.path()),
    ];
    for ctx in &cases {
        ctx.session_boot_state
            .revise(|state| *state = SessionBootState::Checking);
        ctx.bootstrap_pending.revise(|pending| *pending = false);
        let session = &ctx.services.session;
        defer_bootstrap_retry(
            app.scope().downgrade(),
            BootstrapSessionLease::new(session.clone(), session.generation()),
            "temporary failure".to_owned(),
            ctx.connection_status,
            ctx.network_state,
            ctx.last_error,
            ctx.sync_bootstrap_complete,
            ctx.bootstrap_pending,
            ctx.session_boot_state,
        );
        ctx.last_error.revise(|last| *last = None);
    }
    settle(&app, &executor);
    cases[1]
        .session_boot_state
        .revise(|state| *state = SessionBootState::Authenticated);
    cases[2].services.session.suspend();
    tokio::time::sleep(std::time::Duration::from_millis(2050)).await;
    settle(&app, &executor);
    assert!(cases[0].bootstrap_pending.get_untracked());
    assert!(!cases[1].bootstrap_pending.get_untracked());
    assert!(!cases[2].bootstrap_pending.get_untracked());
}
