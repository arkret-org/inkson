use super::*;

#[test]
fn account_sync_keeps_one_consumer_across_realm_navigation() {
    let (app, context, _directory) = crate::views::settings::restored_surface_tests::harness();
    let account = crate::test_support::AccountFixture::new("ak:did_core:web:alice.example").build();
    context
        .active_account
        .revise(|value| *value = Some(account));
    context
        .token
        .revise(|value| *value = "fixture-pending-sync".into());
    context
        .sync_bootstrap_complete
        .revise(|value| *value = true);
    install(app.scope(), context.clone());
    app.flush().unwrap();
    let initial = context.services.effects.registered_for_test("account-sync");
    assert_eq!(initial.len(), 1);
    let first = &initial[0];
    for realm in ["realm-a", "realm-b", "realm-a", ""] {
        context
            .selected_realm_id
            .revise(|value| *value = realm.into());
        app.flush().unwrap();
        assert!(
            !first.is_cancelled(),
            "navigation must update the existing Account demand, not start another consumer"
        );
        assert_eq!(
            context
                .services
                .effects
                .registered_for_test("account-sync")
                .len(),
            1
        );
    }
    context.sync_generation.revise(|value| *value += 1);
    app.flush().unwrap();
    assert!(
        first.is_cancelled(),
        "a new session generation must retire the old consumer"
    );
    let replacement = context.services.effects.registered_for_test("account-sync");
    assert_eq!(replacement.len(), 1);
    assert!(!replacement[0].is_cancelled());
    assert_eq!(replacement[0].key().generation, first.key().generation + 1);
}
