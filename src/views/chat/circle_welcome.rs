//! A selected Circle owns its cancellable Welcome bootstrap.
use super::*;
pub(super) fn circle_welcome(
    scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,
    base_url: String,
    realm_id: String,
    circle_id: Lotus<Option<String>>,
    authority: arkret_sdk::AccountId,
    device_id: arkret_sdk::DeviceId,
    token: Cage<String>,
    sync_cursor: Cage<String>,
    state_store: crate::presentation::SharedStateStore,
) {
    let seen = scope.cage(String::new());
    let revision = scope.cage(0_u64);
    let pending = Rc::new(std::cell::RefCell::new(None::<glory::core::TaskToken>));
    let weak = scope.downgrade();
    scope.effect(move||{
        let circle_id=circle_id.get();
        let credential=token.get();let cursor=sync_cursor.get();let _=context.state_revision.get();let generation=context.session_generation.get();let account=context.active_account.get();
        let keys=crate::app::local_mls_key_material_hint(&authority,&device_id).unwrap_or_default();
        let key=format!("{base_url}|{realm_id}|{circle_id:?}|{authority:?}|{device_id}|{credential}|{cursor}|{keys}|{generation}|{account:?}");
        if seen.get_untracked()==key{return;}seen.revise(|value|*value=key);revision.revise(|value|*value=value.wrapping_add(1));
        if let Some(task)=pending.borrow_mut().take(){task.cancel();}
        let Some(circle)=circle_id.clone()else{return};
        if credential.is_empty()||account.as_ref().is_none_or(|account|account.authority!=authority||account.device_id!=device_id)||state_store.read(|store|store.mls_checkpoint_for_effective_scope(&realm_id,Some(&circle))).is_some(){return;}
        let (Ok(realm),Ok(circle))=(arkret_sdk::RealmId::new(realm_id.clone()),arkret_sdk::CircleId::new(circle))else{return};
        let Some(owner)=weak.upgrade()else{return};let context=context.clone();let base=base_url.clone();let authority=authority.clone();let device=device_id.clone();let store=state_store.handle();
        match owner.spawn(async move{
            if !context.session_matches(generation,&account){return;}
            let work=crate::app::bootstrap_mls_welcome_for_scope(context.clone(),base,credential,authority.principal_id.to_string(),authority,device,arkret_sdk::ScopeRef::Circle{realm_id:realm,circle_id:circle},&store,Some(context.needs_mls_backup));
            if let Err(error)=work.await{tracing::debug!(%error,"selected Circle MLS Welcome remains pending");}
        }){Ok(task)=>*pending.borrow_mut()=Some(task),Err(error)=>owner.report_error(error)}
    });
}
