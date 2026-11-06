use std::rc::Rc;

use glory::prelude::*;

use super::*;
use crate::presentation::InksonContext;

pub(super) fn refresh_connection(_scope: &Scope, context: Rc<InksonContext>) {
    refresh_connection_using(context, connect);
}
pub(super) fn refresh_connection_using(
    context: Rc<InksonContext>,
    connector: impl FnOnce(String, Option<arkret_sdk::DidCoreId>, String, ConnectContext),
) {
    let Some(owner) = context.state_scope() else {
        return;
    };
    context
        .sync_generation
        .revise(|value| *value = value.wrapping_add(1));
    context
        .sync_bootstrap_complete
        .revise(|value| *value = false);
    connector(
        context.base_url.get(),
        context.principal_id.get(),
        context.device_id.get(),
        ConnectContext::for_application(&owner, context),
    );
}
