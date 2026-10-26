use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::{Rc, Weak};

use glory::{Cage, Scope};

use crate::i18n::tr;
use crate::presentation::{InksonContext, View};
use crate::routes::Route;
use crate::views::settings::widgets::*;
mod data;
mod helpers;
mod model;
mod new_space;
mod overview;
mod realms;
use model::{NewRealmStep, SetupSection};
#[derive(Clone, Copy)]
struct SetupDraft {
    create_step: Cage<NewRealmStep>,
    realm_title: Cage<String>,
    realm_summary: Cage<String>,
    realm_alias: Cage<String>,
    realm_discoverability: Cage<String>,
    realm_policy_join_rule: Cage<String>,
    realm_policy_history_access: Cage<String>,
    realm_mls_activation: Cage<String>,
    realm_security_class: Cage<String>,
    realm_federation_policy: Cage<String>,
    realm_digest_algorithm: Cage<String>,
    realm_state: Cage<String>,
    realm_create_busy: Cage<bool>,
    created_realm_id: Cage<String>,
    pending_recovery_gate: Cage<bool>,
    new_space_realm_id: Cage<String>,
    new_space_title: Cage<String>,
    new_space_summary: Cage<String>,
    new_space_kind: Cage<String>,
    new_space_parent_id: Cage<String>,
    new_space_context_seen: Cage<String>,
    new_space_state: Cage<String>,
    new_space_created_id: Cage<String>,
}
thread_local! {static DRAFTS:RefCell<BTreeMap<usize,(Weak<InksonContext>,SetupDraft)>>=const { RefCell::new(BTreeMap::new()) };}
impl SetupDraft {
    fn for_context(scope: &Scope, context: &Rc<InksonContext>) -> Self {
        let key = Rc::as_ptr(context) as usize;
        DRAFTS.with(|drafts| {
            let mut drafts = drafts.borrow_mut();
            drafts.retain(|_, (owner, _)| owner.strong_count() > 0);
            if let Some((_, draft)) = drafts.get(&key) {
                return *draft;
            }
            let owner = context.state_scope().unwrap_or_else(|| scope.clone());
            let draft = Self {
                create_step: owner.cage(NewRealmStep::Basics),
                realm_title: owner.cage(String::new()),
                realm_summary: owner.cage(String::new()),
                realm_alias: owner.cage(String::new()),
                realm_discoverability: owner.cage("listed".to_owned()),
                realm_policy_join_rule: owner.cage("invite".to_owned()),
                realm_policy_history_access: owner.cage("since_join".to_owned()),
                realm_mls_activation: owner.cage("after_create".to_owned()),
                realm_security_class: owner.cage("standard".to_owned()),
                realm_federation_policy: owner.cage("restricted".to_owned()),
                realm_digest_algorithm: owner.cage("sha256".to_owned()),
                realm_state: owner.cage(tr("setup.state.draft")),
                realm_create_busy: owner.cage(false),
                created_realm_id: owner.cage(String::new()),
                pending_recovery_gate: owner.cage(false),
                new_space_realm_id: owner.cage(String::new()),
                new_space_title: owner.cage(String::new()),
                new_space_summary: owner.cage(String::new()),
                new_space_kind: owner.cage("space".to_owned()),
                new_space_parent_id: owner.cage(String::new()),
                new_space_context_seen: owner.cage(String::new()),
                new_space_state: owner.cage(tr("setup.state.draft")),
                new_space_created_id: owner.cage(String::new()),
            };
            drafts.insert(key, (Rc::downgrade(context), draft));
            draft
        })
    }
}
pub fn page(scope: &Scope, context: Rc<InksonContext>, route: Route) -> View {
    let draft = SetupDraft::for_context(scope, &context);
    let section = match route {
        Route::SetupSection { section } => SetupSection::from_slug(Some(&section)),
        _ => SetupSection::from_slug(None),
    };
    stack(
        "timeline setup-panel",
        vec![match section {
            SetupSection::Overview => overview::page(scope, context),
            SetupSection::Realms => realms::page(scope, context, draft),
            SetupSection::NewSpace => new_space::page(scope, context, draft),
        }],
    )
}
