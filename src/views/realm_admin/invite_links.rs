//! Explicit link creation, sharing and complete-account acceptance.

use dioxus::prelude::*;
use zeroize::Zeroize;

use crate::transport::realm_invite_link::{PendingRealmInviteLink, parse_realm_invite_link};

#[component]
pub(crate) fn RealmInviteLinks(
    token: Signal<String>,
    realm_id: Option<String>,
    initial_input: Option<Signal<zeroize::Zeroizing<String>>>,
) -> Element {
    let session = crate::app::SessionContext::get();
    let account = session
        .active_account
        .read()
        .as_ref()
        .map(|a| a.authority.clone());
    let generation = *session.session_generation.read();
    let base = crate::app::SessionContext::base_url_string();
    let mut input = use_signal(|| {
        initial_input
            .map(|mut source| {
                let value = source.peek().to_string();
                source.write().zeroize();
                value
            })
            .unwrap_or_default()
    });
    let mut message = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut pending = use_signal(|| None::<PendingRealmInviteLink>);
    let mut share = use_signal(|| zeroize::Zeroizing::new(String::new()));
    let mut landing = use_signal(|| "https://arkret.org".to_owned());
    let mut days = use_signal(|| "7".to_owned());
    let mut max_uses = use_signal(|| "1".to_owned());
    let mut views = use_signal(Vec::<arkret_sdk::RealmInviteLinkView>::new);
    let mut previous_generation = use_signal(|| generation);
    use_effect(move || {
        let _generation = *session.session_generation.read();
        if _generation != previous_generation() {
            previous_generation.set(_generation);
            input.write().zeroize();
            pending.set(None);
            share.set(zeroize::Zeroizing::new(String::new()));
            views.clear();
            busy.set(false);
            message.set(String::new());
        }
    });
    use_drop(move || {
        input.write().zeroize();
        pending.set(None);
        share.write().zeroize();
    });
    let account_label = account
        .as_ref()
        .map(|a| format!("{} @ {}", a.principal_id, a.station_id))
        .unwrap_or_else(|| {
            "Sign in and choose an account first; then reopen the invitation.".into()
        });
    rsx! {
        section { class:"event", "data-testid":"realm-invite-links",
            h3 { if realm_id.is_some() {"Share a Realm invitation"} else {"Join from an invitation link"} }
            p { "{account_label}" }
            p { "Choose a different account with the account switcher before confirming. Opening or previewing a link does not join." }
            if let Some(realm)=realm_id.clone() {
                label { "Lifetime in days" input { value:days(),type:"number",min:"1",oninput:move |e|days.set(e.value()) } }
                label { "Maximum different accounts" input {value:max_uses(),type:"number",min:"1",oninput:move |e|max_uses.set(e.value())} }
                label { "Share landing URL" input {value:landing(),type:"url",oninput:move |e|landing.set(e.value())} }
                p { "Default: 7 days and one account. You choose how to share the link. Lost link secrets cannot be recovered; revoke and create a new link." }
                button {disabled:busy() || account.is_none() || pending.read().is_some(),onclick:{
                    let realm=realm.clone();let base=base.clone();let account=account.clone();
                    move |_| { let Some(account)=account.clone() else {return}; let realm=realm.clone();let base=base.clone();
                        let seconds=days().parse::<u32>().ok().and_then(|n|n.checked_mul(86400));let uses=max_uses().parse::<u32>().ok();
                        let (Some(seconds),Some(uses))=(seconds,uses) else {message.set("Choose valid positive limits".into());return};
                        busy.set(true);spawn(async move {
                            let result=crate::transport::auth::with_authed_api(&base,token(),|api|async move {api.prepare_realm_invite_link(&account,&arkret_sdk::RealmId::new(realm)?,seconds,uses).await}).await;
                            if *session.session_generation.peek()!=generation {return}
                            busy.set(false);match result {Ok(value)=>{pending.set(Some(value));message.set("Invitation is prepared locally. Publish it to obtain authority acceptance.".into())},Err(e)=>message.set(e.display())}
                        });
                    }
                },"Prepare invitation" }
                if pending.read().is_some() {
                    button {disabled:busy() || account.is_none(),onclick:{
                        let base=base.clone();let account=account.clone();move |_| {
                            let Some(account)=account.clone() else {return};let Some(mut saved)=pending.peek().clone() else {return};let base=base.clone();let landing=landing();busy.set(true);
                            spawn(async move {
                                let result=crate::transport::auth::with_authed_api(&base,token(),|api|async move {let outcome=api.publish_realm_invite_link(&mut saved,&account).await;Ok((saved,outcome))}).await;
                                if *session.session_generation.peek()!=generation {return} busy.set(false);
                                match result {Ok((saved,outcome))=>{
                                    match outcome {Ok(_)=>match saved.share_url(&landing){Ok(url)=>{share.set(url);message.set("Accepted. Copy and share the link yourself.".into())},Err(_)=>message.set("Accepted; use a valid HTTPS landing URL to display the link.".into())},Err(_)=>message.set("Awaiting acceptance. Retry this same invitation; its Event and secret are retained only in this session.".into())}
                                    pending.set(Some(saved));
                                },Err(e)=>message.set(e.display())}
                            });
                        }
                    },"Publish / retry same invitation" }
                    button {disabled:busy(),onclick:move |_| {pending.set(None);share.write().zeroize();message.set("Local secret discarded. Any accepted invitation remains active until revoked below.".into());},"Discard local secret"}
                }
                if !share.read().is_empty() {textarea {readonly:true,"aria-label":"Share invitation link",value:share.read().as_str().to_owned()} }
                button {disabled:busy() || account.is_none(),onclick:{let base=base.clone();let realm=realm.clone();move |_| {let base=base.clone();let realm=realm.clone();busy.set(true);spawn(async move {
                    let result=crate::transport::auth::with_authed_api(&base,token(),|api|async move {api.realm_invite_link_views(&arkret_sdk::RealmId::new(realm)?).await}).await;
                    if *session.session_generation.peek()!=generation {return}busy.set(false);match result {Ok(value)=>views.set(value),Err(e)=>message.set(e.display())}
                });}},"Refresh invitation status"}
                for view in views.read().iter() {
                    { let view=view.clone();let base=base.clone();let account=account.clone();
                        rsx!{div {key:"{view.realm_invite_link_id}",
                            span {"{view.realm_invite_link_id} — {view.use_count}/{view.max_uses}; expires {view.expires_at}; {view.status:?} (as of {view.as_of})"}
                            button {disabled:busy() || account.is_none() || view.status==arkret_sdk::RealmInviteLinkStatus::Revoked,onclick:move |_| {
                                let Some(account)=account.clone() else {return};let view=view.clone();let base=base.clone();busy.set(true);spawn(async move {
                                    let result=crate::transport::auth::with_authed_api(&base,token(),|api|async move {api.revoke_realm_invite_link(&view.realm_id,&view.realm_invite_link_id,&account).await}).await;
                                    if *session.session_generation.peek()!=generation {return}busy.set(false);match result {Ok(progress) if progress.is_committed()=>message.set("Revoked. Existing members keep their membership; refresh to see the new state.".into()),Ok(_)=>message.set("Revocation is pending authority acceptance.".into()),Err(e)=>message.set(e.display())}
                                });
                            },"Revoke"}
                        }}
                    }
                }
            } else {
                input {type:"password",value:input(),placeholder:"Paste invitation link after signing in",disabled:account.is_none(),oninput:move |e|input.set(e.value()),"data-testid":"realm-invite-link-input"}
                button {disabled:busy() || account.is_none() || input.read().is_empty(),onclick:{let base=base.clone();let account=account.clone();move |_| {
                    let Some(account)=account.clone() else {return};let credential=match parse_realm_invite_link(&input()){Ok(v)=>v,Err(_)=>{message.set("Invalid invitation link".into());return}};let base=base.clone();busy.set(true);spawn(async move {
                        let result=crate::transport::auth::with_authed_api(&base,token(),|api|async move {api.preview_realm_invite_link(&credential,&account).await}).await;
                        if *session.session_generation.peek()!=generation {return}busy.set(false);match result {Ok(value)=>message.set(format!("Preview: {}. Confirm below to join with the displayed account.",value.preview.display_name.unwrap_or_else(||value.preview.realm_id.to_string()))),Err(_)=>message.set("Preview is unavailable or restricted. It does not determine final admission.".into())}
                    });
                }},"Preview without joining"}
                button {disabled:busy() || account.is_none() || input.read().is_empty(),"data-testid":"realm-invite-link-confirm",onclick:{let base=base.clone();let account=account.clone();move |_| {
                    let Some(account)=account.clone() else {return};let credential=match parse_realm_invite_link(&input()){Ok(v)=>v,Err(_)=>{message.set("Invalid invitation link".into());return}};input.write().zeroize();let base=base.clone();busy.set(true);spawn(async move {
                        let result=crate::transport::auth::with_authed_api(&base,token(),|api|async move {api.accept_realm_invite_link(&credential,&account).await}).await;
                        if *session.session_generation.peek()!=generation {return}busy.set(false);match result {Ok(progress) if progress.is_committed()=>message.set("Joined. Membership is accepted; encrypted access follows the Realm's normal security flow.".into()),Ok(_)=>message.set("Join submitted; authority acceptance is still pending.".into()),Err(_)=>message.set("Invitation could not be accepted. Reopen the link to retry; pending exact Events continue through the durable queue.".into())}
                    });
                }},"Confirm: join with this account"}
            }
            p {role:"status","{message}"}
        }
    }
}

/// Consume the fragment locally and erase it before any network action or login redirect.
#[component]
pub(crate) fn RealmInviteLinkLanding(token: Signal<String>) -> Element {
    let session = crate::app::SessionContext::get();
    let mut incoming = use_signal(|| zeroize::Zeroizing::new(String::new()));
    let mut open = use_signal(|| false);
    let mut sign_in_first = use_signal(|| false);
    use_future(move || async move {
        let mut eval = dioxus::document::eval(
            r#"
            const fragment = window.location.hash;
            if (fragment.startsWith('#realm/') && fragment.includes('lt=invite')) {
                window.history.replaceState(null, '', window.location.pathname + window.location.search);
                dioxus.send('web+arkret:' + fragment.slice(1));
            } else { dioxus.send(''); }
        "#,
        );
        if let Ok(value) = eval.recv::<String>().await {
            let value = zeroize::Zeroizing::new(value);
            if value.is_empty() {
                return;
            }
            if session.active_account.peek().is_none() {
                sign_in_first.set(true);
                return;
            }
            if parse_realm_invite_link(&value).is_ok() {
                incoming.set(value);
                open.set(true)
            }
        }
    });
    use_drop(move || incoming.write().zeroize());
    rsx! {
        if sign_in_first() {div {role:"status","Sign in, choose your account, then reopen the invitation link. Its secret has been removed from the address bar."}}
        if open() {
            div {role:"dialog","aria-label":"Realm invitation",
                RealmInviteLinks {token,realm_id:None,initial_input:Some(incoming)}
                button {onclick:move |_| {open.set(false);incoming.write().zeroize();},"Close invitation"}
            }
        }
    }
}
