use super::*;

pub(super) fn clamp_sidebar_width(width: f64) -> f64 {
    width.clamp(MIN_SIDEBAR_WIDTH, MAX_SIDEBAR_WIDTH)
}

pub(super) fn load_sidebar_width_preference(state_store: &LocalStateStore) -> f64 {
    state_store
        .load_private_data(UI_PREFERENCES_SCOPE, SIDEBAR_WIDTH_PREFERENCE_KEY)
        .and_then(|value| value.parse::<f64>().ok())
        .map(clamp_sidebar_width)
        .unwrap_or(DEFAULT_SIDEBAR_WIDTH)
}

pub(super) fn save_sidebar_width_preference(state_store: &mut LocalStateStore, width: f64) {
    state_store.save_private_data(
        UI_PREFERENCES_SCOPE,
        SIDEBAR_WIDTH_PREFERENCE_KEY,
        format!("{:.0}", clamp_sidebar_width(width)),
    );
}

pub(super) async fn refresh_oidc_bearer_for_server(
    principal_server_url: &str,
    actor_id: &str,
    device_id: &str,
    previous: &crate::local_state::OidcTokenBundle,
) -> anyhow::Result<crate::local_state::OidcTokenBundle> {
    let refresh_token = previous
        .refresh_token
        .as_deref()
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("OIDC bundle has no refresh_token"))?;
    let _ = (actor_id, device_id);
    // T1.Y1/T1.Y4 — resolve the OIDC method via describe.auth_metadata, then do
    // standard OIDC discovery to find the token_endpoint + client_id for the
    // refresh_token grant. No Cokret-private bridge / topology snapshot.
    let resolver = crate::coauth::AuthorityResolver::discover(principal_server_url)
        .await
        .map_err(|error| anyhow::anyhow!("resolve account authority: {error}"))?;
    let method = resolver
        .oidc_method(None)
        .map_err(|error| anyhow::anyhow!("no oidc method: {error}"))?;
    let discovery_url = method
        .openid_configuration
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            method
                .issuer
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|issuer| {
                    format!(
                        "{}/.well-known/openid-configuration",
                        issuer.trim_end_matches('/')
                    )
                })
        })
        .ok_or_else(|| anyhow::anyhow!("oidc method published no discovery url"))?;
    let discovery = crate::coauth::CoauthApi::fetch_oidc_discovery(&discovery_url).await?;
    let token_endpoint = discovery
        .token_endpoint
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("oidc discovery published no token_endpoint"))?;
    let client_id = method
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("yougen");
    let coauth = crate::coauth::CoauthApi::new(&resolver.gate_account_base)?;
    let response = coauth
        .refresh_oidc_tokens(token_endpoint, client_id, refresh_token)
        .await?;
    Ok(crate::oidc::lifecycle::apply_refresh_response(
        previous, &response,
    ))
}
