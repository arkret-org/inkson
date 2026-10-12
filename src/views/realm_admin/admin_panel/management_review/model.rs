//! Client process state only; sharing uses the SDK's original request JSON.
use arkret_sdk::{AccountId, ManagementReviewRequestBody, RealmId};

pub(super) fn parse_request(
    text: &str,
    realm: &RealmId,
) -> anyhow::Result<ManagementReviewRequestBody> {
    anyhow::ensure!(text.len() <= 1024 * 1024, "Shared request is too large");
    let request: ManagementReviewRequestBody = serde_json::from_str(text)
        .map_err(|_| anyhow::anyhow!("Paste an original SDK management review request"))?;
    let (event, _) = crate::transport::management_review::candidate(&request)?;
    anyhow::ensure!(&event.realm_id == realm, "Request belongs to another Realm");
    Ok(request)
}

pub(super) fn agent_account(principal: &str, station: &str) -> anyhow::Result<AccountId> {
    Ok(AccountId::new(
        arkret_sdk::DidCoreId::new(principal.trim().to_owned())?,
        arkret_sdk::DidCoreId::new(station.trim().to_owned())?,
    ))
}
