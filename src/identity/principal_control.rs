//! Principal Control Realm authority boundary.

pub(crate) async fn resolve_accepted<P: std::fmt::Display + ?Sized>(
    _http: &arkret_sdk::http_client::Client,
    _principal: &P,
) -> anyhow::Result<arkret_sdk::RealmId> {
    anyhow::bail!(
        "principal-control operation requires a frozen PCR authority context; current actor-history resolution is disabled"
    )
}
