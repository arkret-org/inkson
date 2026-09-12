use tokio::sync::OnceCell;

pub(crate) async fn fetch_service_describe(
    http: &arkret_sdk::http_client::Client,
) -> anyhow::Result<crate::models::ServiceDescribe> {
    crate::station_connection::discover(http.base_url().as_str()).await
}

pub(crate) async fn cached_service_describe<'a>(
    http: &arkret_sdk::http_client::Client,
    cache: &'a OnceCell<crate::models::ServiceDescribe>,
) -> anyhow::Result<&'a crate::models::ServiceDescribe> {
    cache
        .get_or_try_init(|| async { fetch_service_describe(http).await })
        .await
}
