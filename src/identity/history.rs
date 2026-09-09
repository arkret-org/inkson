//! Complete method-native DID history retrieval for recovery. Pagination is completed before any
//! cryptographic consumer sees the result, and every page is required to describe one stable
//! DID/method.

pub(crate) async fn fetch_complete_identity_history(
    http: &arkret_sdk::http_client::Client,
    did: &arkret_sdk::Did,
) -> anyhow::Result<arkret_sdk::IdentityLogListOutcome> {
    let mut entries = Vec::new();
    let mut cursor: Option<String> = None;
    let mut method: Option<arkret_sdk::DidMethodUri> = None;
    let mut native_history: Option<bool> = None;
    loop {
        let page = http
            .identity_log(did.as_str(), cursor.as_deref(), Some(100))
            .await?;
        if page.did != *did
            || method.as_ref().is_some_and(|value| value != &page.method)
            || (method.is_some() && page.native_history != native_history)
        {
            anyhow::bail!("DID history pagination changed identity or method metadata");
        }
        method.get_or_insert(page.method);
        native_history = page.native_history;
        entries.extend(page.entries);
        if !page.has_more {
            if page.next_cursor.is_some() {
                anyhow::bail!("terminal DID history page unexpectedly carries a cursor");
            }
            break;
        }
        let next = page
            .next_cursor
            .filter(|next| cursor.as_deref() != Some(next.as_str()))
            .ok_or_else(|| anyhow::anyhow!("DID history pagination did not advance"))?;
        cursor = Some(next);
    }
    Ok(arkret_sdk::IdentityLogListOutcome {
        did: did.clone(),
        method: method.ok_or_else(|| anyhow::anyhow!("DID history returned no page"))?,
        native_history,
        entries,
        next_cursor: None,
        has_more: false,
    })
}
