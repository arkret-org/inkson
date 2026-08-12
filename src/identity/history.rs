//! Complete method-native DID history retrieval shared by registration and
//! recovery. Pagination is completed before any cryptographic consumer sees
//! the result, and every page is required to describe one stable DID/method.

pub(crate) async fn fetch_complete_identity_history(
    http: &arkret_sdk::http_client::Client,
    did: &arkret_sdk::DidFullId,
) -> anyhow::Result<arkret_sdk::IdentityLogListOutcome> {
    let mut entries = Vec::new();
    let mut cursor: Option<String> = None;
    let mut method: Option<String> = None;
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
        method.get_or_insert(page.method.clone());
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

pub(crate) struct FrozenAuthorityHistoryResolver {
    did: arkret_sdk::DidFullId,
    history: serde_json::Value,
}

impl FrozenAuthorityHistoryResolver {
    pub(crate) fn new(history: &arkret_sdk::IdentityLogListOutcome) -> anyhow::Result<Self> {
        Ok(Self {
            did: history.did.clone(),
            history: serde_json::to_value(history)?,
        })
    }
}

impl arkret_sdk::AuthorityDidHistoryResolver for FrozenAuthorityHistoryResolver {
    fn resolve_complete_history(
        &self,
        did: &arkret_sdk::DidFullId,
    ) -> Result<arkret_sdk::IdentityLogListOutcome, arkret_sdk::AuthorityHistoryUnavailable> {
        if did != &self.did {
            return Err(arkret_sdk::AuthorityHistoryUnavailable {
                message: "resolver was pinned to another Account Authority".to_owned(),
            });
        }
        serde_json::from_value(self.history.clone()).map_err(|error| {
            arkret_sdk::AuthorityHistoryUnavailable {
                message: format!("decode frozen Account Authority history: {error}"),
            }
        })
    }
}
