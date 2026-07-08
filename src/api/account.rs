use super::*;

impl CokretApi {
    pub async fn describe(&self) -> anyhow::Result<ServerDescription> {
        self.sdk_http_client()?
            .describe()
            .await
            .map_err(|error| anyhow::anyhow!("server describe: {error}"))
    }

    pub async fn describe_cached(&self) -> anyhow::Result<&ServerDescription> {
        self.service_describe_cache
            .get_or_try_init(|| async { self.describe().await })
            .await
    }

    // ②(A+②): the Principal Server does not mint a second client-visible
    // credential. The held credential is the `ck.session.grant` itself,
    // presented per-request as
    // `Authorization: Bearer <grant>` + a `DPoP` proof (see
    // `CokretApi::with_bearer` / `with_dpop_device`).

    pub async fn request_contact(
        &self,
        target: &str,
    ) -> anyhow::Result<cokret_sdk::ContactRequestOutcome> {
        self.request_contact_scoped(target, "direct_message").await
    }

    pub async fn request_contact_scoped(
        &self,
        target: &str,
        scope: &str,
    ) -> anyhow::Result<cokret_sdk::ContactRequestOutcome> {
        self.request_contact_with_message(target, &[scope.to_owned()], None, None)
            .await
    }

    /// Send a contact request carrying one or more requested scopes plus an
    /// optional free-text greeting.
    ///
    /// Protocol contract (soland finalized): the `contacts/request` body
    /// accepts an optional `message` field (1..2000 chars) and an optional
    /// `recipient_service_did` (the target Principal Server's service DID). The
    /// latter is required for cross-PS addressing since v1 DIDs do not embed a
    /// home PS; leave it empty for same-PS contacts. We only emit either field
    /// when actually populated so same-PS no-greeting requests stay minimal; an
    /// empty / whitespace-only string is dropped client-side rather than sent
    /// as `""`.
    ///
    /// Kept as an inherent method (not migrated to `account_api`) because it
    /// resolves contact addressing through `contact_request_addressing`, which
    /// reads the struct-cached `describe_cached`.
    pub async fn request_contact_with_message(
        &self,
        target: &str,
        scopes: &[String],
        message: Option<&str>,
        recipient_service_did: Option<&str>,
    ) -> anyhow::Result<cokret_sdk::ContactRequestOutcome> {
        let requested_scopes: Vec<String> = scopes
            .iter()
            .map(|scope| scope.trim())
            .filter(|scope| !scope.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        let addressing = self
            .contact_request_addressing(target, recipient_service_did)
            .await?;
        let body = cokret_sdk::ContactRequestRequestBody {
            target: addressing.target,
            requested_scopes,
            message: message
                .map(str::trim)
                .filter(|message| !message.is_empty())
                .map(ToOwned::to_owned),
            idempotency_key: None,
            recipient_service_did: addressing.recipient_service_did,
            introduction_evidence: Some(addressing.introduction_evidence),
        };
        self.sdk_http_client()?
            .contacts_request(&body)
            .await
            .map_err(anyhow::Error::from)
    }
}
