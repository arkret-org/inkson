impl crate::transport::TransportClient {
    pub async fn request_contact(
        &self,
        target: &str,
    ) -> anyhow::Result<arkret_sdk::ContactRequestOutcome> {
        self.request_contact_scoped(target, "direct_message").await
    }

    pub async fn request_contact_scoped(
        &self,
        target: &str,
        scope: &str,
    ) -> anyhow::Result<arkret_sdk::ContactRequestOutcome> {
        self.request_contact_with_message(target, &[scope.to_owned()], None, None)
            .await
    }

    /// Send a contact request carrying one or more requested scopes plus an
    /// optional free-text greeting.
    ///
    /// Kept on the transport while contact addressing depends on the cached
    /// service description and directory evidence assembled by
    /// `contact_request_addressing`.
    pub async fn request_contact_with_message(
        &self,
        target: &str,
        scopes: &[String],
        message: Option<&str>,
        recipient_service_did: Option<&str>,
    ) -> anyhow::Result<arkret_sdk::ContactRequestOutcome> {
        let requested_scopes: Vec<String> = scopes
            .iter()
            .map(|scope| scope.trim())
            .filter(|scope| !scope.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        let addressing = self
            .contact_request_addressing(target, recipient_service_did)
            .await?;
        let body = arkret_sdk::ContactRequestRequestBody {
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
