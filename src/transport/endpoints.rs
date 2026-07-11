#[derive(Clone)]
pub struct EndpointClients {
    transport: super::TransportClient,
}

impl EndpointClients {
    pub fn new(transport: super::TransportClient) -> Self {
        Self { transport }
    }

    pub fn account(&self) -> AccountEndpoints<'_> {
        AccountEndpoints {
            transport: &self.transport,
        }
    }

    pub fn directory(&self) -> DirectoryEndpoints<'_> {
        DirectoryEndpoints {
            transport: &self.transport,
        }
    }
}

pub struct AccountEndpoints<'a> {
    transport: &'a super::TransportClient,
}

impl AccountEndpoints<'_> {
    pub async fn viewer(&self) -> anyhow::Result<arkret_sdk::models::AccountView> {
        crate::account_api::account_viewer(self.transport.http()).await
    }

    pub async fn current(&self) -> anyhow::Result<crate::models::CurrentAccount> {
        crate::account_api::account_me(self.transport.http()).await
    }

    pub async fn contacts(&self) -> anyhow::Result<crate::models::ContactListView> {
        crate::account_api::contacts(self.transport.http()).await
    }
}

pub struct DirectoryEndpoints<'a> {
    transport: &'a super::TransportClient,
}

impl DirectoryEndpoints<'_> {
    pub async fn resolve_handle(
        &self,
        handle: &str,
    ) -> anyhow::Result<crate::models::ResolveHandleView> {
        crate::directory_api::resolve_handle(self.transport.http(), handle).await
    }

    pub async fn list_handles_for_subject(
        &self,
        subject: &str,
        realm_id: Option<&str>,
        intent: Option<&str>,
    ) -> anyhow::Result<arkret_sdk::models::DirectorySubjectHandleList> {
        crate::directory_api::list_handles_for_subject(
            self.transport.http(),
            subject,
            realm_id,
            intent,
        )
        .await
    }
}
