use cokret_sdk::models::{
    AppletInstallOutcome, AppletInstallPreviewRequestBody, AppletInstallRequestBody,
    AppletRevokeOutcome, AppletRevokeRequestBody,
};

use super::*;

impl CokretApi {
    // ── Applet install / revoke — canonical self surface (P3) ─────────
    //
    // Installing / revoking an Applet is a daily-governance action: the
    // canonical install write projects a `ck.realm.admin`-scoped
    // registration onto the effective-scope Realm, and P2 wired the soland
    // `install_endpoint` / `revoke_install_endpoint` behind a
    // `require_realm_admin` gate. These are the yougen-side callers for the
    // spec applet self surface
    // (`/_cokret/self/applets/install[/preview]`, `/{id}/revoke`); the
    // soland-private ghost-provision path is intentionally not surfaced here.

    /// `POST /_cokret/self/applets/install/preview` —
    /// `ck.self.applet.install.command.preview`. Returns the install plan
    /// (`plan_digest` + resolved scopes) the caller echoes back on commit.
    /// No realm-admin gate — preview is read-only planning.
    pub async fn applet_install_preview(
        &self,
        body: &AppletInstallPreviewRequestBody,
    ) -> anyhow::Result<cokret_sdk::AppletInstallPlan> {
        self.sdk_http_client()?
            .applet_install_preview(body)
            .await
            .map_err(anyhow::Error::from)
    }

    /// `POST /_cokret/self/applets/install` — `ck.self.applet.command.install`.
    /// Commits the install previewed above; `idempotency_key` is forwarded
    /// as the required `Idempotency-Key` header (≤128 bytes). soland gates
    /// this on `ck.realm.admin` over the effective-scope Realm (P2), so a
    /// non-admin caller fails closed server-side.
    pub async fn applet_install(
        &self,
        idempotency_key: &str,
        body: &AppletInstallRequestBody,
    ) -> anyhow::Result<AppletInstallOutcome> {
        self.sdk_http_client()?
            .applet_install(idempotency_key, body)
            .await
            .map_err(anyhow::Error::from)
    }

    /// `POST /_cokret/self/applets/{applet_id}/revoke` —
    /// `ck.self.applet.command.revoke`. Revokes an active install; soland
    /// gates this on `ck.realm.admin` over the install's Realm (P2).
    pub async fn applet_revoke(
        &self,
        applet_id: &str,
        body: &AppletRevokeRequestBody,
    ) -> anyhow::Result<AppletRevokeOutcome> {
        self.sdk_http_client()?
            .applet_revoke(applet_id, body)
            .await
            .map_err(anyhow::Error::from)
    }
}
