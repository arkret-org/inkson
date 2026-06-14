use cokret_sdk::model::{
    AppletInstallOutcome, AppletInstallPreviewRequestBody, AppletInstallRequestBody,
    AppletRevokeOutcome, AppletRevokeRequestBody,
};
use reqwest::Method;

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
    // soland-private `/_soland/...` ghost-provision path is intentionally
    // not surfaced here.

    /// `POST /_cokret/self/applets/install/preview` —
    /// `ck.self.applet.install.command.preview`. Returns the install plan
    /// (`plan_digest` + resolved scopes) the caller echoes back on commit.
    /// No realm-admin gate — preview is read-only planning.
    pub async fn applet_install_preview(
        &self,
        body: &AppletInstallPreviewRequestBody,
    ) -> anyhow::Result<Value> {
        self.post_json("_cokret/self/applets/install/preview", body)
            .await
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
        // Explicit serialized bytes (not `.json()`) so PoP signing reads the
        // exact content for the digest, matching `post_json`.
        let bytes = serde_json::to_vec(body)?;
        let request = self
            .http
            .post(self.endpoint("_cokret/self/applets/install")?)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header("Idempotency-Key", idempotency_key)
            .body(bytes);
        self.send_json(self.prepare_request(request), Method::POST)
            .await
    }

    /// `POST /_cokret/self/applets/{applet_id}/revoke` —
    /// `ck.self.applet.command.revoke`. Revokes an active install; soland
    /// gates this on `ck.realm.admin` over the install's Realm (P2).
    pub async fn applet_revoke(
        &self,
        applet_id: &str,
        body: &AppletRevokeRequestBody,
    ) -> anyhow::Result<AppletRevokeOutcome> {
        let applet_id = path_component(applet_id);
        self.post_json(&format!("_cokret/self/applets/{applet_id}/revoke"), body)
            .await
    }
}
