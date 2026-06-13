use super::*;

impl CokretApi {
    pub async fn register_push_device(&self) -> anyhow::Result<PushRegisterView> {
        let request = crate::push::build_register_request("dev_yougen")?;
        self.register_push_device_with_request(&request).await
    }

    pub async fn register_push_device_with_request_at(
        &self,
        path: &str,
        request: &PushRegisterDeviceRequestBody,
    ) -> anyhow::Result<PushRegisterView> {
        let response = self
            .push_client(Some(path), None)
            .register_device_with_request(request, request.idempotency_key.as_deref(), None)
            .await
            .map_err(anyhow::Error::from)?;
        Ok(map_chime_register_response(response.body))
    }

    pub async fn register_push_device_with_request(
        &self,
        request: &PushRegisterDeviceRequestBody,
    ) -> anyhow::Result<PushRegisterView> {
        // Default register path is hardcoded in chime; pass `None` so it's used.
        let response = self
            .push_client(None, None)
            .register_device_with_request(request, request.idempotency_key.as_deref(), None)
            .await
            .map_err(anyhow::Error::from)?;
        Ok(map_chime_register_response(response.body))
    }

    pub async fn unregister_push_device(&self, device_id: &str) -> anyhow::Result<OkOutcome> {
        let request = crate::push::build_unregister_request(device_id, None)?;
        self.unregister_push_device_with_request(&request).await
    }

    pub async fn unregister_push_device_with_request(
        &self,
        request: &PushUnregisterDeviceRequestBody,
    ) -> anyhow::Result<OkOutcome> {
        let response = self
            .push_client(None, None)
            .unregister_device_with_request(request, request.idempotency_key.as_deref(), None)
            .await
            .map_err(anyhow::Error::from)?;
        Ok(OkOutcome {
            ok: response.body.ok,
        })
    }
}
