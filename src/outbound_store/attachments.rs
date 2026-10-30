//! Attachment objects use the existing account vault and native/browser CAS.
use super::*;
use crate::attachments::{AttachmentObject, PreparedAttachment};

#[cfg(test)]
#[path = "attachments_tests.rs"]
mod tests;

#[cfg(not(target_arch = "wasm32"))]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedAttachment {
    device_id: arkret_sdk::DeviceId,
    object_id: String,
    nonce: String,
    ciphertext: String,
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn protect_records(
    value: &mut serde_json::Value,
    authority: &arkret_sdk::AccountId,
    store: &dyn crate::secure_key_store::SecureKeyStore,
) -> anyhow::Result<()> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
    if let Some(records) = value
        .get_mut("attachments")
        .and_then(serde_json::Value::as_array_mut)
    {
        for raw in records {
            let object: AttachmentObject = serde_json::from_value(raw.clone())?;
            object.validate()?;
            anyhow::ensure!(
                &object.authority == authority,
                "attachment belongs to another vault"
            );
            let key = zeroize::Zeroizing::new(super::creator_protection::device_key_for_domain(
                store,
                authority,
                &object.device_id,
                "inkson.attachment_object.v1",
                "record",
            )?);
            let aad = crate::canonical::canonical_json_bytes(&(
                authority,
                &object.device_id,
                &object.id,
                "inkson.attachment_object.v1",
            ))?;
            let mut nonce = [0; 12];
            getrandom::fill(&mut nonce)?;
            let plaintext =
                zeroize::Zeroizing::new(crate::canonical::canonical_json_bytes(&object)?);
            let ciphertext = ChaCha20Poly1305::new((&*key).into())
                .encrypt(
                    &Nonce::from(nonce),
                    Payload {
                        msg: &plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| anyhow::anyhow!("protect attachment object"))?;
            *raw = serde_json::to_value(ProtectedAttachment {
                device_id: object.device_id,
                object_id: object.id,
                nonce: URL_SAFE_NO_PAD.encode(nonce),
                ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
            })?;
        }
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn open_records(
    value: &mut serde_json::Value,
    authority: &arkret_sdk::AccountId,
    store: &dyn crate::secure_key_store::SecureKeyStore,
) -> anyhow::Result<()> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
    if let Some(records) = value
        .get_mut("attachments")
        .and_then(serde_json::Value::as_array_mut)
    {
        for raw in records {
            let protected: ProtectedAttachment = serde_json::from_value(raw.clone())?;
            let key = zeroize::Zeroizing::new(super::creator_protection::device_key_for_domain(
                store,
                authority,
                &protected.device_id,
                "inkson.attachment_object.v1",
                "record",
            )?);
            let aad = crate::canonical::canonical_json_bytes(&(
                authority,
                &protected.device_id,
                &protected.object_id,
                "inkson.attachment_object.v1",
            ))?;
            let nonce: [u8; 12] = URL_SAFE_NO_PAD
                .decode(protected.nonce)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("attachment protection nonce"))?;
            let ciphertext = URL_SAFE_NO_PAD.decode(protected.ciphertext)?;
            let plaintext = zeroize::Zeroizing::new(
                ChaCha20Poly1305::new((&*key).into())
                    .decrypt(
                        &Nonce::from(nonce),
                        Payload {
                            msg: &ciphertext,
                            aad: &aad,
                        },
                    )
                    .map_err(|_| anyhow::anyhow!("open attachment object"))?,
            );
            let object: AttachmentObject = serde_json::from_slice(&plaintext)?;
            anyhow::ensure!(
                &object.authority == authority
                    && object.device_id == protected.device_id
                    && object.id == protected.object_id,
                "attachment protection coordinates differ"
            );
            object.validate()?;
            *raw = serde_json::to_value(object)?;
        }
    }
    Ok(())
}

impl InksonOutboundStore {
    pub(crate) async fn discard_attachment(
        &self,
        id: &str,
        device: &arkret_sdk::DeviceId,
    ) -> garth::Result<()> {
        self.mutate_state(|state| {
            let Some(index) = state
                .attachments
                .iter()
                .position(|a| a.id == id && &a.device_id == device)
            else {
                return Ok(());
            };
            if state.attachments[index].submitted_operation.is_some() {
                return Err(garth::Error::Storage(
                    "attachment is owned by its durable message submission".into(),
                ));
            }
            state.attachments.remove(index);
            Ok(())
        })
        .await
    }
    pub(crate) async fn attachment_object(
        &self,
        id: &str,
    ) -> garth::Result<Option<AttachmentObject>> {
        self.mutate_state(|state| Ok(state.attachments.iter().find(|a| a.id == id).cloned()))
            .await
    }
    pub(crate) async fn freeze_attachment(
        &self,
        object: AttachmentObject,
    ) -> garth::Result<AttachmentObject> {
        object
            .validate()
            .map_err(|e| garth::Error::Storage(format!("attachment intent: {e:#}")))?;
        #[cfg(not(target_arch = "wasm32"))]
        if self
            .protection
            .as_ref()
            .is_some_and(|(authority, _)| authority != &object.authority)
        {
            return Err(garth::Error::Storage(
                "attachment belongs to another account vault".into(),
            ));
        }
        #[cfg(target_arch = "wasm32")]
        if self.authority != object.authority {
            return Err(garth::Error::Storage(
                "attachment belongs to another account vault".into(),
            ));
        }
        self.mutate_state(|state| {
            if let Some(existing) = state.attachments.iter().find(|a| a.id == object.id) {
                if existing == &object {
                    return Ok(existing.clone());
                }
                return Err(garth::Error::Storage(
                    "attachment intent cannot be amended".into(),
                ));
            }
            state.attachments.push(object.clone());
            Ok(object)
        })
        .await
    }

    pub(crate) async fn freeze_attachment_input(
        &self,
        id: &str,
        digest: arkret_sdk::Hash,
    ) -> garth::Result<AttachmentObject> {
        self.mutate_state(|state| {
            let object = state
                .attachments
                .iter_mut()
                .find(|o| o.id == id)
                .ok_or_else(|| garth::Error::Storage("attachment intent is missing".into()))?;
            if let Some(existing) = &object.input_digest {
                if existing != &digest {
                    return Err(garth::Error::Storage(
                        "frozen attachment source differs".into(),
                    ));
                }
            } else {
                object.input_digest = Some(digest);
            }
            Ok(object.clone())
        })
        .await
    }

    pub(crate) async fn freeze_prepared_attachment(
        &self,
        id: &str,
        prepared: PreparedAttachment,
    ) -> garth::Result<AttachmentObject> {
        self.mutate_state(|state| {
            let object = state
                .attachments
                .iter_mut()
                .find(|a| a.id == id)
                .ok_or_else(|| garth::Error::Storage("attachment intent is missing".into()))?;
            if object.prepared.is_none() {
                object.prepared = Some(prepared);
            }
            Ok(object.clone())
        })
        .await
    }

    pub(crate) async fn attachment_objects(
        &self,
        device: &arkret_sdk::DeviceId,
        scope: &arkret_sdk::ScopeRef,
        strand: &arkret_sdk::StrandId,
    ) -> garth::Result<Vec<AttachmentObject>> {
        self.mutate_state(|state| {
            Ok(state
                .attachments
                .iter()
                .filter(|a| {
                    &a.device_id == device
                        && &a.scope == scope
                        && &a.strand_id == strand
                        && a.submitted_operation.is_none()
                })
                .cloned()
                .collect())
        })
        .await
    }

    pub(crate) async fn mark_attachment_uploaded(&self, id: &str) -> garth::Result<()> {
        self.mutate_state(|state| {
            let object = state
                .attachments
                .iter_mut()
                .find(|a| a.id == id)
                .ok_or_else(|| garth::Error::Storage("attachment intent is missing".into()))?;
            if object.prepared.is_none() {
                return Err(garth::Error::Storage("attachment is not prepared".into()));
            }
            object.uploaded = true;
            Ok(())
        })
        .await
    }
}
