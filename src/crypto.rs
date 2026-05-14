use contrix_sdk::EncryptedPayload;
#[cfg(target_arch = "wasm32")]
use contrix_sdk::{EncryptedPayloadScheme, Hash, KeyRefObject};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientEncryptedMessage {
    pub message_id: String,
    pub payload: EncryptedPayload,
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use contrix_sdk::{
        ContrixMlsGroup, ContrixMlsIdentity, DeviceId, Did, EncryptedMessage, MessageCrypto,
        MessageCryptoDecrypt, MlsAddMemberResult, MlsKeyPackageRecord, MlsRemoveMemberResult,
        MlsWelcomeEnvelope,
    };

    use super::ClientEncryptedMessage;

    pub struct LocalMlsDevice {
        identity: Option<ContrixMlsIdentity>,
        group: Option<ContrixMlsGroup>,
        pending: Vec<ClientEncryptedMessage>,
    }

    impl LocalMlsDevice {
        pub fn new(principal_id: &str, device_id: &str) -> anyhow::Result<Self> {
            Ok(Self {
                identity: Some(ContrixMlsIdentity::new_basic(
                    Did::new(principal_id.to_owned())?,
                    DeviceId::new(device_id.to_owned())?,
                )?),
                group: None,
                pending: Vec::new(),
            })
        }

        pub fn key_package_record(&self) -> anyhow::Result<MlsKeyPackageRecord> {
            let identity = self
                .identity
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("MLS identity is already bound to a group"))?;
            Ok(identity.key_package_record()?)
        }

        pub fn create_group(&mut self, group_id: impl AsRef<[u8]>) -> anyhow::Result<()> {
            let identity = self
                .identity
                .take()
                .ok_or_else(|| anyhow::anyhow!("MLS group already created or joined"))?;
            self.group = Some(identity.create_group(group_id)?);
            Ok(())
        }

        pub fn join_from_welcome(&mut self, welcome: &MlsWelcomeEnvelope) -> anyhow::Result<()> {
            let identity = self
                .identity
                .take()
                .ok_or_else(|| anyhow::anyhow!("MLS group already created or joined"))?;
            self.group = Some(ContrixMlsGroup::join_from_welcome(identity, welcome)?);
            Ok(())
        }

        pub fn add_member(
            &mut self,
            member_key_package: &MlsKeyPackageRecord,
        ) -> anyhow::Result<MlsAddMemberResult> {
            let group = self
                .group
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("MLS group is not available"))?;
            Ok(group.add_member(member_key_package)?)
        }

        /// T31 — remove a member by principal DID, advancing the local
        /// MLS epoch. The returned MlsRemoveMemberResult carries the
        /// commit envelope; surviving members must apply this commit
        /// (via `apply_commit`) to converge.
        ///
        /// Returns Err if the principal has no leaf in this group, if
        /// the underlying group is not yet created, or if OpenMLS rejects
        /// the operation. The caller (yougen device_revoke executor) is
        /// expected to surface those errors back to the UI's
        /// device-revoke-plan card so the user can retry / dismiss.
        pub fn remove_member_by_principal(
            &mut self,
            target_principal: &str,
        ) -> anyhow::Result<MlsRemoveMemberResult> {
            let group = self
                .group
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("MLS group is not available"))?;
            let target = Did::new(target_principal.to_owned())?;
            Ok(group.remove_member_by_principal(&target)?)
        }

        /// T31 — remove a single device leaf by raw OpenMLS leaf index.
        /// Used when the caller maintains a (principal, device_id) → leaf
        /// map and wants to revoke just one device of a multi-device
        /// principal.
        pub fn remove_member_by_leaf(
            &mut self,
            leaf_index: u32,
        ) -> anyhow::Result<MlsRemoveMemberResult> {
            let group = self
                .group
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("MLS group is not available"))?;
            Ok(group.remove_member_by_leaf(leaf_index)?)
        }

        pub fn encrypt_message(
            &mut self,
            message_id: impl Into<String>,
            plaintext: &[u8],
        ) -> anyhow::Result<ClientEncryptedMessage> {
            let message_id = message_id.into();
            let group = self
                .group
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("MLS group is not available"))?;
            let encrypted = MessageCrypto::encrypt(
                group,
                message_id,
                "application/vnd.contrix.message+json",
                plaintext,
            )?;
            Ok(ClientEncryptedMessage {
                message_id: encrypted.message_id,
                payload: encrypted.payload,
            })
        }

        pub fn decrypt_or_preserve(
            &mut self,
            message: ClientEncryptedMessage,
        ) -> anyhow::Result<MessageCryptoDecrypt> {
            let decrypted = MessageCrypto::decrypt_or_preserve(
                self.group.as_mut(),
                EncryptedMessage {
                    message_id: message.message_id,
                    payload: message.payload,
                },
            )?;
            if let MessageCryptoDecrypt::Encrypted {
                payload,
                message_id,
                ..
            } = &decrypted
            {
                self.pending.push(ClientEncryptedMessage {
                    message_id: message_id.clone(),
                    payload: payload.clone(),
                });
            }
            Ok(decrypted)
        }

        pub fn pending_count(&self) -> usize {
            self.pending.len()
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use native::LocalMlsDevice;

pub fn compose_local_encrypted_message(
    principal_id: &str,
    device_id: &str,
    space_id: &str,
    message_id: &str,
    body: &str,
) -> anyhow::Result<ClientEncryptedMessage> {
    compose_local_encrypted_message_inner(principal_id, device_id, space_id, message_id, body)
}

#[cfg(not(target_arch = "wasm32"))]
fn compose_local_encrypted_message_inner(
    principal_id: &str,
    device_id: &str,
    space_id: &str,
    message_id: &str,
    body: &str,
) -> anyhow::Result<ClientEncryptedMessage> {
    let mut device = LocalMlsDevice::new(principal_id, device_id)?;
    device.create_group(space_id.as_bytes())?;
    let plaintext = serde_json::to_vec(&serde_json::json!({
        "msgtype": "m.text",
        "body": body
    }))?;
    device.encrypt_message(message_id, &plaintext)
}

#[cfg(target_arch = "wasm32")]
fn compose_local_encrypted_message_inner(
    _principal_id: &str,
    device_id: &str,
    space_id: &str,
    message_id: &str,
    body: &str,
) -> anyhow::Result<ClientEncryptedMessage> {
    let payload_digest = Hash::new(format!(
        "sha256:{:0>64}",
        format!("{:x}", body.len() + device_id.len() + space_id.len())
    ))?;
    Ok(ClientEncryptedMessage {
        message_id: message_id.to_owned(),
        payload: EncryptedPayload {
            scheme: EncryptedPayloadScheme::MlsRfc9420,
            group_id: space_id.replace(':', "_"),
            epoch: 0,
            content_type: "application/vnd.contrix.message+json".to_owned(),
            ciphertext: "b3BhcXVlLXdlYi1lbmNyeXB0ZWQtcGF5bG9hZA".to_owned(),
            aad: Some(serde_json::json!({
                "space_id": space_id,
                "device_id": device_id
            })),
            payload_digest,
            key_ref: Some(KeyRefObject::mls_rfc9420(space_id.replace(':', "_"), 0)),
        },
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use contrix_sdk::{MessageCryptoDecrypt, MessageCryptoUnavailable};

    #[test]
    fn local_mls_devices_encrypt_decrypt_and_preserve_pending_ciphertext() {
        // SDK 0.7 tightened DeviceId validation — only `cx:device:<uuid7>`
        // forms are accepted; legacy `dev_alice_1` style ids no longer pass.
        let mut alice = LocalMlsDevice::new(
            "did:web:alice.example",
            "cx:device:01904100-0000-7000-8000-000000000001",
        )
        .unwrap();
        let mut bob = LocalMlsDevice::new(
            "did:web:bob.example",
            "cx:device:01904100-0000-7000-8000-000000000002",
        )
        .unwrap();
        let bob_keys = bob.key_package_record().unwrap();

        alice.create_group(b"cx:space:local-e2ee").unwrap();
        let welcome = alice.add_member(&bob_keys).unwrap().welcome;
        bob.join_from_welcome(&welcome).unwrap();

        let encrypted = alice
            .encrypt_message("cx:message:local-1", br#"{"body":"hello secure client"}"#)
            .unwrap();
        let ciphertext = encrypted.payload.ciphertext.clone();
        let digest = encrypted.payload.payload_digest.clone();

        let decrypted = bob.decrypt_or_preserve(encrypted.clone()).unwrap();
        let MessageCryptoDecrypt::Plaintext { plaintext, .. } = decrypted else {
            panic!("joined MLS device should decrypt the message");
        };
        assert_eq!(plaintext, br#"{"body":"hello secure client"}"#);

        let mut offline = LocalMlsDevice::new(
            "did:web:carol.example",
            "cx:device:01904100-0000-7000-8000-000000000003",
        )
        .unwrap();
        let pending = offline.decrypt_or_preserve(encrypted).unwrap();
        let MessageCryptoDecrypt::Encrypted {
            payload, reason, ..
        } = pending
        else {
            panic!("device without MLS state should preserve ciphertext");
        };
        assert_eq!(payload.ciphertext, ciphertext);
        assert_eq!(payload.payload_digest, digest);
        assert!(matches!(reason, MessageCryptoUnavailable::NoSession));
        assert_eq!(offline.pending_count(), 1);
    }

    #[test]
    fn local_compose_creates_protocol_mls_envelope() {
        let encrypted = compose_local_encrypted_message(
            "did:web:alice.example",
            "cx:device:01904100-0000-7000-8000-000000000001",
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "cx:message:local-2",
            "encrypted hello",
        )
        .unwrap();

        assert_eq!(encrypted.message_id, "cx:message:local-2");
        assert_eq!(encrypted.payload.scheme.as_str(), "mls-rfc9420");
        assert_eq!(
            encrypted.payload.content_type,
            "application/vnd.contrix.message+json"
        );
    }
}
