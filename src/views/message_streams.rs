//! UI bridge for transient `ak.message.stream` generation previews.

use dioxus::prelude::*;

fn allow_authorized_frame(_: &garth::SignalPlaintext, _: &arkret_sdk::MessageStreamFrame) -> bool {
    true
}

#[derive(Clone, Copy)]
pub struct MessageStreamHub {
    projection: Signal<garth::MessageStreamProjection>,
}

impl MessageStreamHub {
    pub fn new() -> Self {
        Self {
            projection: Signal::new(garth::MessageStreamProjection::new()),
        }
    }

    pub fn try_use() -> Option<Self> {
        try_consume_context::<Self>()
    }

    /// Applies a frame only after the caller has verified the Signal envelope,
    /// decrypted it, and authorized both `ak.message.stream.send` and
    /// `ak.message.create` at the envelope's `seal_ref`.
    pub fn apply_authorized(
        &mut self,
        plaintext: &garth::SignalPlaintext,
        observed_at: chrono::DateTime<chrono::Utc>,
    ) -> garth::Result<garth::MessageStreamApplyOutcome> {
        self.projection
            .write()
            .apply(plaintext, &allow_authorized_frame, observed_at)
    }

    /// Removes a preview only after the durable Event and its sending device
    /// have passed the normal schema, proof, authorization and reducer gates.
    pub fn bind_verified_final(
        &mut self,
        event: &arkret_sdk::Event,
        verified_sender_device_id: &arkret_sdk::DeviceId,
    ) -> garth::Result<Option<garth::MessageStreamPreview>> {
        self.projection
            .write()
            .bind_verified_final(event, verified_sender_device_id)
    }

    pub fn maintain(&mut self, now: chrono::DateTime<chrono::Utc>) {
        let mut projection = self.projection.write();
        projection.mark_stalled(now);
        projection.expire(now);
    }

    pub fn visible_for(&self, realm_id: &str, strand_id: &str) -> Vec<MessageStreamCard> {
        self.projection
            .read()
            .previews()
            .filter(|preview| {
                preview.scope_ref.realm_id().as_str() == realm_id
                    && preview.strand_id.as_str() == strand_id
                    && matches!(
                        preview.status,
                        garth::MessageStreamPreviewStatus::Active
                            | garth::MessageStreamPreviewStatus::Stalled
                    )
            })
            .map(MessageStreamCard::from)
            .collect()
    }
}

impl Default for MessageStreamHub {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageStreamCard {
    pub sender_actor_id: String,
    pub message_id: String,
    pub text: String,
    pub truncated: bool,
    pub stalled: bool,
}

impl From<&garth::MessageStreamPreview> for MessageStreamCard {
    fn from(preview: &garth::MessageStreamPreview) -> Self {
        Self {
            sender_actor_id: preview.sender_actor_id.as_str().to_owned(),
            message_id: preview.message_id.as_str().to_owned(),
            text: preview.text.clone(),
            truncated: preview.truncated,
            stalled: preview.status == garth::MessageStreamPreviewStatus::Stalled,
        }
    }
}
