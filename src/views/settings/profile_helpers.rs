//! Small profile settings helpers.

pub(super) use yoface::utils::dom::copy_text_to_clipboard;

pub(super) use crate::components::avatar_uploader::avatar_preview_data_url;

#[derive(Clone, Debug, PartialEq)]
pub(super) struct PendingAvatarCrop {
    pub(super) bytes: Vec<u8>,
    pub(super) media_type: String,
    pub(super) preview_data_url: String,
    pub(super) dimensions: (u32, u32),
}

/// A file read may finish after a replacement or a cancelled crop. Only the
/// latest selection may publish bytes or an error back into the editor.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(super) struct AvatarSelectionEpoch(u64);

impl AvatarSelectionEpoch {
    pub(super) fn advance(&mut self) -> Self {
        self.0 = self.0.wrapping_add(1);
        *self
    }
}
