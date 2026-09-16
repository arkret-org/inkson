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
