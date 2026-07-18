//! Small profile settings helpers.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
pub(super) use yoface::utils::dom::copy_text_to_clipboard;

#[derive(Clone, Debug, PartialEq)]
pub(super) struct PendingAvatarCrop {
    pub(super) bytes: Vec<u8>,
    pub(super) media_type: String,
    pub(super) preview_data_url: String,
    pub(super) dimensions: (u32, u32),
}

pub(super) fn avatar_preview_data_url(bytes: &[u8], media_type: &str) -> String {
    let media_type = if media_type.trim().is_empty() {
        "application/octet-stream"
    } else {
        media_type
    };
    format!("data:{media_type};base64,{}", BASE64_STANDARD.encode(bytes))
}
