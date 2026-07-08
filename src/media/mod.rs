pub mod rtc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaPreviewPolicy {
    ImagePreview,
    VideoPreview,
    AudioPreview,
    AttachmentOnly,
}

impl MediaPreviewPolicy {
    pub fn label(self) -> &'static str {
        match self {
            Self::ImagePreview => "image preview allowed",
            Self::VideoPreview => "video preview allowed",
            Self::AudioPreview => "audio preview allowed",
            Self::AttachmentOnly => "unsafe or opaque type opens as attachment",
        }
    }
}

pub fn media_type_preview_policy(media_type: &str) -> MediaPreviewPolicy {
    let media_type = media_type
        .split(';')
        .next()
        .unwrap_or(media_type)
        .trim()
        .to_ascii_lowercase();

    if media_type.starts_with("image/") {
        MediaPreviewPolicy::ImagePreview
    } else if media_type.starts_with("video/") {
        MediaPreviewPolicy::VideoPreview
    } else if media_type.starts_with("audio/") {
        MediaPreviewPolicy::AudioPreview
    } else {
        MediaPreviewPolicy::AttachmentOnly
    }
}

pub fn hash_matches(expected_sha256: &str, bytes: &[u8]) -> bool {
    normalize_sha256(expected_sha256) == crate::canonical::sha256_hex(bytes)
}

fn normalize_sha256(value: &str) -> String {
    value
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(value.trim())
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_matches_known_bytes() {
        assert_eq!(
            crate::canonical::sha256_hex(b"inkson encrypted bytes"),
            "962823272bba564e070376ee0b28c2cae5883afeb6d54ef139632e5f1a41608c"
        );
        assert!(hash_matches(
            "sha256:962823272bba564e070376ee0b28c2cae5883afeb6d54ef139632e5f1a41608c",
            b"inkson encrypted bytes"
        ));
    }

    #[test]
    fn preview_policy_allows_only_safe_inline_types() {
        assert_eq!(
            media_type_preview_policy("image/png"),
            MediaPreviewPolicy::ImagePreview
        );
        assert_eq!(
            media_type_preview_policy("video/mp4; codecs=avc1"),
            MediaPreviewPolicy::VideoPreview
        );
        assert_eq!(
            media_type_preview_policy("audio/ogg"),
            MediaPreviewPolicy::AudioPreview
        );
        assert_eq!(
            media_type_preview_policy("application/octet-stream"),
            MediaPreviewPolicy::AttachmentOnly
        );
    }
}
