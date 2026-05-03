use sha2::{Digest, Sha256};

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

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
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
    normalize_sha256(expected_sha256) == sha256_hex(bytes)
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
            sha256_hex(b"yougen encrypted bytes"),
            "01015dc8af66d01f557ea63f13538f1964848840a350c5311d1efc8ad138bb91"
        );
        assert!(hash_matches(
            "sha256:01015dc8af66d01f557ea63f13538f1964848840a350c5311d1efc8ad138bb91",
            b"yougen encrypted bytes"
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
