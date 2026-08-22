pub mod rtc;
pub mod service_route;

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
}
