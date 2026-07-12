//! Deterministic, GitHub-style fallback avatars for identities without an upload.

use dioxus::prelude::*;

const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

fn avatar_hash(seed: &str) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for byte in seed.trim().to_lowercase().bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn identicon_cells(seed: &str) -> Vec<(usize, usize)> {
    let hash = avatar_hash(seed);
    let mut cells = Vec::new();
    for y in 0..5 {
        for x in 0..3 {
            let bit = y * 3 + x;
            if (hash >> bit) & 1 == 0 {
                continue;
            }
            cells.push((x, y));
            if x < 2 {
                cells.push((4 - x, y));
            }
        }
    }
    if cells.is_empty() {
        cells.push((2, 2));
    }
    cells
}

#[derive(Clone, PartialEq, Props)]
pub struct GeneratedAvatarProps {
    pub seed: String,
    pub alt_text: String,
    #[props(default = "avatar-img generated-avatar".to_owned())]
    pub class: String,
    #[props(default)]
    pub test_id: Option<String>,
}

#[component]
pub fn GeneratedAvatar(props: GeneratedAvatarProps) -> Element {
    let GeneratedAvatarProps {
        seed,
        alt_text,
        class,
        test_id,
    } = props;
    let hash = avatar_hash(&seed);
    let hue = hash % 360;
    let color = format!("hsl({hue} 58% 42%)");
    let cells = identicon_cells(&seed);
    let test_id = test_id.unwrap_or_default();

    rsx! {
        div {
            class: "{class}",
            "data-testid": "{test_id}",
            role: "img",
            "aria-label": "{alt_text}",
            svg {
                view_box: "0 0 5 5",
                "aria-hidden": "true",
                "focusable": "false",
                for (x, y) in cells {
                    rect {
                        x: "{x}",
                        y: "{y}",
                        width: "1",
                        height: "1",
                        fill: "{color}",
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identicon_is_stable_and_horizontally_symmetric() {
        let cells = identicon_cells("summary");
        assert_eq!(cells, identicon_cells(" SUMMARY "));
        assert!(!cells.is_empty());
        for (x, y) in &cells {
            assert!(cells.contains(&(4 - x, *y)));
        }
    }

    #[test]
    fn different_seeds_produce_different_patterns() {
        assert_ne!(identicon_cells("alpha"), identicon_cells("beta"));
    }
}
