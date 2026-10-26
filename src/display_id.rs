//! Pure display shortening for opaque protocol identifiers.
pub fn short_protocol_id(value: impl AsRef<str>) -> String {
    let value = value.as_ref().trim();
    if value.len() <= 32 {
        return value.to_owned();
    }
    let elide = |value: &str, head: usize, tail: usize| {
        if value.len() <= head + tail + 3 {
            return value.to_owned();
        }
        if value.is_ascii() {
            return format!("{}...{}", &value[..head], &value[value.len() - tail..]);
        }
        let letters = value.chars().collect::<Vec<_>>();
        if letters.len() <= head + tail + 3 {
            return value.to_owned();
        }
        format!(
            "{}...{}",
            letters[..head].iter().collect::<String>(),
            letters[letters.len() - tail..].iter().collect::<String>()
        )
    };
    if let Some((prefix, tail)) = value.rsplit_once(':')
        && tail.len() >= 20
        && prefix.len() <= 20
    {
        return format!("{prefix}:{}", elide(tail, 8, 6));
    }
    elide(value, 16, 8)
}
