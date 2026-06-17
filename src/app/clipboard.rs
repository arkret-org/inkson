use super::*;

pub(super) fn copy_text_to_clipboard(text: &str) {
    let Ok(encoded) = serde_json::to_string(text) else {
        return;
    };
    let script = format!(
        r#"(async () => {{
    const text = {encoded};
    if (navigator.clipboard && window.isSecureContext) {{
        await navigator.clipboard.writeText(text);
        return true;
    }}
    const node = document.createElement("textarea");
    node.value = text;
    node.setAttribute("readonly", "");
    node.style.position = "fixed";
    node.style.left = "-9999px";
    document.body.appendChild(node);
    node.select();
    const copied = document.execCommand("copy");
    document.body.removeChild(node);
    return copied;
}})()"#
    );
    let _ = document::eval(&script);
}

pub fn merge_timeline_events(
    current: &[TimelineEvent],
    incoming: Vec<TimelineEvent>,
) -> Vec<TimelineEvent> {
    let mut merged = current.to_vec();
    for event in incoming {
        if let Some(existing) = merged.iter_mut().find(|existing| existing.id == event.id) {
            *existing = event;
        } else {
            merged.push(event);
        }
    }
    merged
}
