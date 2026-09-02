// Shared JS-interop helper (single source).
pub(super) use yoface::utils::dom::copy_text_to_clipboard;

use super::*;

pub fn merge_projection_events(
    current: &[ProjectionEvent],
    incoming: Vec<ProjectionEvent>,
) -> Vec<ProjectionEvent> {
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
