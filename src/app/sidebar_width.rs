use super::*;

pub(super) fn clamp_sidebar_width(width: f64) -> f64 {
    width.clamp(MIN_SIDEBAR_WIDTH, MAX_SIDEBAR_WIDTH)
}

pub(super) fn load_sidebar_width_preference(state_store: &LocalStateStore) -> f64 {
    state_store
        .load_private_data(UI_PREFERENCES_SCOPE, SIDEBAR_WIDTH_PREFERENCE_KEY)
        .and_then(|value| value.parse::<f64>().ok())
        .map(clamp_sidebar_width)
        .unwrap_or(DEFAULT_SIDEBAR_WIDTH)
}

pub(super) fn save_sidebar_width_preference(state_store: &mut LocalStateStore, width: f64) {
    state_store.save_private_data(
        UI_PREFERENCES_SCOPE,
        SIDEBAR_WIDTH_PREFERENCE_KEY,
        format!("{:.0}", clamp_sidebar_width(width)),
    );
}
