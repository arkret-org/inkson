//! Recovery-key clipboard access through the selected platform host.
pub(crate) fn copy_recovery_text_to_clipboard(text: &str) {
    crate::components::mls_backup_prompt::copy_text_to_clipboard(text)
}
