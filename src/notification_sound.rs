use crate::state::LocalStateStore;

pub const NOTIFICATION_SOUND_ENABLED_KEY: &str = "notification.sound.enabled.v1";

pub fn notification_sound_enabled(store: &LocalStateStore) -> bool {
    private_bool_preference(
        store.load_plain_local_data(NOTIFICATION_SOUND_ENABLED_KEY),
        true,
    )
}

pub fn set_notification_sound_enabled(store: &mut LocalStateStore, enabled: bool) {
    store.save_plain_local_data(NOTIFICATION_SOUND_ENABLED_KEY, enabled.to_string());
}

pub fn should_play_notification_sound(
    previous_unread: Option<usize>,
    current_unread: usize,
    enabled: bool,
) -> bool {
    enabled && previous_unread.is_some_and(|previous| current_unread > previous)
}

fn private_bool_preference(value: Option<String>, default_value: bool) -> bool {
    match value.as_deref().map(str::trim) {
        Some("true" | "1" | "yes" | "on") => true,
        Some("false" | "0" | "no" | "off") => false,
        Some(_) | None => default_value,
    }
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(module = "/assets/notification_sound.js")]
extern "C" {
    #[wasm_bindgen::prelude::wasm_bindgen(js_name=initializeNotificationAudio)]
    fn initialize_web_audio();
    #[wasm_bindgen::prelude::wasm_bindgen(js_name=playNotificationSound)]
    fn play_web_sound();
}

pub fn initialize_notification_audio() {
    #[cfg(target_arch = "wasm32")]
    initialize_web_audio();
}

pub fn play_notification_sound() {
    #[cfg(target_arch = "wasm32")]
    play_web_sound();
    #[cfg(not(target_arch = "wasm32"))]
    {
        let path = match crate::presentation::host::asset_directory() {
            Ok(directory) => directory.join("notification.wav"),
            Err(error) => {
                tracing::warn!(%error,"notification audio asset directory unavailable");
                return;
            }
        };
        std::thread::spawn(move || {
            use std::process::{Command, Stdio};
            #[cfg(target_os = "windows")]
            let result = {
                use std::os::windows::process::CommandExt;
                Command::new("powershell.exe").args(["-NoProfile","-NonInteractive","-Command","(New-Object System.Media.SoundPlayer $env:INKSON_NOTIFICATION_SOUND).PlaySync()"]).env("INKSON_NOTIFICATION_SOUND",&path).creation_flags(0x08000000).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status()
            };
            #[cfg(target_os = "macos")]
            let result = Command::new("afplay")
                .arg(&path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            #[cfg(not(any(target_os = "windows", target_os = "macos")))]
            let result = Command::new("paplay")
                .arg(&path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .or_else(|error| {
                    if error.kind() == std::io::ErrorKind::NotFound {
                        Command::new("aplay")
                            .arg("-q")
                            .arg(&path)
                            .stdin(Stdio::null())
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .status()
                    } else {
                        Err(error)
                    }
                });
            if let Err(error) = result {
                tracing::warn!(%error,"notification audio playback failed");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_sound_pref_defaults_on_and_parses_false_values() {
        let mut store = crate::state::isolated_store_for_tests("notification-sound-pref");

        assert!(notification_sound_enabled(&store));

        set_notification_sound_enabled(&mut store, false);
        assert!(!notification_sound_enabled(&store));

        set_notification_sound_enabled(&mut store, true);
        assert!(notification_sound_enabled(&store));
    }

    #[test]
    fn should_play_only_when_enabled_and_unread_count_increases() {
        assert!(!should_play_notification_sound(None, 1, true));
        assert!(!should_play_notification_sound(Some(1), 1, true));
        assert!(!should_play_notification_sound(Some(2), 1, true));
        assert!(!should_play_notification_sound(Some(1), 2, false));
        assert!(should_play_notification_sound(Some(1), 2, true));
    }
}
