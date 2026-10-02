use dioxus::prelude::{ReadableExt, Signal, WritableExt};

use crate::runtime::projection::{ClientProjectionEvent, ProjectionSink, SyncStatusEvent};
use crate::state::projection::ProjectionEvent;

pub(super) struct ProjectionAdapter {
    projection_events: Signal<Vec<ProjectionEvent>>,
    sync_cursor: Signal<String>,
    connection_status: Signal<String>,
    network_state: Signal<String>,
    last_error: Signal<Option<String>>,
    device_queue: Signal<usize>,
    theme: Signal<String>,
    selected_realm_id: Signal<String>,
}

impl ProjectionAdapter {
    pub(super) fn new(
        projection_events: Signal<Vec<ProjectionEvent>>,
        sync_cursor: Signal<String>,
        connection_status: Signal<String>,
        network_state: Signal<String>,
        last_error: Signal<Option<String>>,
        device_queue: Signal<usize>,
        theme: Signal<String>,
        selected_realm_id: Signal<String>,
    ) -> Self {
        Self {
            projection_events,
            sync_cursor,
            connection_status,
            network_state,
            last_error,
            device_queue,
            theme,
            selected_realm_id,
        }
    }
}

impl ProjectionSink for ProjectionAdapter {
    fn projection(&self, event: ClientProjectionEvent) {
        match event {
            ClientProjectionEvent::Account(event) | ClientProjectionEvent::Realm(event) => {
                let current = self.projection_events.read().clone();
                self.projection_events
                    .clone()
                    .set(fold_projection_event(&current, event));
            }
            ClientProjectionEvent::CursorCheckpoint { cursor, .. } => {
                self.sync_cursor.clone().set(cursor);
            }
            ClientProjectionEvent::CursorReset { .. } => {
                self.sync_cursor.clone().set(String::new());
            }
            ClientProjectionEvent::DeviceQueue { pending } => {
                self.device_queue.clone().set(pending);
            }
            ClientProjectionEvent::Theme { value } => {
                self.theme.clone().set(value);
            }
            ClientProjectionEvent::SelectedRealm { realm_id } => {
                self.selected_realm_id.clone().set(realm_id);
            }
            ClientProjectionEvent::Reset => {
                self.projection_events.clone().set(Vec::new());
            }
        }
    }

    fn sync_status(&self, event: SyncStatusEvent) {
        let (status, network, error) = fold_sync_status(event);
        self.connection_status.clone().set(status);
        self.network_state.clone().set(network);
        self.last_error.clone().set(error);
    }
}

fn fold_projection_event(
    current: &[ProjectionEvent],
    event: ProjectionEvent,
) -> Vec<ProjectionEvent> {
    super::merge_projection_events(current, vec![event])
}

fn fold_sync_status(event: SyncStatusEvent) -> (String, String, Option<String>) {
    match event {
        SyncStatusEvent::Offline => ("Offline".to_owned(), "offline".to_owned(), None),
        SyncStatusEvent::Connecting => ("Connecting".to_owned(), "online".to_owned(), None),
        SyncStatusEvent::Online => ("Online".to_owned(), "online".to_owned(), None),
        SyncStatusEvent::Retryable { reason } => (
            "Retrying connection".to_owned(),
            "online".to_owned(),
            Some(reason),
        ),
        SyncStatusEvent::NeedsSignIn { reason } => (
            "Sign in required".to_owned(),
            "online".to_owned(),
            Some(reason),
        ),
        SyncStatusEvent::Terminal { reason } => {
            ("Sync stopped".to_owned(), "online".to_owned(), Some(reason))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_events_fold_in_arrival_order() {
        let first = ProjectionEvent {
            id: "first".to_owned(),
            ..ProjectionEvent::default()
        };
        let second = ProjectionEvent {
            id: "second".to_owned(),
            ..ProjectionEvent::default()
        };
        let state = fold_projection_event(&[], first);
        let state = fold_projection_event(&state, second);
        assert_eq!(
            state
                .iter()
                .map(|event| event.id.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
    }

    #[test]
    fn cursor_checkpoint_and_reset_are_explicit_ordered_events() {
        let events = [
            ClientProjectionEvent::CursorCheckpoint {
                scope: "account".to_owned(),
                cursor: "ak:cursor:next".to_owned(),
            },
            ClientProjectionEvent::CursorReset {
                scope: "account".to_owned(),
            },
        ];
        let mut cursor = String::new();
        for event in events {
            match event {
                ClientProjectionEvent::CursorCheckpoint { cursor: next, .. } => cursor = next,
                ClientProjectionEvent::CursorReset { .. } => cursor.clear(),
                _ => unreachable!(),
            }
        }
        assert!(cursor.is_empty());
    }

    #[test]
    fn terminal_status_updates_all_fields_as_one_projection() {
        assert_eq!(
            fold_sync_status(SyncStatusEvent::Terminal {
                reason: "invalid protocol frame".to_owned(),
            }),
            (
                "Sync stopped".to_owned(),
                "online".to_owned(),
                Some("invalid protocol frame".to_owned()),
            )
        );
    }

    #[test]
    fn inactive_session_requires_sign_in_instead_of_reporting_a_protocol_failure() {
        assert_eq!(
            fold_sync_status(SyncStatusEvent::NeedsSignIn {
                reason: "session grant is no longer active".to_owned(),
            }),
            (
                "Sign in required".to_owned(),
                "online".to_owned(),
                Some("session grant is no longer active".to_owned()),
            )
        );
    }
}
