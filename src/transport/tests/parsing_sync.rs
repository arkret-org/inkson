#[test]
fn parses_committed_event_subscribe_ndjson_control_frames() {
    use arkret_models_collaboration::sync_frames::committed_event_subscribe::{
        CommittedEventSubscribeFrame, CommittedEventSubscribeFrameKind,
    };

    // The current authority stream has no Realm-global frontier frame.
    // Checkpoints and catch-up completion carry only their opaque resume
    // cursor, while heartbeat is deliberately positionless.
    let frames = [
        r#"{"kind":"heartbeat"}"#,
        r#"{"cursor":"ak:cursor:checkpoint","kind":"checkpoint"}"#,
        r#"{"cursor":"ak:cursor:live","kind":"catchup_complete"}"#,
    ]
    .into_iter()
    .map(|line| {
        CommittedEventSubscribeFrame::from_ndjson_line(line)
            .unwrap()
            .unwrap()
    })
    .collect::<Vec<_>>();

    assert_eq!(frames[0].kind, CommittedEventSubscribeFrameKind::Heartbeat);
    assert_eq!(frames[1].kind, CommittedEventSubscribeFrameKind::Checkpoint);
    assert_eq!(
        frames[2].kind,
        CommittedEventSubscribeFrameKind::CatchupComplete
    );
}
