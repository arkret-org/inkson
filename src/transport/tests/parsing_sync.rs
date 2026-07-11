#[test]
fn parses_events_subscribe_ndjson_frames() {
    // Round 4 typed frames carry the discriminator-required fields:
    // `heartbeat` requires `emitted_at`; `frontier` requires a nested
    // `frontier` value; `catchup_complete` is a unit variant.
    let frames = [
        r#"{"kind":"heartbeat"}"#,
        r#"{"cursor":"ak:cursor:frontier","kind":"frontier"}"#,
        r#"{"cursor":"ak:cursor:live","kind":"catchup_complete"}"#,
    ]
    .into_iter()
    .map(|line| {
        arkret_sdk::EventsSubscribeFrame::from_ndjson_line(line)
            .unwrap()
            .unwrap()
    })
    .collect::<Vec<_>>();

    assert_eq!(
        frames[0].kind,
        arkret_sdk::EventsSubscribeFrameKind::Heartbeat
    );
    assert_eq!(
        frames[1].kind,
        arkret_sdk::EventsSubscribeFrameKind::Frontier
    );
    assert_eq!(
        frames[2].kind,
        arkret_sdk::EventsSubscribeFrameKind::CatchupComplete
    );
}
