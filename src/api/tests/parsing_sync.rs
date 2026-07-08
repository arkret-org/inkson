use super::super::*;
use crate::sync_parse::parse_events_subscribe_ndjson_text;

#[test]
fn parses_events_subscribe_ndjson_frames() {
    // Round 4 typed frames carry the discriminator-required fields:
    // `heartbeat` requires `emitted_at`; `frontier` requires a nested
    // `frontier` value; `catchup_complete` is a unit variant.
    let frames = parse_events_subscribe_ndjson_text(
        r#"
{"kind":"heartbeat"}
{"kind":"frontier","cursor":"ck:cursor:frontier"}
{"kind":"catchup_complete","cursor":"ck:cursor:live"}
"#,
    )
    .unwrap();

    assert_eq!(
        frames[0].kind,
        cokret_sdk::EventsSubscribeFrameKind::Heartbeat
    );
    assert_eq!(
        frames[1].kind,
        cokret_sdk::EventsSubscribeFrameKind::Frontier
    );
    assert_eq!(
        frames[2].kind,
        cokret_sdk::EventsSubscribeFrameKind::CatchupComplete
    );
}
