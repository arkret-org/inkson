use super::*;

fn row(id: &str, protocol: Option<&str>, version: i64) -> ChatMessage {
    ChatMessage {
        local_scope: None,
        realm_id: "fixture-realm".to_owned(),
        id: id.to_owned(),
        protocol_message_id: protocol.map(str::to_owned),
        actor_id: None,
        sender: "fixture".to_owned(),
        executed_by: None,
        body: format!("body-{id}-{version}"),
        content_format: None,
        timestamp: version.to_string(),
        created_at: chrono::DateTime::from_timestamp(version, 0),
        strand_id: "ordinary".to_owned(),
        reply_to: None,
        reactions: Vec::new(),
        redacted: false,
        edited: false,
        revisions: Vec::new(),
        revision_source: None,
        pending: false,
        failed: false,
        error: None,
        mentions: Vec::new(),
        crypto_state: MessageCryptoState::Plaintext,
    }
}

// Preserve the previous production algorithm as the semantic oracle. This
// deliberately scans and retains per incoming row; it is never used by the UI.
fn naive_merge(target: &mut Vec<ChatMessage>, incoming: Vec<ChatMessage>) {
    for message in incoming {
        let protocol = chat_message_protocol_id(&message).map(str::to_owned);
        if let Some(position) = target.iter().position(|existing| {
            existing.id == message.id
                || protocol
                    .as_deref()
                    .is_some_and(|protocol| chat_message_protocol_id(existing) == Some(protocol))
        }) {
            merge_duplicate_create_message(&mut target[position], message);
            let keep_id = target[position].id.clone();
            let protocol = chat_message_protocol_id(&target[position]).map(str::to_owned);
            let mut kept_primary = false;
            target.retain(|message| {
                if message.id == keep_id {
                    if kept_primary {
                        return false;
                    }
                    kept_primary = true;
                    return true;
                }
                !protocol
                    .as_deref()
                    .is_some_and(|protocol| chat_message_protocol_id(message) == Some(protocol))
            });
        } else {
            target.push(message);
        }
    }
}

fn assert_matches_naive(target: Vec<ChatMessage>, incoming: Vec<ChatMessage>) -> Vec<ChatMessage> {
    let mut expected = target.clone();
    naive_merge(&mut expected, incoming.clone());
    let mut actual = target;
    merge_chat_messages(&mut actual, incoming);
    assert_eq!(actual, expected);
    actual
}

#[test]
fn indexed_merge_bridge_rewrites_remove_old_aliases_and_preserve_untouched_duplicates() {
    let target = vec![
        row("early", Some("old-protocol"), 0),
        row("late", Some("removed-protocol"), 0),
        row("untouched-a", Some("untouched-protocol"), 0),
        row("untouched-b", Some("untouched-protocol"), 0),
    ];
    let actual = assert_matches_naive(
        target,
        vec![
            row("late", Some("old-protocol"), 1),
            row("new", Some("removed-protocol"), 2),
            row("early", Some("fresh-protocol"), 3),
            row("early", Some("rewritten-protocol"), 4),
            row("new-old-protocol", Some("fresh-protocol"), 5),
        ],
    );
    assert_eq!(
        actual.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
        vec![
            "late",
            "untouched-a",
            "untouched-b",
            "new",
            "early",
            "new-old-protocol"
        ]
    );
    assert_eq!(
        actual[4].protocol_message_id.as_deref(),
        Some("rewritten-protocol")
    );
    assert_eq!(
        actual[5].protocol_message_id.as_deref(),
        Some("fresh-protocol")
    );
    let actual = assert_matches_naive(actual, vec![row("touch", Some("untouched-protocol"), 6)]);
    assert_eq!(actual.len(), 5);
    assert_eq!(actual[1].id, "touch");
}

#[test]
fn indexed_merge_keeps_earliest_primary_even_when_updated_slot_is_pruned() {
    let mut tombstone = row("same", Some("second-protocol"), 1);
    tombstone.redacted = true;
    tombstone.body.clear();
    let first = row("same", Some("first-protocol"), 0);
    let actual = assert_matches_naive(
        vec![first.clone(), tombstone],
        vec![
            row("later", Some("second-protocol"), 2),
            row("independent", Some("second-protocol"), 3),
        ],
    );
    assert_eq!(actual[0], first);
    assert_eq!(actual[1].id, "independent");
    assert_eq!(actual.len(), 2);
}

#[test]
fn indexed_merge_matches_naive_for_revisions_tombstones_and_alias_permutations() {
    fn generated(seed: &mut u64) -> ChatMessage {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let bits = *seed;
        let id = format!("id-{}", bits % 7);
        let protocol = match (bits >> 8) % 7 {
            0 => None,
            1 => Some(String::new()),
            2 => Some("   ".to_owned()),
            value => Some(format!(" {} ", value % 3)),
        };
        let mut message = row(&id, protocol.as_deref(), ((bits >> 16) % 8) as i64);
        message.pending = bits & (1 << 30) != 0;
        message.failed = bits & (1 << 31) != 0;
        message.redacted = bits & (1 << 32) != 0;
        message.edited = bits & (1 << 33) != 0;
        if message.edited {
            message.revisions = vec![format!("revision-{}", bits % 3)];
        }
        if message.redacted {
            message.body.clear();
        }
        if bits & (1 << 34) != 0 {
            message.reactions = vec![("+1".to_owned(), vec![format!("actor-{}", bits % 3)])];
        }
        if bits & (1 << 35) != 0 {
            message.created_at = None;
        }
        if bits & (1 << 36) != 0 {
            message.crypto_state = MessageCryptoState::KeyMissing;
            message.body.clear();
        }
        message
    }
    let mut seed = 17;
    for case in 0..512 {
        let target = (0..case % 13)
            .map(|_| generated(&mut seed))
            .collect::<Vec<_>>();
        let incoming = (0..case % 19)
            .map(|_| generated(&mut seed))
            .collect::<Vec<_>>();
        // Check every prefix as well as one combined merge, so stale aliases
        // cannot be masked by a later tombstone or revision.
        for end in 0..=incoming.len() {
            assert_matches_naive(target.clone(), incoming[..end].to_vec());
        }
    }
}

#[test]
fn indexed_merge_ten_thousand_mixed_rows_has_bounded_row_visits() {
    const COUNT: usize = 10_000;
    let target = (0..COUNT)
        .map(|number| {
            let mut message = row(
                &format!("event-{number}"),
                Some(&format!("message-{number}")),
                0,
            );
            if number % 2 == 1 {
                message.strand_id = "private-sidecar".to_owned();
            }
            message
        })
        .collect::<Vec<_>>();
    let incoming = target
        .iter()
        .chain(target.iter())
        .cloned()
        .collect::<Vec<_>>();
    MERGE_INDEX_STEPS.with(|steps| steps.set(0));
    let mut actual = target.clone();
    merge_chat_messages(&mut actual, incoming);
    assert_eq!(actual, target);
    let steps = MERGE_INDEX_STEPS.with(|steps| steps.get());
    // Count index probes, alias row updates, duplicate candidates, and final
    // compaction. This checks structural work without a timing-dependent test.
    assert!(
        steps <= 8 * (COUNT + 2 * COUNT),
        "{steps} row visits exceed the linear budget"
    );
}
