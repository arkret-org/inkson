// Shared signed originals and current cuts for SQLite and IndexedDB searches.
use arkret_models_collaboration::governance::circle::{Circle, CircleState};
use arkret_sdk::*;
use arkret_test_kit::signed_event::SignedEventFixtureBuilder;
use chrono::{TimeZone, Utc};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

pub fn at(seconds: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_000 + seconds, 0).unwrap()
}

fn signature(value: &Value, context: DetachedSignatureContext) -> DetachedObjectSignature {
    arkret_signatures::detached_object::sign_detached_object(
        value,
        context,
        DidUrl::new("did:web:station.example#realm-authority").unwrap(),
        at(50),
        &SigningKey::from_bytes(&[0x71; 32]),
    )
    .unwrap()
}

pub fn seal(snapshot: &mut RealmStateSnapshot) {
    let mut identity = serde_json::to_value(&*snapshot).unwrap();
    identity.as_object_mut().unwrap().remove("signature");
    identity.as_object_mut().unwrap().remove("snapshot_id");
    snapshot.snapshot_id = RealmSnapshotId::from_digest(canonical::sha256_bytes(
        canonical::canonical_json_bytes(&identity).unwrap(),
    ));
    let unsigned = canonical::canonical::unsigned_value(&*snapshot, &["signature"]).unwrap();
    snapshot.signature = signature(&unsigned, DetachedSignatureContext::RealmSnapshot);
    arkret_signatures::detached_object::verify_detached_object_signature(
        &snapshot.signature,
        &unsigned,
        DetachedSignatureContext::RealmSnapshot,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: SigningKey::from_bytes(&[0x71; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        },
    )
    .unwrap();
}

fn accepted(event: Event, previous: Option<&CommittedEventFullView>) -> CommittedEventFullView {
    let mut commit = RealmCommit {
        commit_id: RealmCommitId::from_digest([0; 32]),
        realm_id: event.realm_id.clone(),
        stream_ref: CommitStreamRef::from_scope(&event.scope_ref, None).unwrap(),
        stream_position: previous.map_or(0, |full| full.commit.stream_position + 1),
        previous_commit_ref: previous.map(|full| full.commit.commit_id.clone()),
        event_ref: event.event_id.clone(),
        governance_generation: 0,
        authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone()),
        committed_at: at(50),
        producer_signer_fact_digest: None,
        signature: signature(&json!({}), DetachedSignatureContext::RealmCommit),
    };
    let identity =
        canonical::canonical::unsigned_value(&commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = RealmCommitId::from_digest(canonical::sha256_bytes(
        canonical::canonical_json_bytes(&identity).unwrap(),
    ));
    let unsigned = canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
    commit.signature = signature(&unsigned, DetachedSignatureContext::RealmCommit);
    let full = CommittedEventFullView { commit, event };
    full.validate_shape().unwrap();
    full.event
        .verify_producer_proof_self_consistency(DigestSuite::Sha256)
        .unwrap();
    full
}

fn row(full: &CommittedEventFullView, selector: CurrentSelector, value: Value) -> TypedCurrentRow {
    TypedCurrentRow::Value {
        selector,
        source_stream_ref: full.commit.stream_ref.clone(),
        revision: CurrentRevision {
            commit_id: full.commit.commit_id.clone(),
            stream_position: full.commit.stream_position,
        },
        value,
    }
}

pub struct Fixture {
    pub snapshot: RealmStateSnapshot,
    pub originals: Vec<CommittedEventFullView>,
    pub actor: ActorId,
    pub message: CommittedEventFullView,
}

pub fn account_scope_removal_frame(realm: &RealmId) -> String {
    // The account list counter deliberately exceeds every Realm/Circle position.
    json!({"kind":"delta", "cursor":"ak:cursor:YQ", "realm_list_changes":{
        "upserts":[], "removals":[{"realm_id":realm, "revision":100_000}]
    }})
    .to_string()
}

pub fn account_scope_rejoin_frame(realm: &RealmId) -> String {
    json!({"kind":"delta", "cursor":"ak:cursor:Yg", "realm_list_changes":{
        "upserts":[{"realm_id":realm,"revision":100_001,"activity_position":1,"membership":"join"}],
        "removals":[]
    }})
    .to_string()
}

pub struct DisclosureStep {
    pub frame: String,
    pub snapshot: String,
    pub expected: Vec<CommittedEventFullView>,
}

pub struct PolicyCheck {
    pub now: chrono::DateTime<Utc>,
    pub visible: bool,
    pub recheck_at: Option<chrono::DateTime<Utc>>,
}

pub fn policy_cases() -> Vec<(&'static str, Fixture, Vec<PolicyCheck>)> {
    let mut cases = Vec::new();
    for scenario in [
        "allow",
        "deny",
        "unknown",
        "other_action",
        "other_strand",
        "equal_priority",
        "quarantine",
        "review",
        "window",
        "history_floor",
    ] {
        let mut fixture = Fixture::new();
        let mut value = json!({
            "id":"ak:policy:0198ff00-0000-7000-8000-000000000001",
            "schema":"ak.schema.policy.v1", "realm_id":fixture.snapshot.realm_id,
            "policy_kind":"retention", "default_effect":"allow",
            "created_by":fixture.actor, "created_at":canonical::format_timestamp_canonical(at(6)),
            "rules":[{"rule_id":"read","kind":"action","effect":"deny","actions":["ak.strand.read"]}]
        });
        match scenario {
            "allow" | "history_floor" => {
                value["default_effect"] = json!("deny");
                value["rules"][0]["effect"] = json!("allow");
            }
            "unknown" => value["rules"][0]["conditions"] = json!({"unavailable_fact":true}),
            "other_action" => value["rules"][0]["actions"] = json!(["ak.message.create"]),
            "other_strand" => {
                value["rules"][0]["resources"] = json!([{
                    "kind":"strand", "realm_id":fixture.snapshot.realm_id,
                    "resource_ref":StrandId::from_event_id(&fixture.originals[0].event.event_id)
                }])
            }
            "equal_priority" => value["rules"].as_array_mut().unwrap().push(json!({
                "rule_id":"also_allow","kind":"action","effect":"allow","actions":["ak.strand.read"]
            })),
            "quarantine" => value["rules"][0]["effect"] = json!("quarantine"),
            "review" => value["rules"][0]["effect"] = json!("require_review"),
            "window" => {
                value["not_before"] = json!(canonical::format_timestamp_canonical(at(20)));
                value["expires_at"] = json!(canonical::format_timestamp_canonical(at(30)));
            }
            _ => {}
        }
        let policy: arkret_models_collaboration::governance::operation_wire::Policy =
            serde_json::from_value(value).unwrap();
        policy.validate().unwrap();
        fixture.install_policy(&policy);
        if scenario == "history_floor" {
            // A real later revision advances the Circle stream. A repeated
            // join would be an illegal same-state membership transition.
            fixture.revise_message();
            fixture
                .snapshot
                .retention_and_history_floor
                .stream_floors
                .iter_mut()
                .find(|floor| floor.stream_ref == fixture.message.commit.stream_ref)
                .unwrap()
                .oldest_position = fixture.message.commit.stream_position + 1;
            seal(&mut fixture.snapshot);
        }
        let checks = if scenario == "window" {
            [
                (19, true, Some(20)),
                (20, false, Some(30)),
                (29, false, Some(30)),
                (30, true, None),
            ]
            .into_iter()
            .map(|(now, visible, next)| PolicyCheck {
                now: at(now),
                visible,
                recheck_at: next.map(at),
            })
            .collect()
        } else {
            vec![PolicyCheck {
                now: at(20),
                visible: matches!(scenario, "allow" | "other_action" | "other_strand"),
                recheck_at: None,
            }]
        };
        cases.push((scenario, fixture, checks));
    }
    cases
}

/// Event cropping is independent of the Message terminal state. The client
/// omits an unavailable complete signed source rather than editing its bytes.
pub fn event_redaction_cases() -> Vec<(&'static str, Vec<DisclosureStep>)> {
    let mut cases = Vec::new();
    for scenario in [
        "create",
        "create_empty_preserve",
        "create_metadata_preserve",
        "redaction_first",
        "revised_create",
        "revision",
        "other_event",
    ] {
        let mut fixture = Fixture::new();
        if matches!(scenario, "revised_create" | "revision") {
            fixture.revise_message();
        }
        let originals = fixture
            .originals
            .iter()
            .filter(|full| {
                matches!(
                    full.event.kind,
                    EventKind::MessageCreate | EventKind::MessageRevise
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        let target = match scenario {
            "revision" => originals.last().unwrap().event.event_id.clone(),
            "other_event" => EventId::from_digest(DigestSuite::Sha256, [111; 32]),
            _ => fixture.message.event.event_id.clone(),
        };
        let preserve = match scenario {
            "create_empty_preserve" => Some(vec![]),
            "create_metadata_preserve" => {
                Some(vec!["kind".into(), "actor_id".into(), "created_at".into()])
            }
            _ => None,
        };
        let mut steps = vec![DisclosureStep {
            frame: fixture.frame(scenario != "redaction_first"),
            snapshot: serde_json::to_string(&fixture.snapshot).unwrap(),
            expected: if scenario == "redaction_first" {
                vec![]
            } else {
                originals.clone()
            },
        }];
        fixture.redact_event_current(&target, preserve);
        let expected = if scenario == "other_event" {
            originals
        } else {
            vec![]
        };
        for full in [false, true, true] {
            steps.push(DisclosureStep {
                frame: fixture.frame(full),
                snapshot: serde_json::to_string(&fixture.snapshot).unwrap(),
                expected: expected.clone(),
            });
        }
        // Even a stale cut omitting the assertion cannot reopen an already
        // observed terminal crop when its old Full source is replayed.
        fixture.snapshot.current_state_entries.retain(|row| {
            !matches!(
                row,
                TypedCurrentRow::Value {
                    selector: CurrentSelector::ObjectRedaction { .. },
                    ..
                }
            )
        });
        seal(&mut fixture.snapshot);
        steps.push(DisclosureStep {
            frame: fixture.frame(true),
            snapshot: serde_json::to_string(&fixture.snapshot).unwrap(),
            expected,
        });
        cases.push((scenario, steps));
    }
    cases
}

/// Identical signed inputs and observations for SQLite and IndexedDB.
pub fn disclosure_cases() -> Vec<(&'static str, Vec<DisclosureStep>)> {
    let mut cases = Vec::new();
    for scenario in ["create", "withheld_first", "revised_create", "revision"] {
        let mut fixture = Fixture::new();
        if matches!(scenario, "revised_create" | "revision") {
            fixture.revise_message();
        }
        let expected = fixture
            .originals
            .iter()
            .filter(|full| {
                matches!(
                    full.event.kind,
                    EventKind::MessageCreate | EventKind::MessageRevise
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        let target = if scenario == "revision" {
            expected.last().unwrap().clone()
        } else {
            fixture.message.clone()
        };
        let full = CommittedEventView::Full(target.clone());
        let withheld: CommittedEventView = serde_json::from_value(json!({
            "commit":target.commit,"event_disclosure":{"status":"withheld"}
        }))
        .unwrap();
        let unrelated = fixture
            .originals
            .iter()
            .filter(|row| row.event.event_id != target.event.event_id)
            .cloned()
            .map(CommittedEventView::Full)
            .collect::<Vec<_>>();
        let mut steps = Vec::new();
        let mut push = |views: Vec<CommittedEventView>, visible: bool| {
            let mut frame: Value = serde_json::from_str(&fixture.frame(false)).unwrap();
            frame["realms"][fixture.snapshot.realm_id.as_str()]["committed_events"] = json!(views);
            steps.push(DisclosureStep {
                frame: frame.to_string(),
                snapshot: serde_json::to_string(&fixture.snapshot).unwrap(),
                expected: if visible { expected.clone() } else { vec![] },
            });
        };
        if scenario == "withheld_first" {
            let mut first = unrelated.clone();
            first.push(withheld.clone());
            push(first, false);
        } else {
            push(
                fixture
                    .originals
                    .iter()
                    .cloned()
                    .map(CommittedEventView::Full)
                    .collect(),
                true,
            );
        }
        push(vec![withheld.clone()], false);
        push(vec![], false);
        push(unrelated, false);
        push(vec![full.clone()], true);
        push(vec![full.clone()], true);
        push(vec![full.clone(), withheld.clone()], false);
        push(vec![full.clone()], true);
        push(vec![withheld.clone(), full.clone()], false);
        push(vec![full.clone()], true);
        push(vec![withheld], false);
        drop(push);

        // A legitimate Full backfill cannot reopen a tightened history floor.
        fixture
            .snapshot
            .retention_and_history_floor
            .stream_floors
            .iter_mut()
            .find(|floor| floor.stream_ref == target.commit.stream_ref)
            .unwrap()
            .oldest_position = fixture.originals.last().unwrap().commit.stream_position + 1;
        seal(&mut fixture.snapshot);
        let mut frame: Value = serde_json::from_str(&fixture.frame(true)).unwrap();
        steps.push(DisclosureStep {
            frame: frame.to_string(),
            snapshot: serde_json::to_string(&fixture.snapshot).unwrap(),
            expected: vec![],
        });
        // Even a later disclosure under a readable floor cannot undo redaction.
        fixture
            .snapshot
            .retention_and_history_floor
            .stream_floors
            .iter_mut()
            .find(|floor| floor.stream_ref == target.commit.stream_ref)
            .unwrap()
            .oldest_position = 0;
        let message = MessageId::from_event_id(&fixture.message.event.event_id);
        fixture.redact_message_current(message.as_str());
        frame = serde_json::from_str(&fixture.frame(true)).unwrap();
        steps.push(DisclosureStep {
            frame: frame.to_string(),
            snapshot: serde_json::to_string(&fixture.snapshot).unwrap(),
            expected: vec![],
        });
        cases.push((scenario, steps));
    }
    cases
}

impl Fixture {
    pub fn install_policy(
        &mut self,
        policy: &arkret_models_collaboration::governance::operation_wire::Policy,
    ) {
        let signer = arkret_test_kit::keys::seeded_signer(
            "did:web:alice.example".parse().unwrap(),
            DidUrl::new("did:web:alice.example#ak:device:0196419b-0000-7000-8000-000000000001")
                .unwrap(),
        );
        let event = SignedEventFixtureBuilder::new(
            "ak.policy.set",
            ScopeRef::Realm {
                realm_id: self.snapshot.realm_id.clone(),
            },
            self.actor.clone(),
            json!({"policy_id":policy.id,"value":policy}),
        )
        .with_created_at(at(6))
        .sign_verifiable(&signer)
        .unwrap()
        .expect_verifiable();
        let previous = self
            .originals
            .iter()
            .rev()
            .find(|full| matches!(full.commit.stream_ref, CommitStreamRef::Realm { .. }))
            .unwrap();
        let full = accepted(event, Some(previous));
        let head = self
            .snapshot
            .visible_stream_heads
            .iter_mut()
            .find(|head| head.stream_ref == full.commit.stream_ref)
            .unwrap();
        head.stream_position = full.commit.stream_position;
        head.commit_id = full.commit.commit_id.clone();
        self.snapshot.current_state_entries.push(row(
            &full,
            CurrentSelector::Policy {
                policy_id: policy.id.clone(),
            },
            json!(policy),
        ));
        self.originals.push(full);
        seal(&mut self.snapshot);
    }

    pub fn redact_event_current(&mut self, target: &EventId, preserve: Option<Vec<String>>) {
        let signer = arkret_test_kit::keys::seeded_signer(
            "did:web:alice.example".parse().unwrap(),
            DidUrl::new("did:web:alice.example#ak:device:0196419b-0000-7000-8000-000000000001")
                .unwrap(),
        );
        let mut payload = json!({"target_ref": target});
        if let Some(preserve) = preserve {
            payload["preserve"] = json!(preserve);
        }
        let event = SignedEventFixtureBuilder::new(
            "ak.redaction",
            self.message.event.scope_ref.clone(),
            self.actor.clone(),
            payload.clone(),
        )
        .with_created_at(at(7))
        .sign_verifiable(&signer)
        .unwrap()
        .expect_verifiable();
        let full = accepted(event, self.originals.last());
        let head = self
            .snapshot
            .visible_stream_heads
            .iter_mut()
            .find(|head| head.stream_ref == full.commit.stream_ref)
            .unwrap();
        head.stream_position = full.commit.stream_position;
        head.commit_id = full.commit.commit_id.clone();
        self.snapshot.current_state_entries.push(row(
            &full,
            CurrentSelector::ObjectRedaction {
                target_ref: target.to_string(),
            },
            json!({"assertions":[{"tag_id":format!("{}:0",full.event.event_id),"value":payload}]}),
        ));
        seal(&mut self.snapshot);
    }

    pub fn change_revision(&mut self, scenario: &str) {
        let message_id = MessageId::from_event_id(&self.message.event.event_id);
        let position = self
            .snapshot
            .current_state_entries
            .iter()
            .position(|current| {
                matches!(current, TypedCurrentRow::Value {
                selector: CurrentSelector::MessageRevision { message_id: key }, ..
            } if key == &message_id)
            })
            .unwrap();
        if scenario == "missing" {
            self.snapshot.current_state_entries.remove(position);
        } else {
            let TypedCurrentRow::Value {
                selector,
                source_stream_ref,
                revision,
                value,
            } = &mut self.snapshot.current_state_entries[position];
            match scenario {
                "wrong_source" => {
                    *source_stream_ref = CommitStreamRef::Realm {
                        realm_id: self.message.event.realm_id.clone(),
                    }
                }
                "wrong_commit" => revision.commit_id = RealmCommitId::from_digest([91; 32]),
                "wrong_position" => revision.stream_position -= 1,
                "wrong_payload" => value["content"]["body"] = json!("different current body"),
                "wrong_target" => {
                    *selector = CurrentSelector::MessageRevision {
                        message_id: MessageId::from_event_id(&EventId::from_digest(
                            DigestSuite::Sha256,
                            [92; 32],
                        )),
                    }
                }
                "older_current" => {
                    self.snapshot.current_state_entries[position] = row(
                        &self.message,
                        CurrentSelector::MessageRevision { message_id },
                        json!(self.message.event.payload),
                    );
                }
                _ => panic!("unknown revision scenario"),
            }
        }
        seal(&mut self.snapshot);
    }

    pub fn revise_message(&mut self) {
        let signer = arkret_test_kit::keys::seeded_signer(
            "did:web:alice.example".parse().unwrap(),
            DidUrl::new("did:web:alice.example#ak:device:0196419b-0000-7000-8000-000000000001")
                .unwrap(),
        );
        let event = SignedEventFixtureBuilder::new("ak.message.revise", self.message.event.scope_ref.clone(), self.actor.clone(),
            json!({"message_id":MessageId::from_event_id(&self.message.event.event_id),"content":{"kind":"ak.content.text","format":"plain","body":"revised private circle needle"}}))
            .with_created_at(at(6)).sign_verifiable(&signer).unwrap().expect_verifiable();
        let full = accepted(event, Some(&self.message));
        let head = self
            .snapshot
            .visible_stream_heads
            .iter_mut()
            .find(|head| head.stream_ref == full.commit.stream_ref)
            .unwrap();
        head.stream_position = full.commit.stream_position;
        head.commit_id = full.commit.commit_id.clone();
        let selector = CurrentSelector::MessageRevision {
            message_id: MessageId::from_event_id(&self.message.event.event_id),
        };
        let current = self.snapshot.current_state_entries.iter_mut().find(|current| {
            matches!(current, TypedCurrentRow::Value { selector: key, .. } if key == &selector)
        }).unwrap();
        *current = row(&full, selector, json!(full.event.payload));
        self.originals.push(full);
        seal(&mut self.snapshot);
    }

    pub fn redact_message_current(&mut self, target: &str) {
        let payload = json!({"message_id":target});
        let signer = arkret_test_kit::keys::seeded_signer(
            "did:web:alice.example".parse().unwrap(),
            DidUrl::new("did:web:alice.example#ak:device:0196419b-0000-7000-8000-000000000001")
                .unwrap(),
        );
        let event = SignedEventFixtureBuilder::new(
            "ak.message.redact",
            self.message.event.scope_ref.clone(),
            self.actor.clone(),
            payload.clone(),
        )
        .with_created_at(at(7))
        .sign_verifiable(&signer)
        .unwrap()
        .expect_verifiable();
        let full = accepted(event, self.originals.last());
        let head = self
            .snapshot
            .visible_stream_heads
            .iter_mut()
            .find(|head| head.stream_ref == full.commit.stream_ref)
            .unwrap();
        head.stream_position = full.commit.stream_position;
        head.commit_id = full.commit.commit_id.clone();
        self.snapshot.current_state_entries.push(row(
            &full,
            CurrentSelector::ObjectRedaction {
                target_ref: target.to_owned(),
            },
            json!({"assertions":[{"tag_id":format!("{}:0",full.event.event_id),"value":payload}]}),
        ));
        self.snapshot.created_at = at(12);
        seal(&mut self.snapshot);
    }

    pub fn new() -> Self {
        let realm: RealmId = "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI"
            .parse()
            .unwrap();
        let actor = ActorId::account(AccountId::new(
            "ak:did_core:web:alice.example".parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        ));
        let signer = arkret_test_kit::keys::seeded_signer(
            "did:web:alice.example".parse().unwrap(),
            DidUrl::new("did:web:alice.example#ak:device:0196419b-0000-7000-8000-000000000001")
                .unwrap(),
        );
        let event = |kind: &str, scope: ScopeRef, payload: Value, seconds| {
            let event = SignedEventFixtureBuilder::new(kind, scope, actor.clone(), payload)
                .with_created_at(at(seconds))
                .sign_verifiable(&signer)
                .unwrap()
                .expect_verifiable();
            arkret_signatures::proof::verify_ed25519_detached_jws_proof(
                event.producer_proof.as_ref().unwrap(),
                &canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap(),
                &actor,
                &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                    bytes: signer.verifying_key().to_bytes().to_vec(),
                },
            )
            .unwrap();
            event
        };
        let realm_scope = ScopeRef::Realm {
            realm_id: realm.clone(),
        };
        let parent = accepted(
            event(
                "ak.member.state",
                realm_scope.clone(),
                json!({"member_id":actor,"membership":"join"}),
                1,
            ),
            None,
        );
        let mut circle = Circle::create_object(
            realm.clone(),
            "Private discussion",
            serde_json::from_value(
                json!({"short_name":"Private","color_token":"slate","symbol":{"glyph":"lock"}}),
            )
            .unwrap(),
            actor.clone(),
        );
        circle.created_at = at(2);
        let create = accepted(
            event("ak.circle.create", realm_scope, json!({"object":circle}), 2),
            Some(&parent),
        );
        let circle_id = CircleId::from_event_id(&create.event.event_id);
        circle.id = Some(circle_id.clone());
        let scope = ScopeRef::Circle {
            realm_id: realm.clone(),
            circle_id: circle_id.clone(),
        };
        let parent_revision = CurrentRevision {
            commit_id: parent.commit.commit_id.clone(),
            stream_position: parent.commit.stream_position,
        };
        let join = accepted(
            event(
                "ak.circle.member.state",
                scope.clone(),
                json!({"circle_id":circle_id,"member_id":actor,"membership":"join","parent_membership_revision":parent_revision}),
                3,
            ),
            None,
        );
        let mut strand = Strand::new_create(realm.clone(), "Discussion", actor.clone());
        strand.created_at = at(4);
        strand.state = Some(ObjectState::Active);
        strand.scope_circle_id = Some(circle_id.clone());
        strand.tracks = serde_json::from_value(json!({"discussion":{}})).unwrap();
        let strand_create = accepted(
            event(
                "ak.strand.create",
                scope.clone(),
                json!({"object":strand}),
                4,
            ),
            Some(&join),
        );
        let strand_id = StrandId::from_event_id(&strand_create.event.event_id);
        strand.id = Some(strand_id.clone());
        let message = accepted(
            event(
                "ak.message.create",
                scope,
                json!({"strand_id":strand_id,"track_name":"discussion","content":{"kind":"ak.content.text","format":"plain","body":"private circle search needle"}}),
                5,
            ),
            Some(&strand_create),
        );
        let mut snapshot = RealmStateSnapshot {
            purpose: arkret_wire::RealmSnapshotPurpose::FullRecovery,
            history_basis: None,
            snapshot_id: RealmSnapshotId::from_digest([0; 32]),
            realm_id: realm,
            governance_generation: 0,
            visible_stream_heads: [&create, &message]
                .map(|full| CommitStreamHead {
                    stream_ref: full.commit.stream_ref.clone(),
                    commit_id: full.commit.commit_id.clone(),
                    stream_position: full.commit.stream_position,
                })
                .into(),
            current_state_entries: vec![
                row(
                    &parent,
                    CurrentSelector::MemberState {
                        actor_id: actor.clone(),
                    },
                    json!({"membership":"join"}),
                ),
                row(
                    &create,
                    CurrentSelector::Circle {
                        circle_id: circle_id.clone(),
                    },
                    json!(circle),
                ),
                row(
                    &join,
                    CurrentSelector::CircleMemberState {
                        circle_id,
                        member_actor_id: actor.clone(),
                    },
                    json!({"membership":"join","parent_membership_revision":parent_revision,"effective_at":at(3).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)}),
                ),
                row(
                    &strand_create,
                    CurrentSelector::Strand { strand_id },
                    json!(strand),
                ),
                row(
                    &message,
                    CurrentSelector::MessageRevision {
                        message_id: MessageId::from_event_id(&message.event.event_id),
                    },
                    json!(message.event.payload),
                ),
            ],
            retention_and_history_floor: RetentionAndHistoryFloor {
                history_access: HistoryAccess::SinceJoin,
                stream_floors: [&create, &message]
                    .map(|full| StreamHistoryFloor {
                        stream_ref: full.commit.stream_ref.clone(),
                        oldest_position: 0,
                    })
                    .into(),
            },
            created_at: at(10),
            signature: signature(&json!({}), DetachedSignatureContext::RealmSnapshot),
        };
        seal(&mut snapshot);
        Self {
            snapshot,
            originals: vec![parent, create, join, strand_create, message.clone()],
            actor,
            message,
        }
    }

    pub fn frame(&self, include_originals: bool) -> String {
        let realm = self.snapshot.realm_id.to_string();
        json!({"kind":"delta","cursor":"ak:cursor:YQ","realms":{realm:{
            "current":{"realm_id":self.snapshot.realm_id,"governance_generation":0,"stream_heads":self.snapshot.visible_stream_heads,"entries":self.snapshot.current_state_entries},
            "committed_events":if include_originals { self.originals.clone() } else { vec![] }
        }}}).to_string()
    }

    pub fn change(&mut self, scenario: &str) {
        // A newer signed cut removes or replaces the Circle without deleting
        // the cached message, Strand or canonical Circle join.
        let head = &mut self.snapshot.visible_stream_heads[0];
        head.stream_position += 1;
        head.commit_id = RealmCommitId::from_digest([91; 32]);
        let TypedCurrentRow::Value {
            value, revision, ..
        } = &mut self.snapshot.current_state_entries[1];
        revision.stream_position = head.stream_position;
        revision.commit_id = head.commit_id.clone();
        match scenario {
            "archived" => value["state"] = json!(CircleState::Archived),
            "tombstoned" => value["state"] = json!(CircleState::Tombstoned),
            "wrong_id" => {
                value["id"] = json!(CircleId::from_event_id(&EventId::from_digest(
                    DigestSuite::Sha256,
                    [92; 32]
                )))
            }
            "wrong_realm" => {
                value["realm_id"] = json!("ak:realm:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD")
            }
            "wrong_schema" => value["schema"] = json!(SchemaId::STRAND_V1),
            "wrong_source" => {
                let TypedCurrentRow::Value {
                    source_stream_ref,
                    revision,
                    ..
                } = &mut self.snapshot.current_state_entries[1];
                *source_stream_ref = self.message.commit.stream_ref.clone();
                *revision = CurrentRevision {
                    commit_id: self.message.commit.commit_id.clone(),
                    stream_position: self.message.commit.stream_position,
                };
            }
            "missing" => {
                self.snapshot.current_state_entries.remove(1);
            }
            _ => panic!("unknown Circle search scenario"),
        }
        self.snapshot.created_at = at(11);
        seal(&mut self.snapshot);
    }
}

pub const SCENARIOS: [&str; 7] = [
    "archived",
    "tombstoned",
    "missing",
    "wrong_id",
    "wrong_realm",
    "wrong_schema",
    "wrong_source",
];

pub struct SearchAuthorizationCase {
    pub name: &'static str,
    pub fixture: Fixture,
    pub requester: ActorId,
    pub visible: bool,
    pub malformed_current: bool,
}

impl SearchAuthorizationCase {
    pub fn assert_search_result<T: PartialEq + std::fmt::Debug>(
        &self,
        result: std::result::Result<T, String>,
        expected: T,
        phase: &str,
    ) {
        let expected_error = match self.name {
            "wrong_strand_id" | "wrong_strand_realm" => {
                Some("Strand current differs from its selected subject")
            }
            "wrong_strand_scope" => {
                Some("Strand current source stream differs from its security scope")
            }
            _ => None,
        };
        match expected_error {
            Some(error) => assert_eq!(result, Err(error.to_owned()), "{phase} {}", self.name),
            None => assert_eq!(result, Ok(expected), "{phase} {}", self.name),
        }
    }

    pub fn cached_originals_frame(&self) -> String {
        let mut frame: Value = serde_json::from_str(&self.fixture.frame(true)).unwrap();
        frame["realms"][self.fixture.snapshot.realm_id.as_str()]
            .as_object_mut()
            .unwrap()
            .remove("current");
        frame.to_string()
    }
}

pub fn authorization_cases() -> Vec<SearchAuthorizationCase> {
    [
        "matched",
        "wrong_principal",
        "wrong_station",
        "missing_strand",
        "wrong_strand_id",
        "wrong_strand_scope",
        "wrong_strand_realm",
    ]
    .into_iter()
    .map(|name| {
        let mut fixture = Fixture::new();
        let mut requester = fixture.actor.clone();
        let malformed_current = name == "missing_strand" || name.starts_with("wrong_strand_");
        match name {
            "wrong_principal" => {
                requester = ActorId::account(AccountId::new(
                    "ak:did_core:web:bob.example".parse().unwrap(),
                    fixture.actor.as_account_id().unwrap().station_id.clone(),
                ));
            }
            "wrong_station" => {
                requester = ActorId::account(AccountId::new(
                    fixture.actor.signing_principal_id().clone(),
                    "ak:did_core:web:other-station.example".parse().unwrap(),
                ));
            }
            _ if malformed_current => {
                let position = fixture
                    .snapshot
                    .current_state_entries
                    .iter()
                    .position(|entry| {
                        matches!(
                            entry,
                            TypedCurrentRow::Value {
                                selector: CurrentSelector::Strand { .. },
                                ..
                            }
                        )
                    })
                    .unwrap();
                if name == "missing_strand" {
                    fixture.snapshot.current_state_entries.remove(position);
                } else {
                    let TypedCurrentRow::Value { value, .. } =
                        &mut fixture.snapshot.current_state_entries[position];
                    match name {
                        "wrong_strand_id" => {
                            value["id"] = json!(StrandId::from_event_id(&EventId::from_digest(
                                DigestSuite::Sha256,
                                [93; 32]
                            )))
                        }
                        "wrong_strand_scope" => {
                            value["scope_circle_id"] = json!(CircleId::from_event_id(
                                &EventId::from_digest(DigestSuite::Sha256, [94; 32])
                            ))
                        }
                        "wrong_strand_realm" => {
                            value["realm_id"] =
                                json!("ak:realm:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD")
                        }
                        _ => unreachable!(),
                    }
                }
                // Preserve valid original signatures while signing the exact
                // misbound current cut that the reader must refuse.
                seal(&mut fixture.snapshot);
            }
            "matched" => {}
            _ => unreachable!(),
        }
        SearchAuthorizationCase {
            name,
            fixture,
            requester,
            visible: name == "matched",
            malformed_current,
        }
    })
    .collect()
}
