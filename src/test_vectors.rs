//! Conformance test vectors for protocol compliance verification.
//!
//! These test vectors verify that the client implementation correctly handles
//! encoding, decoding, and validation of protocol data structures.

#[cfg(test)]
mod hlc_vectors {
    use crate::hlc::Hlc;

    /// Test vector for HLC format: `<physical_hex_12>-<logical_hex_8>-<node_hex_8>`
    struct HlcVector {
        physical: u64,
        logical: u32,
        node_id: u32,
        encoded: &'static str,
    }

    const HLC_VECTORS: &[HlcVector] = &[
        HlcVector {
            physical: 0x000000000000,
            logical: 0x00000000,
            node_id: 0x00000000,
            encoded: "000000000000-00000000-00000000",
        },
        HlcVector {
            physical: 0x000000000001,
            logical: 0x00000001,
            node_id: 0x00000001,
            encoded: "000000000001-00000001-00000001",
        },
        HlcVector {
            physical: 0x0000018a2e3c,
            logical: 0x0000002a,
            node_id: 0xdeadbeef,
            encoded: "0000018a2e3c-0000002a-deadbeef",
        },
        HlcVector {
            physical: 0x0000018a2e3d,
            logical: 0x00000000,
            node_id: 0x12345678,
            encoded: "0000018a2e3d-00000000-12345678",
        },
        HlcVector {
            physical: 0xffffffffffff,
            logical: 0xffffffff,
            node_id: 0xffffffff,
            encoded: "ffffffffffff-ffffffff-ffffffff",
        },
        HlcVector {
            physical: 0x00000197a5e0,
            logical: 0x00000003,
            node_id: 0xaabbccdd,
            encoded: "00000197a5e0-00000003-aabbccdd",
        },
    ];

    #[test]
    fn test_hlc_encode() {
        for vector in HLC_VECTORS {
            let hlc = Hlc::from_parts(vector.physical, vector.logical, vector.node_id);
            assert_eq!(hlc.encode(), vector.encoded, "Failed for {:?}", vector.encoded);
        }
    }

    #[test]
    fn test_hlc_parse() {
        for vector in HLC_VECTORS {
            let hlc = Hlc::parse(vector.encoded).unwrap();
            assert_eq!(hlc.physical_ms, vector.physical);
            assert_eq!(hlc.logical, vector.logical);
            assert_eq!(hlc.node_id, vector.node_id);
        }
    }

    #[test]
    fn test_hlc_parse_invalid() {
        let invalid = vec![
            "",
            "abc",
            "000000000000-00000000",
            "000000000000-00000000-00000000-00000000",
            "zzzzzzzzzzzz-00000000-00000000",
            "000000000000-zzzzzzzz-00000000",
            "000000000000-00000000-zzzzzzzz",
            "000000000000_00000000_00000000",
        ];

        for input in invalid {
            assert!(Hlc::parse(input).is_err(), "Should fail for: {input}");
        }
    }

    #[test]
    fn test_hlc_comparison() {
        let hlc1 = Hlc::from_parts(1000, 0, 1);
        let hlc2 = Hlc::from_parts(2000, 0, 1);
        let hlc3 = Hlc::from_parts(1000, 1, 1);
        let hlc4 = Hlc::from_parts(1000, 0, 2);

        assert!(hlc1 < hlc2, "physical should dominate");
        assert!(hlc1 < hlc3, "logical should break physical tie");
        assert!(hlc1 < hlc4, "node_id should break logical tie");
    }

    #[test]
    fn test_hlc_tick_monotonicity() {
        let mut hlc = Hlc::from_parts(1000, 0, 1);

        // Tick should increase logical counter
        let ticked = hlc.tick();
        assert!(ticked > hlc);
        assert_eq!(ticked.physical_ms, hlc.physical_ms);
        assert_eq!(ticked.logical, hlc.logical + 1);
    }

    #[test]
    fn test_hlc_merge() {
        let mut hlc1 = Hlc::from_parts(1000, 0, 1);
        let hlc2 = Hlc::from_parts(2000, 0, 2);

        hlc1.merge(&hlc2);
        assert_eq!(hlc1.physical_ms, 2000);
        assert_eq!(hlc1.logical, 1); // max(0, 0) + 1
    }

    #[test]
    fn test_hlc_merge_same_physical() {
        let mut hlc1 = Hlc::from_parts(1000, 5, 1);
        let hlc2 = Hlc::from_parts(1000, 3, 2);

        hlc1.merge(&hlc2);
        assert_eq!(hlc1.physical_ms, 1000);
        assert_eq!(hlc1.logical, 6); // max(5, 3) + 1
    }

    #[test]
    fn test_hlc_roundtrip() {
        let vectors = vec![
            Hlc::from_parts(1234567890, 42, 0xdeadbeef),
            Hlc::from_parts(0, 0, 0),
            Hlc::from_parts(0xffffffffffff, 0xffffffff, 0xffffffff),
        ];

        for hlc in vectors {
            let encoded = hlc.encode();
            let decoded = Hlc::parse(&encoded).unwrap();
            assert_eq!(hlc, decoded);
        }
    }
}

#[cfg(test)]
mod cursor_vectors {
    use crate::cursor::Cursor;

    /// Test vector for cursor encoding.
    struct CursorVector {
        version: u32,
        description: &'static str,
    }

    const CURSOR_VECTORS: &[CursorVector] = &[
        CursorVector {
            version: 1,
            description: "basic cursor with version 1",
        },
        CursorVector {
            version: 2,
            description: "cursor with version 2",
        },
    ];

    #[test]
    fn test_cursor_roundtrip() {
        let cursor = Cursor::new();
        let encoded = cursor.encode().unwrap();
        let decoded = Cursor::decode(&encoded).unwrap();
        assert_eq!(decoded.version, cursor.version);
    }

    #[test]
    fn test_cursor_base64url_encoding() {
        let cursor = Cursor::new();
        let encoded = cursor.encode().unwrap();
        // Base64URL should not contain +, /, or =
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
    }

    #[test]
    fn test_cursor_expiration() {
        let mut cursor = Cursor::new();
        assert!(!cursor.is_expired());

        cursor.expires_at = Some(chrono::Utc::now().timestamp() - 3600);
        assert!(cursor.is_expired());
    }

    #[test]
    fn test_cursor_space_hlc() {
        let cursor = Cursor::new();
        // Should return None for non-existent space
        assert!(cursor.space_hlc("nonexistent").is_none());
    }

    #[test]
    fn test_cursor_decode_invalid() {
        let invalid = vec!["", "not-base64!!!", "abc"];
        for input in invalid {
            assert!(Cursor::decode(input).is_err(), "Should fail for: {input}");
        }
    }
}

#[cfg(test)]
mod operation_vectors {
    use crate::operation::OperationEnvelope;
    use serde_json::json;

    #[test]
    fn test_operation_envelope_fields() {
        let envelope = json!({
            "operation_id": "op-001",
            "space_id": "cx:space:test",
            "actor": "did:web:alice",
            "type": "cx.message.create",
            "target_ref": "msg-001",
            "causal": {
                "deps": [],
                "hlc": "0000018a2e3c-0000002a-deadbeef",
                "actor_seq": 1
            },
            "body": {"text": "hello"},
            "authz_ref": "grant-001",
            "signature": "sig-001"
        });

        let parsed: OperationEnvelope = serde_json::from_value(envelope).unwrap();
        assert_eq!(parsed.operation_id, "op-001");
        assert_eq!(parsed.space_id, "cx:space:test");
        assert_eq!(parsed.actor, "did:web:alice");
        assert_eq!(parsed.op_type, "cx.message.create");
        assert_eq!(parsed.target_ref, "msg-001");
    }

    #[test]
    fn test_operation_causal_metadata() {
        let causal = json!({
            "deps": ["op-000"],
            "hlc": "0000018a2e3c-0000002a-deadbeef",
            "actor_seq": 5
        });

        let parsed: crate::operation::CausalMetadata = serde_json::from_value(causal).unwrap();
        assert_eq!(parsed.deps, vec!["op-000"]);
        assert_eq!(parsed.actor_seq, 5);
    }

    #[test]
    fn test_standard_operation_types() {
        let types = vec![
            "cx.space.create",
            "cx.space.update",
            "cx.entity.create",
            "cx.entity.update",
            "cx.entity.delete",
            "cx.entity.restore",
            "cx.relation.create",
            "cx.relation.delete",
            "cx.message.create",
            "cx.message.revise",
            "cx.message.redact",
            "cx.reaction.add",
            "cx.reaction.remove",
            "cx.channel.create",
            "cx.topic.create",
            "cx.comment.create",
            "cx.run.create",
            "cx.memory.create",
            "cx.invite.create",
            "cx.read_marker.update",
            "cx.capability.grant",
            "cx.capability.revoke",
        ];

        for op_type in types {
            assert!(
                op_type.starts_with("cx."),
                "Operation type must start with 'cx.'"
            );
            let parts: Vec<&str> = op_type.split('.').collect();
            assert!(
                parts.len() >= 3,
                "Operation type must have at least 3 parts: {op_type}"
            );
        }
    }
}

#[cfg(test)]
mod grant_vectors {
    use crate::capability::{CapabilityGrant, Constraint, EvalContext, ResourceSelector};

    #[test]
    fn test_grant_serialization() {
        let grant = serde_json::json!({
            "grant_id": "grant-001",
            "issuer": "did:web:alice",
            "subject": "did:web:bob",
            "resource_selectors": [{"Space": "cx:space:test"}],
            "actions": ["entity.read", "entity.update"],
            "constraints": [
                {
                    "type": "Temporal",
                    "params": {
                        "not_before": null,
                        "not_after": "2027-01-01T00:00:00Z"
                    }
                }
            ],
            "proofs": [],
            "issued_at": "0000018a2e3c-0000002a-deadbeef",
            "max_delegation_depth": 2,
            "parent_grant_id": null,
            "revocable": true
        });

        let parsed: CapabilityGrant = serde_json::from_value(grant).unwrap();
        assert_eq!(parsed.grant_id, "grant-001");
        assert_eq!(parsed.issuer, "did:web:alice");
        assert_eq!(parsed.subject, "did:web:bob");
        assert_eq!(parsed.actions, vec!["entity.read", "entity.update"]);
        assert_eq!(parsed.max_delegation_depth, 2);
    }

    #[test]
    fn test_constraint_temporal_vector() {
        let constraint = Constraint::Temporal {
            not_before: Some("2025-01-01T00:00:00Z".to_owned()),
            not_after: Some("2027-01-01T00:00:00Z".to_owned()),
        };

        let ctx_in_range = EvalContext {
            current_time: "2026-06-15T00:00:00Z".to_owned(),
            ..Default::default()
        };
        assert_eq!(constraint.evaluate(&ctx_in_range), crate::capability::ConstraintResult::Allow);

        let ctx_before = EvalContext {
            current_time: "2024-01-01T00:00:00Z".to_owned(),
            ..Default::default()
        };
        assert!(matches!(
            constraint.evaluate(&ctx_before),
            crate::capability::ConstraintResult::Deny(_)
        ));

        let ctx_after = EvalContext {
            current_time: "2028-01-01T00:00:00Z".to_owned(),
            ..Default::default()
        };
        assert!(matches!(
            constraint.evaluate(&ctx_after),
            crate::capability::ConstraintResult::Deny(_)
        ));
    }

    #[test]
    fn test_resource_selector_vectors() {
        let space_selector = ResourceSelector::Space("cx:space:test".to_owned());
        let wildcard = ResourceSelector::Wildcard;
        let any = ResourceSelector::Any(vec![
            ResourceSelector::Space("cx:space:a".to_owned()),
            ResourceSelector::Space("cx:space:b".to_owned()),
        ]);
        let except = ResourceSelector::Except(
            Box::new(ResourceSelector::Wildcard),
            vec![ResourceSelector::Space("cx:space:secret".to_owned())],
        );

        let test_resource = crate::capability::ResourceRef {
            space_id: Some("cx:space:a".to_owned()),
            ..Default::default()
        };

        assert!(space_selector.matches(&crate::capability::ResourceRef {
            space_id: Some("cx:space:test".to_owned()),
            ..Default::default()
        }));
        assert!(!space_selector.matches(&test_resource));
        assert!(wildcard.matches(&test_resource));
        assert!(any.matches(&test_resource));
        assert!(except.matches(&test_resource));
        assert!(!except.matches(&crate::capability::ResourceRef {
            space_id: Some("cx:space:secret".to_owned()),
            ..Default::default()
        }));
    }
}

#[cfg(test)]
mod entity_vectors {
    use crate::entity::{Entity, EntityType, Relation, RelationType, ViewProjection, ViewKind};

    #[test]
    fn test_entity_serialization() {
        let entity = serde_json::json!({
            "entity_id": "ent-001",
            "entity_type": "message",
            "space_id": "cx:space:test",
            "creator": "did:web:alice",
            "created_at": "0000018a2e3c-0000002a-deadbeef",
            "content": {"text": "hello"},
            "tags": ["important"],
            "metadata": {}
        });

        let parsed: Entity = serde_json::from_value(entity).unwrap();
        assert_eq!(parsed.entity_id, "ent-001");
        assert_eq!(parsed.entity_type, EntityType::Message);
    }

    #[test]
    fn test_entity_types() {
        let types = vec![
            ("message", EntityType::Message),
            ("topic", EntityType::Topic),
            ("channel", EntityType::Channel),
            ("document", EntityType::Document),
            ("file", EntityType::File),
            ("memory", EntityType::Memory),
            ("run", EntityType::Run),
            ("poll", EntityType::Poll),
            ("actor_profile", EntityType::ActorProfile),
        ];

        for (name, expected) in types {
            let entity = serde_json::json!({
                "entity_id": "ent-001",
                "entity_type": name,
                "space_id": "cx:space:test",
                "creator": "did:web:alice",
                "created_at": "0000018a2e3c-0000002a-deadbeef",
                "content": {},
                "tags": [],
                "metadata": {}
            });

            let parsed: Entity = serde_json::from_value(entity).unwrap();
            assert_eq!(parsed.entity_type, expected, "Failed for type: {name}");
        }
    }

    #[test]
    fn test_relation_serialization() {
        let relation = serde_json::json!({
            "relation_id": "rel-001",
            "relation_type": "replies_to",
            "source_id": "msg-002",
            "target_id": "msg-001",
            "created_at": "0000018a2e3c-0000002a-deadbeef",
            "metadata": {}
        });

        let parsed: Relation = serde_json::from_value(relation).unwrap();
        assert_eq!(parsed.relation_type, RelationType::RepliesTo);
        assert_eq!(parsed.source_id, "msg-002");
        assert_eq!(parsed.target_id, "msg-001");
    }

    #[test]
    fn test_relation_types() {
        let types = vec![
            ("contains", RelationType::Contains),
            ("depends_on", RelationType::DependsOn),
            ("replies_to", RelationType::RepliesTo),
            ("mentions", RelationType::Mentions),
            ("assigned_to", RelationType::AssignedTo),
            ("follows", RelationType::Follows),
            ("contact", RelationType::Contact),
            ("circle_member", RelationType::CircleMember),
            ("blocks_social", RelationType::BlocksSocial),
            ("reposts", RelationType::Reposts),
            ("likes", RelationType::Likes),
        ];

        for (name, expected) in types {
            let relation = serde_json::json!({
                "relation_id": "rel-001",
                "relation_type": name,
                "source_id": "src",
                "target_id": "tgt",
                "created_at": "0000018a2e3c-0000002a-deadbeef",
                "metadata": {}
            });

            let parsed: Relation = serde_json::from_value(relation).unwrap();
            assert_eq!(
                parsed.relation_type, expected,
                "Failed for type: {name}"
            );
        }
    }

    #[test]
    fn test_view_projection_serialization() {
        let view = serde_json::json!({
            "view_id": "view-001",
            "view_kind": "conversation",
            "space_id": "cx:space:test",
            "name": "Chat View",
            "filters": {},
            "visible_fields": ["message.text", "message.sender"],
            "created_at": "0000018a2e3c-0000002a-deadbeef"
        });

        let parsed: ViewProjection = serde_json::from_value(view).unwrap();
        assert_eq!(parsed.view_kind, ViewKind::Conversation);
        assert_eq!(parsed.name, "Chat View");
    }
}

#[cfg(test)]
mod conformance_vectors {
    use crate::conformance::{ConformanceProfile, PlaintextBoundary};

    #[test]
    fn test_conformance_profiles() {
        let profiles = vec![
            ("cx.profile.minimal_client.v1", ConformanceProfile::MinimalClient),
            ("cx.profile.full_client.v1", ConformanceProfile::FullClient),
            ("cx.profile.e2ee_client.v1", ConformanceProfile::E2eeClient),
            ("cx.profile.enterprise_client.v1", ConformanceProfile::EnterpriseClient),
        ];

        for (name, expected) in profiles {
            assert_eq!(expected.as_str(), name);
        }
    }

    #[test]
    fn test_plaintext_boundary() {
        let boundary = PlaintextBoundary {
            visible_services: vec!["did:web:server1".to_owned()],
            require_encryption: false,
        };

        assert!(boundary.can_send_plaintext("did:web:server1"));
        assert!(!boundary.can_send_plaintext("did:web:server2"));
    }

    #[test]
    fn test_plaintext_boundary_require_encryption() {
        let boundary = PlaintextBoundary {
            visible_services: vec!["did:web:server1".to_owned()],
            require_encryption: true,
        };

        assert!(!boundary.can_send_plaintext("did:web:server1"));
        assert!(!boundary.can_send_plaintext("did:web:server2"));
    }

    #[test]
    fn test_should_encrypt() {
        let boundary = PlaintextBoundary {
            visible_services: vec!["did:web:server1".to_owned()],
            require_encryption: false,
        };

        assert!(!boundary.should_encrypt("did:web:server1"));
        assert!(boundary.should_encrypt("did:web:server2"));
    }
}

#[cfg(test)]
mod conflict_vectors {
    use crate::conflict::{ConflictCandidate, ConflictResolver, LwwResolver, ORSet};
    use crate::hlc::Hlc;

    #[test]
    fn test_lww_single_candidate() {
        let resolver = LwwResolver::new();
        let candidates = vec![ConflictCandidate {
            value: serde_json::json!("only"),
            hlc: Hlc::from_parts(1000, 0, 1),
            actor: "alice".to_owned(),
            operation_id: "op-1".to_owned(),
        }];

        let result = resolver.resolve(candidates);
        assert!(!result.had_conflict);
        assert_eq!(result.winner, serde_json::json!("only"));
    }

    #[test]
    fn test_lww_higher_physical_wins() {
        let resolver = LwwResolver::new();
        let candidates = vec![
            ConflictCandidate {
                value: serde_json::json!("old"),
                hlc: Hlc::from_parts(1000, 0, 1),
                actor: "alice".to_owned(),
                operation_id: "op-1".to_owned(),
            },
            ConflictCandidate {
                value: serde_json::json!("new"),
                hlc: Hlc::from_parts(2000, 0, 2),
                actor: "bob".to_owned(),
                operation_id: "op-2".to_owned(),
            },
        ];

        let result = resolver.resolve(candidates);
        assert!(result.had_conflict);
        assert_eq!(result.winner, serde_json::json!("new"));
    }

    #[test]
    fn test_lww_higher_logical_wins_on_same_physical() {
        let resolver = LwwResolver::new();
        let candidates = vec![
            ConflictCandidate {
                value: serde_json::json!("first"),
                hlc: Hlc::from_parts(1000, 1, 1),
                actor: "alice".to_owned(),
                operation_id: "op-1".to_owned(),
            },
            ConflictCandidate {
                value: serde_json::json!("second"),
                hlc: Hlc::from_parts(1000, 2, 2),
                actor: "bob".to_owned(),
                operation_id: "op-2".to_owned(),
            },
        ];

        let result = resolver.resolve(candidates);
        assert!(result.had_conflict);
        assert_eq!(result.winner, serde_json::json!("second"));
    }

    #[test]
    fn test_or_set_add_remove_readd() {
        let mut set = ORSet::new();

        set.add("x", Hlc::from_parts(1000, 0, 1), "alice");
        assert!(set.contains("x"));

        set.remove("x", Hlc::from_parts(2000, 0, 2), "bob");
        assert!(!set.contains("x"));

        set.add("x", Hlc::from_parts(3000, 0, 3), "alice");
        assert!(set.contains("x"));
    }

    #[test]
    fn test_or_set_merge_disjoint() {
        let mut set1 = ORSet::new();
        let mut set2 = ORSet::new();

        set1.add("a", Hlc::from_parts(1000, 0, 1), "alice");
        set2.add("b", Hlc::from_parts(2000, 0, 2), "bob");

        set1.merge(&set2);

        assert!(set1.contains("a"));
        assert!(set1.contains("b"));
        assert_eq!(set1.elements().len(), 2);
    }

    #[test]
    fn test_or_set_merge_overlapping() {
        let mut set1 = ORSet::new();
        let mut set2 = ORSet::new();

        set1.add("x", Hlc::from_parts(1000, 0, 1), "alice");
        set2.add("x", Hlc::from_parts(1000, 0, 1), "alice");

        set1.merge(&set2);

        assert!(set1.contains("x"));
        assert_eq!(set1.elements().len(), 1);
    }

    #[test]
    fn test_conflict_resolver_ordered() {
        let resolver = ConflictResolver::new();

        let items = vec![
            ("c".to_owned(), Hlc::from_parts(3000, 0, 1), "alice".to_owned()),
            ("a".to_owned(), Hlc::from_parts(1000, 0, 2), "bob".to_owned()),
            ("b".to_owned(), Hlc::from_parts(2000, 0, 3), "charlie".to_owned()),
        ];

        let ordered = resolver.resolve_ordered(&items);
        assert_eq!(ordered, vec!["a", "b", "c"]);
    }
}

#[cfg(test)]
mod snapshot_vectors {
    use crate::conflict::SnapshotManager;
    use crate::hlc::Hlc;

    #[test]
    fn test_snapshot_manifest_serialization() {
        let manifest = SnapshotManager::create_manifest(
            "cx:space:test",
            vec!["op-1".to_owned(), "op-2".to_owned()],
            100,
            "reducer-v1",
        );

        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: crate::conflict::SnapshotManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.space_id, "cx:space:test");
        assert_eq!(parsed.operation_count, 100);
        assert_eq!(parsed.reducer_version, "reducer-v1");
    }

    #[test]
    fn test_snapshot_frontier_coverage() {
        let mut manager = SnapshotManager::new();

        let manifest = SnapshotManager::create_manifest(
            "cx:space:test",
            vec![
                "op-1".to_owned(),
                "op-2".to_owned(),
                "op-3".to_owned(),
                "op-4".to_owned(),
                "op-5".to_owned(),
            ],
            50,
            "reducer-v2",
        );

        manager.store(manifest);

        // Subset of covered frontier
        assert!(manager.covers_frontier(
            "cx:space:test",
            &["op-1".to_owned(), "op-3".to_owned()]
        ));

        // Frontier with uncovered operation
        assert!(!manager.covers_frontier(
            "cx:space:test",
            &["op-1".to_owned(), "op-99".to_owned()]
        ));

        // Empty frontier
        assert!(manager.covers_frontier("cx:space:test", &[]));

        // Non-existent space
        assert!(!manager.covers_frontier("cx:space:other", &["op-1".to_owned()]));
    }

    #[test]
    fn test_snapshot_chunks() {
        let mut manager = SnapshotManager::new();
        manager.store(SnapshotManager::create_manifest(
            "cx:space:test",
            vec![],
            0,
            "reducer-v1",
        ));

        manager.add_chunk("cx:space:test", "sha256:abc123", 1024);
        manager.add_chunk("cx:space:test", "sha256:def456", 2048);

        let snapshot = manager.get("cx:space:test").unwrap();
        assert_eq!(snapshot.chunks.len(), 2);
        assert_eq!(snapshot.size_bytes, 3072);
        assert_eq!(snapshot.chunks[0].index, 0);
        assert_eq!(snapshot.chunks[1].index, 1);
    }
}

#[cfg(test)]
mod discovery_vectors {
    use crate::discovery::Discoverability;

    #[test]
    fn test_discoverability_from_str() {
        let vectors = vec![
            ("public", Discoverability::Public),
            ("listed", Discoverability::Listed),
            ("restricted", Discoverability::Restricted),
            ("unlisted", Discoverability::Unlisted),
            ("invite_only", Discoverability::InviteOnly),
            ("secret", Discoverability::Secret),
        ];

        for (input, expected) in vectors {
            assert_eq!(Discoverability::from_str(input), expected);
        }
    }

    #[test]
    fn test_discoverability_unknown_defaults_to_unlisted() {
        assert_eq!(Discoverability::from_str("unknown"), Discoverability::Unlisted);
    }

    #[test]
    fn test_discoverability_access_matrix() {
        // (level, is_member, has_invite, expected_access)
        let vectors = vec![
            (Discoverability::Public, false, false, true),
            (Discoverability::Public, true, true, true),
            (Discoverability::Listed, false, false, true),
            (Discoverability::Listed, true, true, true),
            (Discoverability::Restricted, false, false, false),
            (Discoverability::Restricted, true, false, true),
            (Discoverability::Unlisted, false, false, false),
            (Discoverability::Unlisted, true, true, false),
            (Discoverability::InviteOnly, false, false, false),
            (Discoverability::InviteOnly, false, true, true),
            (Discoverability::Secret, true, true, false),
        ];

        for (level, is_member, has_invite, expected) in vectors {
            assert_eq!(
                level.allows_discovery(is_member, has_invite),
                expected,
                "Failed for {:?} (member={}, invite={})",
                level.as_str(),
                is_member,
                has_invite
            );
        }
    }
}
