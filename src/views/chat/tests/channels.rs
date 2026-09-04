//! Discussion channels derived from Strand events and projections.

use super::*;

#[test]
fn channel_from_strand_event_requires_real_discussion_track() {
    let event = json!({
        "event_id": "ak:event:ACN6-zee0KV01VOfolkRd2zFaZq0QslDtjPt55WGqTpk",
        "kind": "ak.strand.create",
        "realm_id": "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        "strand_id": "ak:strand:Ac19GaGmchhLqPeXsofsVdQCPnHo5URGMEFiQj6tRLz0",
        "title": "Ops discussion",
        "category": "support",
        "summary": "Operations support",
        "strand": {
            "id": "ak:strand:Ac19GaGmchhLqPeXsofsVdQCPnHo5URGMEFiQj6tRLz0",
            "title": "Ops discussion",
            "tracks": {
                "discussion": {"profile": "discussion"}
            }
        }
    });

    let channel = channel_from_strand_event(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        &event,
    )
    .unwrap();

    assert_eq!(
        channel.strand_id,
        "ak:strand:Ac19GaGmchhLqPeXsofsVdQCPnHo5URGMEFiQj6tRLz0"
    );
    assert_eq!(channel.name, "Ops discussion");
    assert_eq!(channel.category, "support");
    assert_eq!(channel.kind, "discussion");
    assert_eq!(channel.topic.as_deref(), Some("Operations support"));
    assert!(!channel.is_default);
    assert!(!channel.is_private_sidecar);
}

#[test]
fn sidecar_strand_title_reads_canonical_metadata_object() {
    let strand_id = "ak:strand:ASy992JMe_xzh5pluAqo5YuyCnAfDdFni4lmeHQldlUM";
    let projection = json!({
        "strand_id": strand_id,
        "metadata": {
            "title": "AI sidecar",
            "summary": "Controller-private AI context"
        },
        "tracks": { "discussion": { "enabled": true } }
    });
    let projected =
        channel_from_strand_projection(&projection, false).expect("discussion projection");
    assert_eq!(projected.name, "AI sidecar");
    assert_ne!(projected.name, strand_id);

    let event = json!({
        "kind": "ak.strand.create",
        "payload": {
            "object": {
                "id": strand_id,
                "metadata": { "title": "AI sidecar" },
                "tracks": { "discussion": { "enabled": true } }
            }
        }
    });
    let projected = channel_from_strand_event(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        &event,
    )
    .expect("discussion event");
    assert_eq!(projected.name, "AI sidecar");
}

#[test]
fn channel_from_strand_event_never_infers_private_sidecar_identity() {
    let event = json!({
        "event_id": "ak:event:AWKTKW6JVP47hz_MHIT7bR8pFouEmtlyLzIyaqjy3Bjw",
        "kind": "ak.strand.create",
        "realm_id": "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        "object": {
            "id": "ak:strand:AkUVEiKlUkt3ZQkgRtsNooAKfHAnagj6Vjh_Xb-Nj5Bo",
            "metadata": {
                "title": "AI sidecar",
                "fields": { "client_private_hint": true }
            },
            "tracks": {
                "discussion": {"enabled": true, "is_primary": true}
            }
        }
    });

    let channel = channel_from_strand_event(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        &event,
    )
    .unwrap();

    assert_eq!(
        channel.strand_id,
        "ak:strand:AkUVEiKlUkt3ZQkgRtsNooAKfHAnagj6Vjh_Xb-Nj5Bo"
    );
    assert!(!channel.is_private_sidecar);
}

#[test]
fn channel_from_strand_event_ignores_non_discussion_strands() {
    let event = json!({
        "event_id": "ak:event:ACN6-zee0KV01VOfolkRd2zFaZq0QslDtjPt55WGqTpk",
        "kind": "ak.strand.create",
        "realm_id": "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        "strand_id": "ak:strand:AwoWa5E6h1_MkJ9iJso4SrkR-9rZJi2ynkhMyYA06pwg",
        "title": "Doc strand",
        "strand": {
            "id": "ak:strand:AwoWa5E6h1_MkJ9iJso4SrkR-9rZJi2ynkhMyYA06pwg",
            "title": "Doc strand",
            "tracks": {
                "document": {"profile": "document"}
            }
        }
    });

    assert!(
        channel_from_strand_event(
            "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
            &event
        )
        .is_none()
    );
}

#[test]
fn default_discussion_channel_uses_realm_default_strand_projection() {
    let body = json!({
        "summary": {
            "title": "Demo Realm",
            "strand": {
                "strand_id": "ak:strand:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL",
                "title": "General",
                "summary": "Realm-wide conversation",
                "tracks": {
                    "discussion": {"enabled": true},
                    "synthesis": {"enabled": true}
                }
            }
        }
    });

    let channel = default_discussion_channel(Some(&body))
        .expect("accepted projection exposes its default Strand");

    assert_eq!(
        channel.strand_id,
        "ak:strand:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL"
    );
    assert_eq!(channel.name, "General");
    assert_eq!(channel.kind, "discussion");
    assert_eq!(channel.topic.as_deref(), Some("Realm-wide conversation"));
    assert!(channel.is_default);
}

#[test]
fn default_discussion_channel_fails_closed_when_projection_is_absent() {
    assert!(default_discussion_channel(None).is_none());
}
