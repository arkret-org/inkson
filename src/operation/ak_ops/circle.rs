//! Circle administration builders.
//!
//! `ak.self.circle.command.create.v1` takes the caller-signed `ak.circle.create`
//! Event, so the Circle the user configures in the UI is authored here and the
//! resulting Circle id falls out of that Event. The server neither names the
//! Circle nor signs for the user.

use super::{TypedOperationBuilder, circle_id_value, realm_id_value, trim_realm_id};

/// Everything the create surface lets a user choose about a new Circle.
///
/// Reducer-owned fields are absent by construction: `mls_group_id` is derived
/// when the MLS group is bound, and the object id comes from the create Event.
#[derive(Clone, Debug)]
pub struct CircleCreateOptions<'a> {
    pub title: &'a str,
    pub summary: Option<&'a str>,
    pub display: arkret_sdk::CircleDisplay,
    pub directory_visibility: arkret_sdk::CircleDirectoryVisibility,
    pub join_rule: arkret_sdk::CircleJoinRule,
    pub history_access: arkret_sdk::HistoryAccess,
    pub encryption_profile: arkret_sdk::EncryptionProfile,
    pub content_scheme: Option<arkret_sdk::ContentScheme>,
    pub durability_policy: Option<arkret_sdk::DurabilityPolicy>,
}

/// Build a canonical `ak.circle.member.state` Control Move.
///
/// Everything the operation acts on is in the payload: the Circle, the target
/// actor and the membership value. Nothing asserts the caller's capability —
/// `circle_member_state_payload` is closed, and the `ak.circle.member.manage`
/// decision is made by admission against projected grants.
pub fn circle_member_state(
    realm_id: &str,
    actor: &str,
    circle_id: &str,
    target_actor: &arkret_sdk::ActorId,
    membership: arkret_sdk::CircleMembership,
) -> anyhow::Result<TypedOperationBuilder> {
    circle_member_state_with_expected(
        realm_id,
        actor,
        circle_id,
        target_actor,
        membership,
        arkret_wire::WirePresence::Missing,
    )
}

/// Build a Circle membership Move with an explicit tri-state CAS guard.
pub fn circle_member_state_with_expected(
    realm_id: &str,
    actor: &str,
    circle_id: &str,
    target_actor: &arkret_sdk::ActorId,
    membership: arkret_sdk::CircleMembership,
    expected_membership: arkret_wire::WirePresence<arkret_sdk::CircleMembership>,
) -> anyhow::Result<TypedOperationBuilder> {
    let payload = arkret_sdk::CircleMemberStatePayload {
        circle_id: circle_id_value(circle_id)?,
        member_id: target_actor.clone(),
        membership,
        reason: None,
        effective_at: None,
        expected_membership,
    };
    Ok(TypedOperationBuilder::new::<
        arkret_sdk::event_spec::CircleMemberState,
    >(realm_id, actor, payload))
}

#[cfg(test)]
mod member_actor_tests {
    use super::*;

    #[test]
    fn circle_membership_preserves_remote_actor_kind_and_station() {
        let principal = arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example").unwrap();
        let station = arkret_sdk::DidCoreId::new("ak:did_core:web:remote.example").unwrap();
        for target in [
            arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                principal.clone(),
                station.clone(),
            )),
            arkret_sdk::ActorId::hosted_principal(principal.clone(), station),
            arkret_sdk::ActorId::service(principal),
        ] {
            for membership in [
                arkret_sdk::CircleMembership::Invite,
                arkret_sdk::CircleMembership::Leave,
            ] {
                let builder = circle_member_state_with_expected(
                    "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                    "ak:did_core:web:alice.example",
                    "ak:circle:AcsXlJSItqSzy43Swu0nFz2ijj4Yaf0RgjmoTeivRt8M",
                    &target,
                    membership,
                    arkret_wire::WirePresence::Value(arkret_sdk::CircleMembership::Join),
                )
                .unwrap();
                assert_eq!(
                    builder.intent().unwrap().payload().get("member_id"),
                    Some(&serde_json::to_value(&target).unwrap())
                );
            }
        }
    }
}

/// Build one of the three canonical Circle lifecycle Control Moves.
///
/// `object_lifecycle_payload` single-sources the target by `target_ref`, so the
/// Circle is named once and the service checks it against the request path.
pub fn circle_lifecycle(
    realm_id: &str,
    actor: &str,
    circle_id: &str,
    kind: arkret_sdk::EventKind,
    reason: Option<&str>,
) -> anyhow::Result<TypedOperationBuilder> {
    let mut payload = arkret_sdk::ObjectLifecyclePayload::new(circle_id_value(circle_id)?.as_str());
    if let Some(reason) = reason.map(str::trim).filter(|reason| !reason.is_empty()) {
        payload = payload.with_reason(reason);
    }
    match kind {
        arkret_sdk::EventKind::CircleArchive => Ok(TypedOperationBuilder::new::<
            arkret_sdk::event_spec::CircleArchive,
        >(realm_id, actor, payload)),
        arkret_sdk::EventKind::CircleRestore => Ok(TypedOperationBuilder::new::<
            arkret_sdk::event_spec::CircleRestore,
        >(realm_id, actor, payload)),
        arkret_sdk::EventKind::CircleTombstone => Ok(TypedOperationBuilder::new::<
            arkret_sdk::event_spec::CircleTombstone,
        >(realm_id, actor, payload)),
        other => anyhow::bail!("unsupported Circle lifecycle kind {}", other.as_str()),
    }
}

/// Derive a Circle's `display` from its title.
///
/// `display.short_name` used to be derived server-side while the service built the
/// create payload. It is a presentation default with no reducer meaning, so it
/// belongs wherever the payload is authored — which is now the client.
pub fn circle_display_from_title(title: &str) -> arkret_sdk::CircleDisplay {
    let mut short_name: String = title
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, ' ' | '_' | '-'))
        .collect();
    short_name = short_name.trim().to_owned();
    if short_name.is_empty() {
        short_name = "Circle".to_owned();
    }
    if let Some(first) = short_name.as_bytes().first().copied() {
        if first.is_ascii_lowercase() {
            short_name.replace_range(0..1, &(first as char).to_ascii_uppercase().to_string());
        } else if !first.is_ascii_uppercase() {
            short_name.insert_str(0, "C ");
        }
    }
    if short_name.len() > 24 {
        short_name.truncate(24);
    }
    arkret_sdk::CircleDisplay {
        short_name: short_name.trim_end().to_owned(),
        color_token: arkret_sdk::CircleColorToken::Slate,
        symbol: arkret_sdk::CircleSymbol::Glyph {
            glyph: arkret_sdk::CircleGlyph::Ring,
        },
    }
}

/// Build the canonical `ak.circle.create` operation for the Circle admin surface.
pub fn circle_create(
    realm_id: &str,
    actor: &str,
    options: CircleCreateOptions<'_>,
) -> anyhow::Result<TypedOperationBuilder> {
    let mut circle = arkret_sdk::Circle::create_object(
        realm_id_value(&trim_realm_id(realm_id))?,
        options.title.trim(),
        options.display,
        crate::mls_api_helpers::local_account_actor_id(actor)?,
    );
    circle.summary = options
        .summary
        .map(str::trim)
        .filter(|summary| !summary.is_empty())
        .map(ToOwned::to_owned);
    circle.directory_visibility = options.directory_visibility;
    circle.join_rule = options.join_rule;
    circle.history_access = options.history_access;
    circle.encryption_profile = options.encryption_profile;
    match (&circle.encryption_profile, options.content_scheme) {
        (arkret_sdk::EncryptionProfile::None, None) => {
            anyhow::ensure!(
                options.durability_policy.is_none(),
                "plaintext Circle cannot declare durability_policy"
            );
        }
        (
            arkret_sdk::EncryptionProfile::MlsRfc9420,
            Some(arkret_sdk::ContentScheme::MlsRfc9420),
        ) => {
            anyhow::ensure!(
                options.durability_policy.is_none(),
                "standard MLS Circle cannot declare durability_policy"
            );
        }
        (
            arkret_sdk::EncryptionProfile::MlsRfc9420,
            Some(arkret_sdk::ContentScheme::MlsExporterAeadV1),
        ) => {
            anyhow::ensure!(
                options.durability_policy.is_some(),
                "exporter MLS Circle requires durability_policy"
            );
        }
        (arkret_sdk::EncryptionProfile::MlsRfc9420, None) => {
            anyhow::bail!("MLS-backed Circle requires content_scheme");
        }
        _ => anyhow::bail!("Circle encryption_profile is not registered"),
    }
    circle.content_scheme = options.content_scheme;
    circle.durability_policy = options.durability_policy;
    Ok(TypedOperationBuilder::new::<
        arkret_sdk::event_spec::CircleCreate,
    >(
        realm_id,
        actor,
        arkret_sdk::CircleCreatePayload { object: circle },
    ))
}
