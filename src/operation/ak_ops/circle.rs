//! Circle administration builders.
//!
//! `ak.self.circle.command.create` takes the caller-signed `ak.circle.create`
//! Event, so the Circle the user configures in the UI is authored here and the
//! resulting Circle id falls out of that Event. The server neither names the
//! Circle nor signs for the user.

use super::{OperationBuilder, did_id, object_create_payload_value, realm_id_value, trim_realm_id};

/// Everything the create surface lets a user choose about a new Circle.
///
/// Reducer-owned fields are absent by construction: `mls_group_ref` is derived
/// when the MLS group is bound, and the object id comes from the create Event.
#[derive(Clone, Debug)]
pub struct CircleCreateOptions<'a> {
    pub title: &'a str,
    pub summary: Option<&'a str>,
    pub display: arkret_sdk::CircleDisplay,
    pub directory_visibility: arkret_sdk::CircleDirectoryVisibility,
    pub join_rule: arkret_sdk::CircleJoinRule,
    pub history_visibility: arkret_sdk::HistoryVisibility,
    pub encryption_profile: arkret_sdk::EncryptionProfile,
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
) -> anyhow::Result<OperationBuilder> {
    let mut circle = arkret_sdk::Circle::create_object(
        realm_id_value(&trim_realm_id(realm_id))?,
        options.title.trim(),
        options.display,
        did_id(actor)?,
    );
    circle.summary = options
        .summary
        .map(str::trim)
        .filter(|summary| !summary.is_empty())
        .map(ToOwned::to_owned);
    circle.directory_visibility = options.directory_visibility;
    circle.join_rule = options.join_rule;
    circle.history_visibility = options.history_visibility;
    circle.encryption_profile = options.encryption_profile;
    let body = object_create_payload_value(circle, "ak.circle.create payload serialize")?;
    Ok(OperationBuilder::new(realm_id, actor, arkret_sdk::EventKind::CircleCreate).body(body))
}
