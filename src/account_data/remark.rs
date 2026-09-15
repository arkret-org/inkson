//! Account-data key helpers for canonical SDK remark payloads.

pub use arkret_models_collaboration::objects::productivity::{
    ContactRemark, ContactRemarkSubject, RealmRemark, RealmRemarkSubject,
};

pub fn realm_remark_account_data_key(realm_id: &str) -> String {
    format!("ak.contacts.realm.{realm_id}")
}

pub fn realm_id_from_realm_remark_key(key: &str) -> Option<&str> {
    key.strip_prefix("ak.contacts.realm.")
}

pub fn contact_remark_account_data_key(
    namespace_key: &[u8],
    principal_id: &arkret_sdk::DidCoreId,
) -> anyhow::Result<String> {
    arkret_sdk::contact_remark_account_data_key(namespace_key, principal_id).map_err(Into::into)
}

pub fn principal_key_from_contact_remark_key(key: &str) -> Option<String> {
    arkret_sdk::parse_contact_remark_account_data_key(key).ok()
}

/// One holder-authored change to a Contact remark.
///
/// A remark is one whole account-data value, so a concurrent write from the
/// holder's other device is resolved by re-reading and re-applying the *change*
/// rather than by resending a whole record assembled from a stale read. Sending
/// the record would silently drop whatever the other device wrote — a petname,
/// a note, a pin, tags, or the confirmation baseline — which is exactly the
/// merge `client-preferences.md` section 3.6 forbids.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContactRemarkEdit {
    /// Holder-authored alias. An empty value clears it.
    Petname(String),
    Note(String),
    Tags(Vec<String>),
    Pinned(bool),
    /// An explicit identity confirmation. Only this refreshes the baseline, and
    /// it never invents a petname.
    ConfirmDisplayName(String),
}

impl ContactRemarkEdit {
    /// Apply this one change on top of whatever record is current, preserving
    /// every field the holder did not just edit.
    pub fn apply(
        &self,
        principal_id: arkret_sdk::DidCoreId,
        current: Option<&ContactRemark>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ContactRemark {
        match self {
            Self::ConfirmDisplayName(display_name) => {
                ContactRemark::with_confirmed_display_name_preserving_fields(
                    principal_id,
                    current,
                    display_name.clone(),
                    now,
                )
            }
            Self::Pinned(pinned) => {
                ContactRemark::with_pinned_preserving_fields(principal_id, current, *pinned, now)
            }
            Self::Petname(petname) => {
                let mut next = touched(principal_id, current, now);
                next.petname = petname.clone();
                next
            }
            Self::Note(note) => {
                let mut next = touched(principal_id, current, now);
                next.note = note.clone();
                next
            }
            Self::Tags(tags) => {
                let mut next = touched(principal_id, current, now);
                next.tags = tags.clone();
                next
            }
        }
    }
}

/// The current record with its key binding normalized and its modification time
/// advanced, ready for one holder field to be overwritten.
///
/// The SDK owns the same shape for the two evidence-bearing fields
/// (`with_confirmed_display_name_preserving_fields`,
/// `with_pinned_preserving_fields`); this is the plain-field counterpart.
fn touched(
    principal_id: arkret_sdk::DidCoreId,
    current: Option<&ContactRemark>,
    now: chrono::DateTime<chrono::Utc>,
) -> ContactRemark {
    let mut next = current
        .cloned()
        .unwrap_or_else(|| ContactRemark::new(principal_id.clone(), "", now));
    next.version = 1;
    next.subject = ContactRemarkSubject {
        kind: "human".to_owned(),
        principal_id,
    };
    next.updated_at = Some(now);
    next
}

/// Re-apply one Contact remark edit onto the authoritative current value.
///
/// Used as the `update_account_data_with_merge` body, so the first attempt and
/// every CAS retry merge against what the server actually holds instead of the
/// snapshot the UI was rendered from.
pub fn merge_contact_remark_account_data(
    authority: &arkret_sdk::AccountId,
    account_data_key: &str,
    principal_id: &arkret_sdk::DidCoreId,
    edit: &ContactRemarkEdit,
    current: Option<&arkret_sdk::AccountDataRow>,
) -> anyhow::Result<ContactRemarkMerge> {
    let namespace_key = super::account_data_namespace_key(authority)?;
    let remote = match current {
        Some(current) => {
            let plaintext =
                super::decrypt_account_data_entry(authority, account_data_key, current)?;
            let remark: ContactRemark = serde_json::from_value(plaintext)?;
            remark.validate_for_account_data_key(&namespace_key, account_data_key)?;
            if &remark.subject.principal_id != principal_id {
                anyhow::bail!("contact remark account-data value names another Contact");
            }
            Some(remark)
        }
        None => None,
    };
    let merged = edit.apply(principal_id.clone(), remote.as_ref(), chrono::Utc::now());
    if merged.is_empty() {
        return Ok(ContactRemarkMerge::Delete);
    }
    merged.validate_for_account_data_key(&namespace_key, account_data_key)?;
    let body = super::encrypt_account_data_value(
        authority,
        account_data_key,
        &serde_json::to_value(&merged)?,
    )?;
    Ok(ContactRemarkMerge::Write(body))
}

/// What a merged Contact remark asks the account-data write path to do.
#[derive(Clone, Debug)]
pub enum ContactRemarkMerge {
    /// The encrypted body to store.
    Write(serde_json::Value),
    /// The merge left nothing holder-authored, so the key is physically
    /// deleted rather than written as an empty record.
    Delete,
}
