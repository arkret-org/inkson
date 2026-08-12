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
