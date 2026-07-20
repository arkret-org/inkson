//! Account-data key helpers for canonical SDK remark payloads.

pub use garth::{ContactRemark, ContactRemarkSubject, RealmRemark, RealmRemarkSubject};

pub fn realm_remark_account_data_key(realm_id: &str) -> String {
    format!("ak.contacts.realm.{realm_id}")
}

pub fn realm_id_from_realm_remark_key(key: &str) -> Option<&str> {
    key.strip_prefix("ak.contacts.realm.")
}

pub fn contact_remark_account_data_key(actor_id: &str) -> String {
    format!("ak.contacts.actor.{actor_id}")
}

pub fn actor_id_from_contact_remark_key(key: &str) -> Option<&str> {
    key.strip_prefix("ak.contacts.actor.")
}
