use serde_json::{Value, json};

use super::BackupKind;

#[cfg(test)]
pub fn attach_key_backup_domain_separation(body: &mut Value, _class: BackupKind, subdomain: &str) {
    let domain_separation = json!({
        "subdomain": subdomain
    });
    body["domain_separation"] = domain_separation;
}
