use super::*;

impl LocalStateStore {
    /// The digest suite every Event authored into `realm` must use.
    ///
    /// The Realm's own identity is its retyped genesis Event id, and that token
    /// carries the registered digest-suite code, so the answer is derived from
    /// the Realm id itself rather than from any service response. A malformed
    /// id yields `None` and the caller fails closed instead of guessing a
    /// suite.
    pub(crate) fn station_realm_digest_suite(
        &self,
        realm: &str,
    ) -> Option<arkret_sdk::DigestSuite> {
        realm_digest_suite(realm)
    }
}

/// The registered digest suite encoded in a canonical `ak:realm:*` identifier.
pub(crate) fn realm_digest_suite(realm: &str) -> Option<arkret_sdk::DigestSuite> {
    arkret_sdk::RealmId::new(realm.trim().to_owned())
        .ok()
        .map(|realm_id| realm_id.digest_suite_code().digest_suite())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_realm_id_carries_its_own_digest_suite() {
        assert_eq!(
            realm_digest_suite("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"),
            Some(arkret_sdk::DigestSuite::Sha256)
        );
        assert_eq!(realm_digest_suite("not-a-realm"), None);
    }
}
