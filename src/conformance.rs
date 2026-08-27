//! Runtime conformance gates backed by explicit service profile claims.

use crate::models::{ServiceDescribe, service_supports_profile};

/// Report whether the server supports a client profile.
///
/// Discovery absence is unknown and therefore fails closed. A conformance
/// profile is not a runtime capability table: only an explicit service claim
/// enables this gate. Operation availability is negotiated separately from
/// the service's advertised operation bundles.
pub fn profile_ready(server: Option<&ServiceDescribe>, profile_id: &str) -> bool {
    server.is_some_and(|description| service_supports_profile(description, profile_id))
}

#[cfg(test)]
mod tests {
    use arkret_wire::ProfileId;

    use super::*;

    #[test]
    fn profile_ready_fails_closed_until_describe_finishes() {
        assert!(!profile_ready(None, ProfileId::E2EE_CLIENT_V1));
    }
}
