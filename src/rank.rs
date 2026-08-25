//! `ak.rank.lexofractional.v1` rank profile per
//! [`spec/v1/zh/conformance/encoding.md`
//! §9](../../arkret-spec/spec/v1/zh/conformance/encoding.md).
//!
//! Ranks are 1..128 ASCII strings drawn from
//! `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz` (62 chars).
//! Ordering is plain byte-wise lexicographic comparison; a shorter string
//! that is a prefix of a longer one sorts before it.
//!
//! The bounded interval algorithm itself is owned by the SDK
//! ([`arkret_event_draft::rank_between`]); this module only adapts it to
//! inkson's conventions: an empty string denotes the container start / end
//! sentinel, and exhaustion surfaces as the recoverable
//! [`RankError::Exhausted`] signal.
//!
//! Callers MUST treat `Exhausted` as a signal to either request a
//! `ak.container.rebalance` Move or fall back to a UI affordance that
//! lets the user trigger one. Inserting an out-of-profile sentinel like
//! `format!("r{millis}")` is a wire-shape violation — reducers reject any
//! rank that contains characters outside the alphabet or exceeds the
//! 128-char limit.

use arkret_event_draft::EventDraftError;

/// Errors from rank generation. `Exhausted` is the recoverable signal —
/// callers should fall back to `ak.container.rebalance`. `Invalid`
/// indicates the input string is not a well-formed rank (alphabet or
/// length violation) or the interval is inverted, and is a programmer
/// error.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RankError {
    /// No rank exists strictly between the given sentinels. Trigger a
    /// container rebalance.
    #[error(
        "rank_exhausted: no valid rank between the given sentinels; trigger ak.container.rebalance"
    )]
    Exhausted,
    /// The SDK rejected an input boundary; the message is its reason
    /// verbatim.
    #[error("invalid rank: {0}")]
    Invalid(String),
}

/// Return a rank strictly between `left` and `right`, or `Exhausted` if
/// no such rank exists within the 128-char bound. Empty `left` means
/// "container start"; empty `right` means "container end".
pub fn rank_between(left: &str, right: &str) -> Result<String, RankError> {
    let before = if left.is_empty() { None } else { Some(left) };
    let after = if right.is_empty() { None } else { Some(right) };
    map_rank_result(arkret_event_draft::rank_between(before, after))
}

/// Convenience wrapper: compute the rank for a card dropped between two
/// neighbours in the same list. `prev` is the card immediately above
/// (lower rank, `None` if dropping at the top); `next` is the card
/// immediately below (higher rank, `None` if dropping at the bottom).
pub fn rank_for_drop(prev: Option<&str>, next: Option<&str>) -> Result<String, RankError> {
    map_rank_result(arkret_event_draft::rank_between(prev, next))
}

/// Map an SDK drafting error onto inkson's rank error. The SDK signals
/// exhaustion through this exact protocol message (its own
/// `rank_exhausted` helper matches the same string); everything else is
/// an input violation.
fn map_rank_result(result: arkret_event_draft::Result<String>) -> Result<String, RankError> {
    result.map_err(|error| match &error {
        EventDraftError::Protocol(message) if message == "rank interval is exhausted" => {
            RankError::Exhausted
        }
        _ => RankError::Invalid(error.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Empty-string sentinels map to the SDK's open interval, and an
    /// unrepresentable gap surfaces as `RankError::Exhausted` so callers
    /// can trigger `ak.container.rebalance` — never a fabricated rank.
    #[test]
    fn rank_between_empty_and_zero_returns_exhausted() {
        let err = rank_between("", "0").unwrap_err();
        assert_eq!(err, RankError::Exhausted);
    }

    /// Between `"0"` and `"00"` no rank exists (any string > "0" with
    /// prefix "0" would be ≥ "00"), so exhaustion MUST be signalled.
    #[test]
    fn rank_between_prefix_collision_returns_exhausted() {
        let err = rank_between("0", "00").unwrap_err();
        assert_eq!(err, RankError::Exhausted);
    }

    /// Out-of-order or off-alphabet input is a programmer error and maps
    /// to `Invalid`, never to the recoverable `Exhausted` signal.
    #[test]
    fn rank_between_rejects_invalid_input() {
        assert!(matches!(
            rank_between("U", "U"),
            Err(RankError::Invalid(_))
        ));
        assert!(matches!(
            rank_between("ab cd", ""),
            Err(RankError::Invalid(_))
        ));
    }

    #[test]
    fn rank_for_drop_plumbs_option_neighbours() {
        let between = rank_for_drop(Some("0"), Some("z")).unwrap();
        assert!(between.as_str() > "0");
        assert!(between.as_str() < "z");
        assert!(rank_for_drop(None, Some("U")).unwrap().as_str() < "U");
        assert!(rank_for_drop(Some("U"), None).unwrap().as_str() > "U");
    }
}
