//! `ck.rank.lexofractional.v1` rank profile per
//! [`spec/v1/zh/conformance/encoding.md`
//! §9](../../cokret-spec/spec/v1/zh/conformance/encoding.md).
//!
//! Ranks are 1..128 ASCII strings drawn from
//! `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz` (62 chars).
//! Ordering is plain byte-wise lexicographic comparison; a shorter string
//! that is a prefix of a longer one sorts before it.
//!
//! [`rank_between`] returns a rank strictly between `left` and `right`
//! sentinels (either may be empty to denote container start / end). It is
//! the bounded reference algorithm from the spec — it never loops past
//! 128 characters and returns [`RankError::Exhausted`] when no valid rank
//! exists (e.g. `rank_between("", "0")`).
//!
//! Callers MUST treat `Exhausted` as a signal to either request a
//! `ck.container.rebalance` Move or fall back to a UI affordance that
//! lets the user trigger one. Inserting an out-of-profile sentinel like
//! `format!("r{millis}")` is a wire-shape violation — reducers reject any
//! rank that contains characters outside the alphabet or exceeds the
//! 128-char limit.

use std::fmt;

const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BASE: i32 = 62;
pub const MAX_RANK_LEN: usize = 128;

/// Errors from rank generation. `Exhausted` is the recoverable signal —
/// callers should fall back to `ck.container.rebalance`. `Invalid`
/// indicates the input string is not a well-formed rank (alphabet or
/// length violation) and is a programmer error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RankError {
    /// No rank exists strictly between `left` and `right`. Trigger a
    /// container rebalance.
    Exhausted,
    /// Input string contained characters outside the alphabet or
    /// exceeded `MAX_RANK_LEN`. Position points at the first bad byte.
    Invalid {
        reason: &'static str,
        position: usize,
    },
}

impl fmt::Display for RankError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exhausted => f.write_str(
                "rank_exhausted: no valid rank between the given sentinels; trigger ck.container.rebalance",
            ),
            Self::Invalid { reason, position } => {
                write!(f, "invalid rank ({reason}) at position {position}")
            }
        }
    }
}

impl std::error::Error for RankError {}

/// Map an alphabet character to its 0..=61 index. Returns `None` for
/// any byte outside the alphabet — callers convert to [`RankError::Invalid`].
fn char_value(b: u8) -> Option<i32> {
    ALPHABET.iter().position(|&c| c == b).map(|v| v as i32)
}

/// Returns `Ok(())` when every byte in `s` is in the alphabet and
/// `s.len() <= MAX_RANK_LEN`. Empty strings are valid sentinels.
pub fn validate(s: &str) -> Result<(), RankError> {
    if s.len() > MAX_RANK_LEN {
        return Err(RankError::Invalid {
            reason: "rank exceeds 128 chars",
            position: MAX_RANK_LEN,
        });
    }
    for (i, &b) in s.as_bytes().iter().enumerate() {
        if char_value(b).is_none() {
            return Err(RankError::Invalid {
                reason: "character outside lexofractional alphabet",
                position: i,
            });
        }
    }
    Ok(())
}

/// Return a rank strictly between `left` and `right`, or `Exhausted` if
/// no such rank exists within the 128-char bound. Empty `left` means
/// "container start"; empty `right` means "container end".
///
/// Mirrors the reference pseudocode in
/// [`encoding.md` §9](../../cokret-spec/spec/v1/zh/conformance/encoding.md):
/// at each position `i`, compute the value of `left[i]` (or sentinel
/// `min = -1` if out of bounds) and `right[i]` (or sentinel `max = 62`
/// if out of bounds or `right` is empty). If the gap > 1, return the
/// midpoint char; otherwise descend into `left[i]` (or append the
/// smallest char if left is exhausted, retrying or bailing as the
/// spec dictates).
pub fn rank_between(left: &str, right: &str) -> Result<String, RankError> {
    validate(left)?;
    validate(right)?;
    if !left.is_empty() && !right.is_empty() && left >= right {
        return Err(RankError::Invalid {
            reason: "left must be lexicographically less than right",
            position: 0,
        });
    }
    let left_bytes = left.as_bytes();
    let right_bytes = right.as_bytes();
    let mut prefix: Vec<u8> = Vec::with_capacity(8);
    let mut i = 0usize;
    while prefix.len() < MAX_RANK_LEN {
        let l: i32 = if i < left_bytes.len() {
            // SAFETY: validate() already ensured every byte is in alphabet.
            char_value(left_bytes[i]).expect("validated")
        } else {
            -1
        };
        let r: i32 = if !right_bytes.is_empty() && i < right_bytes.len() {
            char_value(right_bytes[i]).expect("validated")
        } else {
            BASE
        };
        if r - l > 1 {
            let mid = ((l + r) / 2) as usize;
            prefix.push(ALPHABET[mid]);
            return Ok(String::from_utf8(prefix).expect("alphabet is ASCII"));
        }
        // No gap at this position. Descend into left[i] if present, or
        // extend with alphabet[0] and either return the new prefix or
        // bail out.
        if i < left_bytes.len() {
            prefix.push(left_bytes[i]);
        } else {
            prefix.push(ALPHABET[0]);
            if !right_bytes.is_empty() && prefix.as_slice() == right_bytes {
                return Err(RankError::Exhausted);
            }
            return Ok(String::from_utf8(prefix).expect("alphabet is ASCII"));
        }
        i += 1;
    }
    Err(RankError::Exhausted)
}

/// Convenience wrapper: compute the rank for a card dropped between two
/// neighbours in the same list. `prev` is the card immediately above
/// (lower rank, sentinel "" if dropping at the top); `next` is the card
/// immediately below (higher rank, sentinel "" if dropping at the
/// bottom).
pub fn rank_for_drop(prev: Option<&str>, next: Option<&str>) -> Result<String, RankError> {
    rank_between(prev.unwrap_or(""), next.unwrap_or(""))
}

/// Deterministic rebalance assignment per encoding.md §9. Given an
/// ordered list of `n` items, return the rank each item SHOULD claim
/// after a `ck.container.rebalance` Move. The result is a fixed-width
/// base62 encoding chosen so that `alphabet_length^w >= 2 * (n + 1)`.
/// Returns `Exhausted` if `n` is large enough that even `w == 128`
/// can't accommodate the spacing.
pub fn rebalance_ranks(n: usize) -> Result<Vec<String>, RankError> {
    if n == 0 {
        return Ok(Vec::new());
    }
    // Smallest w such that 62^w >= 2 * (n + 1).
    let target = 2u128
        .checked_mul((n as u128) + 1)
        .ok_or(RankError::Exhausted)?;
    let mut w: usize = 1;
    let mut capacity: u128 = BASE as u128;
    while capacity < target {
        w += 1;
        if w > MAX_RANK_LEN {
            return Err(RankError::Exhausted);
        }
        capacity = capacity
            .checked_mul(BASE as u128)
            .ok_or(RankError::Exhausted)?;
    }
    let denom = (n as u128) + 1;
    let mut out = Vec::with_capacity(n);
    for i in 1..=(n as u128) {
        // floor(i * capacity / (n + 1))
        let value = i * capacity / denom;
        out.push(base62_encode_fixed(value, w));
    }
    Ok(out)
}

/// Encode `value` as a fixed-width base62 string, left-padded with the
/// alphabet's first character (`0`).
fn base62_encode_fixed(mut value: u128, width: usize) -> String {
    let mut bytes = vec![ALPHABET[0]; width];
    let mut idx = width;
    while value > 0 && idx > 0 {
        idx -= 1;
        let digit = (value % (BASE as u128)) as usize;
        bytes[idx] = ALPHABET[digit];
        value /= BASE as u128;
    }
    String::from_utf8(bytes).expect("alphabet is ASCII")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_non_alphabet_characters() {
        let err = validate("ab cd").unwrap_err();
        assert!(matches!(err, RankError::Invalid { position: 2, .. }));
    }

    #[test]
    fn validate_accepts_empty_and_alphabet() {
        validate("").unwrap();
        validate("0").unwrap();
        validate("z").unwrap();
        validate("0aZ9").unwrap();
    }

    #[test]
    fn validate_rejects_overlong_rank() {
        let s = "0".repeat(MAX_RANK_LEN + 1);
        let err = validate(&s).unwrap_err();
        assert!(matches!(err, RankError::Invalid { .. }));
    }

    /// Spec sentinel: between container start and the smallest rank `"0"`
    /// there is no representable rank, so the function MUST signal
    /// exhaustion — never fabricate one.
    #[test]
    fn rank_between_empty_and_zero_returns_exhausted() {
        let err = rank_between("", "0").unwrap_err();
        assert_eq!(err, RankError::Exhausted);
    }

    /// `rank_between("", "")` (both ends are sentinels) MUST produce a
    /// stable mid-alphabet rank so the first card in a brand-new list
    /// has somewhere to sit. We pin to `"U"` (alphabet[30]) so the demo
    /// output stays predictable.
    #[test]
    fn rank_between_double_empty_returns_alphabet_middle() {
        let mid = rank_between("", "").unwrap();
        assert_eq!(mid, "U");
        assert!(mid.as_str() > "");
    }

    #[test]
    fn rank_between_zero_and_z_returns_midpoint() {
        let mid = rank_between("0", "z").unwrap();
        assert!(mid.as_str() > "0");
        assert!(mid.as_str() < "z");
        assert_eq!(mid, "U");
    }

    #[test]
    fn rank_between_adjacent_descends_then_appends() {
        // Between "00" and "01": same first char, second char gap is 0 → must descend.
        let mid = rank_between("00", "01").unwrap();
        assert!(mid.as_str() > "00");
        assert!(mid.as_str() < "01");
        // The spec algorithm descends to position 2 with l=min=-1, r=max=62,
        // returning "00" + alphabet[30] = "00U".
        assert_eq!(mid, "00U");
    }

    #[test]
    fn rank_between_after_last_extends_with_zero() {
        // No right sentinel ⇒ insert at end. Between "U" and "" should
        // pick a midpoint > "U".
        let r = rank_between("U", "").unwrap();
        assert!(r.as_str() > "U");
    }

    #[test]
    fn rank_between_before_first_picks_below_right() {
        // Between "" and "U" should be < "U" and > "".
        let r = rank_between("", "U").unwrap();
        assert!(r.as_str() < "U");
        assert!(r.as_str() > "");
    }

    #[test]
    fn rank_between_rejects_left_ge_right() {
        let err = rank_between("U", "U").unwrap_err();
        assert!(matches!(err, RankError::Invalid { .. }));
        let err = rank_between("V", "U").unwrap_err();
        assert!(matches!(err, RankError::Invalid { .. }));
    }

    /// Insert-after-prefix path that the spec example narrates: between
    /// `"0"` and `"00"` no rank exists (any string > "0" with prefix "0"
    /// would be ≥ "00" or land at "00" itself). Confirms the
    /// `prefix == right` exhaustion branch fires.
    #[test]
    fn rank_between_prefix_collision_returns_exhausted() {
        let err = rank_between("0", "00").unwrap_err();
        assert_eq!(err, RankError::Exhausted);
    }

    #[test]
    fn rank_for_drop_top_uses_empty_prev() {
        let r = rank_for_drop(None, Some("U")).unwrap();
        assert!(r.as_str() < "U");
    }

    #[test]
    fn rank_for_drop_bottom_uses_empty_next() {
        let r = rank_for_drop(Some("U"), None).unwrap();
        assert!(r.as_str() > "U");
    }

    #[test]
    fn rank_for_drop_between_two_neighbours() {
        let r = rank_for_drop(Some("0"), Some("z")).unwrap();
        assert!(r.as_str() > "0");
        assert!(r.as_str() < "z");
    }

    #[test]
    fn rebalance_zero_items_returns_empty() {
        assert!(rebalance_ranks(0).unwrap().is_empty());
    }

    #[test]
    fn rebalance_three_items_are_strictly_increasing_within_capacity() {
        let ranks = rebalance_ranks(3).unwrap();
        assert_eq!(ranks.len(), 3);
        assert!(ranks[0].as_str() < ranks[1].as_str());
        assert!(ranks[1].as_str() < ranks[2].as_str());
        // All same width — fixed-width base62 encoding.
        assert_eq!(ranks[0].len(), ranks[1].len());
        assert_eq!(ranks[1].len(), ranks[2].len());
        // All chars in alphabet.
        for r in &ranks {
            validate(r).unwrap();
        }
    }

    #[test]
    fn rebalance_large_n_picks_wider_width() {
        let ranks = rebalance_ranks(1_000).unwrap();
        assert_eq!(ranks.len(), 1_000);
        // 62^2 = 3844 >= 2 * 1001 = 2002, so w = 2 is sufficient.
        assert_eq!(ranks[0].len(), 2);
        // Strictly increasing.
        for w in ranks.windows(2) {
            assert!(w[0].as_str() < w[1].as_str());
        }
    }
}
