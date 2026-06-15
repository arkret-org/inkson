use super::*;

/// One competing head for a `bottom=expose` cell. Surfaced from sync so the
/// UI can render side-by-side candidates and prefill the "safer side" of a
/// conflict-repair Move.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BottomCellHead {
    /// Move (or Seal head) id that produced this candidate.
    pub move_id: String,
    /// Candidate cell value carried by that Move. `Value::Null` when soland
    /// only published the move_id without an inline value.
    #[serde(default)]
    pub value: Value,
}

/// Per-cell bottom record. `status` is the lattice `bottom=` literal (typically
/// `"expose"`) and `heads` is the competing-candidate list. `heads` may be
/// empty when soland publishes only the bottom flag without per-head values;
/// the UI then falls back to manual JSON entry on the repair dialog.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BottomCellInfo {
    #[serde(default)]
    pub status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub heads: Vec<BottomCellHead>,
}

/// Snapshot of the latest Seal view observed for a Space. Surfaced from
/// the `/sync` Seal view (P0 M3) and threaded into Move submissions so
/// every cell-driven write references the right frontier instead of the
/// `sha256(empty)` placeholder used previously.
///
/// `frontier` lists the Seal head ids the local client currently treats
/// as the predecessor set (typically a single id but multiple while a
/// concurrent fork is unresolved). `state_root` is the post-state Merkle
/// root soland published in the most recent Seal — clients can use it
/// to detect divergence between their projection and the server view.
/// `leaves` lists the Move ids covered by the current Seal batch (the
/// "leaves of the lattice that the next Seal will close over"); UIs
/// surface this so an admin can see which pending Moves an Seal
/// rotation will sweep up.
///
/// The struct is intentionally `Default` so callers that haven't received
/// any Seal view yet (offline, fresh login) still have a clean empty
/// view to feed into builders.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSealView {
    /// Seal head ids that the next Move treats as predecessors. Empty
    /// vec means "no Seal seen yet" — Move builders fall back to the
    /// `sha256(empty)` sentinel.
    #[serde(default)]
    pub frontier: Vec<String>,
    /// Move ids covered by the current Seal batch (or about to be
    /// closed by the next Seal rotation). Surfaced for admin UIs.
    #[serde(default)]
    pub leaves: Vec<String>,
    /// Post-state Merkle root from the most recent Seal. Optional —
    /// brand new spaces / offline clients may not have one yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root: Option<String>,
    /// Cell map snapshot: cell ref → bottom record (status + competing
    /// heads). Populated when the projection contains a `bottom=expose`
    /// cell so the UI can surface a "concurrent candidates unresolved"
    /// banner with side-by-side head values. Other cells are omitted to
    /// keep this struct compact.
    #[serde(default)]
    pub bottom_cells: BTreeMap<String, BottomCellInfo>,
    /// The current MLS epoch as published in the
    /// `ck.component.mls.epoch.v1` cas-register cell, when sync surfaces
    /// it. `None` means the Space hasn't published an MLS epoch yet (no
    /// E2EE group or pre-genesis state).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_epoch: Option<u64>,
    /// The current `governance.covered_seals` cell value - the lattice
    /// frontier cell that governance Moves require predecessor coverage of
    /// before they're accepted. Surfaced as a string so the UI can render
    /// whatever shape soland publishes (typically a `ck:state:sha256:...`
    /// ref). `None` means the governance cell hasn't been observed yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered_seals: Option<String>,
    /// The per-Realm MLS `covered_seals_lag` count - how many
    /// governance Moves the MLS group has yet to acknowledge. Soland
    /// publishes this as `seal_view.covered_seals_lag` (a bare
    /// integer) when it knows the lag; clients combine it with a
    /// configurable warn threshold (default 5) to render an alert banner
    /// in `realm_admin`. `None` means soland hasn't surfaced a lag value -
    /// UI treats that as "no alert".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered_seals_lag: Option<u64>,
    /// MLS key-schedule content hash (`sha256:<hex>`) from the
    /// `ck.component.key_schedule.v1` cas-register cell. The MLS commit
    /// path uses this as `prev_schedule`; the new commit computes a
    /// fresh schedule on top of it. `None` means the Space has not
    /// published a key schedule yet (no prior MLS commit observed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_schedule_hash: Option<String>,
}

impl LocalSealView {
    /// SHA-256 of empty bytes — used as the "no Seal seen yet" sentinel
    /// the Move builders historically defaulted to.
    pub const EMPTY_ANCHOR_REF: &'static str =
        "ck:seal:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// Pick the single Seal ref to feed into a Move builder. Returns the
    /// first frontier head if any, otherwise the empty-bytes sentinel.
    /// When the frontier holds multiple heads (concurrent fork) this picks
    /// the lex-min head so two clients building Moves against the same
    /// view will agree on which predecessor they reference.
    pub fn move_seal_ref(&self) -> String {
        self.frontier
            .iter()
            .min()
            .cloned()
            .unwrap_or_else(|| Self::EMPTY_ANCHOR_REF.to_owned())
    }

    /// True when the view contains at least one cell with `bottom=expose`
    /// status — the UI should surface a banner.
    pub fn has_bottom_cells(&self) -> bool {
        !self.bottom_cells.is_empty()
    }

    /// True when soland has surfaced a covered_seals_lag strictly
    /// greater than `threshold`. Used by the realm_admin covered_seals
    /// alert banner to decide whether to render. Returns `false` when no
    /// lag has been published yet (the field is `None`) - the UI treats
    /// that as "no signal, no alert".
    pub fn covered_seals_lag_above(&self, threshold: u64) -> bool {
        self.covered_seals_lag.is_some_and(|lag| lag > threshold)
    }

    /// For security-relevant cell families (member.state, capability.grant),
    /// return the safer winner candidate from the cell's competing heads —
    /// the more restrictive membership value or the revoked grant. Returns
    /// `None` when:
    /// - the cell isn't a known security-relevant family (operator must pick manually — there's no
    ///   semantic safety ordering to lean on),
    /// - sync hasn't published per-head values yet (`heads` is empty),
    /// - the heads aren't comparable in the safety order.
    ///
    /// The protocol layer never auto-picks a winner; this only powers a UX
    /// "Prefer safer side" prefill — the operator still signs and submits
    /// the resulting repair Move.
    pub fn safer_winner_for(&self, cell_ref: &str) -> Option<(String, String, Value)> {
        let info = self.bottom_cells.get(cell_ref)?;
        if info.heads.len() < 2 {
            return None;
        }
        let head_a = &info.heads[0];
        let head_b = &info.heads[1];
        let safer = if cell_ref.starts_with("ck:cell:ck.component.realm.organization.v1") {
            head_a.value.clone()
        } else {
            safer_value_for_cell(cell_ref, &head_a.value, &head_b.value)?
        };
        Some((head_a.move_id.clone(), head_b.move_id.clone(), safer))
    }
}

/// Rank `a` and `b` on the cell's safety order; return whichever ranks
/// higher (more restrictive). `None` means "no order I'll commit to" —
/// either the cell family is not in the table, or both heads tie. Tying
/// is intentional: ban-vs-ban or revoke-vs-revoke is a content conflict,
/// not a safety call, so we surface no preference and the operator picks.
fn safer_value_for_cell(cell_ref: &str, a: &Value, b: &Value) -> Option<Value> {
    let rank: fn(&Value) -> u8 = if cell_ref.starts_with("ck:cell:ck.component.member.state.v1") {
        member_state_safety_rank
    } else if cell_ref.starts_with("ck:cell:ck.component.capability.grant.v1") {
        capability_grant_safety_rank
    } else {
        return None;
    };
    let ra = rank(a);
    let rb = rank(b);
    match ra.cmp(&rb) {
        std::cmp::Ordering::Greater => Some(a.clone()),
        std::cmp::Ordering::Less => Some(b.clone()),
        std::cmp::Ordering::Equal => None,
    }
}

fn member_state_safety_rank(value: &Value) -> u8 {
    let label = value
        .get("membership")
        .and_then(|v| v.as_str())
        .or_else(|| value.as_str())
        .unwrap_or("");
    match label {
        "ban" => 4,
        "leave" => 3,
        "knock" => 2,
        "invite" => 1,
        "join" => 0,
        _ => 0,
    }
}

fn capability_grant_safety_rank(value: &Value) -> u8 {
    let label = value
        .get("status")
        .and_then(|v| v.as_str())
        .or_else(|| value.as_str())
        .unwrap_or("");
    match label {
        "revoked" => 2,
        "active" => 1,
        _ => 0,
    }
}

impl LocalSealView {
    /// Best-effort extraction of an Seal view from a per-Realm `/sync`
    /// body. The wire shape soland is moving toward (P0 M3) is:
    ///
    /// ```jsonc
    /// {
    ///   "seal_view": {
    ///     "frontier": ["ck:seal:sha256:..."],
    ///     "leaves":   ["sha256:..."],
    ///     "state_root": "ck:state:sha256:...",
    ///     "cells": {
    ///       "ck:cell:ck.component.member.state.v1:did:web:alice": {
    ///         "bottom": "expose"
    ///       }
    ///     }
    ///   }
    /// }
    /// ```
    ///
    /// Until soland publishes the full payload, missing fields default to
    /// empty / `None`. The function is total and never errors — it just
    /// degrades to `LocalSealView::default()` when fields are missing
    /// or have unexpected shapes.
    pub fn from_sync_body(body: &Value) -> Self {
        let seal = body.get("seal_view");
        let mut view = Self::default();
        let Some(seal) = seal else {
            view.ingest_structured_bottoms(body);
            return view;
        };
        if let Some(arr) = seal.get("frontier").and_then(|v| v.as_array()) {
            view.frontier = arr
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect();
        }
        if let Some(arr) = seal.get("leaves").and_then(|v| v.as_array()) {
            view.leaves = arr
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect();
        }
        if let Some(s) = seal.get("state_root").and_then(|v| v.as_str()) {
            view.state_root = Some(s.to_owned());
        }
        // Top-level `covered_seals_lag`: soland publishes this directly
        // on the seal view (sibling of `frontier` / `leaves`) so clients
        // don't have to compute it from cell maps.
        if let Some(lag) = seal.get("covered_seals_lag").and_then(|v| v.as_u64()) {
            view.covered_seals_lag = Some(lag);
        }
        if let Some(cells) = seal.get("cells").and_then(|v| v.as_object()) {
            for (cell_ref, status) in cells {
                let bottom = status.get("bottom").and_then(|v| v.as_str());
                if let Some(b) = bottom
                    && b == "expose"
                {
                    let mut heads = Vec::new();
                    if let Some(arr) = status.get("heads").and_then(|v| v.as_array()) {
                        for h in arr {
                            let move_id = h
                                .get("move_id")
                                .and_then(|v| v.as_str())
                                .map(str::to_owned)
                                .unwrap_or_default();
                            if move_id.is_empty() {
                                continue;
                            }
                            let value = h.get("value").cloned().unwrap_or(Value::Null);
                            heads.push(BottomCellHead { move_id, value });
                        }
                    }
                    view.bottom_cells.insert(
                        cell_ref.clone(),
                        BottomCellInfo {
                            status: b.to_owned(),
                            heads,
                        },
                    );
                }
                // Well-known named cells surfaced for the realm_admin MLS
                // epoch widget. We accept either a raw `value` or a typed
                // `register.value` field - soland's canonical projection
                // uses the latter; tests may emit the former.
                let value_for = |status: &Value| -> Option<Value> {
                    status
                        .get("value")
                        .cloned()
                        .or_else(|| status.get("register").and_then(|r| r.get("value")).cloned())
                };
                if cell_ref.starts_with("ck:cell:ck.component.mls.epoch.v1")
                    && let Some(value) = value_for(status)
                {
                    view.mls_epoch = value
                        .as_u64()
                        .or_else(|| value.get("epoch").and_then(|v| v.as_u64()));
                }
                if cell_ref.starts_with("ck:cell:ck.component.governance.covered_seals.v1")
                    && let Some(value) = value_for(status)
                {
                    view.covered_seals = value.as_str().map(str::to_owned).or_else(|| {
                        value
                            .get("frontier")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned)
                    });
                }
                // B3c: surface the MLS key schedule hash so the next
                // commit's SDK MLS governance binding can carry the
                // SDK-canonical "advance schedule" effect on it.
                if cell_ref.starts_with("ck:cell:ck.component.key_schedule.v1")
                    && let Some(value) = value_for(status)
                {
                    view.key_schedule_hash = value.as_str().map(str::to_owned).or_else(|| {
                        value
                            .get("hash")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned)
                    });
                }
            }
        }
        view.ingest_structured_bottoms(body);
        view
    }

    fn ingest_structured_bottoms(&mut self, body: &Value) {
        let Some(entries) = body.get("bottoms").and_then(|v| v.as_array()) else {
            return;
        };
        for entry in entries {
            let Some(bottom) = entry.get("bottom") else {
                continue;
            };
            let cell_ref = entry.get("cell").and_then(|v| v.as_str()).or_else(|| {
                bottom
                    .get("cells")
                    .and_then(|v| v.as_array())
                    .and_then(|cells| cells.first())
                    .and_then(|v| v.as_str())
            });
            let Some(cell_ref) = cell_ref else {
                continue;
            };
            if self.bottom_cells.contains_key(cell_ref) {
                continue;
            }
            let status = entry
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("bottom");
            let kind = bottom.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            if status != "conflict" && kind != "conflict" {
                continue;
            }
            let event_ids: Vec<String> = bottom
                .get("event_ids")
                .or_else(|| bottom.get("move_ids"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            let mut heads = Vec::new();
            if let Some(arr) = bottom.get("heads").and_then(|v| v.as_array()) {
                for (idx, value) in arr.iter().enumerate() {
                    let move_id = value
                        .get("move_id")
                        .and_then(|v| v.as_str())
                        .or_else(|| value.get("event_id").and_then(|v| v.as_str()))
                        .map(str::to_owned)
                        .or_else(|| event_ids.get(idx).cloned())
                        .unwrap_or_default();
                    let candidate = value.get("value").cloned().unwrap_or_else(|| value.clone());
                    heads.push(BottomCellHead {
                        move_id,
                        value: candidate,
                    });
                }
            } else {
                heads.extend(event_ids.into_iter().map(|move_id| BottomCellHead {
                    move_id,
                    value: Value::Null,
                }));
            }
            self.bottom_cells.insert(
                cell_ref.to_owned(),
                BottomCellInfo {
                    status: status.to_owned(),
                    heads,
                },
            );
        }
    }
}
