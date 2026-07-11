// Pull in (and re-export to children) the symbols that `kanban/mod.rs`
// brought into scope via its own glob imports (`Value`, `json!`, `BTreeSet`,
// `dioxus`, `arkret_sdk`, `crate::transport::*`, `crate::state::*`,
// `crate::operation::*`, etc.). Re-exporting the glob makes those names
// reachable as `crate::views::kanban::model::<name>`, so every child
// sub-module's `use super::*;` resolves them transitively.
// Imports that the model subtree relies on but that the (component-only)
// `kanban/mod.rs` no longer brings into scope after the structural split.
// Re-exported here so every child sub-module's `use super::*;` resolves them.
use std::borrow::Cow;

pub(crate) use super::*;
use crate::components::WriteState;
use crate::operation::trim_realm_id;
use crate::state::RawOperationRecord;

mod board_projection;
mod calendar;
mod constants;
mod entities;
mod mls;
mod overlays;
mod projection;
mod strand;

pub(crate) use board_projection::*;
pub(crate) use calendar::*;
pub(crate) use constants::*;
pub(crate) use entities::*;
pub(crate) use mls::*;
pub(crate) use overlays::*;
pub(crate) use projection::*;
pub(crate) use strand::*;
