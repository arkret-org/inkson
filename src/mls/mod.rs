//! MLS (Messaging Layer Security) integration for yougen.
//!
//! Grouped from the former top-level MLS governance and persistence files.
//! MIMI protocol calls live in `crate::api::mls`, which uses the shared SDK
//! request/response types directly.

pub mod account_recovery;
pub(crate) mod admission;
pub mod durability;
pub mod governance;
pub mod persistence;
pub mod runtime;
pub mod secret_share;
