//! MLS (Messaging Layer Security) integration for yougen.
//!
//! Grouped from the former top-level MLS governance, persistence, and
//! MIMI client files. The `mimi_client` submodule
//! is the MIMI-protocol client built on top of MLS — kept under `mls::`
//! because every MIMI operation requires an MLS group context.

pub mod account_recovery;
pub mod governance;
pub mod mimi_client;
pub mod persistence;
pub mod runtime;
