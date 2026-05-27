//! MLS (Messaging Layer Security) integration for yougen.
//!
//! Grouped from the former top-level `mls_governance` / `mls_passphrase`
//! / `mls_persistence` / `mimi_client` files. The `mimi_client` submodule
//! is the MIMI-protocol client built on top of MLS — kept under `mls::`
//! because every MIMI operation requires an MLS group context.

pub mod governance;
pub mod mimi_client;
pub mod passphrase;
pub mod persistence;
