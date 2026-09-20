//! Unit tests for the typed transport boundary and its wire helpers.
//! (the former inline `#[cfg(test)] mod tests { … }`), then carved by theme
//! into sibling child modules. Each submodule opens with `use super::super::*;`
//! so it resolves against the parent `api` module exactly as before — every
//! helper / classifier / builder under test (including the `pub(crate)`
//! transport methods now living in `transport.rs`) remains reachable unchanged.

mod demo_crypto;
mod endpoints_urls;
mod envelopes_payloads;
mod errors;
mod mls;
mod parsing_sync;
mod retry_requests;
