//! Unit tests for the self-API client. Structural move out of `api/mod.rs`
//! (the former inline `#[cfg(test)] mod tests { … }`), then carved by theme
//! into sibling child modules. Each submodule opens with `use super::super::*;`
//! so it resolves against the parent `api` module exactly as before — every
//! helper / classifier / builder under test (including the `pub(crate)`
//! transport methods now living in `transport.rs`) remains reachable unchanged.

mod demo_crypto;
mod endpoints_urls;
mod envelopes_payloads;
mod errors;
mod handles;
mod parsing_sync;
mod retry_requests;
