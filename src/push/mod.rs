pub mod native;
pub mod registration;

mod binding;
mod gateway;
mod request;
mod token_provider;
mod token_source;

// Re-export the full public surface so external callers keep using the
// historical `crate::push::*` paths unchanged after the structural split.
// Imports kept at the module root so the (glob-importing) `tests`
// submodule resolves the chime types and `std::sync::Arc` it references.
#[cfg(test)]
use std::sync::Arc;

pub use binding::*;
#[cfg(test)]
use chime::{ChimePushRegisterDeviceOutcome, PushBridgeDescribeOutcome};
pub use gateway::*;
pub use request::*;
pub use token_provider::*;

#[cfg(test)]
use crate::secure_key_store::SecureKeyStore;

/// Application identifier stamped into every register-device request.
pub(crate) const APP_ID: &str = "inkson";
#[cfg(test)]
#[allow(clippy::field_reassign_with_default)] // inner gateway field needs a separate type literal.
mod tests;
