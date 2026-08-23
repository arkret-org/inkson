pub mod registration;

mod binding;
mod gateway;
mod request;
mod token_provider;
mod token_source;

// Expose the push API as the module's public surface.
// Imports kept at the module root so the (glob-importing) `tests`
// submodule resolves the chime types and `std::sync::Arc` it references.
#[cfg(test)]
use std::sync::Arc;

#[cfg(test)]
use arkret_models_integration::PushRegisterDeviceOutcome;
pub use binding::*;
#[cfg(test)]
use chime::PushBridgeDescribeOutcome;
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
