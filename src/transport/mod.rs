pub mod account;
pub mod auth;
mod blob;
pub mod circle;
mod contacts;
mod context;
pub(crate) mod describe_cache;
pub mod directory;
mod endpoints;
mod invite;
mod invite_join;
mod key_backup;
pub mod keys;
pub mod media;
pub mod moderation;
pub mod realm_read;
pub mod realm_write;
pub mod websocket;
pub mod websocket_rail;

pub use blob::BlobEndpoints;
pub use context::{RequestContext, TransportClient};
pub use endpoints::EndpointClients;
pub use invite::InviteeResolution;
pub use media::MediaEndpoints;

#[cfg(test)]
mod tests;
