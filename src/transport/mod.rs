pub mod account;
pub mod auth;
mod blob;
pub mod circle;
mod contacts;
mod context;
pub mod directory;
mod endpoints;
mod invite;
mod invite_join;
mod key_backup;
pub mod keys;
pub mod media;
pub mod realm_read;
pub mod realm_write;

pub use blob::{BlobEndpoints, RESUMABLE_UPLOAD_THRESHOLD_BYTES};
pub use context::{RequestContext, TransportClient};
pub use endpoints::{
    AccountEndpoints, DirectoryEndpoints, EndpointClients, KeysEndpoints, MlsEndpoints,
};
pub use media::MediaEndpoints;

#[cfg(test)]
mod tests;
