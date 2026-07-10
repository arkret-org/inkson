use std::sync::LazyLock;

pub use arkret_sdk::{
    AccountSubscribeFolder, AccountSubscribeReconnectAfter, AccountSubscribeSnapshotResult,
};
use tokio::sync::Mutex;

/// Keep account-subscribe network calls globally serial so duplicate UI tasks
/// cannot leave multiple pending long-polls in browser runtimes.
///
/// NDJSON parsing itself lives in the SDK (`account_subscribe_once` /
/// `AccountSubscribeFolder`), which runs the request-aware
/// `StreamTraceValidator` over every frame — inkson keeps no shape-only
/// parsing side path (SPI-INK-002).
pub(crate) static ACCOUNT_SUBSCRIBE_NETWORK_GATE: LazyLock<Mutex<()>> =
    LazyLock::new(|| Mutex::new(()));
