//! Share only live, equivalent projection reads; retain no result cache.

use std::sync::Arc;

use arkret_sdk::http_client::Client;
use arkret_sdk::http_client::own_station_results::OwnStationSessionSnapshot;
use arkret_sdk::{ProjectionSpaceRow, ProjectionStrandRow, RealmId};
use futures_util::FutureExt;
use futures_util::future::{Shared, WeakShared};

#[derive(Clone, PartialEq, Eq)]
struct ReadKey {
    session: OwnStationSessionSnapshot,
    realm: RealmId,
    read_fence: crate::state::RealmListReadFence,
}

#[derive(Clone, Debug)]
struct ReadFailure(Arc<anyhow::Error>);

impl std::fmt::Display for ReadFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.0.as_ref(), formatter)
    }
}

impl std::error::Error for ReadFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref().as_ref())
    }
}

impl From<anyhow::Error> for ReadFailure {
    fn from(error: anyhow::Error) -> Self {
        Self(Arc::new(error))
    }
}

type ReadResult<T> = Result<Arc<Vec<T>>, ReadFailure>;
#[cfg(not(target_arch = "wasm32"))]
type ReadFuture<T> = futures_util::future::BoxFuture<'static, ReadResult<T>>;
#[cfg(target_arch = "wasm32")]
type ReadFuture<T> = futures_util::future::LocalBoxFuture<'static, ReadResult<T>>;

struct ReadFlights<T> {
    entries: Vec<(ReadKey, WeakShared<ReadFuture<T>>)>,
}

impl<T> Default for ReadFlights<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<T> ReadFlights<T> {
    fn join(
        &mut self,
        key: ReadKey,
        make: impl FnOnce() -> ReadFuture<T>,
    ) -> Shared<ReadFuture<T>> {
        // Completed results must not become an accidental current cache, even
        // if a slow original waiter still retains a ready shared future.
        self.entries.retain(|(_, flight)| {
            flight
                .upgrade()
                .is_some_and(|flight| flight.peek().is_none())
        });
        if let Some(flight) = self
            .entries
            .iter()
            .find_map(|(existing, flight)| (existing == &key).then(|| flight.upgrade()).flatten())
        {
            return flight;
        }
        let flight = make().shared();
        if let Some(weak) = flight.downgrade() {
            self.entries.push((key, weak));
        }
        flight
    }
}

#[derive(Default)]
struct ProjectionFlights {
    spaces: ReadFlights<ProjectionSpaceRow>,
    strands: ReadFlights<ProjectionStrandRow>,
}

#[cfg(not(target_arch = "wasm32"))]
fn with_flights<R>(read: impl FnOnce(&mut ProjectionFlights) -> R) -> R {
    static FLIGHTS: std::sync::OnceLock<std::sync::Mutex<ProjectionFlights>> =
        std::sync::OnceLock::new();
    let mut flights = FLIGHTS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    read(&mut flights)
}

#[cfg(target_arch = "wasm32")]
fn with_flights<R>(read: impl FnOnce(&mut ProjectionFlights) -> R) -> R {
    thread_local! {
        static FLIGHTS: std::cell::RefCell<ProjectionFlights> = Default::default();
    }
    FLIGHTS.with(|flights| read(&mut flights.borrow_mut()))
}

async fn read<T: Clone + Send + Sync + 'static>(
    http: &Client,
    realm: RealmId,
    read_fence: Option<crate::state::RealmListReadFence>,
    select: fn(&mut ProjectionFlights) -> &mut ReadFlights<T>,
    fetch: fn(Client, RealmId) -> ReadFuture<T>,
) -> anyhow::Result<Vec<T>> {
    let bound = crate::transport::own_station_results::client_for_http(http).await?;
    let Some(read_fence) = read_fence else {
        // Unscoped callers cannot assert equivalence across a leave/rejoin.
        // Preserve their independent read and the same per-page session gate.
        let result = fetch(bound.http_client()?, realm).await;
        bound.check_session()?;
        return result.map(|rows| (*rows).clone()).map_err(Into::into);
    };
    let key = ReadKey {
        session: bound.session()?.clone(),
        realm: realm.clone(),
        read_fence,
    };
    let worker = bound.clone();
    let http = bound.http_client()?;
    let flight = with_flights(|flights| {
        select(flights).join(key, || {
            Box::pin(async move {
                worker
                    .check_session()
                    .map_err(anyhow::Error::from)
                    .map_err(ReadFailure::from)?;
                let result = fetch(http, realm).await;
                worker
                    .check_session()
                    .map_err(anyhow::Error::from)
                    .map_err(ReadFailure::from)?;
                result
            })
        })
    });
    let result = flight.await;
    // Every waiter checks its own live host session after the shared work.
    // Dropping one waiter drops only its clone; the others keep their read.
    bound.check_session()?;
    result.map(|rows| (*rows).clone()).map_err(Into::into)
}

pub(super) async fn spaces(
    http: &Client,
    realm: RealmId,
    read_fence: Option<crate::state::RealmListReadFence>,
) -> anyhow::Result<Vec<ProjectionSpaceRow>> {
    read(
        http,
        realm,
        read_fence,
        |flights| &mut flights.spaces,
        |http, realm| {
            Box::pin(async move {
                super::list_realm_spaces_pages(&http, &realm)
                    .await
                    .map(Arc::new)
                    .map_err(Into::into)
            })
        },
    )
    .await
}

pub(super) async fn strands(
    http: &Client,
    realm: RealmId,
    read_fence: Option<crate::state::RealmListReadFence>,
) -> anyhow::Result<Vec<ProjectionStrandRow>> {
    read(
        http,
        realm,
        read_fence,
        |flights| &mut flights.strands,
        |http, realm| {
            Box::pin(async move {
                super::list_realm_strands_pages(&http, &realm)
                    .await
                    .map(Arc::new)
                    .map_err(Into::into)
            })
        },
    )
    .await
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
