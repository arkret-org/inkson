//! Browser harness for the durable current index.
//!
//! The index's transaction, cancellation, poison and restart rules are proven
//! against real SQLite and AEAD in the crate's own tests. The IndexedDB backend
//! is a different transaction engine and owes the same evidence, but that can
//! only be collected from a `wasm-bindgen` target running in a real browser,
//! and such a target is an integration test that cannot reach a crate-private
//! type. Every method here forwards to the same production entry point the
//! native regressions drive; the harness adds no behaviour of its own and takes
//! JSON at its boundary so it never grows a second model of the wire types.
//! The observation methods only read durable state the native regressions read
//! directly, such as the reachability cycle position and seen evidence.

use arkret_sdk::CurrentSelector;
use arkret_sdk::sync::AccountSubscribeFrame;

use super::{CurrentIndex, CurrentIndexLocation, GcPhase, GcState, PAGE_LIMIT};

fn message(error: impl std::fmt::Display) -> String {
    error.to_string()
}

pub struct CurrentIndexHarness {
    index: CurrentIndex,
}

impl CurrentIndexHarness {
    /// Open the index of one account authority at its committed generation.
    pub async fn open(authority: &str, committed_generation: u64) -> Result<Self, String> {
        let authority = serde_json::from_str(authority).map_err(message)?;
        let index = CurrentIndex::open(&authority, committed_generation, CurrentIndexLocation {})
            .await
            .map_err(message)?;
        Ok(Self { index })
    }

    /// Install one frame and confirm the account pointer, as a caller that
    /// durably committed the generation does.
    pub async fn commit(&self, expected: u64, frame: &str) -> Result<u64, String> {
        let frame: AccountSubscribeFrame = serde_json::from_str(frame).map_err(message)?;
        let mut stage = self
            .index
            .stage_frame(expected, &frame)
            .await
            .map_err(message)?;
        let generation = stage.generation();
        stage.arm_account_commit();
        stage.finish();
        Ok(generation)
    }

    /// Install one frame and abandon it before the account pointer is armed.
    pub async fn abandon(&self, expected: u64, frame: &str) -> Result<(), String> {
        let frame: AccountSubscribeFrame = serde_json::from_str(frame).map_err(message)?;
        drop(
            self.index
                .stage_frame(expected, &frame)
                .await
                .map_err(message)?,
        );
        Ok(())
    }

    /// Install one frame, arm the account pointer, then lose the caller before
    /// the durable result is known.
    pub async fn abandon_armed(&self, expected: u64, frame: &str) -> Result<(), String> {
        let frame: AccountSubscribeFrame = serde_json::from_str(frame).map_err(message)?;
        let mut stage = self
            .index
            .stage_frame(expected, &frame)
            .await
            .map_err(message)?;
        stage.arm_account_commit();
        drop(stage);
        Ok(())
    }

    pub fn is_poisoned(&self) -> bool {
        self.index.is_poisoned()
    }

    pub fn confirm_durable_pointer(&self, generation: u64) -> Result<(), String> {
        self.index
            .confirm_durable_pointer(generation)
            .map_err(message)
    }

    /// The installed entry a product read would see, as canonical JSON.
    pub async fn read_ready(&self, realm: &str, selector: &str) -> Result<Option<String>, String> {
        let selector: CurrentSelector = serde_json::from_str(selector).map_err(message)?;
        let entry = self
            .index
            .read_selector_ready(realm, &selector)
            .await
            .map_err(message)?;
        entry
            .map(|entry| {
                arkret_sdk::canonical::canonical_json_bytes(&entry)
                    .map_err(message)
                    .and_then(|bytes| String::from_utf8(bytes).map_err(message))
            })
            .transpose()
    }

    /// One bounded page of the Realm's product-ready rows, as canonical JSON,
    /// with the cursor that resumes the scan.
    pub async fn read_realm_page(
        &self,
        realm: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<String>, Option<String>), String> {
        let page = self
            .index
            .read_realm_page(realm, after, limit)
            .await
            .map_err(message)?;
        let rows = page
            .entries
            .iter()
            .map(|entry| {
                arkret_sdk::canonical::canonical_json_bytes(entry)
                    .map_err(message)
                    .and_then(|bytes| String::from_utf8(bytes).map_err(message))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((rows, page.next_cursor))
    }

    pub async fn maintain(&self) -> Result<bool, String> {
        self.index.maintain().await.map_err(message)
    }

    /// Observation only: the durable reachability cycle's epoch and whether it
    /// has reached its sweep phase.
    pub async fn gc_position(&self) -> Result<(u64, bool), String> {
        let state: GcState = self
            .index
            .load_state(&self.index.gc_state_key())
            .await
            .map_err(message)?;
        Ok((state.epoch, state.phase == GcPhase::Sweep))
    }

    /// Observation only: the seen versions one snapshot holds for a selector.
    pub async fn seen_versions(
        &self,
        snapshot: &str,
        realm: &str,
        selector: &str,
    ) -> Result<usize, String> {
        let selector: CurrentSelector = serde_json::from_str(selector).map_err(message)?;
        let prefix = self
            .index
            .seen_prefix(snapshot, realm, &selector)
            .map_err(message)?;
        self.index
            .backend
            .keys(&prefix, None, None, PAGE_LIMIT)
            .await
            .map(|keys| keys.len())
            .map_err(message)
    }

    /// Observation only: the storage key prefix every entry of this account's
    /// index lives under.
    pub fn storage_prefix(&self) -> &str {
        &self.index.prefix
    }
}
