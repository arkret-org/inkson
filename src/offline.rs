use std::collections::VecDeque;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::api::{ContrixApi, NetworkState};
use crate::hlc::Hlc;

/// An operation queued while offline.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueuedOperation {
    /// Unique ID for this queued operation.
    pub id: String,
    /// The API endpoint path.
    pub endpoint: String,
    /// HTTP method (POST, PUT, DELETE).
    pub method: String,
    /// Request body (JSON).
    pub body: serde_json::Value,
    /// When the operation was queued.
    pub queued_at: Hlc,
    /// Space ID this operation belongs to (if any).
    pub space_id: Option<String>,
    /// Operation type for conflict resolution.
    pub op_type: Option<String>,
    /// Number of retry attempts.
    pub retries: u32,
    /// Maximum retries before giving up.
    pub max_retries: u32,
}

/// Result of replaying a queued operation.
#[derive(Clone, Debug)]
pub enum ReplayResult {
    /// Operation succeeded.
    Success(String),
    /// Operation failed but should be retried.
    RetryLater(String),
    /// Operation failed permanently.
    Failed(String),
    /// Operation was superseded by a newer operation.
    Superseded,
}

/// Offline queue for storing operations while disconnected.
#[derive(Clone, Debug)]
pub struct OfflineQueue {
    queue: Arc<RwLock<VecDeque<QueuedOperation>>>,
    max_size: usize,
}

impl OfflineQueue {
    pub fn new(max_size: usize) -> Self {
        Self {
            queue: Arc::new(RwLock::new(VecDeque::new())),
            max_size,
        }
    }

    /// Add an operation to the queue.
    pub async fn enqueue(&self, op: QueuedOperation) -> Result<(), OfflineError> {
        let mut queue = self.queue.write().await;
        if queue.len() >= self.max_size {
            return Err(OfflineError::QueueFull);
        }
        queue.push_back(op);
        Ok(())
    }

    /// Get the next operation to replay.
    pub async fn dequeue(&self) -> Option<QueuedOperation> {
        self.queue.write().await.pop_front()
    }

    /// Peek at the next operation without removing it.
    pub async fn peek(&self) -> Option<QueuedOperation> {
        self.queue.read().await.front().cloned()
    }

    /// Get the current queue size.
    pub async fn size(&self) -> usize {
        self.queue.read().await.len()
    }

    /// Check if the queue is empty.
    pub async fn is_empty(&self) -> bool {
        self.queue.read().await.is_empty()
    }

    /// Clear all queued operations.
    pub async fn clear(&self) {
        self.queue.write().await.clear();
    }

    /// Get all queued operations (for persistence).
    pub async fn drain_all(&self) -> Vec<QueuedOperation> {
        self.queue.write().await.drain(..).collect()
    }

    /// Restore operations from persistence.
    pub async fn restore(&self, ops: Vec<QueuedOperation>) {
        let mut queue = self.queue.write().await;
        for op in ops {
            if queue.len() < self.max_size {
                queue.push_back(op);
            }
        }
    }

    /// Remove operations matching a filter.
    pub async fn remove_where<F>(&self, predicate: F)
    where
        F: Fn(&QueuedOperation) -> bool,
    {
        self.queue.write().await.retain(|op| !predicate(op));
    }
}

impl Default for OfflineQueue {
    fn default() -> Self {
        Self::new(1000)
    }
}

/// Coordinates reconnection and replay of queued operations.
#[derive(Clone)]
pub struct ReconnectionCoordinator {
    queue: OfflineQueue,
    network_state: Arc<RwLock<NetworkState>>,
    on_state_change: Arc<RwLock<Option<Box<dyn Fn(NetworkState) + Send + Sync>>>>,
}

impl ReconnectionCoordinator {
    pub fn new(queue: OfflineQueue) -> Self {
        Self {
            queue,
            network_state: Arc::new(RwLock::new(NetworkState::Online)),
            on_state_change: Arc::new(RwLock::new(None)),
        }
    }

    /// Set a callback for network state changes.
    pub async fn on_state_change<F>(&self, callback: F)
    where
        F: Fn(NetworkState) + Send + Sync + 'static,
    {
        *self.on_state_change.write().await = Some(Box::new(callback));
    }

    /// Update network state and trigger callback.
    pub async fn set_state(&self, state: NetworkState) {
        {
            *self.network_state.write().await = state.clone();
        }
        if let Some(ref callback) = *self.on_state_change.read().await {
            callback(state);
        }
    }

    /// Get current network state.
    pub async fn state(&self) -> NetworkState {
        self.network_state.read().await.clone()
    }

    /// Check if we're online.
    pub async fn is_online(&self) -> bool {
        *self.network_state.read().await == NetworkState::Online
    }

    /// Replay all queued operations against the API.
    pub async fn replay_all(&self, api: &ContrixApi) -> Vec<ReplayResult> {
        let mut results = Vec::new();

        loop {
            let op = match self.queue.dequeue().await {
                Some(op) => op,
                None => break,
            };

            let result = self.replay_operation(api, &op).await;

            match &result {
                ReplayResult::RetryLater(_) => {
                    // Put it back at the front
                    let mut queue = self.queue.queue.write().await;
                    queue.push_front(op);
                    break; // Stop replaying
                }
                ReplayResult::Failed(_) => {
                    // Log failure but continue with next operation
                    results.push(result);
                    continue;
                }
                _ => {}
            }

            results.push(result);
        }

        results
    }

    /// Replay a single operation.
    async fn replay_operation(&self, api: &ContrixApi, op: &QueuedOperation) -> ReplayResult {
        // Use the API client to replay the operation
        // This is a simplified version - in production, you'd want proper
        // method dispatch and error handling
        match op.method.as_str() {
            "POST" => {
                let endpoint = api.endpoint(&op.endpoint);
                match endpoint {
                    Ok(url) => {
                        let response = api.http.post(url.as_str()).json(&op.body).send().await;

                        match response {
                            Ok(resp) => {
                                if resp.status().is_success() {
                                    ReplayResult::Success(format!(
                                        "replayed {} to {}",
                                        op.id, op.endpoint
                                    ))
                                } else if resp.status().is_server_error() {
                                    ReplayResult::RetryLater(format!(
                                        "server error: {}",
                                        resp.status()
                                    ))
                                } else {
                                    ReplayResult::Failed(format!("client error: {}", resp.status()))
                                }
                            }
                            Err(e) => ReplayResult::RetryLater(format!("network error: {e}")),
                        }
                    }
                    Err(e) => ReplayResult::Failed(format!("invalid endpoint: {e}")),
                }
            }
            "PUT" => {
                let endpoint = api.endpoint(&op.endpoint);
                match endpoint {
                    Ok(url) => {
                        let response = api.http.put(url.as_str()).json(&op.body).send().await;

                        match response {
                            Ok(resp) => {
                                if resp.status().is_success() {
                                    ReplayResult::Success(format!(
                                        "replayed {} to {}",
                                        op.id, op.endpoint
                                    ))
                                } else {
                                    ReplayResult::RetryLater(format!("error: {}", resp.status()))
                                }
                            }
                            Err(e) => ReplayResult::RetryLater(format!("network error: {e}")),
                        }
                    }
                    Err(e) => ReplayResult::Failed(format!("invalid endpoint: {e}")),
                }
            }
            "DELETE" => {
                let endpoint = api.endpoint(&op.endpoint);
                match endpoint {
                    Ok(url) => {
                        let response = api.http.delete(url.as_str()).send().await;

                        match response {
                            Ok(resp) => {
                                if resp.status().is_success() {
                                    ReplayResult::Success(format!(
                                        "replayed {} to {}",
                                        op.id, op.endpoint
                                    ))
                                } else {
                                    ReplayResult::RetryLater(format!("error: {}", resp.status()))
                                }
                            }
                            Err(e) => ReplayResult::RetryLater(format!("network error: {e}")),
                        }
                    }
                    Err(e) => ReplayResult::Failed(format!("invalid endpoint: {e}")),
                }
            }
            _ => ReplayResult::Failed(format!("unsupported method: {}", op.method)),
        }
    }

    /// Start a background connectivity monitor (native only).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn start_monitor(self, api: ContrixApi, check_interval: std::time::Duration) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(check_interval);
            loop {
                interval.tick().await;
                let was_online = self.is_online().await;
                let is_online = api.check_connectivity().await;

                if was_online && !is_online {
                    self.set_state(NetworkState::Offline).await;
                } else if !was_online && is_online {
                    self.set_state(NetworkState::Online).await;
                    // Replay queued operations
                    self.replay_all(&api).await;
                }
            }
        });
    }
}

/// Errors that can occur in offline operations.
#[derive(Clone, Debug, PartialEq)]
pub enum OfflineError {
    QueueFull,
    OperationFailed(String),
    NetworkOffline,
}

impl std::fmt::Display for OfflineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QueueFull => write!(f, "offline queue is full"),
            Self::OperationFailed(msg) => write!(f, "operation failed: {msg}"),
            Self::NetworkOffline => write!(f, "network is offline"),
        }
    }
}

impl std::error::Error for OfflineError {}

/// Builder for creating queued operations.
pub struct QueuedOperationBuilder {
    op: QueuedOperation,
}

impl QueuedOperationBuilder {
    pub fn new(endpoint: &str, method: &str) -> Self {
        Self {
            op: QueuedOperation {
                id: format!("qop-{}", crate::operation::uuid_v8()),
                endpoint: endpoint.to_owned(),
                method: method.to_owned(),
                body: serde_json::Value::Null,
                queued_at: Hlc::now("chask"),
                space_id: None,
                op_type: None,
                retries: 0,
                max_retries: 3,
            },
        }
    }

    pub fn with_body(mut self, body: serde_json::Value) -> Self {
        self.op.body = body;
        self
    }

    pub fn with_space(mut self, space_id: &str) -> Self {
        self.op.space_id = Some(space_id.to_owned());
        self
    }

    pub fn with_op_type(mut self, op_type: &str) -> Self {
        self.op.op_type = Some(op_type.to_owned());
        self
    }

    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.op.max_retries = max_retries;
        self
    }

    pub fn build(self) -> QueuedOperation {
        self.op
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_offline_queue_enqueue_dequeue() {
        let queue = OfflineQueue::new(100);
        let op = QueuedOperationBuilder::new("api/v1/messages", "POST")
            .with_body(serde_json::json!({"text": "hello"}))
            .build();
        let op_id = op.id.clone();

        queue.enqueue(op).await.unwrap();
        assert_eq!(queue.size().await, 1);

        let dequeued = queue.dequeue().await.unwrap();
        assert_eq!(dequeued.id, op_id);
        assert!(queue.is_empty().await);
    }

    #[tokio::test]
    async fn test_offline_queue_max_size() {
        let queue = OfflineQueue::new(2);

        for i in 0..2 {
            let op = QueuedOperationBuilder::new(&format!("api/v1/op/{i}"), "POST").build();
            queue.enqueue(op).await.unwrap();
        }

        let op = QueuedOperationBuilder::new("api/v1/op/overflow", "POST").build();
        assert!(queue.enqueue(op).await.is_err());
    }

    #[tokio::test]
    async fn test_offline_queue_clear() {
        let queue = OfflineQueue::new(100);
        let op = QueuedOperationBuilder::new("api/v1/messages", "POST").build();
        queue.enqueue(op).await.unwrap();

        queue.clear().await;
        assert!(queue.is_empty().await);
    }

    #[tokio::test]
    async fn test_offline_queue_drain_restore() {
        let queue = OfflineQueue::new(100);

        for i in 0..3 {
            let op = QueuedOperationBuilder::new(&format!("api/v1/op/{i}"), "POST").build();
            queue.enqueue(op).await.unwrap();
        }

        let ops = queue.drain_all().await;
        assert_eq!(ops.len(), 3);
        assert!(queue.is_empty().await);

        queue.restore(ops).await;
        assert_eq!(queue.size().await, 3);
    }

    #[tokio::test]
    async fn test_offline_queue_remove_where() {
        let queue = OfflineQueue::new(100);

        let op1 = QueuedOperationBuilder::new("api/v1/messages", "POST")
            .with_op_type("message")
            .build();
        let op2 = QueuedOperationBuilder::new("api/v1/reactions", "POST")
            .with_op_type("reaction")
            .build();
        let op3 = QueuedOperationBuilder::new("api/v1/messages", "POST")
            .with_op_type("message")
            .build();

        queue.enqueue(op1).await.unwrap();
        queue.enqueue(op2).await.unwrap();
        queue.enqueue(op3).await.unwrap();

        queue
            .remove_where(|op| op.op_type.as_deref() == Some("message"))
            .await;
        assert_eq!(queue.size().await, 1);
    }

    #[tokio::test]
    async fn test_reconnection_coordinator_state() {
        let queue = OfflineQueue::new(100);
        let coordinator = ReconnectionCoordinator::new(queue);

        assert!(coordinator.is_online().await);

        coordinator.set_state(NetworkState::Offline).await;
        assert!(!coordinator.is_online().await);
        assert_eq!(coordinator.state().await, NetworkState::Offline);

        coordinator.set_state(NetworkState::Online).await;
        assert!(coordinator.is_online().await);
    }

    #[test]
    fn test_queued_operation_builder() {
        let op = QueuedOperationBuilder::new("api/v1/messages", "POST")
            .with_body(serde_json::json!({"text": "hello"}))
            .with_space("cx:space:test")
            .with_op_type("message")
            .with_max_retries(5)
            .build();

        assert_eq!(op.endpoint, "api/v1/messages");
        assert_eq!(op.method, "POST");
        assert_eq!(op.space_id, Some("cx:space:test".to_owned()));
        assert_eq!(op.op_type, Some("message".to_owned()));
        assert_eq!(op.max_retries, 5);
    }

    #[test]
    fn test_offline_error_display() {
        assert_eq!(OfflineError::QueueFull.to_string(), "offline queue is full");
        assert_eq!(
            OfflineError::OperationFailed("test".to_owned()).to_string(),
            "operation failed: test"
        );
    }
}
