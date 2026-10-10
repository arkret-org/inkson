//! One authenticated socket with independently owned canonical rail channels.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};

use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeFrameKind, AccountSubscribeSnapshotResult, SyncRequestBody,
};
use arkret_models_collaboration::sync_frames::websocket::*;
use arkret_wire::websocket_binding::WebSocketOperationId;
use garth::websocket::{BoxSocketFuture, WebSocketPacer};

use super::websocket::{
    WebSocketHandshakeFailure, WebSocketTransportDecision, WebSocketTransportSelector,
};

const CHANNEL_FRAMES: usize = 32;
const CHANNEL_BYTES: usize = 8 * 1024 * 1024;
const CONNECTION_FRAMES: usize = 128;
const CONNECTION_BYTES: usize = 16 * 1024 * 1024;
const USED_CHANNELS: usize = 4096;

#[derive(Clone, Copy, Debug, Default)]
pub struct InksonPacer;
impl WebSocketPacer for InksonPacer {
    fn pace(&self) -> BoxSocketFuture<'_, ()> {
        Box::pin(async move {
            crate::runtime_helpers::sleep_for(garth::websocket::socket::CHANNEL_PACE).await;
            Ok(())
        })
    }
}

#[derive(Debug)]
enum ChannelFailure {
    Local(String),
    Remote(arkret_wire::Problem),
}

#[derive(Debug)]
struct ChannelQueue {
    operation: WebSocketOperationId,
    selector: Vec<u8>,
    frames: VecDeque<(WebSocketServerFrame, usize)>,
    bytes: usize,
    sent: bool,
    opened: bool,
    abandoned: bool,
    closed: bool,
    failure: Option<ChannelFailure>,
}
#[derive(Debug, Default)]
struct RailQueues {
    channels: BTreeMap<String, ChannelQueue>,
    commands: VecDeque<WebSocketClientFrame>,
    refused: BTreeSet<Vec<u8>>,
    used: usize,
    pending_bytes: usize,
    pending_frames: usize,
    ready: bool,
    closed: bool,
}
#[derive(Clone, Debug, Default)]
pub struct SharedConnection {
    queues: Arc<Mutex<RailQueues>>,
}

fn operation(parameters: &WebSocketOpenParameters) -> WebSocketOperationId {
    match parameters {
        WebSocketOpenParameters::Account(_) => WebSocketOperationId::AccountStreamSubscribe,
        WebSocketOpenParameters::Events(_) => WebSocketOperationId::CommittedEventStreamSubscribe,
        WebSocketOpenParameters::Signal(_) => WebSocketOperationId::SignalStreamSubscribe,
    }
}
fn selector_key(parameters: &WebSocketOpenParameters) -> garth::Result<Vec<u8>> {
    let mut value =
        serde_json::to_value(parameters).map_err(|e| garth::Error::Protocol(e.to_string()))?;
    if let Some(object) = value.as_object_mut() {
        for name in ["after", "catchup", "replace_filter"] {
            object.remove(name);
        }
    }
    Ok(arkret_sdk::canonical::canonical_json_bytes(&(
        operation(parameters),
        value,
    ))?)
}

impl SharedConnection {
    pub fn new() -> Self {
        Self::default()
    }
    fn with<R>(&self, f: impl FnOnce(&mut RailQueues) -> R) -> R {
        f(&mut self.queues.lock().unwrap_or_else(|p| p.into_inner()))
    }
    pub fn set_ready(&self, ready: bool) {
        self.with(|q| q.ready = ready);
    }
    pub fn can_open(&self, parameters: &WebSocketOpenParameters) -> bool {
        let Ok(key) = selector_key(parameters) else {
            return false;
        };
        self.with(|q| q.ready && !q.closed && !q.refused.contains(&key))
    }
    pub fn open(
        &self,
        parameters: WebSocketOpenParameters,
    ) -> garth::Result<Option<SocketChannel>> {
        let key = selector_key(&parameters)?;
        parameters.validate_for(operation(&parameters))?;
        self.with(|q| {
            if !q.ready || q.closed || q.refused.contains(&key) {
                return Ok(None);
            }
            if q.used >= USED_CHANNELS
                || q.channels
                    .values()
                    .filter(|c| !c.closed && !c.abandoned)
                    .count()
                    >= 16
            {
                return Ok(None);
            }
            let operation = operation(&parameters);
            if operation != WebSocketOperationId::CommittedEventStreamSubscribe
                && q.channels
                    .values()
                    .any(|c| c.operation == operation && !c.closed && !c.abandoned)
            {
                return Err(garth::Error::Protocol(
                    "another consumer owns this socket operation".to_owned(),
                ));
            }
            let id = crate::operation::uuid_v7();
            let open = WebSocketClientFrame::Open {
                channel_id: id.clone(),
                operation_id: operation,
                parameters,
            };
            open.validate()?;
            q.channels.insert(
                id.clone(),
                ChannelQueue {
                    operation,
                    selector: key,
                    frames: VecDeque::new(),
                    bytes: 0,
                    sent: false,
                    opened: false,
                    abandoned: false,
                    closed: false,
                    failure: None,
                },
            );
            q.used += 1;
            q.commands.push_back(open);
            Ok(Some(SocketChannel {
                id,
                connection: self.clone(),
            }))
        })
    }
    pub fn next_command(&self) -> Option<WebSocketClientFrame> {
        self.with(|q| {
            let command = if q.ready {
                q.commands.pop_front()?
            } else {
                let index = q
                    .commands
                    .iter()
                    .position(|command| !matches!(command, WebSocketClientFrame::Open { .. }))?;
                q.commands.remove(index)?
            };
            if let WebSocketClientFrame::Open { channel_id, .. } = &command
                && let Some(c) = q.channels.get_mut(channel_id)
            {
                c.sent = true;
            }
            Some(command)
        })
    }
    fn abandon(&self, id: &str) {
        self.with(|q| {
            let Some(c) = q.channels.get_mut(id) else { return; };
            if c.abandoned { return; }
            q.pending_bytes -= c.bytes;
            q.pending_frames -= c.frames.len();
            c.bytes = 0;
            c.frames.clear();
            c.abandoned = true;
            if !c.sent {
                q.commands.retain(|f| !matches!(f, WebSocketClientFrame::Open { channel_id, .. } if channel_id == id));
                q.channels.remove(id);
            } else if !c.closed {
                q.commands.push_back(WebSocketClientFrame::Close { channel_id: id.to_owned(), reason: WebSocketCloseReason::ClientRequest });
            }
        });
    }
    /// A failure is confined to this selector on this physical connection.
    pub fn refuse(&self, id: &str, reason: &str) {
        self.with(|q| {
            if let Some(c) = q.channels.get_mut(id) {
                q.refused.insert(c.selector.clone());
                c.failure = Some(ChannelFailure::Local(reason.to_owned()));
            }
        });
        self.abandon(id);
    }
    pub fn close(&self) {
        self.with(|q| {
            q.closed = true;
            q.ready = false;
            for c in q.channels.values_mut() {
                c.closed = true;
            }
        });
    }
    pub fn publish(&self, frame: WebSocketServerFrame) -> garth::Result<()> {
        let id = frame
            .channel_id()
            .ok_or_else(|| {
                garth::Error::Protocol("connection frame cannot enter a channel queue".to_owned())
            })?
            .to_owned();
        let bytes = arkret_sdk::canonical::canonical_json_bytes(&frame)?.len();
        let full = self.with(|q| -> garth::Result<bool> {
            let c = q.channels.get_mut(&id).ok_or_else(|| garth::Error::Protocol("unsolicited socket channel".to_owned()))?;
            match &frame {
                WebSocketServerFrame::Opened { operation_id, .. } => {
                    if c.opened || *operation_id != c.operation { return Err(garth::Error::Protocol("unexpected opened operation".to_owned())); }
                    c.opened = true;
                    return Ok(false);
                }
                WebSocketServerFrame::Data { .. } | WebSocketServerFrame::ChannelControl { .. } if !c.opened => {
                    return Err(garth::Error::Protocol("data before opened".to_owned()));
                }
                WebSocketServerFrame::ChannelError { error, .. } => {
                    let problem = arkret_wire::Problem::new(
                        error.code.as_str(), error.code.http_status(), error.message.clone(),
                    );
                    let failure = garth::Error::Api {
                        status: problem.status,
                        error: Box::new(problem.clone()),
                    };
                    // A bad resume handle retires only that handle. The
                    // consumer can reopen this selector after clearing it.
                    if !failure.is_invalid_cursor() {
                        q.refused.insert(c.selector.clone());
                    }
                    c.failure = Some(ChannelFailure::Remote(problem));
                    c.closed = true;
                    return Ok(false);
                }
                WebSocketServerFrame::Closed { .. } => { c.closed = true; return Ok(false); }
                _ => {}
            }
            if c.abandoned { return Ok(false); }
            if c.closed { return Err(garth::Error::Protocol("frame after channel termination".to_owned())); }
            let signal_data = matches!(&frame, WebSocketServerFrame::Data { payload: WebSocketDataPayload::Signal(_), .. });
            let account = c.operation == WebSocketOperationId::AccountStreamSubscribe;
            let full = c.frames.len() >= CHANNEL_FRAMES || c.bytes + bytes > CHANNEL_BYTES
                || q.pending_frames >= CONNECTION_FRAMES - if account { 0 } else { CHANNEL_FRAMES }
                || q.pending_bytes + bytes > CONNECTION_BYTES - if account { 0 } else { CHANNEL_BYTES };
            if full { return Ok(!signal_data); }
            if matches!(&frame, WebSocketServerFrame::ChannelControl { payload, .. } if payload.is_terminal()) { c.closed = true; }
            c.bytes += bytes;
            c.frames.push_back((frame, bytes));
            q.pending_bytes += bytes;
            q.pending_frames += 1;
            Ok(false)
        })?;
        if full {
            self.refuse(&id, "socket channel backlog");
        }
        Ok(())
    }
    fn pop(&self, id: &str) -> garth::Result<Option<WebSocketServerFrame>> {
        self.with(|q| {
            let c = q
                .channels
                .get_mut(id)
                .ok_or_else(|| garth::Error::Http("socket channel retired".to_owned()))?;
            if let Some((frame, bytes)) = c.frames.pop_front() {
                c.bytes -= bytes;
                q.pending_bytes -= bytes;
                q.pending_frames -= 1;
                return Ok(Some(frame));
            }
            if let Some(failure) = &c.failure {
                return Err(match failure {
                    ChannelFailure::Local(reason) => garth::Error::Http(reason.clone()),
                    ChannelFailure::Remote(problem) => garth::Error::Api {
                        status: problem.status,
                        error: Box::new(problem.clone()),
                    },
                });
            }
            if q.closed || c.closed {
                return Err(garth::Error::Http("socket channel closed".to_owned()));
            }
            Ok(None)
        })
    }
}

/// Only the consumer owns this handle; dropping it cancels this channel.
#[derive(Debug)]
pub struct SocketChannel {
    id: String,
    connection: SharedConnection,
}
impl Drop for SocketChannel {
    fn drop(&mut self) {
        self.connection.abandon(&self.id);
    }
}
impl SocketChannel {
    pub async fn next_frame(&mut self) -> garth::Result<WebSocketServerFrame> {
        loop {
            if let Some(frame) = self.connection.pop(&self.id)? {
                return Ok(frame);
            }
            InksonPacer.pace().await?;
        }
    }
    pub async fn next_event_frame(&mut self) -> garth::Result<Option<arkret_models_collaboration::sync_frames::committed_event_subscribe::CommittedEventSubscribeFrame>>{
        match self.next_frame().await? {
            WebSocketServerFrame::Data {
                payload: WebSocketDataPayload::Events(frame),
                ..
            }
            | WebSocketServerFrame::ChannelControl {
                payload: WebSocketChannelControlPayload::Events(frame),
                ..
            } => Ok(Some(*frame)),
            WebSocketServerFrame::ChannelControl {
                payload: WebSocketChannelControlPayload::Heartbeat(_),
                ..
            } => Ok(Some(
                serde_json::from_value(serde_json::json!({"kind":"heartbeat"}))
                    .map_err(|e| garth::Error::Protocol(e.to_string()))?,
            )),
            _ => Err(garth::Error::Protocol(
                "wrong committed channel payload".to_owned(),
            )),
        }
    }
}
impl garth::signal::SignalFrameSource for SocketChannel {
    async fn next_frame(&mut self) -> garth::Result<Option<arkret_wire::SignalStreamFrame>> {
        match SocketChannel::next_frame(self).await? {
            WebSocketServerFrame::Data {
                payload: WebSocketDataPayload::Signal(frame),
                ..
            }
            | WebSocketServerFrame::ChannelControl {
                payload: WebSocketChannelControlPayload::Signal(frame),
                ..
            } => Ok(Some(*frame)),
            WebSocketServerFrame::ChannelControl {
                payload: WebSocketChannelControlPayload::Heartbeat(_),
                ..
            } => Ok(Some(arkret_wire::SignalStreamFrame::Heartbeat)),
            _ => Err(garth::Error::Protocol(
                "wrong Signal channel payload".to_owned(),
            )),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct WebSocketRail {
    inner: Arc<Mutex<RailState>>,
}
#[derive(Debug, Default)]
struct RailState {
    connection: Option<SharedConnection>,
    selector: Option<WebSocketTransportSelector>,
}
impl WebSocketRail {
    fn with<R>(&self, f: impl FnOnce(&mut RailState) -> R) -> R {
        f(&mut self.inner.lock().unwrap_or_else(|p| p.into_inner()))
    }
    pub fn set_selector(&self, selector: WebSocketTransportSelector) {
        self.with(|s| s.selector = Some(selector));
    }
    pub fn is_advertised(&self) -> bool {
        self.with(|s| {
            s.selector
                .as_ref()
                .is_some_and(|v| v.descriptor().is_some())
        })
    }
    pub fn base_url(&self) -> Option<String> {
        self.with(|s| {
            s.selector
                .as_ref()
                .and_then(|v| v.descriptor())
                .map(|v| v.base_url.clone())
        })
    }
    pub fn max_frame_bytes(&self) -> Option<u32> {
        self.with(|s| {
            s.selector
                .as_ref()
                .and_then(|v| v.descriptor())
                .map(|v| v.max_frame_bytes)
        })
    }
    pub fn attach(&self, connection: SharedConnection) {
        self.with(|s| s.connection = Some(connection));
    }
    pub fn detach(&self) {
        self.with(|s| {
            if let Some(c) = s.connection.take() {
                c.close();
            }
        });
    }
    pub fn is_live(&self) -> bool {
        self.connection()
            .is_some_and(|c| c.with(|q| q.ready && !q.closed))
    }
    pub fn connection(&self) -> Option<SharedConnection> {
        self.with(|s| s.connection.clone())
    }
    pub fn can_open(&self, parameters: &WebSocketOpenParameters) -> bool {
        self.connection().is_some_and(|c| c.can_open(parameters))
    }
    pub fn open(
        &self,
        parameters: WebSocketOpenParameters,
    ) -> garth::Result<Option<SocketChannel>> {
        match self.connection() {
            Some(c) => c.open(parameters),
            None => Ok(None),
        }
    }
    pub fn on_close(
        &self,
        code: arkret_wire::websocket_binding::WebSocketCloseCode,
        delay: Option<u32>,
    ) -> WebSocketTransportDecision {
        self.detach();
        self.with(|s| {
            s.selector
                .as_mut()
                .map_or(WebSocketTransportDecision::FallbackHttp, |v| {
                    v.on_close(code, delay)
                })
        })
    }
    pub fn on_handshake_failure(
        &self,
        failure: WebSocketHandshakeFailure,
    ) -> WebSocketTransportDecision {
        self.detach();
        self.with(|s| {
            s.selector
                .as_mut()
                .map_or(WebSocketTransportDecision::FallbackHttp, |v| {
                    v.on_handshake_failure(failure)
                })
        })
    }
    pub fn welcomed(&self) {
        self.with(|s| {
            if let Some(v) = s.selector.as_mut() {
                v.welcomed();
            }
        });
    }
}

#[derive(Clone, Debug)]
pub struct StreamRail<H> {
    http: H,
    rail: WebSocketRail,
}
impl<H> StreamRail<H> {
    pub fn select(rail: &WebSocketRail, http: H) -> Self {
        Self {
            http,
            rail: rail.clone(),
        }
    }
    pub fn http(&self) -> &H {
        &self.http
    }
}
impl<H: garth::AccountSubscribeTransport> garth::AccountSubscribeTransport for StreamRail<H> {
    async fn subscribe(
        &self,
        request: &SyncRequestBody,
    ) -> garth::Result<AccountSubscribeSnapshotResult> {
        let parameters = WebSocketOpenParameters::Account(WebSocketAccountOpenParameters {
            after: request.after.clone(),
            catchup: request.catchup,
            filter: request.filter.clone(),
            wait_for: None,
            realm_list: request.realm_list.clone(),
            replace_filter: request.replace_filter,
        });
        if let Some(mut channel) = self.rail.open(parameters.clone())? {
            let mut folder = arkret_sdk::http_client::AccountSubscribeFolder::for_request(request);
            loop {
                let frame = match channel.next_frame().await? {
                    WebSocketServerFrame::Data {
                        payload: WebSocketDataPayload::Account(f),
                        ..
                    }
                    | WebSocketServerFrame::ChannelControl {
                        payload: WebSocketChannelControlPayload::Account(f),
                        ..
                    } => *f,
                    WebSocketServerFrame::ChannelControl {
                        payload: WebSocketChannelControlPayload::Heartbeat(_),
                        ..
                    } => serde_json::from_value(serde_json::json!({"kind":"heartbeat"}))
                        .map_err(|e| garth::Error::Protocol(e.to_string()))?,
                    _ => {
                        return Err(garth::Error::Protocol(
                            "wrong account channel payload".to_owned(),
                        ));
                    }
                };
                let kind = frame.kind;
                let interrupt = frame.interrupt()?;
                let done = folder.push(frame)?;
                if let Some(interrupt) = interrupt {
                    return Err(
                        arkret_sdk::http_client::Error::AccountStreamInterrupt(interrupt).into(),
                    );
                }
                if done
                    || (!request.catchup.unwrap_or(false)
                        && kind == AccountSubscribeFrameKind::Delta)
                    || (kind == AccountSubscribeFrameKind::Heartbeat
                        && folder.reconnect_cursor().is_some()
                        && !request.catchup.unwrap_or(false))
                {
                    return Ok(folder.finish()?);
                }
            }
        }
        let pending = self.http.subscribe(request);
        let mut pending = Box::pin(pending);
        loop {
            use futures_util::future::{Either, select};
            match select(pending, Box::pin(InksonPacer.pace())).await {
                Either::Left((result, _)) => return result,
                Either::Right((paced, future)) => {
                    paced?;
                    pending = future;
                    if self.rail.can_open(&parameters) {
                        // Dropping the HTTP future precedes any socket open.
                        return Err(garth::Error::Http("account transport handoff".to_owned()));
                    }
                }
            }
        }
    }
}

pub enum CommittedRailSource {
    Http { stream: arkret_sdk::http_client::CommittedEventSubscribeFrameStream, rail: WebSocketRail, parameters: WebSocketOpenParameters },
    Socket { channel: SocketChannel, trace: arkret_models_collaboration::sync_frames::committed_event_subscribe::CommittedEventStreamTrace },
}
impl CommittedRailSource {
    pub async fn open(
        http: &arkret_sdk::http_client::Client,
        rail: &WebSocketRail,
        realm: arkret_sdk::RealmId,
        after: Option<String>,
    ) -> garth::Result<Self> {
        let parameters = WebSocketOpenParameters::Events(WebSocketEventsOpenParameters {
            realm_ids: Some(vec![realm.clone()]),
            actor_ids: None,
            catchup: after.as_ref().map(|_| true),
            after: after.clone(),
        });
        if let Some(channel) = rail.open(parameters.clone())? {
            return Ok(Self::Socket { channel, trace: arkret_models_collaboration::sync_frames::committed_event_subscribe::CommittedEventStreamTrace::new(after.is_some(), after) });
        }
        let mut options =
            arkret_sdk::http_client::CommittedEventSubscribeOptions::new().realm(realm);
        if let Some(after) = after {
            options = options.after(after).catchup(true);
        }
        Ok(Self::Http {
            stream: http.committed_event_subscribe_frames(&options).await?,
            rail: rail.clone(),
            parameters,
        })
    }
    pub async fn next_frame(&mut self) -> garth::Result<Option<arkret_models_collaboration::sync_frames::committed_event_subscribe::CommittedEventSubscribeFrame>>{
        match self {
            Self::Socket { channel, trace } => {
                let frame = channel.next_event_frame().await?;
                if let Some(frame) = &frame {
                    trace
                        .push(frame)
                        .map_err(|e| garth::Error::Protocol(e.to_string()))?;
                }
                Ok(frame)
            }
            Self::Http {
                stream,
                rail,
                parameters,
            } => loop {
                use futures_util::future::{Either, select};
                if rail.can_open(parameters) {
                    return Err(garth::Error::Http("committed transport handoff".to_owned()));
                }
                match select(Box::pin(stream.next_frame()), Box::pin(InksonPacer.pace())).await {
                    Either::Left((frame, _)) => return Ok(frame?),
                    Either::Right((paced, _)) => {
                        paced?;
                    }
                }
            },
        }
    }
}

pub enum SignalRailSource {
    Http {
        stream: arkret_sdk::http_client::SignalSubscribeFrameStream,
        rail: WebSocketRail,
    },
    Socket(SocketChannel),
}
impl SignalRailSource {
    pub async fn open(
        http: &arkret_sdk::http_client::Client,
        rail: &WebSocketRail,
    ) -> garth::Result<Self> {
        if let Some(channel) = rail.open(WebSocketOpenParameters::Signal(
            WebSocketSignalOpenParameters {},
        ))? {
            return Ok(Self::Socket(channel));
        }
        Ok(Self::Http {
            stream: http.signal_subscribe_frames().await?,
            rail: rail.clone(),
        })
    }
}
impl garth::signal::SignalFrameSource for SignalRailSource {
    async fn next_frame(&mut self) -> garth::Result<Option<arkret_wire::SignalStreamFrame>> {
        match self {
            Self::Socket(channel) => garth::signal::SignalFrameSource::next_frame(channel).await,
            Self::Http { stream, rail } => loop {
                use futures_util::future::{Either, select};
                if rail.can_open(&WebSocketOpenParameters::Signal(
                    WebSocketSignalOpenParameters {},
                )) {
                    return Err(garth::Error::Http("Signal transport handoff".to_owned()));
                }
                match select(Box::pin(stream.next_frame()), Box::pin(InksonPacer.pace())).await {
                    Either::Left((frame, _)) => return Ok(frame?),
                    Either::Right((paced, _)) => {
                        paced?;
                    }
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn account_wait_targets_have_distinct_channel_identity() {
        let first = WebSocketOpenParameters::Account(WebSocketAccountOpenParameters {
            wait_for: Some("ak:cursor:01".into()),
            ..Default::default()
        });
        let second = WebSocketOpenParameters::Account(WebSocketAccountOpenParameters {
            wait_for: Some("ak:cursor:02".into()),
            ..Default::default()
        });
        assert_ne!(
            selector_key(&first).unwrap(),
            selector_key(&second).unwrap()
        );
    }
    fn signal() -> WebSocketOpenParameters {
        WebSocketOpenParameters::Signal(WebSocketSignalOpenParameters::default())
    }
    fn events() -> WebSocketOpenParameters {
        WebSocketOpenParameters::Events(WebSocketEventsOpenParameters {
            realm_ids: Some(vec![arkret_sdk::RealmId::from_event_id(
                &arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [7; 32]),
            )]),
            actor_ids: None,
            after: None,
            catchup: None,
        })
    }
    #[test]
    fn unpublished_and_unadvertised_rail_keeps_http_available() {
        let rail = WebSocketRail::default();
        assert!(!rail.is_live());
        assert!(!rail.is_advertised());
        assert!(rail.open(signal()).unwrap().is_none());
    }
    #[test]
    fn consumers_own_opens_and_dropping_unsent_channel_cancels_only_that_open() {
        let c = SharedConnection::new();
        c.set_ready(true);
        let s = c.open(signal()).unwrap().unwrap();
        let e = c.open(events()).unwrap().unwrap();
        assert!(c.open(signal()).is_err());
        drop(s);
        assert!(matches!(
            c.next_command(),
            Some(WebSocketClientFrame::Open {
                operation_id: WebSocketOperationId::CommittedEventStreamSubscribe,
                ..
            })
        ));
        assert!(c.next_command().is_none());
        drop(e);
        assert!(matches!(
            c.next_command(),
            Some(WebSocketClientFrame::Close { .. })
        ));
    }
    #[test]
    fn invalid_resume_preserves_api_semantics_and_only_reopens_its_selector() {
        let connection = SharedConnection::new();
        connection.set_ready(true);
        let events = events();
        let stream = connection.open(events.clone()).unwrap().unwrap();
        let signal = connection.open(signal()).unwrap().unwrap();
        connection.next_command();
        connection.next_command();
        connection
            .publish(WebSocketServerFrame::ChannelError {
                frame_scope: WebSocketChannelScope::Channel,
                channel_id: stream.id.clone(),
                error: arkret_wire::WebSocketTransportError::new(
                    arkret_wire::ErrorCode::ParamInvalid,
                    "invalid committed stream cursor",
                ),
            })
            .unwrap();
        let failure = connection.pop(&stream.id).unwrap_err();
        assert!(failure.is_invalid_cursor());
        assert!(connection.can_open(&events));
        assert!(connection.pop(&signal.id).unwrap().is_none());
        drop(stream);
        assert!(connection.open(events).unwrap().is_some());
        assert!(connection.with(|q| !q.closed && q.pending_bytes == 0));
    }

    #[test]
    fn refused_selector_does_not_disable_other_operations_or_invent_a_cursor() {
        let c = SharedConnection::new();
        c.set_ready(true);
        let mut s = c.open(signal()).unwrap().unwrap();
        let e = c.open(events()).unwrap().unwrap();
        let _ = c.next_command();
        c.refuse(&s.id, "denied");
        assert!(!c.can_open(&signal()));
        assert!(c.can_open(&events()));
        assert!(c.pop(&s.id).is_err());
        assert!(c.pop(&e.id).unwrap().is_none());
        assert!(c.with(|q| q.pending_bytes == 0 && q.pending_frames == 0));
        let _ = &mut s;
    }

    #[tokio::test]
    async fn http_future_is_cancelled_before_a_socket_consumer_can_open() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Cancelled(Arc<AtomicBool>);
        impl Drop for Cancelled {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        struct Http {
            started: Arc<AtomicBool>,
            cancelled: Arc<AtomicBool>,
        }
        impl garth::AccountSubscribeTransport for Http {
            async fn subscribe(
                &self,
                _: &SyncRequestBody,
            ) -> garth::Result<AccountSubscribeSnapshotResult> {
                let _cancelled = Cancelled(self.cancelled.clone());
                self.started.store(true, Ordering::SeqCst);
                futures_util::future::pending().await
            }
        }
        let started = Arc::new(AtomicBool::new(false));
        let cancelled = Arc::new(AtomicBool::new(false));
        let rail = WebSocketRail::default();
        let transport = StreamRail::select(
            &rail,
            Http {
                started: started.clone(),
                cancelled: cancelled.clone(),
            },
        );
        let attempt = tokio::spawn(async move {
            garth::AccountSubscribeTransport::subscribe(&transport, &SyncRequestBody::default())
                .await
        });
        while !started.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        let connection = SharedConnection::new();
        connection.set_ready(true);
        rail.attach(connection.clone());
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(2), attempt)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert!(cancelled.load(Ordering::SeqCst));
        assert!(connection.next_command().is_none());
    }

    #[test]
    fn channel_backlog_preserves_other_queues_and_releases_global_accounting() {
        let connection = SharedConnection::new();
        connection.set_ready(true);
        let signal = connection.open(signal()).unwrap().unwrap();
        let event = connection.open(events()).unwrap().unwrap();
        let _ = connection.next_command();
        let _ = connection.next_command();
        for channel in [&signal, &event] {
            connection
                .publish(WebSocketServerFrame::Opened {
                    channel_id: channel.id.clone(),
                    operation_id: connection.with(|q| q.channels[&channel.id].operation),
                })
                .unwrap();
        }
        let heartbeat = |id: &str| WebSocketServerFrame::ChannelControl {
            frame_scope: WebSocketChannelScope::Channel,
            channel_id: id.to_owned(),
            payload: WebSocketChannelControlPayload::Heartbeat(
                WebSocketChannelHeartbeat::Heartbeat,
            ),
        };
        connection.publish(heartbeat(&event.id)).unwrap();
        for _ in 0..=CHANNEL_FRAMES {
            connection.publish(heartbeat(&signal.id)).unwrap();
        }
        assert!(connection.pop(&signal.id).is_err());
        assert!(connection.pop(&event.id).unwrap().is_some());
        assert!(connection.with(|q| q.pending_bytes == 0 && q.pending_frames == 0 && !q.closed));
        assert!(
            matches!(connection.next_command(), Some(WebSocketClientFrame::Close { channel_id, .. }) if channel_id == signal.id)
        );
    }

    #[test]
    fn reauth_pause_does_not_hide_a_close_behind_a_pending_open() {
        let connection = SharedConnection::new();
        connection.set_ready(true);
        let signal = connection.open(signal()).unwrap().unwrap();
        let _ = connection.next_command();
        let event = connection.open(events()).unwrap().unwrap();
        connection.set_ready(false);
        let signal_id = signal.id.clone();
        drop(signal);
        assert!(
            matches!(connection.next_command(), Some(WebSocketClientFrame::Close {channel_id,..}) if channel_id==signal_id)
        );
        assert!(connection.next_command().is_none());
        connection.set_ready(true);
        assert!(
            matches!(connection.next_command(), Some(WebSocketClientFrame::Open {channel_id,..}) if channel_id==event.id)
        );
    }
}
