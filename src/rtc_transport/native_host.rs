//! A bounded, private pipe to a dedicated native media WebView event loop.
use std::io::{self, BufRead, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, SyncSender};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const MAX_FRAME: usize = 64 * 1024;
const QUEUE: usize = 64;
const EXIT_GRACE: Duration = Duration::from_secs(3);
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DriverConfig {
    pub connect_url: String,
    pub backend_token: String,
    pub audio: bool,
    pub video: bool,
    pub frame_key: Vec<u8>,
    pub local_identity: String,
}
impl DriverConfig {
    fn validate(&self) -> io::Result<()> {
        let url = url::Url::parse(&self.connect_url).map_err(invalid)?;
        if !matches!(url.scheme(), "ws" | "wss" | "http" | "https")
            || url.host_str().is_none()
            || self.connect_url.len() > 8192
            || self.backend_token.is_empty()
            || self.backend_token.len() > 16384
            || self.frame_key.len() != 32
            || self.local_identity.is_empty()
            || self.local_identity.len() > 2048
        {
            return Err(invalid("invalid media configuration"));
        }
        Ok(())
    }
}
impl Drop for DriverConfig {
    fn drop(&mut self) {
        self.backend_token.zeroize();
        self.frame_key.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum DriverCommand {
    Init {
        config: DriverConfig,
    },
    SetE2eeKey {
        identity: String,
        key: Vec<u8>,
        #[serde(rename = "keyIndex")]
        key_index: u32,
    },
    Publish {
        audio: Option<bool>,
        video: Option<bool>,
    },
    SetMuted {
        kind: MediaKind,
        muted: bool,
    },
    SetScreen {
        enabled: bool,
    },
    Leave,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum MediaKind {
    Audio,
    Video,
    Screen,
}
impl DriverCommand {
    fn validate(&self) -> io::Result<()> {
        match self {
            Self::Init { config } => config.validate(),
            Self::SetE2eeKey { identity, key, .. }
                if identity.is_empty() || identity.len() > 2048 || key.len() != 32 =>
            {
                Err(invalid("invalid sender key"))
            }
            _ => Ok(()),
        }
    }
    fn clear_secrets(&mut self) {
        if let Self::SetE2eeKey { key, .. } = self {
            key.zeroize();
        }
    }
}
impl Drop for DriverCommand {
    fn drop(&mut self) {
        self.clear_secrets();
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum DriverEvent {
    Ready,
    Connected,
    Participant { identity: String },
    Failed { reason: Option<String> },
    Left,
}
impl DriverEvent {
    fn validate(&self) -> io::Result<()> {
        match self {
            Self::Participant { identity } if identity.is_empty() || identity.len() > 2048 => {
                Err(invalid("invalid participant event"))
            }
            Self::Failed {
                reason: Some(reason),
            } if reason.len() > 128 => Err(invalid("invalid media failure")),
            _ => Ok(()),
        }
    }
}
fn invalid(value: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, value.to_string())
}
fn frame<T: Serialize>(value: &T) -> io::Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut bytes = zeroize::Zeroizing::new(serde_json::to_vec(value).map_err(invalid)?);
    if bytes.len() > MAX_FRAME {
        return Err(invalid("media frame is too large"));
    }
    bytes.push(b'\n');
    Ok(bytes)
}
fn read_frame(reader: &mut impl BufRead) -> io::Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    let count = reader
        .take((MAX_FRAME + 2) as u64)
        .read_until(b'\n', &mut bytes)?;
    if count == 0 {
        return Ok(None);
    }
    if count > MAX_FRAME + 1 || bytes.last() != Some(&b'\n') {
        return Err(invalid("invalid bounded media frame"));
    }
    bytes.pop();
    Ok(Some(bytes))
}
pub(super) struct MediaHost {
    sender: std::cell::RefCell<Option<SyncSender<zeroize::Zeroizing<Vec<u8>>>>>,
    child: std::cell::RefCell<Option<Child>>,
    writer: std::cell::RefCell<Option<std::thread::JoinHandle<()>>>,
}
impl MediaHost {
    pub fn launch(
        config: DriverConfig,
    ) -> io::Result<(Self, tokio::sync::mpsc::Receiver<DriverEvent>)> {
        config.validate()?;
        if !cfg!(feature = "desktop") {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "desktop media host is unavailable in this binary",
            ));
        }
        let mut command = Command::new(std::env::current_exe()?);
        command
            .arg("--inkson-media-host")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command.spawn()?;
        let Some(mut input) = child.stdin.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(invalid("media input pipe missing"));
        };
        let Some(output) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(invalid("media output pipe missing"));
        };
        let (sender, commands) = mpsc::sync_channel::<zeroize::Zeroizing<Vec<u8>>>(QUEUE);
        let writer = std::thread::spawn(move || {
            while let Ok(bytes) = commands.recv() {
                if input.write_all(&bytes).and_then(|_| input.flush()).is_err() {
                    break;
                }
            }
        });
        let (events, receiver) = tokio::sync::mpsc::channel(QUEUE);
        std::thread::spawn(move || {
            let mut reader = io::BufReader::new(output);
            loop {
                let bytes = match read_frame(&mut reader) {
                    Ok(Some(bytes)) => bytes,
                    _ => break,
                };
                let event = match serde_json::from_slice::<DriverEvent>(&bytes) {
                    Ok(event) if event.validate().is_ok() => event,
                    _ => break,
                };
                if events.try_send(event).is_err() {
                    break;
                }
            }
        });
        let host = Self {
            sender: std::cell::RefCell::new(Some(sender)),
            child: std::cell::RefCell::new(Some(child)),
            writer: std::cell::RefCell::new(Some(writer)),
        };
        host.send(DriverCommand::Init { config })?;
        Ok((host, receiver))
    }
    pub fn send(&self, mut command: DriverCommand) -> io::Result<()> {
        command.validate()?;
        let bytes = frame(&command);
        command.clear_secrets();
        self.sender
            .borrow()
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "media host is closed"))?
            .try_send(bytes?)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "media command channel closed or full",
                )
            })
    }
    pub fn shutdown(&self) {
        if let Some(sender) = self.sender.borrow_mut().take()
            && let Ok(bytes) = frame(&DriverCommand::Leave)
        {
            let _ = sender.try_send(bytes);
        }
        if let Some(mut child) = self.child.borrow_mut().take() {
            let writer = self.writer.borrow_mut().take();
            std::thread::spawn(move || {
                let deadline = Instant::now() + EXIT_GRACE;
                loop {
                    match child.try_wait() {
                        Ok(Some(_)) => break,
                        _ if Instant::now() >= deadline => {
                            let _ = child.kill();
                            let _ = child.wait();
                            break;
                        }
                        _ => std::thread::sleep(Duration::from_millis(25)),
                    }
                }
                if let Some(writer) = writer {
                    let _ = writer.join();
                }
            });
        }
    }
}
impl Drop for MediaHost {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(feature = "desktop")]
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    use tao::event::{Event, WindowEvent};
    use tao::event_loop::{ControlFlow, EventLoopBuilder};
    use tao::window::WindowBuilder;
    enum HostEvent {
        Wake,
        ParentGone,
    }
    let mut reader = io::BufReader::new(io::stdin());
    let first = read_frame(&mut reader)?.ok_or_else(|| invalid("media initialization missing"))?;
    let initial = serde_json::from_slice::<DriverCommand>(&first)?;
    initial.validate()?;
    drop(first);
    let DriverCommand::Init { ref config } = initial else {
        return Err(invalid("first media frame must initialize").into());
    };
    let permissions = std::sync::Arc::new((
        std::sync::atomic::AtomicBool::new(config.audio),
        std::sync::atomic::AtomicBool::new(config.video),
    ));
    let event_loop = EventLoopBuilder::<HostEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();
    let input_proxy = proxy.clone();
    let (input_sender, input_receiver) = mpsc::sync_channel::<DriverCommand>(QUEUE);
    let (driver_sender, driver_receiver) = mpsc::sync_channel::<DriverEvent>(QUEUE);
    std::thread::spawn(move || {
        loop {
            let next = match read_frame(&mut reader) {
                Ok(Some(bytes)) => serde_json::from_slice::<DriverCommand>(&bytes).ok(),
                _ => None,
            };
            match next {
                Some(command) if command.validate().is_ok() => {
                    if input_sender.send(command).is_err()
                        || input_proxy.send_event(HostEvent::Wake).is_err()
                    {
                        return;
                    }
                }
                _ => {
                    let _ = input_proxy.send_event(HostEvent::ParentGone);
                    return;
                }
            }
        }
    });
    let window = WindowBuilder::new()
        .with_title("Inkson call media")
        .with_inner_size(tao::dpi::LogicalSize::new(480.0, 320.0))
        .build(&event_loop)?;
    let (event_writer, event_receiver) =
        mpsc::sync_channel::<(zeroize::Zeroizing<Vec<u8>>, Option<SyncSender<()>>)>(QUEUE);
    std::thread::spawn(move || {
        let mut output = io::stdout().lock();
        while let Ok((bytes, acknowledged)) = event_receiver.recv() {
            if output
                .write_all(&bytes)
                .and_then(|_| output.flush())
                .is_err()
            {
                return;
            }
            if let Some(acknowledged) = acknowledged {
                let _ = acknowledged.try_send(());
            }
        }
    });
    let ipc_proxy = proxy.clone();
    let ipc_closed = std::cell::Cell::new(false);
    let allow = permissions.clone();
    let directory = media_data_directory()?;
    std::fs::create_dir_all(&directory)?;
    let mut web_context = wry::WebContext::new(Some(directory));
    let mut builder = wry::WebViewBuilder::new_with_web_context(&mut web_context)
        .with_incognito(true)
        .with_enable_media_stream(true)
        .with_permission_handler(move |kind| {
            use std::sync::atomic::Ordering;
            match kind {
                wry::PermissionKind::Microphone if allow.0.load(Ordering::Relaxed) => {
                    wry::PermissionResponse::Allow
                }
                wry::PermissionKind::Camera if allow.1.load(Ordering::Relaxed) => {
                    wry::PermissionResponse::Allow
                }
                wry::PermissionKind::DisplayCapture => wry::PermissionResponse::Default,
                _ => wry::PermissionResponse::Deny,
            }
        })
        .with_custom_protocol("inkson-media".into(), move |_, request| {
            let path = request.uri().path();
            let (mime, body) = match path {
                "/" | "/index.html" => ("text/html", MEDIA_HTML.as_bytes()),
                "/driver.js" => (
                    "text/javascript",
                    include_bytes!("../../assets/livekit_desktop_driver.js").as_slice(),
                ),
                "/livekit.js" => (
                    "text/javascript",
                    include_bytes!("../../assets/vendor/livekit-client.umd.min.js").as_slice(),
                ),
                _ => ("text/plain", b"Not found".as_slice()),
            };
            let mut response = wry::http::Response::new(std::borrow::Cow::Borrowed(body));
            *response.status_mut() = if body == b"Not found" {
                wry::http::StatusCode::NOT_FOUND
            } else {
                wry::http::StatusCode::OK
            };
            response.headers_mut().insert(
                wry::http::header::CONTENT_TYPE,
                wry::http::HeaderValue::from_static(mime),
            );
            response.headers_mut().insert(
                wry::http::header::CACHE_CONTROL,
                wry::http::HeaderValue::from_static("no-store"),
            );
            response
        })
        .with_navigation_handler(|url| {
            url == "inkson-media://localhost/" || url == "https://inkson-media.localhost/"
        })
        .with_ipc_handler(move |request| {
            if ipc_closed.get() {
                return;
            }
            if request.body().len() > MAX_FRAME {
                return;
            }
            if let Ok(event) = serde_json::from_str::<DriverEvent>(request.body())
                && event.validate().is_ok()
            {
                if driver_sender.try_send(event).is_ok() {
                    let _ = ipc_proxy.send_event(HostEvent::Wake);
                } else {
                    ipc_closed.set(true);
                    let _ = ipc_proxy.send_event(HostEvent::ParentGone);
                }
            }
        })
        .with_url("inkson-media://localhost/");
    #[cfg(windows)]
    {
        use wry::WebViewBuilderExtWindows;
        builder = builder.with_https_scheme(true);
    }
    let webview = builder.build(&window)?;
    let mut pending = std::collections::VecDeque::from([initial]);
    let mut ready = false;
    let mut deadline = None;
    event_loop.run(move |event, _, flow| {
        *flow = deadline
            .map(ControlFlow::WaitUntil)
            .unwrap_or(ControlFlow::Wait);
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            *flow = ControlFlow::Exit;
            return;
        }
        let shutting_down = matches!(
            event,
            Event::UserEvent(HostEvent::ParentGone)
                | Event::WindowEvent {
                    event: WindowEvent::CloseRequested,
                    ..
                }
        );
        if shutting_down {
            pending.push_back(DriverCommand::Leave);
            deadline = Some(Instant::now() + EXIT_GRACE);
            *flow = ControlFlow::WaitUntil(Instant::now() + EXIT_GRACE);
        }
        for command in input_receiver.try_iter() {
            if matches!(command, DriverCommand::Init { .. }) || pending.len() >= QUEUE {
                *flow = ControlFlow::Exit;
                return;
            }
            if matches!(command, DriverCommand::SetScreen { enabled: true }) {
                window.set_visible(true);
                window.set_focus();
            }
            pending.push_back(command);
        }
        for event in driver_receiver.try_iter() {
            if matches!(event, DriverEvent::Ready) {
                ready = true;
                continue;
            }
            let left = matches!(event, DriverEvent::Left);
            if let Ok(bytes) = frame(&event) {
                let (ack, received) = mpsc::sync_channel(1);
                if event_writer.try_send((bytes, left.then_some(ack))).is_err() {
                    *flow = ControlFlow::Exit;
                    return;
                }
                if left {
                    let _ = received.recv_timeout(Duration::from_millis(150));
                    *flow = ControlFlow::Exit;
                    return;
                }
            }
        }
        if ready {
            while let Some(mut command) = pending.pop_front() {
                use std::sync::atomic::Ordering;
                match &command {
                    DriverCommand::SetMuted {
                        kind: MediaKind::Audio,
                        muted,
                    } => permissions.0.store(!muted, Ordering::Relaxed),
                    DriverCommand::SetMuted {
                        kind: MediaKind::Video,
                        muted,
                    } => permissions.1.store(!muted, Ordering::Relaxed),
                    DriverCommand::Publish { audio, video } => {
                        if let Some(value) = audio {
                            permissions.0.store(*value, Ordering::Relaxed);
                        }
                        if let Some(value) = video {
                            permissions.1.store(*value, Ordering::Relaxed);
                        }
                    }
                    _ => {}
                }
                if let Ok(bytes) = serde_json::to_string(&command) {
                    let bytes = zeroize::Zeroizing::new(bytes);
                    let script = zeroize::Zeroizing::new(format!(
                        "window.__inksonMediaReceive({});",
                        bytes.as_str()
                    ));
                    if webview.evaluate_script(&script).is_err() {
                        *flow = ControlFlow::Exit;
                    }
                }
                command.clear_secrets();
            }
        }
        let _ = &window;
        let _ = &web_context;
    });
}
#[cfg(feature = "desktop")]
fn media_data_directory() -> io::Result<std::path::PathBuf> {
    let path = std::env::var_os("INKSON_MEDIA_DATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            #[cfg(windows)]
            {
                std::path::PathBuf::from("D:/BuildCache/inkson-glory/media")
            }
            #[cfg(not(windows))]
            {
                std::env::temp_dir().join("inkson-media")
            }
        });
    if !path.is_absolute() {
        return Err(invalid("media data directory must be absolute"));
    }
    Ok(path)
}
#[cfg(feature = "desktop")]
const MEDIA_HTML: &str = r#"<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; connect-src ws: wss: http: https:; media-src blob:; worker-src blob:; style-src 'unsafe-inline'"><title>Inkson call media</title></head><body><h1>Inkson call media</h1><p>Close this window to leave media.</p><button id="share-screen">Share screen</button><button id="leave-media">Leave media</button><section id="remote-media"></section><script src="/livekit.js"></script><script src="/driver.js"></script></body></html>"#;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_close_retires_commands_while_the_event_owner_is_retained() {
        let (sender, receiver) = mpsc::sync_channel(QUEUE);
        let host = std::rc::Rc::new(MediaHost {
            sender: std::cell::RefCell::new(Some(sender)),
            child: std::cell::RefCell::new(None),
            writer: std::cell::RefCell::new(None),
        });
        let retained_event_owner = host.clone();
        host.shutdown();
        assert!(retained_event_owner.send(DriverCommand::Leave).is_err());
        let leave = receiver.try_recv().unwrap();
        assert!(matches!(
            serde_json::from_slice::<DriverCommand>(&leave).unwrap(),
            DriverCommand::Leave
        ));
        retained_event_owner.shutdown();
        assert!(receiver.try_recv().is_err());
        assert_eq!(std::rc::Rc::strong_count(&host), 2);
    }
    #[test]
    fn framing_rejects_large_unterminated_and_unknown_commands() {
        assert!(read_frame(&mut io::Cursor::new(vec![b'x'; MAX_FRAME + 2])).is_err());
        assert!(read_frame(&mut io::Cursor::new(b"{}".as_slice())).is_err());
        assert!(
            serde_json::from_str::<DriverCommand>(
                r#"{"cmd":"set_muted","kind":"unknown","muted":true}"#
            )
            .is_err()
        );
    }
    #[test]
    fn typed_sender_keys_are_exact_and_frames_round_trip() {
        let command = DriverCommand::SetE2eeKey {
            identity: "sender".into(),
            key: vec![7; 32],
            key_index: 0,
        };
        let bytes = frame(&command).unwrap();
        let bytes = read_frame(&mut io::Cursor::new(bytes.to_vec()))
            .unwrap()
            .unwrap();
        assert!(
            serde_json::from_slice::<DriverCommand>(&bytes)
                .unwrap()
                .validate()
                .is_ok()
        );
        assert!(
            DriverCommand::SetE2eeKey {
                identity: "sender".into(),
                key: vec![7; 31],
                key_index: 0
            }
            .validate()
            .is_err()
        );
    }
}
