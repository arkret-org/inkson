use serde::{Deserialize, Serialize};
use tao::window::WindowId;

#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum UserWindowEvent {
    /// A global hotkey event
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    GlobalHotKeyEvent(global_hotkey::GlobalHotKeyEvent),

    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    MudaMenuEvent(muda::MenuEvent),

    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    TrayIconEvent(tray_icon::TrayIconEvent),

    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    TrayMenuEvent(tray_icon::menu::MenuEvent),

    /// Poll the virtualdom
    Poll(WindowId),

    /// Handle an ipc message eminating from the window.postMessage of a given webview
    Ipc {
        id: WindowId,
        msg: IpcMessage,
    },

    /// Dispatch a custom protocol request on its owning window's main thread.
    ProtocolRequest(ProtocolRequest),

    /// Handle a hotreload event, basically telling us to update our templates
    #[cfg(all(feature = "devtools", debug_assertions))]
    HotReloadEvent(dioxus_devtools::DevserverMsg),

    // Windows-only drag-n-drop fix events.
    WindowsDragDrop(WindowId),
    WindowsDragOver(WindowId, i32, i32),
    WindowsDragLeave(WindowId),

    /// Create a new window
    NewWindow,

    /// Close a given window (could be any window!)
    CloseWindow(WindowId),

    /// Gracefully shutdown the entire app
    Shutdown,
}

/// A message struct that manages the communication between the webview and the eventloop code
///
/// This needs to be serializable across the JS boundary, so the method names and structs are
/// sensitive.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct IpcMessage {
    method: String,
    params: serde_json::Value,
}

/// A set of known messages that we need to respond to
#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum IpcMethod<'a> {
    UserEvent,
    Query,
    BrowserOpen,
    Initialize,
    Other(&'a str),
}

impl IpcMessage {
    pub(crate) fn method(&self) -> IpcMethod<'_> {
        match self.method.as_str() {
            "user_event" => IpcMethod::UserEvent,
            "query" => IpcMethod::Query,
            "browser_open" => IpcMethod::BrowserOpen,
            "initialize" => IpcMethod::Initialize,
            _ => IpcMethod::Other(&self.method),
        }
    }

    pub(crate) fn params(self) -> serde_json::Value {
        self.params
    }
}

/// A cloneable event owns one response, consumed exactly once on the UI thread.
/// Protocol callbacks may run off-thread; they never carry the Rc-backed DOM.
#[derive(Clone)]
pub struct ProtocolRequest {
    pub(crate) window_id: WindowId,
    pub(crate) instance_id: u64,
    pub(crate) handler_id: usize,
    payload: std::sync::Arc<std::sync::Mutex<Option<ProtocolPayload>>>,
}

pub(crate) struct ProtocolPayload {
    pub(crate) webview_id: String,
    pub(crate) request: wry::http::Request<Vec<u8>>,
    pub(crate) responder: wry::RequestAsyncResponder,
}

impl std::fmt::Debug for ProtocolRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolRequest")
            .field("window_id", &self.window_id)
            .field("instance_id", &self.instance_id)
            .field("handler_id", &self.handler_id)
            .finish_non_exhaustive()
    }
}

impl ProtocolRequest {
    pub(crate) fn new(
        window_id: WindowId,
        instance_id: u64,
        handler_id: usize,
        webview_id: &str,
        request: wry::http::Request<Vec<u8>>,
        responder: wry::RequestAsyncResponder,
    ) -> Self {
        Self {
            window_id,
            instance_id,
            handler_id,
            payload: std::sync::Arc::new(std::sync::Mutex::new(Some(ProtocolPayload {
                webview_id: webview_id.to_owned(),
                request,
                responder,
            }))),
        }
    }

    pub(crate) fn take(&self) -> Option<ProtocolPayload> {
        self.payload
            .lock()
            .expect("protocol payload mutex poisoned")
            .take()
    }

    pub(crate) fn reject(&self) {
        if let Some(payload) = self.take() {
            payload.responder.respond(
                wry::http::Response::builder()
                    .status(wry::http::StatusCode::GONE)
                    .body(Vec::new())
                    .expect("valid closed-window response"),
            );
        }
    }
}
