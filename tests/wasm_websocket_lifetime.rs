//! Actual Inkson browser callbacks across socket retirement. Transport only:
//! the controlled browser socket does not prove Station admission or DPoP.
#![cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]

use std::future::Future;
use std::task::{Context, Poll, Waker};

use arkret_wire::websocket_binding::WebSocketCloseCode;
use garth::websocket::socket::WebSocketSocket;
use inkson::websocket::open_for_lifetime_test;
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen(inline_js = r#"
let fixture;
export function install_socket_fixture(mode) {
    if (fixture) throw new Error('socket fixture already active');
    const state = { original: globalThis.WebSocket, latest: null,
        close_calls: 0, callback_errors: 0, callback_lifetime_errors: 0, registered: 0 };
    fixture = state;
    globalThis.WebSocket = class {
        constructor(_url, protocol) {
            this.protocol = mode === 'protocol_mismatch' ? '' : protocol;
            this.retired = false;
            state.latest = this;
            if (mode !== 'cancel_pending') queueMicrotask(() => {
                state.registered = ['onopen', 'onerror', 'onclose', 'onmessage']
                    .filter(name => typeof this[name] === 'function').length;
                if (mode === 'handshake_error') this.onerror?.(new Event('error'));
                else this.onopen?.(new Event('open'));
            });
        }
        close() {
            if (this.retired) return;
            this.retired = true;
            state.close_calls++;
            queueMicrotask(() => {
                try { this.onclose?.(new CloseEvent('close', { code: 1000 })); }
                catch (error) {
                    state.callback_errors++;
                    if (error instanceof Error && error.message === 'closure invoked recursively or after being dropped') {
                        state.callback_lifetime_errors++;
                    }
                }
            });
        }
    };
}
export function pending_handler_count() {
    const value = ['onopen', 'onerror', 'onclose', 'onmessage']
        .filter(name => typeof fixture.latest[name] === 'function').length;
    fixture.registered = value;
    return value;
}
export function force_late_close() { fixture.latest.close(); }
export function settle_socket_fixture() {
    return new Promise(resolve => setTimeout(resolve, 10));
}
export function socket_fixture_report() {
    return JSON.stringify({ close_calls: fixture.close_calls,
        callback_errors: fixture.callback_errors, callback_lifetime_errors: fixture.callback_lifetime_errors,
        registered: fixture.registered,
        handlers_removed: ['onopen', 'onerror', 'onclose', 'onmessage']
            .every(name => fixture.latest[name] == null) });
}
export function restore_socket_fixture() {
    if (fixture) globalThis.WebSocket = fixture.original;
    fixture = null;
}
"#)]
extern "C" {
    fn install_socket_fixture(mode: &str);
    fn pending_handler_count() -> u32;
    fn force_late_close();
    fn settle_socket_fixture() -> js_sys::Promise;
    fn socket_fixture_report() -> String;
    fn restore_socket_fixture();
}

struct RestoreSocket;
impl Drop for RestoreSocket {
    fn drop(&mut self) {
        restore_socket_fixture();
    }
}

#[wasm_bindgen_test(async)]
async fn retired_socket_callbacks_never_run_after_normal_error_or_cancelled_handshakes() {
    for mode in [
        "close_then_drop",
        "drop_open",
        "handshake_error",
        "protocol_mismatch",
        "cancel_pending",
    ] {
        install_socket_fixture(mode);
        let _restore = RestoreSocket;
        let mut opening = Box::pin(open_for_lifetime_test(
            "ws://127.0.0.1:1/controlled-transport",
        ));
        if mode == "cancel_pending" {
            let mut context = Context::from_waker(Waker::noop());
            assert!(matches!(opening.as_mut().poll(&mut context), Poll::Pending));
            assert_eq!(pending_handler_count(), 4);
            drop(opening);
        } else {
            let result = opening.await;
            if mode == "handshake_error" || mode == "protocol_mismatch" {
                assert!(result.is_err());
            } else {
                let mut socket = result.unwrap();
                if mode == "close_then_drop" {
                    socket
                        .close(WebSocketCloseCode::Normal, "fixture done")
                        .await
                        .unwrap();
                }
                drop(socket);
            }
        }
        let retired: serde_json::Value = serde_json::from_str(&socket_fixture_report()).unwrap();
        assert_eq!(retired["close_calls"], serde_json::json!(1), "{mode}");
        force_late_close();
        wasm_bindgen_futures::JsFuture::from(settle_socket_fixture())
            .await
            .unwrap();
        let observed: serde_json::Value = serde_json::from_str(&socket_fixture_report()).unwrap();
        console_log!("socket lifetime public report: mode={mode} report={observed}");
        assert_eq!(observed["registered"], serde_json::json!(4), "{mode}");
        assert_eq!(observed["callback_errors"], serde_json::json!(0), "{mode}");
        assert_eq!(
            observed["handlers_removed"],
            serde_json::json!(true),
            "{mode}"
        );
        assert_eq!(observed["close_calls"], serde_json::json!(1), "{mode}");
    }
}
