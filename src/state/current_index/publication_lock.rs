//! A stable lock object covers publication and maintenance in other processes.

#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct PublicationLock {
    _file: std::fs::File,
}

#[cfg(not(target_arch = "wasm32"))]
impl PublicationLock {
    pub(super) async fn acquire(location: super::CurrentIndexLocation) -> anyhow::Result<Self> {
        tokio::task::spawn_blocking(move || {
            let path = location.path.with_extension("current.lock");
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)?;
            file.lock()?;
            Ok(Self { _file: file })
        })
        .await?
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) struct PublicationLock {
    _release: tokio::sync::oneshot::Sender<()>,
}

#[cfg(target_arch = "wasm32")]
impl PublicationLock {
    pub(super) async fn acquire(_location: super::CurrentIndexLocation) -> anyhow::Result<Self> {
        use std::cell::RefCell;
        use std::rc::Rc;

        use wasm_bindgen::closure::Closure;
        use wasm_bindgen::{JsCast, JsValue};

        let navigator = web_sys::window()
            .ok_or_else(|| anyhow::anyhow!("current publication requires a browser window"))?
            .navigator();
        let locks = js_sys::Reflect::get(navigator.as_ref(), &JsValue::from_str("locks"))
            .map_err(|error| anyhow::anyhow!("Web Locks unavailable: {error:?}"))?;
        let request: js_sys::Function = js_sys::Reflect::get(&locks, &JsValue::from_str("request"))
            .map_err(|error| anyhow::anyhow!("Web Locks request unavailable: {error:?}"))?
            .dyn_into()
            .map_err(|_| anyhow::anyhow!("Web Locks request is not callable"))?;
        let (acquired, ready) = tokio::sync::oneshot::channel::<Result<(), String>>();
        let acquired = Rc::new(RefCell::new(Some(acquired)));
        let notify = acquired.clone();
        let (release, released) = tokio::sync::oneshot::channel();
        let mut released = Some(released);
        let callback = Closure::<dyn FnMut(JsValue) -> js_sys::Promise>::new(move |_| {
            if let Some(sender) = notify.borrow_mut().take() {
                let _ = sender.send(Ok(()));
            }
            let released = released.take();
            wasm_bindgen_futures::future_to_promise(async move {
                if let Some(released) = released {
                    let _ = released.await;
                }
                Ok(JsValue::UNDEFINED)
            })
        });
        let promise: js_sys::Promise = request
            .call2(
                &locks,
                &JsValue::from_str("inkson.current.v1/publication"),
                callback.as_ref(),
            )
            .map_err(|error| anyhow::anyhow!("Web Locks request failed: {error:?}"))?
            .dyn_into()
            .map_err(|_| anyhow::anyhow!("Web Locks request returned no promise"))?;
        // Keep the callback alive even when a waiting caller is cancelled.
        // Dropping its release sender makes an eventual grant release itself.
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(error) = wasm_bindgen_futures::JsFuture::from(promise).await
                && let Some(sender) = acquired.borrow_mut().take()
            {
                let _ = sender.send(Err(format!("Web Locks request rejected: {error:?}")));
            }
            drop(callback);
        });
        let lock = Self { _release: release };
        ready
            .await
            .map_err(|_| anyhow::anyhow!("publication lock grant ended"))?
            .map_err(anyhow::Error::msg)?;
        Ok(lock)
    }
}
