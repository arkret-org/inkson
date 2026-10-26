//! Window-owned authenticated image bytes behind the official native provider.
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use glory::blitz::assets::{Body, Bytes, Method, NetHandler, NetProvider, Request};
use tokio::sync::Notify;

const HOST: &str = "inkson-live";

#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub entries: usize,
    pub entry_bytes: usize,
    pub total_bytes: usize,
    pub pending: usize,
    pub owners: usize,
    pub timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            entries: 128,
            entry_bytes: 8 * 1024 * 1024,
            total_bytes: 32 * 1024 * 1024,
            pending: 16,
            owners: 256,
            timeout: Duration::from_secs(15),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Stats {
    pub entries: usize,
    pub bytes: usize,
    pub pending: usize,
    pub owners: usize,
    pub peak_pending: usize,
    pub completed: u64,
    pub failed: u64,
    pub cancelled: u64,
    pub rejected: u64,
    pub closed: bool,
    pub stopped: bool,
}

#[derive(Default)]
struct Cancel {
    cancelled: AtomicBool,
    notify: Notify,
}
impl Cancel {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notify.notify_one();
    }
    async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            if self.cancelled.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}
struct Pending {
    url: String,
    cancel: Arc<Cancel>,
}
struct Entry {
    owner: glory::core::InstanceId,
    bytes: Bytes,
}
#[derive(Default)]
struct State {
    doc: Option<usize>,
    epoch: u64,
    next: u64,
    next_job: u64,
    entries: BTreeMap<String, Entry>,
    owners: HashMap<glory::core::InstanceId, BTreeSet<String>>,
    pending: BTreeMap<u64, Pending>,
    stats: Stats,
}
struct Inner {
    state: Mutex<State>,
    limits: Limits,
    namespace: String,
    queue: Mutex<Option<mpsc::SyncSender<Job>>>,
    stopped: AtomicBool,
}
struct Job {
    id: u64,
    epoch: u64,
    request: Request,
    bytes: Bytes,
    handler: Box<dyn NetHandler>,
    cancel: Arc<Cancel>,
    deadline: Instant,
}

pub(crate) struct ScopedImageRegistry {
    inner: Arc<Inner>,
}

impl ScopedImageRegistry {
    pub(crate) fn new(limits: Limits) -> io::Result<Arc<Self>> {
        if limits.entries == 0
            || limits.entry_bytes == 0
            || limits.total_bytes == 0
            || limits.pending == 0
            || limits.owners == 0
            || limits.timeout.is_zero()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native image limits must be finite and nonzero",
            ));
        }
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(io::Error::other)?;
        let namespace = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let (sender, receiver) = mpsc::sync_channel(limits.pending);
        let inner = Arc::new(Inner {
            state: Mutex::new(State::default()),
            limits,
            namespace,
            queue: Mutex::new(Some(sender)),
            stopped: AtomicBool::new(false),
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let owner = Arc::downgrade(&inner);
        std::thread::Builder::new()
            .name("inkson-images".into())
            .spawn(move || {
                while let Ok(job) = receiver.recv() {
                    let Some(inner) = owner.upgrade() else {
                        break;
                    };
                    runtime.block_on(process(&inner, job));
                }
                if let Some(inner) = owner.upgrade() {
                    inner.stopped.store(true, Ordering::Release);
                }
            })?;
        Ok(Arc::new(Self { inner }))
    }

    pub(crate) fn register(
        self: &Arc<Self>,
        scope: &glory::Scope,
        mime: &str,
        bytes: Vec<u8>,
    ) -> Result<String, String> {
        let owner = scope.id();
        if !owner.is_alive() {
            return Err("The native image scope is retired.".into());
        }
        if !matches!(
            mime.split(';').next().unwrap_or_default().trim(),
            "image/png" | "image/jpeg" | "image/webp" | "image/gif"
        ) {
            return Err("The native image host supports PNG, JPEG, WebP and static GIF.".into());
        }
        let raster = bytes.starts_with(b"\x89PNG\r\n\x1a\n")
            || bytes.starts_with(b"\xff\xd8\xff")
            || bytes.starts_with(b"GIF87a")
            || bytes.starts_with(b"GIF89a")
            || (bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP"));
        if !raster {
            return Err("The attachment is not a supported native raster image.".into());
        }
        if bytes.len() > self.inner.limits.entry_bytes {
            return Err("The native image exceeds its byte limit.".into());
        }
        let (url, install_cleanup) = {
            let mut state = self
                .inner
                .state
                .lock()
                .map_err(|_| "The native image registry is unavailable.")?;
            if state.stats.closed {
                return Err("The native image window is closed.".into());
            }
            if state.entries.len() >= self.inner.limits.entries
                || (!state.owners.contains_key(&owner)
                    && state.owners.len() >= self.inner.limits.owners)
                || state.stats.bytes.saturating_add(bytes.len()) > self.inner.limits.total_bytes
            {
                return Err("The native image registry is full.".into());
            }
            let id = state
                .next
                .checked_add(1)
                .ok_or("The native image identity limit was reached.")?;
            state.next = id;
            let url = format!(
                "asset://{HOST}/{}/{}/{id}",
                self.inner.namespace, state.epoch
            );
            state.stats.bytes += bytes.len();
            state.entries.insert(
                url.clone(),
                Entry {
                    owner,
                    bytes: Bytes::from(bytes),
                },
            );
            let install_cleanup = !state.owners.contains_key(&owner);
            state.owners.entry(owner).or_default().insert(url.clone());
            (url, install_cleanup)
        };
        if install_cleanup {
            let cleanup = self.clone();
            if let Err(error) = scope.on_cleanup(move || cleanup.revoke_owner(owner)) {
                self.revoke_owner(owner);
                return Err(error.to_string());
            }
        }
        Ok(url)
    }

    pub(crate) fn revoke(&self, url: &str) {
        let Ok(mut state) = self.inner.state.lock() else {
            return;
        };
        if let Some(entry) = state.entries.remove(url) {
            state.stats.bytes -= entry.bytes.len();
            if let Some(urls) = state.owners.get_mut(&entry.owner) {
                urls.remove(url);
            }
        }
        cancel_matching(&state, Some(url));
    }
    fn revoke_owner(&self, owner: glory::core::InstanceId) {
        let Ok(mut state) = self.inner.state.lock() else {
            return;
        };
        if let Some(urls) = state.owners.remove(&owner) {
            for url in urls {
                if let Some(entry) = state.entries.remove(&url) {
                    state.stats.bytes -= entry.bytes.len();
                }
                cancel_matching(&state, Some(&url));
            }
        }
    }
    pub(crate) fn retire(&self) {
        let Ok(mut state) = self.inner.state.lock() else {
            return;
        };
        if let Some(epoch) = state.epoch.checked_add(1) {
            state.epoch = epoch;
        } else {
            state.stats.closed = true;
        }
        state.entries.clear();
        state.owners.values_mut().for_each(BTreeSet::clear);
        state.stats.bytes = 0;
        cancel_matching(&state, None);
    }
    pub(crate) fn stats(&self) -> Result<Stats, String> {
        let state = self
            .inner
            .state
            .lock()
            .map_err(|_| "The native image registry is unavailable.")?;
        Ok(Stats {
            entries: state.entries.len(),
            pending: state.pending.len(),
            owners: state.owners.len(),
            stopped: self.inner.stopped.load(Ordering::Acquire),
            ..state.stats
        })
    }
    fn claim(&self, doc: usize) -> bool {
        let Ok(mut state) = self.inner.state.lock() else {
            return false;
        };
        if state.stats.closed || state.doc.is_some_and(|owner| owner != doc) {
            return false;
        }
        state.doc = Some(doc);
        true
    }
    fn fetch(&self, doc: usize, request: Request, handler: Box<dyn NetHandler>) {
        let url = request.url.to_string();
        if !self.claim(doc) {
            handler.error(url, "The native image document is retired.".into());
            return;
        }
        let admitted = (|| {
            if request.url.scheme() != "asset"
                || request.url.host_str() != Some(HOST)
                || request.url.port().is_some()
                || !request.url.username().is_empty()
                || request.url.password().is_some()
                || request.url.query().is_some()
                || request.url.fragment().is_some()
                || request.method != Method::GET
                || !request.headers.is_empty()
                || !matches!(request.body, Body::Empty)
            {
                return Err("The native image request is not admitted.".to_owned());
            }
            let mut state = self
                .inner
                .state
                .lock()
                .map_err(|_| "The native image registry is unavailable.".to_owned())?;
            if state.pending.len() >= self.inner.limits.pending {
                return Err("The native image request queue is full.".into());
            }
            let bytes = state
                .entries
                .get(&url)
                .map(|entry| entry.bytes.clone())
                .ok_or("The native image lease is unavailable.")?;
            let id = state
                .next_job
                .checked_add(1)
                .ok_or("The native image request identity limit was reached.")?;
            state.next_job = id;
            let cancel = Arc::new(Cancel::default());
            state.pending.insert(
                id,
                Pending {
                    url: url.clone(),
                    cancel: cancel.clone(),
                },
            );
            state.stats.peak_pending = state.stats.peak_pending.max(state.pending.len());
            Ok((id, state.epoch, bytes, cancel))
        })();
        let (id, epoch, bytes, cancel) = match admitted {
            Ok(parts) => parts,
            Err(error) => {
                if let Ok(mut state) = self.inner.state.lock() {
                    state.stats.rejected = state.stats.rejected.saturating_add(1);
                }
                handler.error(url, error);
                return;
            }
        };
        let job = Job {
            id,
            epoch,
            request,
            bytes,
            handler,
            cancel,
            deadline: Instant::now() + self.inner.limits.timeout,
        };
        let queued = match self.inner.queue.lock() {
            Ok(queue) => match queue.as_ref() {
                Some(sender) => sender.try_send(job),
                None => Err(mpsc::TrySendError::Disconnected(job)),
            },
            Err(_) => Err(mpsc::TrySendError::Disconnected(job)),
        };
        match queued {
            Ok(()) => {}
            Err(error) => {
                let job = match error {
                    mpsc::TrySendError::Full(job) | mpsc::TrySendError::Disconnected(job) => job,
                };
                if let Ok(mut state) = self.inner.state.lock() {
                    state.pending.remove(&id);
                    state.stats.rejected = state.stats.rejected.saturating_add(1);
                }
                job.handler
                    .error(url, "The native image worker is unavailable.".into());
            }
        }
    }
    fn cancel(&self, doc: usize, url: &str) {
        if let Ok(state) = self.inner.state.lock()
            && state.doc == Some(doc)
        {
            cancel_matching(&state, Some(url));
        }
    }
    fn close(&self, doc: usize) {
        if let Ok(mut state) = self.inner.state.lock()
            && state.doc.is_none_or(|owner| owner == doc)
        {
            state.stats.closed = true;
            state.entries.clear();
            state.owners.clear();
            state.stats.bytes = 0;
            cancel_matching(&state, None);
            if let Ok(mut queue) = self.inner.queue.lock() {
                queue.take();
            }
        }
    }
}

fn cancel_matching(state: &State, url: Option<&str>) {
    for pending in state.pending.values() {
        if url.is_none_or(|url| url == pending.url) {
            pending.cancel.cancel();
        }
    }
}

async fn process(inner: &Arc<Inner>, mut job: Job) {
    let url = job.request.url.to_string();
    let cancelled = async {
        loop {
            if job
                .request
                .signal
                .as_ref()
                .is_some_and(|signal| signal.aborted())
            {
                return;
            }
            tokio::select! {_=job.cancel.wait()=>return,_=tokio::time::sleep(Duration::from_millis(20))=>{}}
        }
    };
    let result = tokio::select! {
        biased;
        _=cancelled=>None,
        prepared=tokio::time::timeout_at(job.deadline.into(),job.handler.prepare(&url,&job.bytes))=>Some(prepared.unwrap_or_else(|_|Err("The native image preparation timed out.".into()))),
    };
    let publish = if let Ok(mut state) = inner.state.lock() {
        state.pending.remove(&job.id);
        let publish = !state.stats.closed
            && state.epoch == job.epoch
            && state.entries.contains_key(&url)
            && !job.cancel.cancelled.load(Ordering::Acquire)
            && !job
                .request
                .signal
                .as_ref()
                .is_some_and(|signal| signal.aborted())
            && result.is_some();
        if !publish {
            state.stats.cancelled = state.stats.cancelled.saturating_add(1);
        } else if result.as_ref().is_some_and(Result::is_ok) {
            state.stats.completed = state.stats.completed.saturating_add(1);
        } else {
            state.stats.failed = state.stats.failed.saturating_add(1);
        }
        publish
    } else {
        false
    };
    // This is the acceptance point, matching the official Loader. Renderer
    // request identities reject a consumer retired after this point.
    if publish {
        match result {
            Some(Ok(())) => job.handler.bytes(url, job.bytes),
            Some(Err(error)) => job.handler.error(url, error),
            None => {}
        }
    }
}

pub(crate) struct CompositeProvider {
    pub images: Arc<ScopedImageRegistry>,
    pub assets: Arc<dyn NetProvider>,
}
impl NetProvider for CompositeProvider {
    fn fetch(&self, doc: usize, request: Request, handler: Box<dyn NetHandler>) {
        if !self.images.claim(doc) {
            handler.error(
                request.url.to_string(),
                "The native window resource owner is retired.".into(),
            );
            return;
        }
        if request.url.scheme() == "asset" && request.url.host_str() == Some(HOST) {
            self.images.fetch(doc, request, handler);
        } else {
            self.assets.fetch(doc, request, handler);
        }
    }
    fn cancel(&self, doc: usize, url: &str) {
        self.images.cancel(doc, url);
        self.assets.cancel(doc, url);
    }
    fn close(&self, doc: usize) {
        self.images.close(doc);
        self.assets.close(doc);
    }
}

#[cfg(test)]
mod tests;
