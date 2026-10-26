//! Selected host identities provide bounded input to the unchanged attachment vault.
use std::future::Future;
use std::pin::Pin;

#[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
#[path = "attachment_lifetime_fixture.rs"]
mod attachment_lifetime_fixture;

#[derive(Clone)]
pub(super) struct AttachmentFile {
    name: String,
    media_type: String,
    size: u64,
    source: FileSource,
}

#[derive(Clone)]
enum FileSource {
    #[cfg(target_arch = "wasm32")]
    Host {
        owner: glory::ui::WeakScope,
        controller: sapid::FileController,
        file: glory::render::FileToken,
        available: glory::Cage<bool>,
        _lease: std::rc::Rc<SelectedFileLease>,
    },
    #[cfg(not(target_arch = "wasm32"))]
    Native {
        file: std::sync::Arc<std::sync::Mutex<std::fs::File>>,
        modified: std::time::SystemTime,
    },
}

#[cfg(target_arch = "wasm32")]
struct SelectedFileLease {
    active: glory::Cage<usize>,
}
#[cfg(target_arch = "wasm32")]
impl Drop for SelectedFileLease {
    fn drop(&mut self) {
        let _ = self
            .active
            .try_revise(|value| *value = value.saturating_sub(1));
    }
}

impl AttachmentFile {
    #[cfg(not(target_arch = "wasm32"))]
    pub(super) fn open(path: &std::path::Path) -> anyhow::Result<Self> {
        let file = std::fs::File::open(path)?;
        let metadata = file.metadata()?;
        anyhow::ensure!(metadata.is_file(), "attachment selection must be a file");
        Ok(Self {
            name: path
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("attachment filename unavailable"))?
                .to_string_lossy()
                .into_owned(),
            media_type: mime_guess::from_path(path)
                .first_or_octet_stream()
                .to_string(),
            size: metadata.len(),
            source: FileSource::Native {
                file: std::sync::Arc::new(std::sync::Mutex::new(file)),
                modified: metadata.modified()?,
            },
        })
    }
    #[cfg(target_arch = "wasm32")]
    pub(super) fn selected(
        scope: &glory::Scope,
        controller: sapid::FileController,
        info: glory::render::FileInfo,
        active: glory::Cage<usize>,
        available: glory::Cage<bool>,
    ) -> Self {
        active.revise(|value| *value = value.saturating_add(1));
        Self {
            name: info.name,
            media_type: info.media_type,
            size: info.size,
            source: FileSource::Host {
                owner: scope.downgrade(),
                controller,
                file: info.token,
                available,
                _lease: std::rc::Rc::new(SelectedFileLease { active }),
            },
        }
    }
    pub(super) fn name(&self) -> String {
        self.name.clone()
    }
    pub(super) fn size(&self) -> u64 {
        self.size
    }
    pub(super) fn content_type(&self) -> Option<String> {
        (!self.media_type.is_empty()).then(|| self.media_type.clone())
    }
}

impl crate::attachments::AttachmentSource for AttachmentFile {
    fn size(&self) -> u64 {
        self.size
    }
    fn verify_snapshot(&self) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + '_>> {
        Box::pin(async move {
            match &self.source {
                #[cfg(target_arch = "wasm32")]
                FileSource::Host {
                    owner,
                    controller,
                    file,
                    available,
                    ..
                } => {
                    wait_until_available(owner, *available).await?;
                    anyhow::ensure!(owner.upgrade().is_some(), "attachment picker owner retired");
                    anyhow::ensure!(
                        controller
                            .files()
                            .get()
                            .iter()
                            .any(|selected| selected.token == *file && selected.size == self.size),
                        "attachment selection changed"
                    );
                }
                #[cfg(not(target_arch = "wasm32"))]
                FileSource::Native { file, modified } => {
                    let file = file
                        .lock()
                        .map_err(|_| anyhow::anyhow!("attachment file owner poisoned"))?;
                    let metadata = file.metadata()?;
                    anyhow::ensure!(
                        metadata.len() == self.size && metadata.modified()? == *modified,
                        "attachment input changed after selection"
                    );
                }
            }
            Ok(())
        })
    }
    fn read_range(
        &self,
        offset: u64,
        length: usize,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Vec<u8>>> + '_>> {
        Box::pin(async move {
            let end = offset
                .checked_add(u64::try_from(length)?)
                .ok_or_else(|| anyhow::anyhow!("attachment read range overflow"))?;
            anyhow::ensure!(end <= self.size, "attachment read exceeds selected input");
            match &self.source {
                #[cfg(target_arch = "wasm32")]
                FileSource::Host {
                    owner,
                    controller,
                    file,
                    available,
                    ..
                } => {
                    let scope = owner
                        .upgrade()
                        .ok_or_else(|| anyhow::anyhow!("attachment picker owner retired"))?;
                    let mut bytes = Vec::with_capacity(length);
                    while bytes.len() < length {
                        wait_until_available(owner, *available).await?;
                        let available_revision = available.try_version()?;
                        let chunk_len = (length - bytes.len()).min(65536);
                        let (sender, receiver) = tokio::sync::oneshot::channel();
                        controller
                            .read_in(
                                &scope,
                                glory::render::FileRead {
                                    file: *file,
                                    offset: offset + bytes.len() as u64,
                                    length: chunk_len as u32,
                                },
                                move |result| {
                                    let _ = sender.send(result);
                                },
                            )
                            .map_err(|error| anyhow::anyhow!("attachment file read: {error}"))?;
                        let result = receiver
                            .await
                            .map_err(|_| anyhow::anyhow!("attachment read owner retired"))?;
                        let chunk = match result {
                            Ok(chunk) => chunk,
                            Err(_) if available.try_version()? != available_revision => continue,
                            Err(error) => anyhow::bail!("attachment file read: {error}"),
                        };
                        anyhow::ensure!(
                            chunk.len() == chunk_len,
                            "attachment file read was incomplete"
                        );
                        bytes.extend_from_slice(&chunk);
                    }
                    Ok(bytes)
                }
                #[cfg(not(target_arch = "wasm32"))]
                FileSource::Native { file, modified } => {
                    let file = file.clone();
                    let modified = *modified;
                    let expected_size = self.size;
                    let (sender, receiver) = tokio::sync::oneshot::channel();
                    std::thread::spawn(move || {
                        use std::io::{Read, Seek, SeekFrom};
                        let result = (|| -> anyhow::Result<Vec<u8>> {
                            let mut file = file
                                .lock()
                                .map_err(|_| anyhow::anyhow!("attachment file owner poisoned"))?;
                            let metadata = file.metadata()?;
                            anyhow::ensure!(
                                metadata.len() == expected_size && metadata.modified()? == modified,
                                "attachment input changed before range read"
                            );
                            file.seek(SeekFrom::Start(offset))?;
                            let mut bytes = vec![0; length];
                            file.read_exact(&mut bytes)?;
                            let metadata = file.metadata()?;
                            anyhow::ensure!(
                                metadata.len() == expected_size && metadata.modified()? == modified,
                                "attachment input changed during range read"
                            );
                            Ok(bytes)
                        })();
                        let _ = sender.send(result);
                    });
                    receiver
                        .await
                        .map_err(|_| anyhow::anyhow!("attachment reader stopped"))?
                }
            }
        })
    }
}

#[cfg(any(target_arch = "wasm32", test))]
async fn wait_until_available(
    owner: &glory::ui::WeakScope,
    available: glory::Cage<bool>,
) -> anyhow::Result<()> {
    use glory::prelude::*;
    let scope = owner
        .upgrade()
        .ok_or_else(|| anyhow::anyhow!("attachment picker owner retired"))?;
    if available.try_get()? {
        return Ok(());
    }
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let sender = std::rc::Rc::new(std::cell::RefCell::new(Some(sender)));
    let watcher = scope.mount_with(|| {
        widget(move |scope| {
            let sender = sender.clone();
            scope.effect(move || {
                if available.get()
                    && let Some(sender) = sender.borrow_mut().take()
                {
                    let _ = sender.send(());
                }
            });
            Ok(())
        })
    })?;
    let result = receiver
        .await
        .map_err(|_| anyhow::anyhow!("attachment picker owner retired while suspended"));
    drop(watcher);
    result
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod availability_tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use glory::prelude::*;

    use super::wait_until_available;

    fn pump(app: &glory::App, executor: &glory::core::executor::Executor) {
        for _ in 0..16 {
            executor.poll_one();
            app.flush().unwrap();
        }
    }

    #[test]
    fn attachment_wait_resumes_and_releases_temporary_owner() {
        let executor = Rc::new(glory::core::executor::Executor::new(256));
        let app = glory::App::with_host(executor.clone(), glory::render::memory::Memory::new);
        let available = app.scope().cage(false);
        let owner = app.scope().downgrade();
        let outcome = Rc::new(RefCell::new(None));
        let result = outcome.clone();
        let before = app.graph_stats().nodes;
        let task = app
            .scope()
            .spawn(async move {
                *result.borrow_mut() = Some(wait_until_available(&owner, available).await.is_ok());
            })
            .unwrap();
        pump(&app, &executor);
        assert!(outcome.borrow().is_none());
        available.revise(|value| *value = true);
        pump(&app, &executor);
        assert_eq!(*outcome.borrow(), Some(true));
        assert_eq!(app.graph_stats().nodes, before);
        task.cancel();
    }

    #[test]
    fn retiring_picker_owner_finishes_suspended_attachment_wait() {
        let executor = Rc::new(glory::core::executor::Executor::new(256));
        let app = glory::App::with_host(executor.clone(), glory::render::memory::Memory::new);
        let available = app.scope().cage(false);
        let picker = Rc::new(RefCell::new(None));
        let observed = picker.clone();
        let owner = app
            .scope()
            .mount_with(|| {
                widget(move |scope| {
                    *observed.borrow_mut() = Some(scope.downgrade());
                    Ok(())
                })
            })
            .unwrap();
        let picker = picker.borrow().clone().unwrap();
        let outcome = Rc::new(RefCell::new(None));
        let result = outcome.clone();
        let task = app
            .scope()
            .spawn(async move {
                *result.borrow_mut() =
                    Some(wait_until_available(&picker, available).await.is_err());
            })
            .unwrap();
        pump(&app, &executor);
        assert!(outcome.borrow().is_none());
        drop(owner);
        pump(&app, &executor);
        assert_eq!(*outcome.borrow(), Some(true));
        task.cancel();
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) async fn choose_files() -> anyhow::Result<Vec<AttachmentFile>> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let result = rfd::FileDialog::new()
            .pick_files()
            .unwrap_or_default()
            .into_iter()
            .map(|path| AttachmentFile::open(&path))
            .collect();
        let _ = sender.send(result);
    });
    receiver
        .await
        .map_err(|_| anyhow::anyhow!("attachment picker stopped"))?
}
