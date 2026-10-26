//! Exercise production attachment grants across a suspended presentation owner.
use std::cell::RefCell;
use std::rc::Rc;

use glory::prelude::*;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

use super::AttachmentFile;
use crate::attachments::AttachmentSource;
use crate::presentation::View;
use crate::presentation::widgets::{empty, paragraph, reactive_distinct};

thread_local! {
    static APP: RefCell<Option<glory::web::WebApp>> = const { RefCell::new(None) };
}

type Task = Rc<RefCell<Option<glory::core::TaskToken>>>;

#[wasm_bindgen(js_name = mountAttachmentLifetimeFixture)]
pub fn mount_attachment_lifetime_fixture(
    root: web_sys::Element,
) -> std::result::Result<(), JsValue> {
    APP.with(|slot| slot.borrow_mut().take());
    root.set_inner_html("");
    root.set_class_name("inkson-root inkson-theme-dark");
    let app = glory::web::launch_with(root, fixture)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    crate::presentation::host::prioritize_browser_styles()?;
    APP.with(|slot| *slot.borrow_mut() = Some(app));
    Ok(())
}

fn fixture(scope: &Scope) -> View {
    let available = scope.cage(true);
    let opened = scope.cage(true);
    let status = scope.cage("Choose an attachment larger than 128 KiB".to_owned());
    let task: Task = Rc::new(RefCell::new(None));
    let root = scope.downgrade();
    let picker = reactive_distinct(opened, move |scope, opened| {
        if !opened {
            return empty();
        }
        picker(scope, root.clone(), available, status, task.clone())
    });
    Box::new(view().class("attachment-lifetime-fixture").fill(vec![
            picker,
            Box::new(
                sapid::button()
                    .label("Resume attachment")
                    .enabled(scope.bond(move || !available.get() && opened.get()))
                    .on_press(move || available.revise(|value| *value = true)),
            ),
            Box::new(
                sapid::button()
                    .label("Retire picker")
                    .enabled(opened)
                    .on_press(move || opened.revise(|value| *value = false)),
            ),
            paragraph("attachment-lifetime-status", status),
        ]))
}

fn picker(
    scope: &Scope,
    root: glory::ui::WeakScope,
    available: Cage<bool>,
    status: Cage<String>,
    task: Task,
) -> View {
    let control = scope.cage(None::<sapid::FileController>);
    let leases = scope.cage(0usize);
    let owner = scope.downgrade();
    let picker = Box::new(
        sapid::file_button()
            .label("Read attachment")
            .controller_ref(control)
            .configuration(glory::render::FileConfig {
                max_files: 1,
                max_file_bytes: 1024 * 1024,
                max_total_bytes: 1024 * 1024,
                ..Default::default()
            })
            .enabled(scope.bond(move || available.get() || leases.get() > 0))
            .on_files(move |files| {
                let Some(owner) = owner.upgrade() else { return };
                let Some(root) = root.upgrade() else { return };
                let Some(control) = control.get_untracked() else {
                    return;
                };
                let Some(file) = files.into_iter().next() else {
                    return;
                };
                if let Some(previous) = task.borrow_mut().take() {
                    previous.cancel();
                }
                let source = AttachmentFile::selected(&owner, control, file, leases, available);
                match root.spawn(async move {
                    let result = read(source, available, status).await;
                    if let Err(error) = result {
                        let _ = status.try_revise(|value| *value = format!("error:{error}"));
                    }
                }) {
                    Ok(next) => *task.borrow_mut() = Some(next),
                    Err(error) => status.revise(|value| *value = format!("error:{error}")),
                }
            }),
    ) as View;
    super::super::super::panel::retained_surface(scope, available, picker)
}

async fn read(
    source: AttachmentFile,
    available: Cage<bool>,
    status: Cage<String>,
) -> anyhow::Result<()> {
    anyhow::ensure!(source.size() > 128 * 1024, "select more than 128 KiB");
    source.verify_snapshot().await?;
    let mut bytes = source.read_range(0, 65536).await?;
    available.revise(|value| *value = false);
    status.revise(|value| *value = format!("paused:{}", bytes.len()));
    while bytes.len() < source.size() as usize {
        let length = (source.size() as usize - bytes.len()).min(65536);
        bytes.extend(source.read_range(bytes.len() as u64, length).await?);
    }
    source.verify_snapshot().await?;
    let digest = crate::canonical::hex_encode(&Sha256::digest(&bytes));
    status.revise(|value| *value = format!("complete:{}:{digest}", bytes.len()));
    Ok(())
}
