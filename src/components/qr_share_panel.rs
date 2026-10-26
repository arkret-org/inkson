//! Shared QR and readable URL handoff, with owner-scoped copy feedback.
use std::rc::Rc;
use std::time::Duration;

use glory::prelude::*;
use glory::render::{GraphicPoint as Point, GraphicProps, PathCommand as Cmd};
use glory::style::Color;

use crate::presentation::widgets::{line, paragraph, reactive, stack};
use crate::presentation::{InksonContext, View};
#[derive(Clone)]
pub struct QrSharePanelProps {
    pub qr_svg: String,
    pub url: String,
    pub qr_aria_label: String,
    pub url_aria_label: String,
    pub qr_test_id: String,
    pub url_test_id: String,
    pub copy_test_id: String,
    pub url_rows: u32,
}
fn qr_image(url: &str, label: String, key: String) -> View {
    let Ok(code) = qrcode::QrCode::new(url.as_bytes()) else {
        return paragraph(
            "muted qr-share-empty",
            crate::i18n::tr("qr_share.unavailable"),
        );
    };
    let side = code.width();
    let width = (side + 8) as f64;
    let mut layers = Vec::new();
    let mut commands = Vec::new();
    for y in 0..side {
        for x in 0..side {
            if code[(x, y)] != qrcode::Color::Dark {
                continue;
            }
            let (x, y) = ((x + 4) as f64, (y + 4) as f64);
            commands.extend([
                Cmd::Move(Point::new(x, y)),
                Cmd::Line(Point::new(x + 1.0, y)),
                Cmd::Line(Point::new(x + 1.0, y + 1.0)),
                Cmd::Line(Point::new(x, y + 1.0)),
                Cmd::Close,
            ]);
            if commands.len() >= 250 {
                layers.push(std::mem::take(&mut commands));
            }
        }
    }
    if !commands.is_empty() {
        layers.push(commands);
    }
    Box::new(
        view()
            .class(format!("qr-image qr-share-image {key}"))
            .name(label)
            .fill(
                layers
                    .into_iter()
                    .map(move |commands| {
                        glory::ui::graphic()
                            .class("qr-share-geometry")
                            .drawing(GraphicProps {
                                width,
                                height: width,
                                commands,
                                fill: Some(Color(0, 0, 0, 255)),
                                ..Default::default()
                            })
                    })
                    .collect::<Vec<_>>(),
            ),
    )
}
pub fn qr_share_panel(scope: &Scope, context: Rc<InksonContext>, props: QrSharePanelProps) -> View {
    let copied = scope.cage(false);
    let error = scope.cage(String::new());
    let copy_epoch = scope.cage(0_u64);
    let owner = scope.downgrade();
    let copy_value = props.url.clone();
    let ctx = context.clone();
    let label = scope.bond(move || {
        ctx.tr(if copied.get() {
            "qr_share.copied"
        } else {
            "qr_share.copy_link"
        })
    });
    let copy = Box::new(
        sapid::button()
            .unstyled()
            .class(format!(
                "btn qr-share-copy secondary {}",
                props.copy_test_id
            ))
            .label(label)
            .enabled(!props.url.is_empty())
            .on_press(move || {
                let Some(scope) = owner.upgrade() else { return };
                let value = copy_value.clone();
                let owner = scope.downgrade();
                copy_epoch.revise(|epoch| *epoch = epoch.wrapping_add(1));
                let epoch = copy_epoch.get();
                let _ = scope.owner().spawn(async move {
                    match super::platform_io::copy_text(&value).await {
                        Ok(()) => {
                            if owner.upgrade().is_none() {
                                return;
                            }
                            copied.revise(|v| *v = true);
                            error.revise(|v| v.clear());
                        }
                        Err(message) => {
                            if owner.upgrade().is_some() {
                                error.revise(|v| *v = message);
                            }
                            return;
                        }
                    }
                    crate::runtime_helpers::sleep_for(Duration::from_millis(2000)).await;
                    if owner.upgrade().is_some() && copy_epoch.get() == epoch {
                        copied.revise(|v| *v = false);
                    }
                });
            }),
    ) as View;
    let image = if props.qr_svg.is_empty() {
        paragraph(
            "muted qr-share-empty",
            context.translated(scope, "qr_share.unavailable"),
        )
    } else {
        qr_image(&props.url, props.qr_aria_label, props.qr_test_id)
    };
    let value = props.url;
    let field = Box::new(
        sapid::text_field()
            .unstyled()
            .class(format!(
                "mono qr-share-url-field {} qr-share-rows-{}",
                props.url_test_id,
                props.url_rows.clamp(1, 12)
            ))
            .name(props.url_aria_label)
            .value(value)
            .multiline(true)
            .readonly(true),
    ) as View;
    let error_view = reactive(error, |_, value| paragraph("muted qr-share-error", value));
    stack(
        "qr-share-container",
        vec![line(
            "qr-share-panel",
            vec![
                stack(
                    "qr-share-qr-pane",
                    vec![
                        paragraph(
                            "qr-share-pane-label",
                            context.translated(scope, "qr_share.scan"),
                        ),
                        image,
                    ],
                ),
                stack(
                    "qr-share-url-pane",
                    vec![
                        line(
                            "qr-share-url-head",
                            vec![
                                paragraph(
                                    "qr-share-pane-label",
                                    context.translated(scope, "qr_share.use_link"),
                                ),
                                copy,
                            ],
                        ),
                        field,
                        paragraph(
                            "muted qr-share-hint",
                            context.translated(scope, "qr_share.private_hint"),
                        ),
                        error_view,
                    ],
                ),
            ],
        )],
    )
}
