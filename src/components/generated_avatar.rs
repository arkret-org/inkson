//! Deterministic, GitHub-style fallback avatars for identities without an upload.

use std::rc::Rc;

use glory::prelude::*;
use glory::render::{GraphicPoint as Point, GraphicProps, PathCommand as Cmd};
use glory::style::Color;

use crate::presentation::{InksonContext, View};

const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

fn avatar_hash(seed: &str) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for byte in seed.trim().to_lowercase().bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn identicon_cells(seed: &str) -> Vec<(usize, usize)> {
    let hash = avatar_hash(seed);
    let mut cells = Vec::new();
    for y in 0..5 {
        for x in 0..3 {
            let bit = y * 3 + x;
            if (hash >> bit) & 1 == 0 {
                continue;
            }
            cells.push((x, y));
            if x < 2 {
                cells.push((4 - x, y));
            }
        }
    }
    if cells.is_empty() {
        cells.push((2, 2));
    }
    cells
}

#[derive(Clone)]
pub struct GeneratedAvatarProps {
    pub seed: String,
    pub alt_text: String,
    pub class: String,
    pub test_id: Option<String>,
}
#[derive(Clone)]
pub struct IdentityAvatarProps {
    pub seed: String,
    pub alt_text: String,
    pub blob_ref: Option<String>,
    pub class: String,
    pub test_id: Option<String>,
}
fn avatar_color(hue: f64) -> Color {
    let chroma = (1.0_f64 - (2.0_f64 * 0.42 - 1.0_f64).abs()) * 0.58;
    let x = chroma * (1.0 - ((hue / 60.0) % 2.0 - 1.0).abs());
    let (r, g, b) = match (hue / 60.0) as u8 {
        0 => (chroma, x, 0.0),
        1 => (x, chroma, 0.0),
        2 => (0.0, chroma, x),
        3 => (0.0, x, chroma),
        4 => (x, 0.0, chroma),
        _ => (chroma, 0.0, x),
    };
    let m = 0.42 - chroma / 2.0;
    Color(
        ((r + m) * 255.0).round() as u8,
        ((g + m) * 255.0).round() as u8,
        ((b + m) * 255.0).round() as u8,
        255,
    )
}
fn avatar_drawing(seed: &str, alt_text: String) -> GraphicProps {
    let mut commands = Vec::new();
    for (x, y) in identicon_cells(seed) {
        let (x, y) = (x as f64 + 0.75, y as f64 + 0.75);
        commands.extend([
            Cmd::Move(Point::new(x, y)),
            Cmd::Line(Point::new(x + 1.0, y)),
            Cmd::Line(Point::new(x + 1.0, y + 1.0)),
            Cmd::Line(Point::new(x, y + 1.0)),
            Cmd::Close,
        ]);
    }
    GraphicProps {
        width: 6.5,
        height: 6.5,
        commands,
        fill: Some(avatar_color((avatar_hash(seed) % 360) as f64)),
        alternative: (!alt_text.trim().is_empty()).then_some(alt_text),
        ..Default::default()
    }
}
pub fn generated_avatar(
    _scope: &Scope,
    _context: Rc<InksonContext>,
    props: GeneratedAvatarProps,
) -> View {
    Box::new(
        view()
            .class(format!(
                "{} {}",
                props.class,
                props.test_id.unwrap_or_default()
            ))
            .name(props.alt_text.clone())
            .fill(
                glory::ui::graphic()
                    .drawing(avatar_drawing(&props.seed, props.alt_text))
                    .style(
                        Style::new()
                            .width(Length::Percent(100.0))
                            .height(Length::Percent(100.0)),
                    ),
            ),
    )
}
fn generated_avatar_inline(props: GeneratedAvatarProps) -> View {
    let name = props.alt_text.clone();
    let avatar = glory::ui::graphic()
        .class(format!(
            "{} {} generated-avatar",
            props.class,
            props.test_id.unwrap_or_default()
        ))
        .drawing(avatar_drawing(&props.seed, props.alt_text));
    Box::new(if name.trim().is_empty() {
        avatar
    } else {
        avatar.name(name)
    })
}
fn avatar_inline_from_source(
    scope: &Scope,
    props: GeneratedAvatarProps,
    data: Cage<Option<std::result::Result<String, String>>>,
) -> View {
    let ready = scope.bond(move || matches!(data.get(), Some(Ok(source)) if !source.is_empty()));
    let source = scope.bond(move || {
        data.get()
            .and_then(std::result::Result::ok)
            .unwrap_or_default()
    });
    let class = format!(
        "{} {}",
        props.class,
        props.test_id.clone().unwrap_or_default()
    );
    let alt = props.alt_text.clone();
    Box::new(
        glory::ui::when(ready, move || {
            let image = image().class(class.clone()).source(source);
            Box::new(if alt.trim().is_empty() {
                image.decorative()
            } else {
                image.alt(alt.clone())
            }) as View
        })
        .otherwise(move || generated_avatar_inline(props.clone())),
    )
}
/// Identity image for an intrinsic button; all descendants remain inline semantic nodes.
pub fn identity_avatar_inline(
    scope: &Scope,
    context: Rc<InksonContext>,
    props: IdentityAvatarProps,
) -> View {
    let fallback = GeneratedAvatarProps {
        seed: props.seed,
        alt_text: props.alt_text,
        class: props.class,
        test_id: props.test_id,
    };
    let Some(blob) = props.blob_ref.filter(|blob| !blob.trim().is_empty()) else {
        return generated_avatar_inline(fallback);
    };
    let mime = crate::content::renderer::blob_ref_media_type_hint(&blob)
        .unwrap_or_else(|| "image/png".into());
    let source =
        crate::content::authenticated_blob_source(scope, context, blob.trim().to_owned(), mime);
    avatar_inline_from_source(scope, fallback, source.data)
}
pub fn identity_avatar(
    scope: &Scope,
    context: Rc<InksonContext>,
    props: IdentityAvatarProps,
) -> View {
    if let Some(blob_ref) = props.blob_ref.filter(|value| !value.trim().is_empty()) {
        return Box::new(
            view()
                .class(format!(
                    "{} {}",
                    props.class,
                    props.test_id.clone().unwrap_or_default()
                ))
                .fill(crate::content::renderer::authenticated_blob_image(
                    scope,
                    context,
                    blob_ref.trim().to_owned(),
                    props.alt_text,
                )),
        );
    }
    let class = if props
        .class
        .split_ascii_whitespace()
        .any(|name| name == "generated-avatar")
    {
        props.class
    } else {
        format!("{} generated-avatar", props.class)
    };
    generated_avatar(
        scope,
        context,
        GeneratedAvatarProps {
            seed: props.seed,
            alt_text: props.alt_text,
            class,
            test_id: props.test_id,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identicon_is_stable_and_horizontally_symmetric() {
        let cells = identicon_cells("summary");
        assert_eq!(cells, identicon_cells(" SUMMARY "));
        assert!(!cells.is_empty());
        for (x, y) in &cells {
            assert!(cells.contains(&(4 - x, *y)));
        }
    }

    #[test]
    fn different_seeds_produce_different_patterns() {
        assert_ne!(identicon_cells("alpha"), identicon_cells("beta"));
    }

    #[test]
    fn inline_avatar_loading_success_and_failure_keep_a_valid_button_owner() {
        use glory::render::{NodeId, Props};
        fn nodes(app: &App) -> Vec<NodeId> {
            let tree = app.tree();
            let mut pending = tree.roots().to_vec();
            let mut nodes = Vec::new();
            while let Some(id) = pending.pop() {
                nodes.push(id);
                pending.extend(tree.node(id).unwrap().children.iter().copied());
            }
            nodes
        }
        let app = App::memory();
        let data = app
            .scope()
            .cage(None::<std::result::Result<String, String>>);
        let props = GeneratedAvatarProps {
            seed: "Alice".into(),
            alt_text: "Alice".into(),
            class: "sidebar-nav-icon contact-sidebar-user-avatar avatar-img".into(),
            test_id: None,
        };
        app.mount(
            sapid::button()
                .unstyled()
                .name("Account")
                .fill(avatar_inline_from_source(app.scope(), props, data)),
        )
        .unwrap();
        app.flush().unwrap();
        let button = nodes(&app)
            .into_iter()
            .find(|id| {
                matches!(
                    app.tree().node(*id).unwrap().descriptor.view().props,
                    Props::Button(_)
                )
            })
            .unwrap();
        let is_graphic = || {
            nodes(&app).into_iter().any(|id| {
                matches!(
                    app.tree().node(id).unwrap().descriptor.view().props,
                    Props::Graphic(_)
                )
            })
        };
        let is_image = || {
            nodes(&app).into_iter().any(|id| {
                matches!(
                    app.tree().node(id).unwrap().descriptor.view().props,
                    Props::Image(_)
                )
            })
        };
        assert!(is_graphic());
        assert!(!is_image());
        data.revise(|data| *data = Some(Ok("data:image/png;base64,aGVsbG8=".into())));
        app.flush().unwrap();
        assert!(is_image());
        assert!(!is_graphic());
        assert!(app.scope().is_active(button).unwrap());
        data.revise(|data| *data = Some(Err("Authenticated image unavailable".into())));
        app.flush().unwrap();
        assert!(is_graphic());
        assert!(!is_image());
        assert!(app.scope().is_active(button).unwrap());
        let tree = app.tree();
        assert!(nodes(&app).iter().any(|id| {
            tree.node(*id)
                .unwrap()
                .descriptor
                .view()
                .classes
                .iter()
                .any(|class| class == "generated-avatar")
        }));
    }

    #[test]
    fn empty_alt_inline_avatar_is_explicitly_decorative_in_both_branches() {
        let app = App::memory();
        let data = app
            .scope()
            .cage(None::<std::result::Result<String, String>>);
        app.mount(sapid::button().unstyled().name("Show own agents").fill(
            avatar_inline_from_source(
                app.scope(),
                GeneratedAvatarProps {
                    seed: String::new(),
                    alt_text: String::new(),
                    class: "avatar-img".into(),
                    test_id: None,
                },
                data,
            ),
        ))
        .unwrap();
        app.flush().unwrap();
        let assert_decorative = || {
            let tree = app.tree();
            let mut pending = tree.roots().to_vec();
            let mut found = false;
            while let Some(id) = pending.pop() {
                let node = tree.node(id).unwrap();
                pending.extend(node.children.iter().copied());
                match node.descriptor.view().props {
                    glory::render::Props::Graphic(graphic) => {
                        assert!(graphic.alternative.is_none());
                        found = true;
                    }
                    glory::render::Props::Image(image) => {
                        assert!(image.alternative.is_none());
                        found = true;
                    }
                    _ => {}
                }
            }
            assert!(found);
        };
        assert_decorative();
        data.revise(|data| *data=Some(Ok("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScLbtAAAAABJRU5ErkJggg==".into())));
        app.flush().unwrap();
        assert_decorative();
    }
}
