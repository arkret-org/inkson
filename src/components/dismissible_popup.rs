//! Focus-managed popup; the host only dismisses a completed outside press.
use std::rc::Rc;

use glory::prelude::*;

use crate::presentation::{InksonContext, View};
pub struct DismissiblePopupProps {
    pub overlay_class: String,
    pub surface_class: String,
    pub aria_label: String,
    pub on_dismiss: Rc<dyn Fn(())>,
    pub children: Rc<dyn Fn(&Scope) -> View>,
    pub overlay_test_id: Option<String>,
    pub surface_test_id: Option<String>,
    pub overlay_style: Option<Style>,
    pub surface_style: Option<Style>,
}
pub fn dismissible_popup(
    _scope: &Scope,
    _context: Rc<InksonContext>,
    props: DismissiblePopupProps,
) -> View {
    let dismiss = props.on_dismiss;
    let children = props.children;
    let key = props
        .surface_test_id
        .clone()
        .unwrap_or_else(|| props.surface_class.replace(' ', "-"));
    let popup = sapid::dialog(key.clone())
        .unstyled()
        .class(format!("{} {}", props.surface_class, key))
        .name(props.aria_label)
        .open(true)
        .show_trigger(false)
        .show_close(false)
        .style(props.surface_style.unwrap_or_default())
        .on_dismiss(move |_| dismiss(()))
        .content(move || {
            let children = children.clone();
            widget(move |scope| children(scope).build(scope))
        });
    Box::new(
        view()
            .class(format!(
                "{} {}",
                props.overlay_class,
                props.overlay_test_id.unwrap_or_default()
            ))
            .style(props.overlay_style.unwrap_or_default())
            .fill(popup),
    )
}
