//! Circle scope controls preserve the caller-filtered membership boundary.
use std::rc::Rc;

use glory::prelude::*;

use crate::circle::{CircleScope, CircleSummary};
use crate::presentation::widgets::{line, paragraph, reactive, stack};
use crate::presentation::{InksonContext, View};
#[derive(Clone)]
pub struct CircleScopePickerProps {
    pub selected: Cage<CircleScope>,
    pub circles: Vec<CircleSummary>,
    pub test_id: Option<String>,
    pub onchange: Rc<dyn Fn(CircleScope)>,
}
pub fn circle_scope_picker(
    scope: &Scope,
    context: Rc<InksonContext>,
    props: CircleScopePickerProps,
) -> View {
    let selected = props.selected;
    let value = scope.bond(move || {
        Some(match selected.get() {
            CircleScope::Realm => "__realm__".into(),
            CircleScope::Circle { circle_id, .. } => circle_id,
        })
    });
    let key = props
        .test_id
        .unwrap_or_else(|| "circle-scope-picker".into());
    let circles = props.circles.clone();
    let handler = props.onchange;
    let ctx = context.clone();
    let picker_context = context.clone();
    let select = reactive(context.locale, move |_, _| {
        let realm_label = picker_context.tr("circle.scope.realm_everyone");
        let key = key.clone();
        let circles = circles.clone();
        let handler = handler.clone();
        #[cfg(not(target_arch = "wasm32"))]
        let close_label = picker_context.tr("common.close");
        Box::new(
            sapid::field(format!("{key}-field"))
                .unstyled()
                .class("field circle-scope-picker")
                .label("Scope")
                .control(move |field| {
                    let handler = handler.clone();
                    #[cfg(not(target_arch = "wasm32"))]
                    {
                        use crate::presentation::native_choice::{
                            NativeChoiceOption, NativeChoiceProps, native_choice,
                        };
                        let circles = circles.clone();
                        let key = key.clone();
                        let realm_label = realm_label.clone();
                        let close_label = close_label.clone();
                        widget(move |scope| {
                            let mut options =
                                vec![NativeChoiceOption::new("__realm__", realm_label.clone())];
                            options.extend(circles.iter().map(|circle| {
                                NativeChoiceOption::new(
                                    circle.id.clone(),
                                    format!("{} ({} members)", circle.title, circle.member_count),
                                )
                            }));
                            let circles = circles.clone();
                            let handler = handler.clone();
                            native_choice(
                                scope,
                                NativeChoiceProps::new(
                                    key.clone(),
                                    "Scope",
                                    value,
                                    options,
                                    move |value| {
                                        let Some(value) = value else { return };
                                        if value == "__realm__" {
                                            handler(CircleScope::Realm)
                                        } else if let Some(circle) =
                                            circles.iter().find(|circle| circle.id == value)
                                        {
                                            handler(circle.clone().into_scope())
                                        }
                                    },
                                )
                                .class("select")
                                .control_id(field.id.clone())
                                .close_label(close_label.clone()),
                            )
                            .build(scope)
                        })
                    }
                    #[cfg(target_arch = "wasm32")]
                    {
                        let mut options = vec![
                            sapid::select_option("__realm__", realm_label.clone())
                                .value("__realm__"),
                        ];
                        options.extend(circles.iter().map(|circle| {
                            sapid::select_option(
                                circle.id.clone(),
                                format!("{} ({} members)", circle.title, circle.member_count),
                            )
                            .value(circle.id.clone())
                        }));
                        let circles = circles.clone();
                        sapid::select(key.clone())
                            .unstyled()
                            .class("select")
                            .field(field)
                            .value(value)
                            .options(options)
                            .on_value_change(move |value| {
                                let Some(value) = value else { return };
                                if value == "__realm__" {
                                    handler(CircleScope::Realm)
                                } else if let Some(circle) =
                                    circles.iter().find(|circle| circle.id == value)
                                {
                                    handler(circle.clone().into_scope())
                                }
                            })
                    }
                }),
        ) as View
    });
    let circles = props.circles;
    let badge = reactive(selected, move |scope, selected| {
        match circles
            .iter()
            .find(|circle| selected.circle_id() == Some(circle.id.as_str()))
        {
            Some(circle) => circle_identity_badge(
                scope,
                ctx.clone(),
                CircleIdentityBadgeProps {
                    color: circle.display.color_token,
                    symbol: circle.display.symbol.clone(),
                    short_name: Some(circle.display.short_name.clone()),
                },
            ),
            None => Box::new(widget(|_| Ok(()))),
        }
    });
    stack(
        "circle-scope-picker-container",
        vec![
            select,
            badge,
            paragraph(
                "field-help muted",
                context.translated(scope, "circle.scope.help"),
            ),
        ],
    )
}
#[derive(Clone)]
pub struct CircleComposerBannerProps {
    pub scope: CircleScope,
    pub display: Option<arkret_sdk::CircleDisplay>,
    pub encrypted: Option<bool>,
}
pub fn circle_composer_banner(
    scope: &Scope,
    context: Rc<InksonContext>,
    props: CircleComposerBannerProps,
) -> View {
    let CircleScope::Circle {
        circle_id: _,
        title,
        member_count,
    } = props.scope
    else {
        return Box::new(widget(|_| Ok(())));
    };
    let icon = if let Some(display) = props.display {
        circle_identity_badge(
            scope,
            context,
            CircleIdentityBadgeProps {
                color: display.color_token,
                symbol: display.symbol,
                short_name: Some(display.short_name),
            },
        )
    } else {
        paragraph("banner-icon", "◯")
    };
    let encryption = match props.encrypted {
        Some(true) => "E2EE active",
        Some(false) => "Restricted delivery · not E2EE",
        None => "Waiting for verified encryption state",
    };
    let visibility = if member_count == 0 {
        "This message is visible only to Circle members.".into()
    } else {
        format!("This message is visible only to {member_count} Circle member(s).")
    };
    line(
        "banner circle-composer-banner",
        vec![
            icon,
            stack(
                "banner-body",
                vec![
                    paragraph("", format!("Circle scope · {title}")),
                    paragraph("muted", encryption),
                    paragraph("muted", visibility),
                ],
            ),
        ],
    )
}
#[derive(Clone)]
pub struct CircleIdentityBadgeProps {
    pub color: arkret_sdk::CircleColorToken,
    pub symbol: arkret_sdk::CircleSymbol,
    pub short_name: Option<String>,
}
pub fn circle_identity_badge(
    _scope: &Scope,
    _context: Rc<InksonContext>,
    props: CircleIdentityBadgeProps,
) -> View {
    use arkret_sdk::{CircleColorToken as Color, CircleGlyph as Glyph, CircleSymbol as Symbol};
    let CircleIdentityBadgeProps {
        color,
        symbol,
        short_name,
    } = props;
    let symbol_label = match symbol {
        Symbol::Emoji { emoji } => emoji,
        Symbol::Glyph { glyph } => match glyph {
            Glyph::Lock => "🔒",
            Glyph::Shield => "🛡",
            Glyph::Eye => "◉",
            Glyph::EyeOff => "◌",
            Glyph::UserShield => "♙",
            Glyph::Fingerprint => "◎",
            Glyph::Key => "⚿",
            Glyph::Diamond => "◇",
            Glyph::Flame => "♨",
            Glyph::Leaf => "♧",
            Glyph::Stamp => "▣",
            Glyph::Compass => "✥",
            Glyph::Atom => "⚛",
            Glyph::Bolt => "ϟ",
            Glyph::Moon => "☾",
            Glyph::Sun => "☀",
            Glyph::Star => "☆",
            Glyph::Globe => "⊕",
            Glyph::Satellite => "✧",
            Glyph::Ring => "◯",
            Glyph::Chain => "∞",
            Glyph::Tag => "⌑",
            Glyph::Flag => "⚑",
            Glyph::Scroll => "▤",
            Glyph::Scale => "⚖",
            Glyph::Hourglass => "⌛",
            Glyph::Spark => "✦",
        }
        .to_owned(),
    };

    let mut children = vec![paragraph("circle-identity-symbol", symbol_label)];
    if let Some(name) = short_name {
        children.push(paragraph("circle-identity-short-name", name));
    }
    let class = match color {
        Color::Slate => "slate",
        Color::Red => "red",
        Color::Orange => "orange",
        Color::Amber => "amber",
        Color::Yellow => "yellow",
        Color::Lime => "lime",
        Color::Green => "green",
        Color::Emerald => "emerald",
        Color::Teal => "teal",
        Color::Cyan => "cyan",
        Color::Sky => "sky",
        Color::Blue => "blue",
        Color::Indigo => "indigo",
        Color::Violet => "violet",
        Color::Fuchsia => "fuchsia",
        Color::Pink => "pink",
        Color::GrayHighContrast => "high-contrast",
    };
    line(
        format!("circle-identity-badge circle-identity-{class}"),
        children,
    )
}
#[derive(Clone)]
pub struct ConfidentialDiscussionOfBannerProps {
    pub target_strand_id: String,
    pub target_title: String,
    pub target_realm_id: Option<String>,
}
pub fn confidential_discussion_of_banner(
    _scope: &Scope,
    context: Rc<InksonContext>,
    props: ConfidentialDiscussionOfBannerProps,
) -> View {
    let href = match props.target_realm_id.as_deref() {
        Some(realm) if !realm.trim().is_empty() => {
            format!("/kanban/{realm}/task/{}", props.target_strand_id)
        }
        _ => format!("#strand:{}", props.target_strand_id),
    };
    line(
        "banner confidential-discussion-of-banner",
        vec![
            paragraph("banner-icon", "💬"),
            stack(
                "banner-body",
                vec![
                    line(
                        "",
                        vec![
                            paragraph("", "Confidential discussion of "),
                            if let Some(realm_id) = props
                                .target_realm_id
                                .filter(|value| !value.trim().is_empty())
                            {
                                let route = crate::routes::Route::KanbanTask {
                                    realm_id,
                                    task_id: props.target_strand_id,
                                    tab: String::new(),
                                };
                                Box::new(
                                    crate::presentation::widgets::internal_link()
                                        .target(href)
                                        .on(glory::render::EventKind::Activate, move |_| {
                                            context.navigate(route.clone())
                                        })
                                        .fill(glory::prelude::text().content(props.target_title)),
                                ) as View
                            } else {
                                Box::new(
                                    sapid::anchor()
                                        .unstyled()
                                        .href(href)
                                        .label(props.target_title),
                                ) as View
                            },
                        ],
                    ),
                    paragraph(
                        "muted",
                        "This Strand is the confidential side of another Strand. Members of this Circle can see both sides.",
                    ),
                ],
            ),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: &str) -> CircleSummary {
        CircleSummary {
            id: id.to_owned(),
            realm_id: "ak:realm:A28oJpDpEI80mVokdt5Yo0vuv0Z1SXEPt1X593Rirmn8".to_owned(),
            title: format!("Title {id}"),
            display: crate::operation::ak_ops::circle_display_from_title("T"),
            member_count: 3,
            state: arkret_sdk::CircleState::Active,
            viewer_is_member: true,
        }
    }

    #[test]
    fn picker_default_selection_is_realm() {
        // Smoke test: constructing the prop struct with defaults yields
        // a Realm-scope selection. The component itself is a semantic
        // surface; full render coverage lives in the e2e harness.
        let selected = CircleScope::default();
        assert_eq!(selected.label(), "Realm");
    }

    #[test]
    fn picker_circle_list_round_trips() {
        let one = sample("ak:circle:one");
        let two = sample("ak:circle:two");
        assert_eq!(one.into_scope().circle_id(), Some("ak:circle:one"));
        assert_eq!(two.into_scope().circle_id(), Some("ak:circle:two"));
    }
}
