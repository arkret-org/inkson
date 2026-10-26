use glory::render::{RichBlock, RichBlockKind, RichDocument, RichMarks, RichRun};

use super::*;
fn inline_runs(value: &str) -> Vec<RichRun> {
    use pulldown_cmark::{Event, Parser, Tag, TagEnd};
    let mut marks = RichMarks::default();
    let mut runs = vec![];
    let mut image = None::<String>;
    for event in Parser::new(value) {
        match event {
            Event::Start(Tag::Strong) => marks.bold = true,
            Event::End(TagEnd::Strong) => marks.bold = false,
            Event::Start(Tag::Emphasis) => marks.italic = true,
            Event::End(TagEnd::Emphasis) => marks.italic = false,
            Event::Start(Tag::Link { dest_url, .. }) => {
                if ["http:", "https:", "mailto:"]
                    .iter()
                    .any(|prefix| dest_url.starts_with(prefix))
                {
                    marks.link = Some(dest_url.to_string());
                }
            }
            Event::End(TagEnd::Link) => marks.link = None,
            Event::Start(Tag::Image { dest_url, .. }) => {
                image = Some(dest_url.to_string());
                runs.push(RichRun {
                    text: "![".into(),
                    marks: marks.clone(),
                });
            }
            Event::End(TagEnd::Image) => {
                if let Some(url) = image.take() {
                    runs.push(RichRun {
                        text: format!("]({url})"),
                        marks: marks.clone(),
                    });
                }
            }
            Event::Text(text) | Event::Html(text) | Event::InlineHtml(text) => runs.push(RichRun {
                text: text.to_string(),
                marks: marks.clone(),
            }),
            Event::Code(text) => {
                let mut code = marks.clone();
                code.code = true;
                runs.push(RichRun {
                    text: text.to_string(),
                    marks: code,
                });
            }
            Event::SoftBreak | Event::HardBreak => runs.push(RichRun {
                text: "\n".into(),
                marks: marks.clone(),
            }),
            _ => {}
        }
    }
    if runs.is_empty() {
        runs.push(RichRun {
            text: value.to_owned(),
            marks: RichMarks::default(),
        });
    }
    runs
}
fn markdown_document(value: &str) -> RichDocument {
    let mut blocks = vec![];
    for line in value.split('\n') {
        let (kind, body) = if let Some(body) = line.strip_prefix("> ") {
            (RichBlockKind::Quote, body)
        } else {
            let level = line.chars().take_while(|ch| *ch == '#').count();
            if (1..=6).contains(&level) && line.as_bytes().get(level) == Some(&b' ') {
                (RichBlockKind::Heading(level as u8), &line[level + 1..])
            } else {
                (RichBlockKind::Paragraph, line)
            }
        };
        let literal = body.starts_with("- ")
            || body.starts_with("* ")
            || body.starts_with("\x60\x60\x60")
            || body.starts_with('|')
            || body.chars().next().is_some_and(|ch| ch.is_ascii_digit());
        let runs = if literal {
            vec![RichRun {
                text: body.to_owned(),
                marks: RichMarks::default(),
            }]
        } else {
            inline_runs(body)
        };
        blocks.push(RichBlock { kind, runs });
    }
    if blocks.is_empty() {
        RichDocument::default()
    } else {
        RichDocument { blocks }
    }
}
#[cfg(any(target_arch = "wasm32", test))]
fn document_markdown(document: &RichDocument) -> String {
    document
        .blocks
        .iter()
        .map(|block| {
            let mut value = match block.kind {
                RichBlockKind::Heading(level) => format!("{} ", "#".repeat(level as usize)),
                RichBlockKind::Quote => "> ".into(),
                RichBlockKind::Paragraph => String::new(),
            };
            for run in &block.runs {
                let mut text = run.text.clone();
                if run.marks.code {
                    text = format!("\x60{text}\x60");
                }
                if run.marks.italic {
                    text = format!("*{text}*");
                }
                if run.marks.bold {
                    text = format!("**{text}**");
                }
                if let Some(link) = &run.marks.link {
                    text = format!("[{text}]({link})");
                }
                value.push_str(&text);
            }
            value
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(any(target_arch = "wasm32", test))]
fn native_rich_editor(
    label: String,
    value: Cage<String>,
    document: Cage<Rc<RichDocument>>,
    editor: Cage<Option<sapid::EditorController>>,
    status: Cage<String>,
) -> View {
    Box::new(
        sapid::rich_text_editor()
            .unstyled()
            .class("card-rich-editor-host card-detail-description-rich-editor")
            .name(label)
            .document(document)
            .controller_ref(editor)
            .on_document_change(move |next| {
                let markdown = document_markdown(&next);
                if markdown.len() <= 8192 {
                    document.revise(|value| *value = next);
                    value.revise(|value| *value = markdown);
                } else {
                    status.revise(|value| *value = "The editor accepts at most 8192 bytes.".into());
                }
            }),
    )
}

pub(super) fn card_markdown_editor(
    scope: &Scope,
    app: Rc<InksonContext>,
    key: &str,
    label: &str,
    value: Cage<String>,
    realm: String,
    allow_image_upload: bool,
) -> View {
    let initial = markdown_document(&value.get_untracked());
    let source = scope.cage(initial.validate().is_err());
    let document = scope.cage(Rc::new(if initial.validate().is_ok() {
        initial
    } else {
        RichDocument::default()
    }));
    let editor = scope.cage(None::<sapid::EditorController>);
    let status = scope.cage(String::new());
    scope.effect(move || {
        let next = markdown_document(&value.get());
        if next.validate().is_ok() && document.get_untracked().as_ref() != &next {
            document.revise(|current| *current = Rc::new(next));
        }
    });
    let editor_actions = scope.bond(move || cfg!(target_arch = "wasm32") || source.get());
    #[cfg(target_arch = "wasm32")]
    let mode_label: glory::Lotus<String> = "Markdown / Rich text".to_owned().into();
    #[cfg(not(target_arch = "wasm32"))]
    let mode_label: glory::Lotus<String> = {
        let app = app.clone();
        scope
            .bond(move || {
                app.tr(if source.get() {
                    "kanban.editor.choose_rich"
                } else {
                    "kanban.editor.choose_markdown"
                })
            })
            .into()
    };
    let mode: View = Box::new(
        sapid::button()
            .unstyled()
            .class("btn secondary editor-mode-toggle")
            .label(mode_label)
            .on_press(move || source.revise(|value| *value = !*value)),
    );
    let rich = {
        let key = key.to_owned();
        let label = label.to_owned();
        #[cfg(not(target_arch = "wasm32"))]
        let app = app.clone();
        reactive(source, move |scope, source| {
            if source {
                return Box::new(
                    sapid::text_field()
                        .unstyled()
                        .class(format!("textarea card-rich-editor-fallback {key}"))
                        .name(label.clone())
                        .value(value)
                        .multiline(true)
                        .on_value_change(move |next| {
                            if next.len() <= 8192 {
                                value.revise(|value| *value = next);
                            }
                        }),
                );
            }
            #[cfg(target_arch = "wasm32")]
            {
                let _ = scope;
                native_rich_editor(label.clone(), value, document, editor, status)
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                Box::new(
                    glory::ui::view()
                        .class("callout card-rich-editor-unavailable")
                        .role(glory::render::Role::Status)
                        .fill(paragraph(
                            "",
                            app.translated(scope, "kanban.editor.native_rich_unavailable"),
                        )),
                )
            }
        })
    };
    let mut toolbar = vec![mode];
    for (label, syntax) in [
        ("List", "\n- List item"),
        ("Numbered list", "\n1. List item"),
        ("Task list", "\n- [ ] Task"),
        (
            "Table",
            "\n| Column | Column |\n| --- | --- |\n| Value | Value |",
        ),
        ("Code block", "\n\x60\x60\x60\ncode\n\x60\x60\x60"),
        ("Horizontal line", "\n---\n"),
    ] {
        toolbar.push(Box::new(
            sapid::button()
                .unstyled()
                .class("btn secondary editor-insert")
                .label(label)
                .enabled(editor_actions)
                .on_press(move || {
                    if !editor_actions.get_untracked() {
                        return;
                    }
                    if source.get_untracked() {
                        value.revise(|value| value.push_str(syntax));
                    } else if let Some(editor) = editor.get_untracked() {
                        let selection = editor.selection().get();
                        if let Err(error) =
                            editor.insert_at(selection, syntax, RichMarks::default())
                        {
                            status.revise(|value| *value = error.to_string());
                        }
                    }
                }),
        ));
    }
    if allow_image_upload {
        let weak = scope.downgrade();
        let context = app.clone();
        toolbar.push(crate::components::avatar_uploader::image_file_picker_labeled(scope,app.clone(),format!("{key}-image"),"Upload image".to_owned().into(),editor_actions.into(),Rc::new(move|selected|{if !editor_actions.get_untracked(){return;}let Some(scope)=weak.upgrade()else{return;};let owner=scope.downgrade();let context=context.clone();let realm=realm.clone();let generation=context.session_generation.get();let account=context.active_account.get();let _=scope.owner().spawn(async move{use base64::Engine as _;let request=json!({"content_base64":base64::engine::general_purpose::STANDARD.encode(&selected.bytes),"media_type":selected.media_type,"filename":selected.filename});let result=toast_editor_upload_via_api(&context.base_url.get_untracked(),context.token.get_untracked(),&realm,true,&request).await;if owner.upgrade().is_none()||!context.session_matches(generation,&account){return;}match result{Ok((blob,_))=>{let text=format!("![image]({blob})");if source.get_untracked() || !cfg!(target_arch="wasm32"){value.revise(|value|value.push_str(&text));}else if let Some(editor)=editor.get_untracked(){let _=editor.insert_at(editor.selection().get(),&text,RichMarks::default());}},Err(error)=>status.revise(|value|*value=error)}});}),Rc::new(move|error|status.revise(|value|*value=error))));
    }
    let preview = {
        let app = app.clone();
        reactive(value, move |scope, value| {
            let blocks = crate::content::renderer::parse_message_body(&value);
            stack(
                "card-rich-editor-preview",
                vec![crate::content::render_blocks(scope, app.clone(), &blocks)],
            )
        })
    };
    stack(
        "card-rich-editor",
        vec![
            line("card-rich-editor-toolbar", toolbar),
            rich,
            preview,
            paragraph("muted card-rich-editor-status", status),
        ],
    )
}
pub(super) fn edit_actions(
    scope: &Scope,
    app: Rc<InksonContext>,
    status: Cage<String>,
    enabled: impl Into<glory::Lotus<bool>>,
    save: impl FnMut() + 'static,
    cancel: impl FnMut() + 'static,
) -> View {
    stack(
        "card-detail-edit-controls",
        vec![
            paragraph("card-detail-edit-status", status),
            line(
                "card-detail-form-actions",
                vec![
                    action(
                        scope,
                        app.clone(),
                        "card-detail-save-button",
                        "common.save",
                        "primary",
                        enabled,
                        save,
                    ),
                    action(
                        scope,
                        app,
                        "card-detail-cancel-edit-button",
                        "common.cancel",
                        "secondary",
                        true,
                        cancel,
                    ),
                ],
            ),
        ],
    )
}
pub(super) fn update_calendar_draft(
    calendar: Cage<CalendarCardFields>,
    update: impl FnOnce(&mut CalendarCardFields),
) {
    calendar.revise(update);
}
fn calendar_text(
    scope: &Scope,
    app: Rc<InksonContext>,
    calendar: Cage<CalendarCardFields>,
    key: &str,
    label: &str,
    get: fn(&CalendarCardFields) -> String,
    set: fn(&mut CalendarCardFields, String),
) -> View {
    let value = scope.cage(get(&calendar.get_untracked()));
    scope.effect(move || {
        let next = get(&calendar.get());
        if next != value.get_untracked() {
            value.revise(|value| *value = next);
        }
    });
    field(scope, app, key, label, value, true, false, move |next| {
        value.revise(|value| *value = next.clone());
        update_calendar_draft(calendar, |calendar| set(calendar, next));
    })
}
pub(super) fn calendar_schedule_edit_form(
    scope: &Scope,
    app: Rc<InksonContext>,
    calendar: Cage<CalendarCardFields>,
    status: Cage<String>,
    enabled: glory::Lotus<bool>,
    save: impl FnMut() + 'static,
    cancel: impl FnMut() + 'static,
) -> View {
    macro_rules! edit {
        ($scope:expr, $app:expr, $name:ident, $key:literal, $label:literal) => {
            calendar_text(
                $scope,
                $app,
                calendar,
                $key,
                $label,
                |calendar| calendar.$name.clone(),
                |calendar, next| calendar.$name = next,
            )
        };
    }
    let mut primary = vec![
        edit!(
            scope,
            app.clone(),
            start,
            "card-detail-calendar-start-input",
            "kanban.ui.start"
        ),
        edit!(
            scope,
            app.clone(),
            end,
            "card-detail-calendar-end-input",
            "kanban.ui.end"
        ),
        toggle(
            scope,
            app.clone(),
            "card-detail-calendar-all-day",
            "kanban.ui.all_day",
            scope.bond(move || calendar.get().all_day),
            true,
            move |next| calendar.revise(|calendar| calendar.all_day = next),
        ),
        edit!(
            scope,
            app.clone(),
            timezone,
            "card-detail-calendar-timezone-input",
            "kanban.ui.timezone"
        ),
        calendar_text(
            scope,
            app.clone(),
            calendar,
            "card-detail-calendar-location-input",
            "kanban.ui.location",
            |calendar| calendar.location.clone(),
            |calendar, next| {
                calendar.location = next;
                calendar.location_locked = false;
            },
        ),
    ];
    let frequency = scope.cage(
        if calendar.get_untracked().recurrence_frequency.is_empty() {
            "none".into()
        } else {
            calendar.get_untracked().recurrence_frequency
        },
    );
    scope.effect(move || {
        let next = calendar.get().recurrence_frequency;
        let next = if next.is_empty() {
            "none".to_owned()
        } else {
            next
        };
        if frequency.get_untracked() != next {
            frequency.revise(|value| *value = next);
        }
    });
    primary.push(choice(
        scope,
        app.clone(),
        "card-detail-calendar-recurrence-select",
        "kanban.ui.repeat",
        frequency,
        [
            ("none", "kanban.ui.does_not_repeat"),
            ("daily", "kanban.ui.daily"),
            ("weekly", "kanban.ui.weekly"),
            ("monthly", "kanban.ui.monthly"),
            ("yearly", "kanban.ui.yearly"),
        ]
        .into_iter()
        .map(|(value, label)| (value.into(), crate::i18n::tr(label)))
        .collect(),
        true,
        move |next| {
            frequency.revise(|value| *value = next.clone());
            calendar.revise(|calendar| {
                if next == "none" {
                    calendar.recurrence_frequency.clear();
                    calendar.recurrence_interval.clear();
                    calendar.recurrence_by_day.clear();
                    calendar.recurrence_by_month.clear();
                    calendar.recurrence_by_month_day.clear();
                    calendar.recurrence_by_set_position.clear();
                    calendar.recurrence_first_day_of_week.clear();
                    calendar.recurrence_count.clear();
                    calendar.recurrence_until.clear();
                } else {
                    calendar.recurrence_frequency = next;
                }
            });
        },
    ));
    let recurrence = {
        let app = app.clone();
        reactive(
            scope.bond(move || !calendar.get().recurrence_frequency.is_empty()),
            move |scope, repeat| {
                if !repeat {
                    return empty();
                }
                let open = scope.cage(false);
                let ctx = app.clone();
                stack(
                    "calendar-schedule-disclosure card-detail-calendar-recurrence-options",
                    vec![
                        action(
                            scope,
                            app.clone(),
                            "calendar-recurrence-disclosure",
                            "kanban.ui.customize_recurrence",
                            "calendar-schedule-disclosure-summary",
                            true,
                            move || open.revise(|value| *value = !*value),
                        ),
                        reactive(open, move |scope, open| {
                            if open {
                                stack(
                                    "calendar-schedule-field-grid calendar-schedule-disclosure-body",
                                    vec![
                                        edit!(
                                            scope,
                                            ctx.clone(),
                                            recurrence_interval,
                                            "card-detail-calendar-interval-input",
                                            "kanban.ui.repeat_every"
                                        ),
                                        edit!(
                                            scope,
                                            ctx.clone(),
                                            recurrence_by_day,
                                            "card-detail-calendar-by-day-input",
                                            "kanban.ui.days_of_week"
                                        ),
                                        edit!(
                                            scope,
                                            ctx.clone(),
                                            recurrence_by_month,
                                            "card-detail-calendar-by-month-input",
                                            "kanban.ui.months"
                                        ),
                                        edit!(
                                            scope,
                                            ctx.clone(),
                                            recurrence_by_month_day,
                                            "card-detail-calendar-by-month-day-input",
                                            "kanban.ui.days_of_month"
                                        ),
                                        edit!(
                                            scope,
                                            ctx.clone(),
                                            recurrence_by_set_position,
                                            "card-detail-calendar-by-set-position-input",
                                            "kanban.ui.position_in_period"
                                        ),
                                        edit!(
                                            scope,
                                            ctx.clone(),
                                            recurrence_first_day_of_week,
                                            "card-detail-calendar-first-weekday-input",
                                            "kanban.ui.week_starts_on"
                                        ),
                                        edit!(
                                            scope,
                                            ctx.clone(),
                                            recurrence_count,
                                            "card-detail-calendar-count-input",
                                            "kanban.ui.end_after_occurrences"
                                        ),
                                        edit!(
                                            scope,
                                            ctx.clone(),
                                            recurrence_until,
                                            "card-detail-calendar-until-input",
                                            "kanban.ui.end_on"
                                        ),
                                    ],
                                )
                            } else {
                                empty()
                            }
                        }),
                    ],
                )
            },
        )
    };
    let advanced = scope.cage(false);
    let ctx = app.clone();
    let details = reactive(advanced, move |scope, open| {
        if open {
            let state = scope.cage(if calendar.get_untracked().status.is_empty() {
                "confirmed".into()
            } else {
                calendar.get_untracked().status
            });
            stack(
                "calendar-schedule-field-grid calendar-schedule-disclosure-body",
                vec![
                    choice(
                        scope,
                        ctx.clone(),
                        "card-detail-calendar-status-select",
                        "kanban.ui.calendar_status",
                        state,
                        ["confirmed", "tentative", "cancelled"]
                            .into_iter()
                            .map(|value| {
                                (value.into(), crate::i18n::tr(&format!("kanban.ui.{value}")))
                            })
                            .collect(),
                        true,
                        move |next| {
                            state.revise(|value| *value = next.clone());
                            calendar.revise(|calendar| calendar.status = next);
                        },
                    ),
                    edit!(
                        scope,
                        ctx.clone(),
                        tzdb_version,
                        "card-detail-calendar-tzdb-input",
                        "kanban.ui.tzdb_version"
                    ),
                ],
            )
        } else {
            empty()
        }
    });
    stack(
        "workflow-form card-detail-edit-form calendar-schedule-edit-form card-detail-calendar-edit-form",
        vec![
            stack(
                "calendar-schedule-section calendar-schedule-primary",
                vec![stack("calendar-schedule-field-grid", primary)],
            ),
            recurrence,
            stack(
                "calendar-schedule-disclosure card-detail-calendar-advanced-options",
                vec![
                    action(
                        scope,
                        app.clone(),
                        "calendar-advanced-disclosure",
                        "kanban.ui.advanced_calendar_settings",
                        "calendar-schedule-disclosure-summary",
                        true,
                        move || advanced.revise(|value| *value = !*value),
                    ),
                    details,
                ],
            ),
            edit_actions(scope, app, status, enabled, save, cancel),
        ],
    )
}
#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(feature = "desktop", not(target_arch = "wasm32")))]
    #[test]
    fn actual_blitz_keeps_rich_mode_explicit_and_edits_only_after_markdown_choice() {
        use glory::render::{Event, NodeId, Props};
        fn nodes(app: &glory::ui::App) -> Vec<NodeId> {
            let tree = app.tree();
            let mut pending = tree.roots().to_vec();
            let mut nodes = Vec::new();
            while let Some(id) = pending.pop() {
                nodes.push(id);
                pending.extend(tree.node(id).unwrap().children.iter().copied());
            }
            nodes
        }
        fn find(app: &glory::ui::App, class: &str) -> NodeId {
            nodes(app)
                .into_iter()
                .find(|id| {
                    app.tree()
                        .node(*id)
                        .unwrap()
                        .descriptor
                        .view()
                        .classes
                        .iter()
                        .any(|value| value == class)
                })
                .unwrap()
        }
        let directory = tempfile::tempdir().unwrap();
        let window = glory::blitz::shell::WindowApp::new();
        let app = window.app();
        let scope = app.scope();
        let context = InksonContext::new(
            scope,
            crate::presentation::BootState {
                config_store: crate::config::LocalConfigStore::with_path(
                    directory.path().join("config.json"),
                ),
                config: crate::config::ClientConfig::default(),
                state_store: SharedStateStore::new(LocalStateStore::with_path(
                    directory.path().join("state.json"),
                )),
                initial_credential: String::new(),
                realm_tree_nodes: vec![],
            },
            Route::Dashboard,
            |_| Box::pin(std::future::pending()),
        );
        let value = scope.cage("# Title\nOriginal **body**".to_owned());
        window
            .mount(card_markdown_editor(
                scope,
                context,
                "native-editor",
                "Description",
                value,
                String::new(),
                true,
            ))
            .unwrap();
        find(app, "card-rich-editor-unavailable");
        assert!(!nodes(app).into_iter().any(|id| matches!(
            app.tree().node(id).unwrap().descriptor.view().props,
            Props::RichEditor(_)
        )));
        assert!(
            !nodes(app).into_iter().any(|id| matches!(
                app.tree().node(id).unwrap().descriptor.view().props,
                Props::Input(_)
            )),
            "rich mode must not silently become Markdown"
        );
        let upload = find(app, "native-editor-image");
        assert!(!scope.is_enabled(upload).unwrap());
        assert!(!scope.is_enabled(find(app, "editor-insert")).unwrap());
        let mode = find(app, "editor-mode-toggle");
        app.dispatch(mode, Event::Activate).unwrap();
        assert!(scope.is_enabled(upload).unwrap());
        assert!(scope.is_enabled(find(app, "editor-insert")).unwrap());
        let input = find(app, "native-editor");
        let revision = match app.tree().node(input).unwrap().descriptor.view().props {
            Props::Input(input) => input.revision,
            _ => panic!("actual Markdown textarea"),
        };
        let changed = "# Title\nChanged **body**";
        app.dispatch(
            input,
            Event::ValueChanged {
                value: changed.into(),
                composing: false,
                revision,
            },
        )
        .unwrap();
        assert_eq!(value.get_untracked(), changed);
        app.dispatch(mode, Event::Activate).unwrap();
        assert_eq!(
            find(app, "editor-mode-toggle"),
            mode,
            "mode action retains its semantic identity"
        );
        find(app, "card-rich-editor-unavailable");
        assert!(!scope.is_enabled(upload).unwrap());
        assert_eq!(
            value.get_untracked(),
            changed,
            "returning to unavailable rich mode preserves the exact draft"
        );
        assert!(nodes(app).into_iter().any(|id|matches!(app.tree().node(id).unwrap().descriptor.view().props,Props::Text(text)if text.content.contains("Changed"))),"the original-format read-only preview still renders the edited value");
    }
    #[test]
    fn portable_editor_retains_markdown_source_without_executing_markup() {
        let source = "# Title\n- item\n| a | b |\n<script>literal</script>";
        let document = markdown_document(source);
        assert!(document.validate().is_ok());
        assert_eq!(document_markdown(&document), source);
    }
    #[test]
    fn native_editor_mounts_real_control_without_external_assets() {
        let app = glory::ui::App::memory();
        let scope = app.scope();
        let value = scope.cage("Original **content**".to_owned());
        let document = scope.cage(Rc::new(markdown_document(&value.get_untracked())));
        let editor = scope.cage(None);
        let status = scope.cage(String::new());
        app.mount(native_rich_editor(
            "Description".into(),
            value,
            document,
            editor,
            status,
        ))
        .unwrap();
        let tree = app.tree();
        let mut pending = tree.roots().to_vec();
        let mut rich = 0;
        while let Some(id) = pending.pop() {
            let node = tree.node(id).unwrap();
            if matches!(
                node.descriptor.view().props,
                glory::render::Props::RichEditor(_)
            ) {
                rich += 1;
            }
            pending.extend(&node.children);
        }
        assert_eq!(rich, 1);
        assert_eq!(value.get_untracked(), "Original **content**");
        assert!(editor.get_untracked().is_some());
        assert!(status.get_untracked().is_empty());
    }
    #[test]
    fn native_editor_retirement_revokes_old_change_callback() {
        let app = glory::ui::App::memory();
        let scope = app.scope();
        let value = scope.cage("Original".to_owned());
        let document = scope.cage(Rc::new(markdown_document(&value.get_untracked())));
        let editor = scope.cage(None);
        let status = scope.cage(String::new());
        app.mount(native_rich_editor(
            "Description".into(),
            value,
            document,
            editor,
            status,
        ))
        .unwrap();
        let old = editor.get_untracked().unwrap();
        assert!(
            old.insert_at(old.selection().get(), "edited ", RichMarks::default())
                .is_ok()
        );
        app.flush().unwrap();
        assert!(value.get_untracked().contains("edited"));
        app.clear().unwrap();
        let accepted = value.get_untracked();
        assert!(
            old.insert_at(
                glory::render::RichSelection::default(),
                "stale",
                RichMarks::default()
            )
            .is_err()
        );
        app.flush().unwrap();
        assert_eq!(
            value.get_untracked(),
            accepted,
            "retired editor cannot publish stale changes into the next owner"
        );
    }
}
