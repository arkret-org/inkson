use super::*;

#[test]
fn card_due_projection_retains_absence_and_explicit_dates_without_display_placeholders() {
    for fields in [
        json!({}),
        json!({"due_date": null}),
        json!({"due_date": ""}),
    ] {
        let strand: crate::state::projection_views::StrandProjectionView =
            serde_json::from_value(json!({
                "strand_id": "ak:strand:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2",
                "realm_id": TEST_REALM_ID,
                "state": "active",
                "fields": fields,
            }))
            .unwrap();
        let card = card_from_strand_projection(&strand, None);
        assert!(card.due.is_empty());
        assert!(!due_value_is_overdue(&card.due));
    }
    let strand: crate::state::projection_views::StrandProjectionView =
        serde_json::from_value(json!({
            "strand_id": "ak:strand:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2",
            "realm_id": TEST_REALM_ID,
            "state": "active",
            "fields": {"due_date": "2020-01-01"},
        }))
        .unwrap();
    assert_eq!(card_from_strand_projection(&strand, None).due, "2020-01-01");
}

#[test]
fn parse_card_labels_trims_and_deduplicates() {
    assert_eq!(
        parse_card_labels(" release, ops, release, ,OPS "),
        vec!["release".to_owned(), "ops".to_owned()]
    );
}

#[test]
fn due_calendar_parses_date_and_rfc3339_values() {
    assert_eq!(
        parse_due_calendar_date("2026-06-09"),
        Some(NaiveDate::from_ymd_opt(2026, 6, 9).unwrap())
    );
    assert_eq!(
        parse_due_calendar_date("2026-06-09T18:30:00.000Z"),
        Some(NaiveDate::from_ymd_opt(2026, 6, 9).unwrap())
    );
    assert_eq!(parse_due_calendar_date("unscheduled"), None);
}

fn calendar_nodes(app: &glory::App) -> Vec<glory::render::NodeId> {
    fn visit(
        tree: &glory::render::memory::Memory,
        id: glory::render::NodeId,
        found: &mut Vec<glory::render::NodeId>,
    ) {
        found.push(id);
        for child in &tree.node(id).unwrap().children {
            visit(tree, *child, found);
        }
    }
    let tree = app.tree();
    let mut found = Vec::new();
    for root in tree.roots() {
        visit(&tree, *root, &mut found);
    }
    found
}
fn exercise_due_calendar(app: glory::App) {
    let value = app.scope().cage("2026-06-09T18:30:00.000Z".to_owned());
    let month = app
        .scope()
        .cage(NaiveDate::from_ymd_opt(2026, 6, 1).unwrap());
    let locale = app.scope().cage(crate::i18n::UiLocale::En);
    app.mount(due_calendar_widget(
        app.scope(),
        locale,
        sapid::Theme::default(),
        "Due date".to_owned().into(),
        value,
        month,
    ))
    .unwrap();
    app.flush().unwrap();
    assert_eq!(value.get_untracked(), "2026-06-09T18:30:00.000Z");
    let day = calendar_nodes(&app).into_iter().find(|id| {
        let tree = app.tree(); let descriptor = tree.node(*id).unwrap().descriptor.view();
        descriptor.classes.iter().any(|class| class == "sapid-calendar-day")
            && matches!(descriptor.props, glory::render::Props::Button(button) if button.label == "10")
    }).expect("June 10 in the Sapid calendar");
    app.dispatch(day, glory::render::Event::Activate).unwrap();
    app.flush().unwrap();
    assert_eq!(value.get_untracked(), "2026-06-10");
    assert_eq!(
        month.get_untracked(),
        NaiveDate::from_ymd_opt(2026, 6, 1).unwrap()
    );
    locale.revise(|locale| *locale = crate::i18n::UiLocale::Zh);
    app.flush().unwrap();
    assert_eq!(value.get_untracked(), "2026-06-10");
}
#[test]
fn due_calendar_sapid_selection_preserves_imported_value_until_explicit_choice() {
    exercise_due_calendar(glory::App::memory());
}
#[cfg(feature = "desktop")]
#[test]
fn actual_apace_due_calendar_uses_the_production_sapid_date_picker() {
    exercise_due_calendar(glory::App::new(glory::apace::Renderer::new));
}
