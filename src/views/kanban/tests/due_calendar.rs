use super::*;

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

#[test]
fn due_calendar_month_navigation_crosses_years() {
    let jan_2026 = NaiveDate::from_ymd_opt(2026, 1, 17).unwrap();
    assert_eq!(
        add_due_calendar_months(jan_2026, -1),
        NaiveDate::from_ymd_opt(2025, 12, 1).unwrap()
    );
    let dec_2026 = NaiveDate::from_ymd_opt(2026, 12, 9).unwrap();
    assert_eq!(
        add_due_calendar_months(dec_2026, 1),
        NaiveDate::from_ymd_opt(2027, 1, 1).unwrap()
    );
}

#[test]
fn due_calendar_cells_cover_sunday_first_six_week_grid() {
    let month = NaiveDate::from_ymd_opt(2026, 6, 1).unwrap();
    let cells = due_calendar_cells(month);
    assert_eq!(cells.len(), 42);
    assert_eq!(cells.first().unwrap().iso_date, "2026-05-31");
    assert_eq!(cells[1].iso_date, "2026-06-01");
    assert_eq!(cells.last().unwrap().iso_date, "2026-07-11");
    assert!(!cells[0].in_current_month);
    assert!(cells[1].in_current_month);
    assert!(!cells.last().unwrap().in_current_month);
}
