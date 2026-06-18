//! Pure calculation helpers and cell types for the kanban due calendar.
//!
//! YOU-07-001: mechanically moved from `views/kanban/mod.rs` as one contiguous
//! block. This is move-only: logic, signatures, and canonical bytes are
//! unchanged. Visibility was raised from module-private to `pub(super)`, so
//! after `mod.rs` re-exports with `use due_calendar::*;`, `KanbanPanel` and
//! `tests.rs` (`use super::*`) resolution paths remain unchanged.

// Re-export `NaiveDate` through this module back to the kanban root. The
// `use due_calendar::*` in `mod.rs` makes it appear in the parent scope again,
// so existing unqualified references in `tests.rs` (`use super::*`) still
// resolve without changing tests.
pub(super) use chrono::NaiveDate;
use chrono::{Datelike, Duration};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DueCalendarCell {
    pub(super) date: NaiveDate,
    pub(super) day: u32,
    pub(super) in_current_month: bool,
    pub(super) iso_date: String,
}

pub(super) fn default_due_calendar_month() -> NaiveDate {
    start_of_due_calendar_month(due_calendar_today())
}

pub(super) fn due_calendar_today() -> NaiveDate {
    chrono::Utc::now().date_naive()
}

pub(super) fn start_of_due_calendar_month(date: NaiveDate) -> NaiveDate {
    date.with_day(1).expect("every month has day one")
}

pub(super) fn due_calendar_month_for_value(value: &str) -> NaiveDate {
    parse_due_calendar_date(value)
        .map(start_of_due_calendar_month)
        .unwrap_or_else(default_due_calendar_month)
}

pub(super) fn parse_due_calendar_date(value: &str) -> Option<NaiveDate> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    NaiveDate::parse_from_str(trimmed, "%Y-%m-%d")
        .ok()
        .or_else(|| {
            chrono::DateTime::parse_from_rfc3339(trimmed)
                .ok()
                .map(|timestamp| timestamp.date_naive())
        })
}

pub(super) fn due_calendar_month_label(month: NaiveDate) -> String {
    month.format("%B %Y").to_string()
}

pub(super) fn add_due_calendar_months(month: NaiveDate, delta: i32) -> NaiveDate {
    let month = start_of_due_calendar_month(month);
    let index = month.year() * 12 + month.month0() as i32 + delta;
    let year = index.div_euclid(12);
    let month0 = index.rem_euclid(12);
    NaiveDate::from_ymd_opt(year, month0 as u32 + 1, 1).unwrap_or(month)
}

pub(super) fn due_calendar_cells(month: NaiveDate) -> Vec<DueCalendarCell> {
    let month = start_of_due_calendar_month(month);
    let first_weekday_offset = month.weekday().num_days_from_sunday() as i64;
    let first_cell = month - Duration::days(first_weekday_offset);
    (0..42)
        .map(|offset| {
            let date = first_cell + Duration::days(offset);
            DueCalendarCell {
                date,
                day: date.day(),
                in_current_month: date.year() == month.year() && date.month() == month.month(),
                iso_date: date.format("%Y-%m-%d").to_string(),
            }
        })
        .collect()
}
