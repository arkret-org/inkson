//! 看板卡片到期日历(due calendar)纯计算 helper 与单元格类型。
//!
//! YOU-07-001:从 `views/kanban/mod.rs` 机械外迁的连续块——仅移动,不改
//! 逻辑 / 签名 / canonical 字节。可见性从模块私有抬升为 `pub(super)`,使
//! `mod.rs` 通过 `use due_calendar::*;` 重导出后,`KanbanPanel` 与
//! `tests.rs`(`use super::*`)的解析路径均保持不变。

// `NaiveDate` 通过本模块再导出回 kanban 根:`mod.rs` 的 `use due_calendar::*`
// 使其重新出现在父作用域,`tests.rs`(`use super::*`)的既有未限定引用因此
// 仍能解析,无需改动测试。
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
