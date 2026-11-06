//! Due-date projection helpers and a thin Sapid DatePicker value adapter.
use chrono::Datelike;
pub(super) use chrono::NaiveDate;

pub(super) fn default_due_calendar_month() -> NaiveDate {
    start_of_due_calendar_month(due_calendar_today())
}

pub(super) fn due_calendar_today() -> NaiveDate {
    chrono::Utc::now().date_naive()
}

pub(super) fn start_of_due_calendar_month(date: NaiveDate) -> NaiveDate {
    date.with_day(1).unwrap_or(date)
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

/// Whether a card's `due` display value is strictly before today (UTC). A
/// blank / placeholder / unscheduled value is never overdue. Drives the
/// overdue badge on the board card (scenario E16.F, relation/strand fields are
/// opaque to the reducer so the past-due semantics live in the UI).
pub(super) fn due_value_is_overdue(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "\u{2014}" || trimmed.eq_ignore_ascii_case("unscheduled") {
        return false;
    }
    match parse_due_calendar_date(trimmed) {
        Some(due) => due < due_calendar_today(),
        None => false,
    }
}

pub(super) fn due_calendar_widget(
    scope: &glory::Scope,
    locale: glory::Cage<crate::i18n::UiLocale>,
    theme: sapid::Theme,
    label: glory::Vary<String>,
    value: glory::Cage<String>,
    month: glory::Cage<NaiveDate>,
) -> crate::presentation::View {
    let Ok(today) =
        sapid::CivilDate::parse_iso(&due_calendar_today().format("%Y-%m-%d").to_string())
    else {
        return crate::presentation::widgets::paragraph(
            "error",
            "The current date is outside the calendar range.",
        );
    };
    let provider = scope.bond(move || {
        sapid::DatesProvider::new(today)
            .today(Some(today))
            .week_start(sapid::Weekday::Sunday)
            .locale(if locale.get() == crate::i18n::UiLocale::Zh {
                sapid::DateLocale::ZhCn
            } else {
                sapid::DateLocale::En
            })
    });
    let selected = scope.bond(move || {
        sapid::DateSelection::Single(parse_due_calendar_date(&value.get()).and_then(|date| {
            sapid::CivilDate::parse_iso(&date.format("%Y-%m-%d").to_string()).ok()
        }))
    });
    let visible = scope.bond(move || {
        sapid::CivilDate::parse_iso(&month.get().format("%Y-%m-%d").to_string())
            .map(sapid::CivilDate::year_month)
            .unwrap_or_else(|_| today.year_month())
    });
    Box::new(
        sapid::date_picker(format!("card-due-calendar-{}", scope.id().slot()), provider)
            .theme(theme)
            .class("due-calendar")
            .name(label)
            .value(selected)
            .month(visible)
            .allow_deselect(false)
            .on_month_change(move |next| {
                if let Some(next) = parse_due_calendar_date(&next.first().to_string()) {
                    month.revise(|month| *month = next);
                }
            })
            .on_value_change(move |selection| {
                if let sapid::DateSelection::Single(Some(date)) = selection {
                    let iso = date.to_string();
                    value.revise(|value| *value = iso);
                    if let Some(first) =
                        parse_due_calendar_date(&date.year_month().first().to_string())
                    {
                        month.revise(|month| *month = first);
                    }
                }
            }),
    )
}
