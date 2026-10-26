//! Gate: UI modules must not carry bare English display text.
//!
//! Inkson's dictionaries are complete (en / zh are within a couple of keys of
//! each other), but for a long time most feature pages never called `tr()` —
//! they hardcoded English literals. The result was a shell that followed the
//! selected locale while the page content stayed English, and the existing
//! `i18n::missing_translation_snapshot()` warning could not see it: a literal
//! that never reaches `tr()` is invisible to a missing-key sink.
//!
//! This test closes that hole for modules that have been migrated. It is a
//! source scan rather than a runtime check for exactly that reason — the
//! defect is text that never enters the i18n system at all.
//!
//! Deliberately scoped: [`MIGRATED_ROOTS`] lists what is enforced today.
//! The remaining UI modules are reported (see `report_unmigrated_ui_modules`)
//! but do not fail the build, so the backlog is visible without blocking work
//! that is unrelated to it. Move a path into `MIGRATED_ROOTS` as it is
//! converted; never remove one.

use std::fs;
use std::path::{Path, PathBuf};

/// Paths under `src/` whose display text must be fully localized.
const MIGRATED_ROOTS: &[&str] = &["views/setup", "app/feature_gate.rs"];

/// Attribute names whose values are never user-visible prose: CSS classes,
/// test hooks, protocol/wire constants, element ids.
const NON_PROSE_ATTRS: &[&str] = &[
    "class:",
    "id:",
    "r#type:",
    "rows:",
    "index:",
    "value:",
    "to:",
    "html_for:",
    "r#for:",
    "\"data-",
    "\"aria-hidden\"",
    "lang:",
    "href:",
    "src:",
];

fn crate_src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_files_under(root: &Path) -> Vec<PathBuf> {
    if root.is_file() {
        return vec![root.to_path_buf()];
    }
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(rust_files_under(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// Strip `{placeholder}` spans so an interpolation-only literal such as
/// `"{title} ({id})"` is not mistaken for prose.
fn strip_placeholders(literal: &str) -> String {
    let mut out = String::new();
    let mut depth = 0_usize;
    for ch in literal.chars() {
        match ch {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(ch),
            _ => {}
        }
    }
    out
}

/// A literal counts as prose when, after placeholders are removed, it has at
/// least two whitespace-separated runs containing an ASCII letter. One word is
/// not enough: wire values (`"high_assurance"`), ids and single-token markers
/// are all one word, and flagging them would make the gate unusable.
fn looks_like_prose(literal: &str) -> bool {
    let stripped = strip_placeholders(literal);
    stripped
        .split_whitespace()
        .filter(|word| word.chars().any(|ch| ch.is_ascii_alphabetic()))
        .count()
        >= 2
}

/// An i18n key, e.g. `setup.action.create_realm` — allowed anywhere.
fn is_i18n_key(literal: &str) -> bool {
    !literal.is_empty()
        && literal
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '.' || ch == '_')
}

/// Extract double-quoted literals from one line, honouring `\"` escapes.
fn string_literals(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '"' {
            continue;
        }
        let mut literal = String::new();
        let mut closed = false;
        while let Some(inner) = chars.next() {
            match inner {
                '\\' => {
                    // Keep the escaped char so `\n` inside a literal does not
                    // terminate the scan early.
                    if let Some(escaped) = chars.next() {
                        literal.push(escaped);
                    }
                }
                '"' => {
                    closed = true;
                    break;
                }
                _ => literal.push(inner),
            }
        }
        if closed {
            out.push(literal);
        }
    }
    out
}

fn line_is_skippable(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return true;
    }
    NON_PROSE_ATTRS
        .iter()
        .any(|attr| trimmed.starts_with(attr) || trimmed.contains(&format!(" {attr}")))
}

/// `tracing::warn!(...)` and friends carry operator-facing diagnostics that
/// stay English on purpose — they are read in journals, not in the UI. The
/// message is often on a different line from the macro name, so track bracket
/// depth to skip the whole invocation rather than just its first line.
fn tracing_span_depth_delta(line: &str) -> isize {
    line.chars().fold(0_isize, |depth, ch| match ch {
        '(' => depth + 1,
        ')' => depth - 1,
        _ => depth,
    })
}

#[derive(Default)]
struct NativeFrame {
    close: char,
    callee: String,
    argument: usize,
}
/// Class/identity arguments have the same role as the old non-prose attributes.
/// Display arguments, including names/placeholders and button labels, remain checked.
fn native_nonprose_literals(source: &str) -> std::collections::BTreeSet<(usize, String)> {
    let mut ignored = std::collections::BTreeSet::new();
    let chars = source.chars().collect::<Vec<_>>();
    let mut frames = Vec::<NativeFrame>::new();
    let mut token = String::new();
    let (mut index, mut line) = (0, 1);
    while index < chars.len() {
        let ch = chars[index];
        if ch == '\n' {
            line += 1;
        }
        if ch == '/' && chars.get(index + 1) == Some(&'/') {
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
            continue;
        }
        if ch == '"' {
            let start_line = line;
            let mut literal = String::new();
            index += 1;
            while index < chars.len() {
                let ch = chars[index];
                if ch == '\n' {
                    line += 1;
                }
                if ch == '\\'
                    && let Some(next) = chars.get(index + 1)
                {
                    literal.push(*next);
                    index += 2;
                    continue;
                }
                if ch == '"' {
                    break;
                }
                literal.push(ch);
                index += 1;
            }
            let nearest = frames.iter().rev().find(|frame| !frame.callee.is_empty());
            let structural = nearest.is_some_and(|frame| {
                let name = frame.callee.rsplit("::").next().unwrap_or(&frame.callee);
                matches!(
                    (name, frame.argument),
                    (
                        "stack" | "line" | "paragraph" | "class" | "href" | "target" | "source",
                        0
                    ) | ("heading", 1)
                )
            });
            if structural {
                ignored.insert((start_line, literal));
            }
            token.clear();
            index += 1;
            continue;
        }
        match ch {
            '(' => {
                frames.push(NativeFrame {
                    close: ')',
                    callee: {
                        let mut end = index;
                        while end > 0 && chars[end - 1].is_whitespace() {
                            end -= 1;
                        }
                        let mut start = end;
                        while start > 0
                            && (chars[start - 1].is_alphanumeric()
                                || matches!(chars[start - 1], '_' | ':'))
                        {
                            start -= 1;
                        }
                        chars[start..end].iter().collect()
                    },
                    argument: 0,
                });
            }
            '[' | '{' => {
                frames.push(NativeFrame {
                    close: if ch == '[' { ']' } else { '}' },
                    ..Default::default()
                });
                token.clear();
            }
            ')' | ']' | '}' => {
                if frames.last().is_some_and(|frame| frame.close == ch) {
                    frames.pop();
                }
                token.clear();
            }
            ',' => {
                if let Some(frame) = frames.last_mut()
                    && frame.close == ')'
                {
                    frame.argument += 1;
                }
                token.clear();
            }
            ch if ch.is_alphanumeric() || ch == '_' || ch == ':' => token.push(ch),
            ch if ch.is_whitespace() => {}
            _ => token.clear(),
        }
        index += 1;
    }
    ignored
}
fn bare_prose_in_file(path: &Path) -> Vec<(usize, String)> {
    let Ok(source) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let structural = native_nonprose_literals(&source);
    let mut findings = Vec::new();
    let mut tracing_depth = 0_isize;
    for (index, line) in source.lines().enumerate() {
        if tracing_depth > 0 {
            tracing_depth += tracing_span_depth_delta(line);
            continue;
        }
        if line.contains("tracing::") {
            let delta = tracing_span_depth_delta(line);
            if delta > 0 {
                tracing_depth = delta;
            }
            continue;
        }
        if line_is_skippable(line) {
            continue;
        }
        for literal in string_literals(line) {
            if structural.contains(&(index + 1, literal.clone()))
                || is_i18n_key(&literal)
                || !looks_like_prose(&literal)
            {
                continue;
            }
            findings.push((index + 1, literal));
        }
    }
    findings
}

#[test]
fn migrated_ui_modules_carry_no_bare_english_text() {
    let src = crate_src_dir();
    let mut violations = Vec::new();

    for root in MIGRATED_ROOTS {
        let root_path = src.join(root);
        assert!(
            root_path.exists(),
            "MIGRATED_ROOTS entry no longer exists: {root} — update the list \
             instead of dropping coverage"
        );
        for file in rust_files_under(&root_path) {
            let relative = file
                .strip_prefix(&src)
                .unwrap_or(&file)
                .display()
                .to_string();
            for (line, literal) in bare_prose_in_file(&file) {
                violations.push(format!("  src/{relative}:{line}  \"{literal}\""));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "bare English UI text found in migrated modules — move it into \
         src/i18n/en.rs + zh.rs and render it with crate::i18n::tr(key):\n{}",
        violations.join("\n")
    );
}

#[test]
fn realm_creation_has_no_private_sovereign_deployment_controls() {
    let setup = crate_src_dir().join("views/setup");
    let source = rust_files_under(&setup)
        .into_iter()
        .map(|path| {
            fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
                .to_ascii_lowercase()
        })
        .collect::<Vec<_>>()
        .join("\n");

    for retired in [
        "sovereign",
        "hosted_on",
        "deployment_profile",
        "profile_override",
        "enclave_realms",
        "/_coland/admin/deployment",
    ] {
        assert!(
            !source.contains(retired),
            "Realm creation must not expose retired private deployment control {retired:?}"
        );
    }
}

/// Not a gate — a visible backlog. Prints every UI file that still renders
/// through Glory/Sapid but never translates display text, so the remaining work is measurable
/// instead of being discovered by a user seeing a half-translated page.
#[test]
fn report_unmigrated_ui_modules() {
    let src = crate_src_dir();
    let mut pending: Vec<String> = Vec::new();

    for file in rust_files_under(&src) {
        let relative = file
            .strip_prefix(&src)
            .unwrap_or(&file)
            .display()
            .to_string()
            .replace('\\', "/");
        if relative.contains("tests") || relative.starts_with("i18n/") {
            continue;
        }
        if MIGRATED_ROOTS
            .iter()
            .any(|root| relative.starts_with(&root.replace('\\', "/")))
        {
            continue;
        }
        let Ok(source) = fs::read_to_string(&file) else {
            continue;
        };
        if is_native_ui_source(&source) && !has_translation_path(&source) {
            pending.push(relative);
        }
    }

    pending.sort();
    eprintln!(
        "i18n backlog: {} UI file(s) render with Glory/Sapid but never translate display text:\n{}",
        pending.len(),
        pending
            .iter()
            .map(|path| format!("  src/{path}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

fn is_native_ui_source(source: &str) -> bool {
    let code = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    code.contains("-> View")
        || code.contains("->View")
        || code.contains("sapid::")
        || code.contains("glory::prelude::view(")
        || code.contains("glory::ui::view(")
}
fn has_translation_path(source: &str) -> bool {
    ["tr(", "tr_args(", "translated(", "tr_for_locale("]
        .iter()
        .any(|needle| source.contains(needle))
}
#[test]
fn native_ui_scan_checks_display_text_and_preserves_structural_arguments() {
    let source = "stack(\"event error-banner\",vec![paragraph(\"muted body\",\"English display text\"),sapid::button().class(\"btn secondary\").label(\"Untranslated action label\")])";
    let structural = native_nonprose_literals(source);
    assert!(structural.contains(&(1, "event error-banner".into())));
    assert!(structural.contains(&(1, "muted body".into())));
    assert!(structural.contains(&(1, "btn secondary".into())));
    assert!(!structural.contains(&(1, "English display text".into())));
    assert!(!structural.contains(&(1, "Untranslated action label".into())));
    assert!(is_native_ui_source(
        "pub fn page()->View { paragraph(\"\",\"bare prose\") }"
    ));
    assert!(!has_translation_path(
        "sapid::button().label(\"bare prose\")"
    ));
}
#[test]
fn native_route_entrypoints_remain_covered() {
    let src = crate_src_dir();
    let routing =
        fs::read_to_string(src.join("app/route_surface.rs")).expect("production view routing");
    for module in [
        "dashboard",
        "contacts",
        "directory",
        "setup",
        "settings",
        "realm_admin",
        "kanban",
        "chat",
        "call",
        "applets",
        "notifications",
        "onboarding",
        "quarantine",
        "global_search",
    ] {
        let file = src.join(format!("views/{module}.rs"));
        let file = if file.exists() {
            file
        } else {
            src.join(format!("views/{module}/mod.rs"))
        };
        let dir = src.join(format!("views/{module}"));
        let mut paths = if dir.is_dir() {
            rust_files_under(&dir)
        } else {
            vec![]
        };
        if !paths.contains(&file) {
            paths.push(file.clone());
        }
        let source = paths
            .into_iter()
            .map(|path| {
                fs::read_to_string(&path).unwrap_or_else(|error| {
                    panic!("missing actual UI entry {}: {error}", path.display())
                })
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            is_native_ui_source(&source),
            "{module} has no actual native UI entry"
        );
        assert!(
            source.contains("pub fn page("),
            "{module} must expose its real Glory page entry"
        );
        assert!(
            routing.contains(&format!("{module}::page")),
            "{module} is not reached by production routing"
        );
    }
}
