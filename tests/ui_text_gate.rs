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

fn bare_prose_in_file(path: &Path) -> Vec<(usize, String)> {
    let Ok(source) = fs::read_to_string(path) else {
        return Vec::new();
    };
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
            if is_i18n_key(&literal) || !looks_like_prose(&literal) {
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
/// with `rsx!` but never calls `tr()`, so the remaining work is measurable
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
        if source.contains("rsx!") && !source.contains("tr(\"") && !source.contains("i18n::tr(") {
            pending.push(relative);
        }
    }

    pending.sort();
    eprintln!(
        "i18n backlog: {} UI file(s) render with rsx! but never call tr():\n{}",
        pending.len(),
        pending
            .iter()
            .map(|path| format!("  src/{path}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
