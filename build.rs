//! Stamps a per-build identifier into the binary via `INKSON_BUILD_ID` so the
//! running wasm can print which bundle the browser actually loaded. Comparing
//! the printed id against the latest rebuild is the definitive way to spot a
//! stale cached wasm bundle (the recurring "is the browser running old wasm?"
//! question during MLS debugging).
//!
//! Cargo does not treat Git metadata as a package input. Track HEAD and its
//! current loose ref explicitly so a commit-only change cannot leave a fresh
//! bundle stamped with the previous source identity.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn build_style_bundle(manifest_dir: &Path) {
    let list = manifest_dir.join("web/styles.list");
    println!("cargo:rerun-if-changed={}", list.display());
    let sources = fs::read_to_string(&list).expect("read web/styles.list");
    let root = manifest_dir
        .canonicalize()
        .expect("resolve manifest directory");
    let mut combined = String::new();
    for entry in sources
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let path = manifest_dir
            .join(entry)
            .canonicalize()
            .unwrap_or_else(|error| panic!("stylesheet {entry}: {error}"));
        assert!(
            path.starts_with(&root),
            "stylesheet must remain in the Inkson source tree"
        );
        println!("cargo:rerun-if-changed={}", path.display());
        combined.push_str(
            &fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("stylesheet {entry}: {error}")),
        );
        combined.push('\n');
    }
    assert!(
        !combined.is_empty(),
        "web/styles.list must declare the application styles"
    );
    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    fs::write(output.join("inkson.css"), combined).expect("write native stylesheet bundle");
}

// Sapid's typed paints cannot refer to CSS variables. Generate their values
// from the same theme declarations that style the HTML and native documents.
fn build_sapid_palettes(manifest_dir: &Path) {
    let path = manifest_dir.join("src/styles/base/tokens.css");
    println!("cargo:rerun-if-changed={}", path.display());
    let source = fs::read_to_string(path).expect("read semantic color tokens");
    let mut generated = String::new();
    for (class, scheme) in [
        (".inkson-theme-light", "Light"),
        (".inkson-theme-dark", "Dark"),
    ] {
        let declarations = source
            .split('}')
            .filter_map(|rule| rule.split_once('{'))
            .find(|(selectors, _)| {
                selectors
                    .split(',')
                    .any(|selector| selector.trim() == class)
            })
            .unwrap_or_else(|| panic!("missing palette {class}"))
            .1;
        let colors: BTreeMap<_, _> = declarations
            .split(';')
            .filter_map(|declaration| declaration.split_once(':'))
            .map(|(name, value)| (name.trim(), value.trim()))
            .collect();
        writeln!(
            generated,
            "pub const {}: sapid::Palette = sapid::Palette {{",
            scheme.to_uppercase()
        )
        .unwrap();
        for (field, token) in [
            ("canvas", "--bg"),
            ("surface", "--surface-solid"),
            ("input", "--surface-solid"),
            ("foreground", "--text"),
            ("muted", "--text-2"),
            ("border", "--border"),
            ("accent", "--accent"),
            ("accent_hover", "--accent-strong"),
            ("accent_soft", "--accent-soft"),
            ("accent_text", "--accent-ink"),
            ("on_accent", "--text-on-accent"),
            ("focus_ring", "--focus"),
            ("input_focus", "--focus"),
            ("success", "--success"),
            ("success_soft", "--success-soft"),
            ("danger", "--danger"),
            ("danger_fill", "--danger"),
            ("on_danger", "--text-on-accent"),
            ("danger_soft", "--danger-soft"),
            ("warning", "--warning"),
            ("warning_soft", "--warning-soft"),
            ("disabled", "--surface-3"),
            ("disabled_text", "--text-3"),
        ] {
            let hex = colors
                .get(token)
                .and_then(|value| value.strip_prefix('#'))
                .filter(|value| value.len() == 6)
                .and_then(|value| u32::from_str_radix(value, 16).ok())
                .unwrap_or_else(|| {
                    panic!("{class} {token} must be a six-digit hex color for Sapid")
                });
            writeln!(
                generated,
                "    {field}: glory::style::Color({}, {}, {}, 255),",
                hex >> 16,
                hex >> 8 & 0xff,
                hex & 0xff
            )
            .unwrap();
        }
        writeln!(
            generated,
            "    ..sapid::BLUE.resolve(sapid::ColorScheme::{scheme}).unwrap()
}};"
        )
        .unwrap();
    }
    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    fs::write(output.join("inkson_palettes.rs"), generated).expect("write Sapid palettes");
}

fn git_output(manifest_dir: &Path, args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .current_dir(manifest_dir)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|output| !output.is_empty())
}

fn main() {
    let manifest_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by Cargo"),
    );
    build_style_bundle(&manifest_dir);
    build_sapid_palettes(&manifest_dir);

    #[cfg(feature = "desktop")]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rerun-if-changed=windows/inkson.rc");
        println!("cargo:rerun-if-changed=windows/arkret.ico");
        embed_resource::compile_for(
            "windows/inkson.rc",
            ["inkson"],
            embed_resource::ParamsIncludeDirs(["windows"]),
        )
        .manifest_required()
        .expect("embed the Arkret application icon");
    }

    // Emitting any `rerun-if-changed` instruction disables Cargo's default
    // package-wide build-script invalidation. We also track Git metadata below,
    // so explicitly retain the inputs that can change this crate's wasm. Without
    // these entries Cargo recompiles `src`, but reuses an old INKSON_BUILD_ID,
    // making a fresh browser bundle look stale in the console.
    for package_input in ["src", "Cargo.toml", "build.rs"] {
        println!("cargo:rerun-if-changed={package_input}");
    }

    if let Some(git_dir) = git_output(&manifest_dir, &["rev-parse", "--absolute-git-dir"]) {
        let git_dir = PathBuf::from(git_dir);
        let head_path = git_dir.join("HEAD");
        println!("cargo:rerun-if-changed={}", head_path.display());
        if let Ok(head) = fs::read_to_string(&head_path)
            && let Some(reference) = head.trim().strip_prefix("ref: ")
        {
            // Worktree branch refs live in Git's common directory, unlike HEAD.
            if let Some(path) = git_output(
                &manifest_dir,
                &[
                    "rev-parse",
                    "--path-format=absolute",
                    "--git-path",
                    reference,
                ],
            ) {
                let path = PathBuf::from(path);
                // A packed ref has no loose file. Watch its existing parent
                // so a subsequent commit creating the loose ref invalidates us.
                if let Some(watched) = path.ancestors().find(|candidate| candidate.exists()) {
                    println!("cargo:rerun-if-changed={}", watched.display());
                }
            }
            if let Some(path) = git_output(
                &manifest_dir,
                &[
                    "rev-parse",
                    "--path-format=absolute",
                    "--git-path",
                    "packed-refs",
                ],
            ) {
                let path = PathBuf::from(path);
                if path.exists() {
                    println!("cargo:rerun-if-changed={}", path.display());
                }
            }
        }
    }

    let built_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S %z");

    let git_short = git_output(&manifest_dir, &["rev-parse", "--short", "HEAD"])
        .unwrap_or_else(|| "nogit".to_owned());

    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(&manifest_dir)
        .output()
        .ok()
        .map(|out| !out.stdout.is_empty())
        .unwrap_or(false);
    let dirty_suffix = if dirty { "+dirty" } else { "" };

    println!("cargo:rustc-env=INKSON_BUILD_ID={built_at} {git_short}{dirty_suffix}");
}
