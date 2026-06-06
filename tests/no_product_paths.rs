//! T E.1 — product-namespace literal gate (allowlist-first / ratchet).
//!
//! 通用 Cokret 客户端核心只应依赖协议面 `/_cokret/...` 或 describe 发现的路径。
//! 实现私有的 `/_soland/...` 字面量是耦合债(详见 `_url_report.md`)。
//!
//! 本门禁**冻结当前现状并禁止新增**:它按文件记录当前 `_soland/` 出现的行数基线,
//! 任何文件超过基线、或新文件引入 `_soland/`,即测试失败。随着迁移推进
//! (A/B/C/D 各 Track),把对应文件的基线**下调**(ratchet down)即可;
//! 目标终态是除受限适配器外基线归零(T E.3)。
//!
//! 统计口径:含 `_soland/` 子串的**行数**(与审计所用 grep count 一致)。

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// 每个文件允许出现 `_soland/` 的最大行数(相对 `yougen/src/` 的 POSIX 路径)。
/// 基线锚定 2026-06-04 审计现状(共 34 行 / 14 文件)。迁移完成后**只允许下调**。
const BASELINE: &[(&str, usize)] = &[
    ("api/account.rs", 13),
    ("api/directory.rs", 2),
    ("api/keys.rs", 1),
    ("api/mod.rs", 1),
    ("api/moderation.rs", 1),
    ("api/realm.rs", 1),
    ("models.rs", 2),
    ("operation.rs", 1),
    ("routes.rs", 1),
    ("views/global_search.rs", 1),
    ("views/mod.rs", 1),
    ("views/settings/mod.rs", 1),
    ("views/realm_admin.rs", 3),
    ("workflows.rs", 1),
];

const NEEDLE: &str = "_soland/";

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn rel_posix(src_root: &Path, path: &Path) -> String {
    path.strip_prefix(src_root)
        .expect("path under src_root")
        .to_string_lossy()
        .replace('\\', "/")
}

#[test]
fn no_new_product_namespace_literals_in_src() {
    let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_root, &mut files);

    let baseline: BTreeMap<&str, usize> = BASELINE.iter().copied().collect();

    let mut actual: BTreeMap<String, usize> = BTreeMap::new();
    for file in &files {
        let content = fs::read_to_string(file).unwrap_or_else(|e| panic!("read {file:?}: {e}"));
        let count = content.lines().filter(|line| line.contains(NEEDLE)).count();
        if count > 0 {
            actual.insert(rel_posix(&src_root, file), count);
        }
    }

    let mut violations: Vec<String> = Vec::new();

    // 超基线 / 新文件引入。
    for (rel, &count) in &actual {
        match baseline.get(rel.as_str()) {
            Some(&allowed) if count <= allowed => {}
            Some(&allowed) => violations.push(format!(
                "  {rel}: {count} 行含 `_soland/`,超过基线 {allowed}(请改用 /_cokret/ 协议路径或 describe 发现)"
            )),
            None => violations.push(format!(
                "  {rel}: {count} 行含 `_soland/`,该文件不在基线白名单内(通用核心不得新增产品命名空间字面量)"
            )),
        }
    }

    assert!(
        violations.is_empty(),
        "检测到新增的 `_soland/` 产品命名空间字面量:\n{}\n\n如属合理新增(如受限适配器),请在 tests/no_product_paths.rs 的 BASELINE 中登记;\n如属迁移完成,请下调对应基线。",
        violations.join("\n")
    );
}

/// 防止基线"只增不减"地腐烂:基线里登记了、但源码里已经消失/低于的条目,
/// 应及时把基线下调到实际值(ratchet)。此测试提示哪些基线可以收紧。
#[test]
fn baseline_has_no_stale_overcount() {
    let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_root, &mut files);

    let mut actual: BTreeMap<String, usize> = BTreeMap::new();
    for file in &files {
        let content = fs::read_to_string(file).unwrap_or_else(|e| panic!("read {file:?}: {e}"));
        let count = content.lines().filter(|line| line.contains(NEEDLE)).count();
        actual.insert(rel_posix(&src_root, file), count);
    }

    let mut stale: Vec<String> = Vec::new();
    for (rel, allowed) in BASELINE {
        let count = actual.get(*rel).copied().unwrap_or(0);
        if count < *allowed {
            stale.push(format!(
                "  {rel}: 基线 {allowed},实际仅 {count} —— 可把基线下调到 {count}"
            ));
        }
    }

    assert!(
        stale.is_empty(),
        "基线高于实际,请 ratchet down(收紧门禁):\n{}",
        stale.join("\n")
    );
}
