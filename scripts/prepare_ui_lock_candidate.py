#!/usr/bin/env python3
"""Produce a review-only UI lock candidate in a disposable remote workspace."""
from __future__ import annotations
import argparse
import copy
import difflib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import time
import tomllib
from urllib.parse import urlsplit, urlunsplit, parse_qs

REPOSITORIES = ("arkret-spec", "arkret-rust-sdk", "floria", "coland", "coauth", "garth", "chime", "inkson", "cotest", "codmin")
UI = {"glory": "https://github.com/glory-rs/glory.git", "sapid": "https://github.com/sapid-ui/sapid.git"}
FEATURE_RENAMES = {"glory/blitz-shell": "glory/apace-shell", "glory/blitz-assets": "glory/apace-assets", "glory/blitz-accesskit": "glory/apace-accesskit"}

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

DEADLINE = None

def native(argv, cwd, env=None, timeout=900):
    if DEADLINE is not None:
        remaining = DEADLINE - time.monotonic()
        assert remaining > 0, "candidate total deadline reached"
        timeout = min(timeout, remaining)
    return subprocess.check_output(argv, cwd=cwd, env=env, timeout=timeout)

def git(root, *args):
    return native(["git", "--no-optional-locks", "-C", str(root), *args], root, timeout=60)

def latest_expected(name, expected, root):
    assert re.fullmatch("[a-f0-9]{40}", expected)
    rows = git(root, "ls-remote", "--exit-code", UI[name], "refs/heads/main").decode("ascii").splitlines()
    assert rows == [expected + "\trefs/heads/main"], "reviewed UI main moved; do not resolve another API " + json.dumps({"repository": UI[name], "name": name, "expectedSHA": expected, "actualrows": rows}, sort_keys=True)

def transform_manifest(raw):
    original = tomllib.loads(raw.decode("utf-8"))
    expected = copy.deepcopy(original)
    deps = expected["workspace"]["dependencies"]
    assert deps["glory"]["git"] == UI["glory"] and deps["glory"]["branch"] == "main" and deps["glory"]["version"] == "0.3.1"
    assert deps["sapid"]["git"] == UI["sapid"] and deps["sapid"]["branch"] == "main" and deps["sapid"]["version"] == "0.1.0"
    patch = expected["patch"][UI["sapid"]]["glory"]
    assert patch == {"git": UI["glory"], "branch": "main", "version": "0.3.1"}
    deps["glory"]["version"] = deps["sapid"]["version"] = patch["version"] = "0.6.1"
    assert set(FEATURE_RENAMES) <= set(expected["features"]["desktop"])
    expected["features"]["desktop"] = [FEATURE_RENAMES.get(v, v) for v in expected["features"]["desktop"]]
    text = raw.decode("utf-8")
    for name, old, count in (("glory", "0.3.1", 2), ("sapid", "0.1.0", 1)):
        pattern = r'(?m)^(' + name + r' = \{ git = "' + re.escape(UI[name]) + r'", branch = "main", version = ")' + re.escape(old) + r'(")'
        text, changed = re.subn(pattern, lambda m: m[1] + "0.6.1" + m[2], text)
        assert changed == count, "unexpected inline manifest layout"
    for old, new in FEATURE_RENAMES.items():
        assert text.count('"' + old + '"') == 1
        text = text.replace('"' + old + '"', '"' + new + '"')
    assert tomllib.loads(text) == expected, "manifest changes exceeded reviewed scope"
    return text.encode("utf-8")

def tracked_copy(source, target):
    assert not target.exists()
    target.mkdir()
    rows = git(source, "ls-files", "--stage", "-z").split(b"\0")
    for row in rows:
        if not row:
            continue
        header, name = row.split(b"\t", 1)
        mode, _oid, stage = header.split()
        rel = name.decode("utf-8", errors="strict")
        part = PurePosixPath(rel)
        assert mode in {b"100644", b"100755"} and stage == b"0"
        assert rel and not part.is_absolute() and ".." not in part.parts and "\\" not in rel and ":" not in rel
        original = source / rel
        assert original.is_file() and not original.is_symlink() and original.resolve().is_relative_to(source.resolve())
        destination = target / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, destination)
        destination.chmod(0o755 if mode == b"100755" else 0o644)

def resolved_ui(metadata, expected):
    selected = {}
    for name in UI:
        found = [p for p in metadata["packages"] if p["name"] == name]
        assert len(found) == 1
        package = found[0]
        assert package["version"] == "0.6.1"
        assert package["source"] == "git+" + UI[name] + "?branch=main#" + expected[name], "actual Cargo UI source differs"
        selected[name] = {"version": package["version"], "source": package["source"]}
    for package in metadata["packages"]:
        if package["name"].startswith("glory-"):
            assert package["version"] == "0.6.1" and package["source"] == selected["glory"]["source"], "mixed Glory source closure"
    return selected

def canonical_git_url(url):
    value = urlsplit(url)
    assert value.scheme == "https" and value.netloc == "github.com" and not value.query and not value.fragment
    assert not value.username and not value.password
    path = value.path.removesuffix(".git")
    assert re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", path)
    return "https://github.com" + path

def validate_source_contract(contract):
    assert contract["schema"] == "reviewed-UI-engine-Git-source-closure-v1"
    assert set(contract["inputs"]) == {"glory", "sapid", "apace", "takia", "wingy"}
    expected_urls = {**UI, "apace": "https://github.com/glory-rs/apace", "takia": "https://github.com/glory-rs/takia", "wingy": "https://github.com/glory-rs/wingy"}
    seen = set()
    for name, item in contract["inputs"].items():
        assert item["git"] == expected_urls[name] and re.fullmatch("[a-f0-9]{40}", item["commit"])
        assert item["selector"] == ("branch" if name in UI else "rev")
        assert re.fullmatch("[a-f0-9]{64}", item["root_manifest_sha256"])
        assert item["packages"]
        for package, spec in item["packages"].items():
            assert package not in seen, "ambiguous engine package ownership"
            seen.add(package)
            path = PurePosixPath(spec["manifest"])
            assert not path.is_absolute() and ".." not in path.parts and "\\" not in spec["manifest"] and ":" not in spec["manifest"]
            assert path.name == "Cargo.toml" and re.fullmatch("[a-f0-9]{64}", spec["manifest_sha256"])
            assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", spec["version"])
    expected = {UI["sapid"]: {"glory": "glory"}, UI["glory"]: {"apace-dom": "apace", "apace-traits": "apace", "apace-paint": "apace", "apace-shell": "apace", "apace_accesskit": "apace", "wingy": "wingy"}, expected_urls["apace"]: {"takia": "takia", "wingy": "wingy"}}
    assert contract["patches"] == expected, "only reviewed normal/build escaping edges may be patched"
    for source, packages in contract["patches"].items():
        for package, target in packages.items():
            item = contract["inputs"][target]
            assert canonical_git_url(source) != canonical_git_url(item["git"]), "Cargo source patch must change its source"
            assert package in item["packages"]
    return contract

def verify_source_inputs(root, contract):
    result = {}
    for name, item in contract["inputs"].items():
        source = root / ".ui-lock-inputs" / name
        assert git(source, "rev-parse", "HEAD").decode("ascii").strip() == item["commit"]
        assert not git(source, "status", "--porcelain").strip()
        rootraw = (source / "Cargo.toml").read_bytes()
        assert sha(rootraw) == item["root_manifest_sha256"]
        workspace = tomllib.loads(rootraw.decode("utf-8"))
        for package, spec in item["packages"].items():
            path = source / spec["manifest"]
            assert path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(source.resolve())
            raw = path.read_bytes()
            assert sha(raw) == spec["manifest_sha256"], "fixed fork manifest identity changed"
            actual = tomllib.loads(raw.decode("utf-8"))["package"]
            version = actual["version"]
            if isinstance(version, dict):
                assert version == {"workspace": True}
                version = workspace["workspace"]["package"]["version"]
            assert actual["name"] == package and version == spec["version"], "actual fork version does not satisfy reviewed closure"
        result[name] = {"git": item["git"], "commit": item["commit"], "root_manifest_sha256": sha(rootraw)}
    verify_escaping_paths(root, contract)
    return result

def verify_escaping_paths(root, contract):
    covered = {}
    for edge in contract["library_escaping_edges"]:
        source = root / ".ui-lock-inputs" / edge["source"]
        manifest = source / edge["manifest"]
        raw = manifest.read_bytes()
        assert sha(raw) == edge["manifest_sha256"]
        document = tomllib.loads(raw.decode("utf-8"))
        section = edge["section"]
        if section == "dependencies":
            entry = document["dependencies"][edge["alias"]]
        else:
            assert section.startswith("target.") and section.endswith(".dependencies")
            target = section[len("target."):-len(".dependencies")]
            entry = document["target"][target]["dependencies"][edge["alias"]]
        base = manifest.parent
        if entry.get("workspace"):
            workspace = tomllib.loads((source / "Cargo.toml").read_text())
            inherited = workspace["workspace"]["dependencies"][edge["alias"]]
            entry = {**inherited, **{key: value for key, value in entry.items() if key != "workspace"}}
            base = source
        owner = contract["inputs"][edge["source"]]["git"]
        target_owner = contract["patches"][owner][edge["target_name"]]
        target = contract["inputs"][target_owner]["packages"][edge["target_name"]]
        assert edge["target_name"] == entry.get("package", edge["alias"])
        assert entry["version"] == "=" + edge["target_version"] == "=" + target["version"], "actual escaping dependency requires a different fork version"
        path = root / ".ui-lock-inputs" / target_owner / target["manifest"]
        assert (base / entry["path"] / "Cargo.toml").resolve() == path.resolve(), "escaping path target is not the reviewed package"
        covered.setdefault(owner, {})[edge["target_name"]] = target_owner
    assert covered == contract["patches"], "patch source/package set must exactly cover reviewed library edges"

def apply_engine_source_patches(raw, contract):
    original = tomllib.loads(raw.decode("utf-8"))
    expected = copy.deepcopy(original)
    assert set(original.get("patch", {})) == {UI["sapid"]}, "unexpected existing source override"
    additions = []
    for source, packages in contract["patches"].items():
        table = {}
        for package, target in sorted(packages.items()):
            item = contract["inputs"][target]
            entry = {"git": item["git"], "version": "=" + item["packages"][package]["version"]}
            entry["branch" if item["selector"] == "branch" else "rev"] = "main" if item["selector"] == "branch" else item["commit"]
            table[package] = entry
        if source in expected["patch"]:
            # The existing Sapid-to-Glory override is kept byte-for-byte after its version migration.
            actual = expected["patch"][source]
            assert set(actual) == set(table)
            for package, entry in actual.items():
                compared = dict(entry, version="=" + entry["version"].removeprefix("="))
                assert compared == table[package]
            continue
        expected["patch"][source] = table
        additions += ["", '[patch.' + json.dumps(source) + ']']
        for package, entry in table.items():
            fields = ", ".join(key + " = " + json.dumps(value) for key, value in entry.items())
            additions.append(package + " = { " + fields + " }")
    result = raw + ("\n".join(additions) + "\n").encode("utf-8")
    assert tomllib.loads(result.decode("utf-8")) == expected
    return result

def source_matches(actual, item):
    if not isinstance(actual, str) or not actual.startswith("git+"):
        return False
    try:
        parsed = urlsplit(actual[4:])
        base = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        if canonical_git_url(base) != canonical_git_url(item["git"]):
            return False
        query = parse_qs(parsed.query, strict_parsing=True)
        selector = item["selector"]
        required = "main" if selector == "branch" else item["commit"]
        return query == {selector: [required]} and parsed.fragment == item["commit"]
    except (AssertionError, ValueError):
        return False

def resolved_engine_sources(metadata, contract):
    result = {}
    for name, item in contract["inputs"].items():
        if name in UI:
            continue
        observed = {}
        for package, spec in item["packages"].items():
            matches = [p for p in metadata["packages"] if p["name"] == package]
            if not matches:
                continue
            assert len(matches) == 1, "engine package has more than one source identity"
            actual = matches[0]
            assert actual["version"] == spec["version"] and source_matches(actual.get("source"), item), "actual engine graph is not the reviewed Git fork/version"
            observed[package] = {"version": actual["version"], "source": actual["source"]}
        required = {"apace": {"apace-dom", "apace-traits", "apace-paint", "apace-shell", "apace_accesskit"}, "takia": {"takia"}, "wingy": {"wingy"}}[name]
        assert required <= set(observed), "all-features engine resolution is incomplete"
        result[name] = observed
    return result

def publish_metadata(metadata):
    # Source graph only: omit absolute manifest/target paths and package text fields.
    identity = {p["id"]: sha(p["id"].encode()) for p in metadata["packages"]}
    packages = [{"id_sha256": identity[p["id"]], "name": p["name"], "version": p["version"], "source": p.get("source"), "features": p["features"]} for p in metadata["packages"]]
    graph = [{"id_sha256": identity[n["id"]], "features": n["features"], "dependencies": [identity[x] for x in n["dependencies"]]} for n in metadata["resolve"]["nodes"]]
    return {"schema": "normalized-cargo-resolution-only-v1", "packages": packages, "resolve": graph, "raw_metadata_sha256": None, "runtime_credit": None, "approved": False}

def main():
    global DEADLINE
    DEADLINE = time.monotonic() + 3300
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--expected-glory-main", required=True)
    parser.add_argument("--expected-sapid-main", required=True)
    parser.add_argument("--source-contract", type=Path, required=True)
    parser.add_argument("--source-contract-sha256", required=True)
    args = parser.parse_args()
    contract_raw = args.source_contract.read_bytes()
    assert sha(contract_raw) == args.source_contract_sha256
    contract = validate_source_contract(json.loads(contract_raw))
    root = args.workspace_root.resolve(strict=True)
    output = args.output.resolve()
    assert not output.exists(), "never overwrite a previous candidate"
    output.mkdir(parents=True)
    status = {"phase": "initial", "candidate_complete": False, "root_approved": False, "allows_publication": False, "merge_ready": False, "runtime_credit": None}
    try:
        sources = {}
        originals = {}
        for name in REPOSITORIES:
            source = root / name
            assert not git(source, "status", "--porcelain").strip(), "input repository must be clean"
            sources[name] = git(source, "rev-parse", "HEAD").decode("ascii").strip()
            assert re.fullmatch("[a-f0-9]{40}", sources[name])
            for filename in ("Cargo.toml", "Cargo.lock"):
                path = source / filename
                originals[(name, filename)] = sha(path.read_bytes()) if path.is_file() else None
        manifest = (root / "inkson/Cargo.toml").read_bytes()
        assert sha(manifest) == args.expected_manifest_sha256
        expected = {"glory": args.expected_glory_main, "sapid": args.expected_sapid_main}
        assert all(expected[name] == contract["inputs"][name]["commit"] for name in UI)
        for name, commit in expected.items():
            latest_expected(name, commit, root / "inkson")
        upstream_inputs = verify_source_inputs(root, contract)
        status["phase"] = "copy_inputs"
        with tempfile.TemporaryDirectory(prefix="inkson-ui-lock-", dir=os.environ["RUNNER_TEMP"]) as directory:
            temporary = Path(directory)
            for name in REPOSITORIES:
                tracked_copy(root / name, temporary / name)
            candidate = temporary / "inkson"
            (candidate / "Cargo.toml").write_bytes(apply_engine_source_patches(transform_manifest(manifest), contract))
            environment = dict(os.environ, CARGO_TARGET_DIR=str(temporary / "target"), CARGO_NET_GIT_FETCH_WITH_CLI="true")
            status["phase"] = "official_cargo_update"
            native(["cargo", "update", "-p", "glory", "-p", "sapid", "-p", "wasm-bindgen-test"], candidate, environment)
            status["phase"] = "official_locked_metadata"
            raw_metadata = native(["cargo", "metadata", "--locked", "--all-features", "--format-version", "1"], candidate, environment)
            metadata = json.loads(raw_metadata)
            assert Path(metadata["target_directory"]).resolve() == (temporary / "target").resolve()
            ui = resolved_ui(metadata, expected)
            engines = resolved_engine_sources(metadata, contract)
            status["phase"] = "official_locked_tree"
            tree = native(["cargo", "tree", "--locked", "--workspace", "--all-features", "--prefix", "none", "--format", "{p}"], candidate, environment)
            for name, commit in expected.items():
                latest_expected(name, commit, root / "inkson")
            assert verify_source_inputs(root, contract) == upstream_inputs
            public = publish_metadata(metadata)
            public["raw_metadata_sha256"] = sha(raw_metadata)
            (output / "metadata.json").write_text(json.dumps(public, indent=2) + "\n")
            for filename in ("Cargo.toml", "Cargo.lock"):
                shutil.copyfile(candidate / filename, output / filename)
            patch = ""
            for filename in ("Cargo.toml", "Cargo.lock"):
                patch += "".join(difflib.unified_diff((root / "inkson" / filename).read_text().splitlines(True), (candidate / filename).read_text().splitlines(True), "a/" + filename, "b/" + filename))
            (output / "candidate.patch").write_text(patch)
            context = {"actual_repository_heads": sources, "reviewed_UI_main": expected, "resolved_UI": ui, "resolved_engines": engines, "reviewed_upstream_inputs": upstream_inputs, "source_contract_sha256": sha(contract_raw), "original_manifest_sha256": sha(manifest), "raw_locked_metadata_sha256": sha(raw_metadata), "locked_tree_sha256": sha(tree), "root_approved": False, "runtime_credit": None}
            (output / "input-context.json").write_text(json.dumps(context, indent=2) + "\n")
        status["phase"] = "verify_original_sources_unchanged"
        for (name, filename), original in originals.items():
            path = root / name / filename
            assert (sha(path.read_bytes()) if path.is_file() else None) == original, "original source lock/manifest changed"
        assert all(git(root / name, "rev-parse", "HEAD").decode("ascii").strip() == commit and not git(root / name, "status", "--porcelain").strip() for name, commit in sources.items())
        status.update(phase="review_only_candidate_complete", candidate_complete=True)
    except (AssertionError, OSError, ValueError, subprocess.SubprocessError) as error:
        status.update(phase="candidate_unavailable_" + status["phase"], exception_type=type(error).__name__)
        raise
    finally:
        (output / "status.json").write_text(json.dumps(status, indent=2) + "\n")
        artifacts = [{"file": p.name, "bytes": p.stat().st_size, "sha256": sha(p.read_bytes())} for p in output.iterdir() if p.is_file()]
        (output / "manifest.json").write_text(json.dumps({"files": artifacts, "approved": False, "runtime_credit": None}, indent=2) + "\n")

if __name__ == "__main__":
    main()
