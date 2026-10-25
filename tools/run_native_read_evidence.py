"""Produce the complete archival read corpus through the native Coland contract.

Run after freezing Rust and normative artifacts. The source fence covers the
entire invocation; a failed or moving producer cannot update checked-in data.
Cargo configuration and the caller's environment choose the actual target.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from check_native_read_evidence import ROOT, REPO, PRODUCER_TEST, accept, digest, source_files, validate_error_surface

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=REPO / "artifacts/native-read-evidence")
    parser.add_argument("--accept", action="store_true", help="update the checked-in corpus only after native success")
    args = parser.parse_args()
    validate_error_surface()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    corpus = output / "native-read-evidence.json"
    log = output / "native-read-contract.log"
    result = output / "native-read-contract-result.json"
    before = {path: digest(ROOT / path) for path in source_files()}
    env = {**os.environ, "ARKRET_NATIVE_READ_EVIDENCE_OUTPUT": str(corpus), "PYTHONUTF8": "1"}
    metadata = subprocess.run(["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"],
        cwd=ROOT / "coland", env=env, capture_output=True, text=True, encoding="utf-8", timeout=1800)
    assert metadata.returncode == 0, metadata.stderr
    (output / "coland-metadata.json").write_text(metadata.stdout, encoding="utf-8", newline="\n")
    command = [sys.executable, "-B", str(ROOT / "cotest/scripts/run-native-rust-tests.py"), "--",
        "cargo", "test", "--locked", "-p", "coland-storage-postgres", "--features", "test-support",
        "--test", "realm_actor_control", PRODUCER_TEST, "--", "--exact", "--nocapture"]
    started = time.monotonic()
    with log.open("w", encoding="utf-8", newline="\n") as stream:
        completed = subprocess.run(command, cwd=ROOT / "coland", env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=7200)
    after = {path: digest(ROOT / path) for path in source_files()}
    record = {"command": command, "exit_code": completed.returncode, "seconds": time.monotonic() - started,
        "source_sha256": before, "source_unchanged": before == after,
        "target_directory": json.loads(metadata.stdout)["target_directory"]}
    result.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8", newline="\n")
    assert before == after, "native source changed during validation"
    if completed.returncode:
        return completed.returncode
    summaries = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored", log.read_text(encoding="utf-8"))
    assert summaries == [("1", "0", "0")], "exact native producer must execute"
    if args.accept:
        accept(corpus, log, result)
    print(json.dumps({"native_read_operations": 14, "exit_code": 0, "output": str(corpus)}))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
