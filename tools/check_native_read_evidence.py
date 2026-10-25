"""Keep archival responses coupled to the native producer and accepted originals."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
from datetime import datetime

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO.parent
FIXTURE = REPO / "tests/contract/fixtures/native-read-evidence.json"
MANIFEST = FIXTURE.with_suffix(".manifest.json")
PRODUCER_TEST = "public_read_contracts_preserve_fourteen_native_authority_closures"

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def operation_ids():
    source = (REPO / "tests/contract/nativeReadEvidence.ts").read_text(encoding="utf-8")
    section = source.split("NATIVE_READ_OPERATIONS = new Set([", 1)[1].split("]);", 1)[0]
    ids = set(re.findall(r'"(ak\.[^"\n]+)"', section))
    assert len(ids) == 14
    return ids

def validate_error_surface():
    rows = read(ROOT / "arkret-spec/spec/v1/artifacts/registry/operations-error-mapping.json")["operations"]
    mapping = {row["operation_id"]: row for row in rows}
    for identifier in ("ak.edge.applet.third_party_users.read.list.v1", "ak.self.realm_actor.read.material.v1"):
        assert "not_found" in mapping[identifier]["operation_specific"], f"native non-enumerating error missing: {identifier}"
    assert "not_found" not in mapping["ak.self.consent.read.list.v1"]["operation_specific"], "an unavailable archive is not an absent Consent collection"

def source_files():
    files = [
        "inkson/tools/run_native_read_evidence.py",
        "inkson/tools/check_native_read_evidence.py",
        "coland/Cargo.toml",
        "coland/Cargo.lock",
        "arkret-rust-sdk/Cargo.toml",
        "arkret-rust-sdk/Cargo.lock",
        "arkret-rust-sdk/crates/models-integration/src/applet_models.rs",
        "arkret-rust-sdk/crates/http-client/src/endpoints/applet.rs",
        "arkret-rust-sdk/crates/sdk/src/mls_roster_authority.rs",
        "arkret-rust-sdk/crates/identity/src/service_resolution_evidence.rs",
        "bridges/crates/runtime/src/web.rs",
        "coland/crates/storage-postgres/tests/realm_actor_control.rs",
        "coland/crates/test-support/src/pcr_genesis.rs",
        "coland/crates/test-support/src/device_authorization_history.rs",
        "coland/crates/services/src/authority_commit.rs",
        "coland/crates/storage-postgres/src/authority_commit.rs",
        "coland/crates/storage-postgres/src/actor_profiles.rs",
        "coland/crates/storage-postgres/src/mls_roster_authority_read.rs",
        "coland/crates/storage-postgres/src/mls_group_state_material_read.rs",
        "coland/crates/http/src/routing/identity/account.rs",
        "coland/crates/http/src/routing/identity/consent.rs",
        "coland/crates/http/src/routing/identity/realm_actor_material.rs",
        "coland/crates/http/src/routing/identity/realm_actor_account_material.rs",
        "coland/crates/http/src/routing/system/principal_resolution.rs",
        "coland/crates/http/src/routing/self_current_reads.rs",
        "coland/crates/http/src/routing/media_service_binding.rs",
        "coland/crates/http/src/routing/realm_join.rs",
        "coland/crates/http/src/state/replica_anchor.rs",
    ]
    files += [str(path.relative_to(ROOT)).replace("\\", "/") for path in
              (ROOT / "coland/crates/storage-postgres/tests/support").glob("*.rs")]
    files += [str(path.relative_to(ROOT)).replace("\\", "/") for path in
              (ROOT / "arkret-spec/spec/v1/artifacts").rglob("*.json")]
    files.append("arkret-spec/spec/v1/artifacts/openapi/arkret-service-api.openapi.yaml")
    # Wire serializers and native admission/read implementations are part of
    # the producing SUT, including transitive helpers beyond the test module.
    for repository, crates in (
        ("arkret-rust-sdk", ("canonical", "identifiers", "wire", "models-crypto", "models-identity",
            "models-collaboration", "models-discovery", "models-integration", "identity", "signatures", "mls", "sdk", "http-client")),
        ("coland", ("contracts", "domain", "storage", "storage-postgres", "services", "http", "test-support")),
        ("bridges", ("runtime",)),
    ):
        for crate in crates:
            files += [str(path.relative_to(ROOT)).replace("\\", "/") for path in
                (ROOT / repository / "crates" / crate / "src").rglob("*.rs")]
    return sorted(set(files))

def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values(): yield from walk(child)
    elif isinstance(value, list):
        for child in value: yield from walk(child)

def validate(corpus, manifest, fixture_digest=None, check_sources=True):
    validate_error_surface()
    assert corpus["format_version"] == 1
    assert manifest["format_version"] == 1
    assert corpus["semantics"] == "archival_native_read_transcript"
    assert "trusted test channel" in corpus["authentication_boundary"]
    rows = corpus["operations"]
    assert len(rows) == 14 and {row["operation_id"] for row in rows} == operation_ids(), "all fourteen successful native reads are mandatory"
    assert manifest["producer_test"] == PRODUCER_TEST
    assert manifest["native_result"] == {"passed": 1, "failed": 0, "ignored": 0}
    assert fixture_digest is None or fixture_digest == manifest["corpus_sha256"], "archival response bytes changed; rerun the native producer"
    if check_sources:
        assert set(manifest["source_sha256"]) == set(source_files()), "native evidence source set drift"
        for path, expected in manifest["source_sha256"].items():
            assert digest(ROOT / path) == expected, f"native evidence source changed: {path}"
    inventory = {row["operation_id"]: row for row in read(REPO / "tests/e2e/mock-operation-inventory.json")["operations"]}
    for row in rows:
        identifier = row["operation_id"]
        operation = inventory[identifier]
        assert row["method"] == operation["method"]
        assert row["path"].startswith("/_arkret/") and "{" not in row["path"]
        assert bool(row["request_body"]) if operation["request"]["schema_ref"] else row["request_body"] is None
        assert row["accepted_originals"] and row["response_body"] and row["verified_at"]
        originals = list(walk(row["accepted_originals"]))
        assert any("event" in item and "commit" in item for item in originals) or identifier == "ak.self.identity.read.resolution_audit.v1", identifier
        for item in originals:
            if "event" in item and "commit" in item:
                assert item["event"]["event_id"] == item["commit"]["event_ref"], identifier
                assert item["event"].get("producer_proof") and item["commit"].get("signature"), identifier
        body = row["response_body"]
        observed = datetime.fromisoformat(row["verified_at"].replace("Z", "+00:00"))
        expiry = body.get("expires_at")
        if identifier == "ak.open.identity.read.resolution.v1":
            expiry = body["projection_attestation"]["attestation"]["expires_at"]
        if expiry:
            assert observed < datetime.fromisoformat(expiry.replace("Z", "+00:00")), identifier
        if identifier.startswith("ak.edge.applet."):
            assert body["exists"] is True and body["actor_id"]["kind"] == "realm", identifier
        if identifier == "ak.edge.applet.third_party_users.read.list.v1": assert body["external_ref"]
        if identifier == "ak.self.actor_profile.read.resolve.v1":
            assert body["profiles"] and all(profile["profile_event"] and profile["profile_commit"] for profile in body["profiles"])
        if identifier == "ak.self.consent.read.list.v1": assert body["consents"] and body["consents"][0]["permission_scopes"]
        if identifier == "ak.self.consent.resource.get.v1": assert body["permission_scopes"]
        if identifier == "ak.self.media_service_binding.read.resolve.v1": assert body["signing_keys"] and body["route"]["service_kind"] == "station"
        if ".mls.read.group_state_material." in identifier: assert body["group_info_base64url"] and body["ratchet_tree_base64url"]
        if ".mls.read.roster_authority." in identifier:
            roster = body.get("roster", body)
            assert roster["records"] and roster["manifest"]["signature"]
        if identifier == "ak.self.identity.read.resolution_audit.v1": assert body["principal_genesis_event"] and len(body["genesis_commits"]) == 2
        if ".realm_actor.read.material." in identifier:
            assert any(item.get("status") == "present" and item.get("source_ref") for item in walk(body)), identifier
    return {"native_read_operations": 14, "archival_replay_is_live_authorization": False}

def accept(output: Path, log: Path, result: Path):
    run = read(result)
    assert run["exit_code"] == 0 and PRODUCER_TEST in run["command"], "only a completed native producer may update the corpus"
    summaries = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored", log.read_text(encoding="utf-8"))
    assert summaries == [("1", "0", "0")], "a nonempty exact native contract must pass"
    corpus = read(output)
    manifest = {"format_version": 1, "producer_test": PRODUCER_TEST,
                "native_result": {"passed": 1, "failed": 0, "ignored": 0},
                "corpus_sha256": digest(output), "source_sha256": {path: digest(ROOT / path) for path in source_files()}}
    assert run["source_unchanged"] is True and run["source_sha256"] == manifest["source_sha256"], "native invocation did not freeze the recorded source"
    validate(corpus, manifest, digest(output))
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_bytes(output.read_bytes())
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--accept-output", type=Path)
    parser.add_argument("--native-log", type=Path)
    parser.add_argument("--native-result", type=Path)
    args = parser.parse_args()
    if args.accept_output:
        assert args.native_log and args.native_result
        accept(args.accept_output, args.native_log, args.native_result)
    print(json.dumps(validate(read(FIXTURE), read(MANIFEST), digest(FIXTURE))))
