"""Keep the remaining-operation review exact and separate from executed coverage."""
from __future__ import annotations
import json
from pathlib import Path
import re
from check_native_read_evidence import FIXTURE, MANIFEST, digest as native_digest, operation_ids as native_ids, validate as validate_native

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO.parent
REVIEW = REPO / "tests/contract/mock-operation-review.json"

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def implemented_ids():
    source = (REPO / "tests/contract/remainingOperationProbes.ts").read_text(encoding="utf-8")
    section = source.split("IMPLEMENTED_REMAINING_OPERATIONS = new Set([", 1)[1].split("]);", 1)[0]
    return set(re.findall(r'"(ak\.[^"\n]+)"', section))

def verify_contract_bindings(document):
    # Reuse the canonical recursive closure, including schemas and error rules.
    # A review binds to actual contract bytes rather than an arbitrary revision.
    import sys
    sys.path.insert(0, str(ROOT / "arkret-spec/tools"))
    from check_operation_closure_locks import operation_closures

    assert set(document) == {"operations"}, "review has redundant or unknown root fields"
    catalog = read(ROOT / "arkret-spec/spec/v1/artifacts/registry/contract-registry.json")
    registry = {row["operation_id"]: row for row in catalog["operation_registry"]["operations"]}
    contracts = {row["operation_id"]: row["sha256"] for row in operation_closures(catalog)}
    source = (REPO / "tests/contract/mockOperationCoverage.ts").read_text(encoding="utf-8")
    expected = set(re.findall(r'"(ak\.[^"\n]+)"', source)) - {"ak.self.realm_join.command.prepare.v1", "ak.self.realm_join.read.preview.v1"}
    implemented, native = implemented_ids(), native_ids()
    expected |= implemented
    rows = document["operations"]
    identifiers = {row["operation_id"] for row in rows}
    assert len(rows) == len(identifiers), "duplicate reviewed operation"
    assert identifiers == expected, "review operation set drift"
    required = {"operation_id", "verification_need", "reason", "contract_digest", "normative_documents", "source_references", "mock_test"}
    for row in rows:
        identifier = row["operation_id"]
        assert set(row) == required, identifier
        assert row["contract_digest"] == contracts[identifier], f"reviewed operation contract changed: {identifier}"
        assert len(row["reason"]) >= 100 and "TODO" not in row["reason"], identifier
        assert row["source_references"], f"missing implementation reference: {identifier}"
        for reference in row["source_references"]:
            assert isinstance(reference, str) and (ROOT / reference).is_file(), reference
        for path in row["normative_documents"]:
            assert (ROOT / "arkret-spec/spec/v1" / path).is_file(), path
    for row in rows:
        identifier = row["operation_id"]
        if identifier in native:
            assert row["verification_need"] == "native_fixture_replay", identifier
            assert row["mock_test"] == {"file": "tests/contract/native-read-evidence.spec.ts", "name": f"native accepted read replay preserves original contract: {identifier}"}, identifier
            assert "native accepted read replay preserves original contract: ${id}, install ${index}" in (REPO / row["mock_test"]["file"]).read_text(encoding="utf-8")
        elif identifier in implemented:
            assert row["verification_need"] == "mock_behavior", identifier
            test = row["mock_test"]
            assert test["name"] == f"remaining valid request and response contract: {identifier}", identifier
            assert "remaining valid request and response contract: ${id}, install ${index}" in (REPO / test["file"]).read_text(encoding="utf-8")
        else:
            assert row["mock_test"] is None, identifier
            assert row["verification_need"] in {"native_authority", "native_evidence_fixture"}, identifier
    return registry


def validate(document):
    verify_contract_bindings(document)
    implemented = implemented_ids()
    native = native_ids()
    validate_native(read(FIXTURE), read(MANIFEST), native_digest(FIXTURE))
    rows = document["operations"]
    return {"operations": len(rows), "mock_behavior": len(implemented), "native_fixture_replay": len(native), "uncovered": len(rows) - len(implemented) - len(native)}


def render(document):
    labels = {"mock_behavior": "mock behavior", "native_authority": "native authority", "native_evidence_fixture": "native evidence fixture missing", "native_fixture_replay": "native accepted fixture / archival replay"}
    lines = ["# Remaining mock operation contract review", "", "Generated from mock-operation-review.json. Classification is not executed coverage.", "Fourteen reads have a mandatory native PostgreSQL/registered-route fixture producer and exact archival replay. The replay is not live authorization; StandardGrant introspection uses the trusted native test channel. Five IVS operations were withdrawn from the original 140-operation review; withdrawal grants no native coverage. The other 92 native contracts remain independently tracked. Source references alone never certify execution.", "", "| Operation | Mock implementation | Verification need | Reason / scope |", "| --- | --- | --- | --- |"]
    implemented, native = implemented_ids(), native_ids()
    for row in document["operations"]:
        implementation = "implemented" if row["operation_id"] in implemented else "archival_fixture" if row["operation_id"] in native else "missing"
        lines.append(f"| `{row['operation_id']}` | {implementation} | {labels[row['verification_need']]} | {row['reason'].replace('|', '/')} |")
    return "\n".join(lines) + "\n"

if __name__ == "__main__":
    import sys
    document = read(REVIEW)
    result = validate(document)
    table = REVIEW.with_suffix(".md")
    if "--write" in sys.argv:
        table.write_text(render(document), encoding="utf-8", newline="\n")
    else:
        assert table.read_text(encoding="utf-8") == render(document), "stale human-readable operation review"
    print(json.dumps(result, sort_keys=True))
