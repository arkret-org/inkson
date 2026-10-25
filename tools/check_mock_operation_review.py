"""Keep the remaining-operation review exact and separate from executed coverage."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import re

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO.parent
REVIEW = REPO / "tests/contract/mock-operation-review.json"

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def implemented_ids():
    source = (REPO / "tests/contract/remainingOperationProbes.ts").read_text(encoding="utf-8")
    section = source.split("IMPLEMENTED_REMAINING_OPERATIONS = new Set([", 1)[1].split("]);", 1)[0]
    return set(re.findall(r'"(ak\.[^"\n]+)"', section))

def validate(document):
    registry = read(ROOT / "arkret-spec/spec/v1/artifacts/registry/contract-registry.json")["operation_registry"]["operations"]
    error_rows = read(ROOT / "arkret-spec/spec/v1/artifacts/registry/operations-error-mapping.json")["operations"]
    error_lookup = {row["operation_id"]: (index, row) for index, row in enumerate(error_rows)}
    inventory = {row["operation_id"]: row for row in read(REPO / "tests/e2e/mock-operation-inventory.json")["operations"]}
    source = (REPO / "tests/contract/mockOperationCoverage.ts").read_text(encoding="utf-8")
    expected = set(re.findall(r'"(ak\.[^"\n]+)"', source)) - {"ak.self.realm_join.command.prepare.v1", "ak.self.realm_join.read.preview.v1"}
    implemented = implemented_ids()
    expected |= implemented
    assert len(expected) == 140, "review scope must retain all 140 original operations"
    rows = document["operations"]
    assert len(rows) == len({row["operation_id"] for row in rows}) == 140, "missing or duplicate reviewed operation"
    assert {row["operation_id"] for row in rows} == expected, "review operation set drift"
    assert document["classification_is_not_coverage"] is True
    definitions = {row["operation_id"]: (index, row) for index, row in enumerate(registry)}
    for row in rows:
        identifier = row["operation_id"]
        index, operation = definitions[identifier]
        binding = inventory[identifier]
        assert row["spec_operation_ref"] == f"registry/contract-registry.json#/operation_registry/operations/{index}", identifier
        digest = hashlib.sha256(json.dumps(operation, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        assert row["spec_operation_sha256"] == digest, f"stale normative operation: {identifier}"
        assert row["normative_notes"] == operation.get("notes", ""), identifier
        assert (row["method"], row["path"]) == (binding["method"], binding["path_template"]), identifier
        assert row["request_schema_ref"] == binding["request"]["schema_ref"], identifier
        assert row["response_schema_ref"] == operation.get("response_schema_ref"), identifier
        error_index, error_row = error_lookup[identifier]
        assert row["error_mapping_ref"] == f"registry/operations-error-mapping.json#/operations/{error_index}", identifier
        assert row["error_mapping_sha256"] == hashlib.sha256(json.dumps(error_row, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest(), f"stale error mapping: {identifier}"
        assert row["operation_specific_errors"] == error_row["operation_specific"], identifier
        assert row["native_authority_contract"] == "not_run", "source or classification cannot certify native execution"
        assert len(row["reason"]) >= 100 and "TODO" not in row["reason"], identifier
        assert row["source_references"], f"missing implementation reference: {identifier}"
        for reference in row["source_references"]:
            assert (ROOT / reference["path"]).is_file(), reference
            assert reference["evidence_kind"] == "family_source_reference" and reference["execution"] == "not_run", reference
        for path in row["normative_documents"]:
            assert (ROOT / "arkret-spec/spec/v1" / path).is_file(), path
        if identifier in implemented:
            assert row["mock_implementation"] == "implemented" and row["verification_need"] == "mock_behavior", identifier
            test = row["mock_test"]
            assert test["name"] == f"remaining valid request and response contract: {identifier}", identifier
            assert "remaining valid request and response contract: ${id}, install ${index}" in (REPO / test["file"]).read_text(encoding="utf-8")
        else:
            assert row["mock_implementation"] == "missing" and row["mock_test"] is None, identifier
            assert row["verification_need"] in {"native_authority", "native_evidence_fixture"}, identifier
    return {"operations": len(rows), "mock_behavior": len(implemented), "uncovered": len(rows) - len(implemented)}

def render(document):
    labels = {"mock_behavior": "mock behavior", "native_authority": "native authority", "native_evidence_fixture": "native evidence fixture missing"}
    lines = ["# Remaining mock operation contract review", "", "Generated from mock-operation-review.json. Classification is not executed coverage.", "Native authority contracts are NOT RUN for every row. The mock behavior rows cover only the scenarios specified below; source references do not certify native execution.", "", "| Operation | Mock implementation | Verification need | Reason / scope |", "| --- | --- | --- | --- |"]
    for row in document["operations"]:
        lines.append(f"| `{row['operation_id']}` | {row['mock_implementation']} | {labels[row['verification_need']]} | {row['reason'].replace('|', '/')} |")
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
