#!/usr/bin/env python3
"""Generate and check the Inkson E2E mock operation inventory.

Operation identifiers and response schemas are resolved exclusively from the
checked-out spec OpenAPI and registry artifacts.  The mock source is only used
to retain auditable route evidence; it never supplies protocol identifiers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml


REPO = Path(__file__).resolve().parents[1]
SPEC_ARTIFACTS = Path(
    os.environ.get(
        "ARKRET_SPEC_ARTIFACTS",
        REPO.parent / "arkret-spec" / "spec" / "v1" / "artifacts",
    )
)
OPENAPI_PATH = SPEC_ARTIFACTS / "openapi" / "arkret-service-api.openapi.yaml"
OPERATION_REGISTRY_PATH = SPEC_ARTIFACTS / "registry" / "operation-registry.json"
SCHEMA_REGISTRY_PATH = SPEC_ARTIFACTS / "registry" / "schema-registry.json"
OUTPUT_PATH = REPO / "tests" / "e2e" / "mock-operation-inventory.json"
MOCK_SOURCES = (REPO / "tests" / "e2e" / "mockArkretApi.ts",)
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "query", "head"}
RETIRED_MOCK_FIELDS = {"registry_mode", "supported_receipts"}
RETIRED_NESTED_MOCK_FIELDS = {"auth_metadata": "mode", "method_evidence": "mode"}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def typescript_tokens(source: str) -> list[str]:
    """Return the identifier/punctuation tokens needed by the fixture guard."""
    tokens: list[str] = []
    index = 0
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if char == "/" and following == "/":
            index = source.find("\n", index + 2)
            if index < 0:
                break
            continue
        if char == "/" and following == "*":
            end = source.find("*/", index + 2)
            index = len(source) if end < 0 else end + 2
            continue
        if char in {'"', "'", "`"}:
            quote = char
            index += 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                    continue
                if source[index] == quote:
                    index += 1
                    break
                index += 1
            continue
        if char.isalpha() or char in {"_", "$"}:
            end = index + 1
            while end < len(source) and (
                source[end].isalnum() or source[end] in {"_", "$"}
            ):
                end += 1
            tokens.append(source[index:end])
            index = end
            continue
        if char in "{}:":
            tokens.append(char)
        index += 1
    return tokens


def check_retired_mock_fields() -> None:
    for path in MOCK_SOURCES:
        tokens = typescript_tokens(path.read_text(encoding="utf-8"))
        for index, token in enumerate(tokens[:-1]):
            if token in RETIRED_MOCK_FIELDS and tokens[index + 1] == ":":
                raise ValueError(
                    f"retired positive mock fixture field {token} in {path.name}"
                )
            nested_field = RETIRED_NESTED_MOCK_FIELDS.get(token)
            if nested_field is None or tokens[index + 1 : index + 3] != [":", "{"]:
                continue
            depth = 1
            cursor = index + 3
            while cursor < len(tokens) and depth:
                current = tokens[cursor]
                if current == "{":
                    depth += 1
                elif current == "}":
                    depth -= 1
                elif (
                    depth == 1
                    and current == nested_field
                    and cursor + 1 < len(tokens)
                    and tokens[cursor + 1] == ":"
                ):
                    raise ValueError(
                        f"retired positive mock fixture field {token}.{nested_field} in {path.name}"
                    )
                cursor += 1


def json_pointer(document: Any, pointer: str) -> Any:
    value = document
    for raw_part in pointer.removeprefix("#/").split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def resolve_local_ref(openapi: dict[str, Any], value: Any) -> Any:
    seen: set[str] = set()
    while isinstance(value, dict) and set(value) == {"$ref"}:
        reference = value["$ref"]
        if not reference.startswith("#/"):
            return value
        if reference in seen:
            raise ValueError(f"cyclic OpenAPI reference {reference}")
        seen.add(reference)
        value = json_pointer(openapi, reference)
    return value


def external_schema_reference(openapi: dict[str, Any], schema: Any) -> str | None:
    schema = resolve_local_ref(openapi, schema)
    if not isinstance(schema, dict) or set(schema) != {"$ref"}:
        return None
    reference = schema["$ref"]
    if reference.startswith("../schemas/"):
        return reference.removeprefix("../")
    return None


def operation_selector(operation: dict[str, Any]) -> str:
    selectors = {
        parameter.get("schema", {}).get("const")
        for parameter in operation.get("parameters", [])
        if parameter.get("name") == "Arkret-Operation"
        and parameter.get("in") == "header"
    }
    selectors.discard(None)
    if len(selectors) != 1:
        raise ValueError(
            f"operation {operation.get('operationId')} has {len(selectors)} selectors"
        )
    return selectors.pop()


def response_schema(
    openapi: dict[str, Any],
    response: Any,
    schema_ids: dict[str, str],
) -> tuple[str | None, str | None]:
    response = resolve_local_ref(openapi, response)
    content = response.get("content", {}) if isinstance(response, dict) else {}
    media = content.get("application/json")
    if not isinstance(media, dict) or "schema" not in media:
        return None, None
    reference = external_schema_reference(openapi, media["schema"])
    if reference is None:
        raise ValueError(f"JSON response schema is not one external $ref: {media['schema']}")
    return reference, schema_ids.get(reference)


def route_evidence() -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for path in MOCK_SOURCES:
        for line_number, original in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            normalized = original.replace(r"\/", "/")
            if "/_arkret/" not in normalized:
                continue
            snippet = normalized.strip()
            key = (path.name, line_number, snippet)
            if key in seen:
                continue
            seen.add(key)
            evidence.append(
                {"file": path.relative_to(REPO).as_posix(), "line": line_number, "source": snippet}
            )
    return evidence


def generate() -> dict[str, Any]:
    check_retired_mock_fields()
    openapi_bytes = OPENAPI_PATH.read_bytes()
    operation_registry_bytes = OPERATION_REGISTRY_PATH.read_bytes()
    schema_registry_bytes = SCHEMA_REGISTRY_PATH.read_bytes()
    openapi = yaml.safe_load(openapi_bytes)
    operation_rows = json.loads(operation_registry_bytes)["operations"]
    registered_operations = {row["operation_id"] for row in operation_rows}
    schema_rows = json.loads(schema_registry_bytes)["schemas"]
    schema_ids: dict[str, str] = {}
    for row in schema_rows:
        reference = row["file"] + row.get("fragment", "")
        previous = schema_ids.setdefault(reference, row["schema_id"])
        if previous != row["schema_id"]:
            raise ValueError(f"ambiguous schema registry reference {reference}")

    operations: list[dict[str, Any]] = []
    for path_template, path_item in openapi["paths"].items():
        for method, operation in path_item.items():
            if method not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            selector = operation_selector(operation)
            if selector not in registered_operations:
                raise ValueError(f"OpenAPI selector {selector} is absent from operation registry")
            responses: dict[str, Any] = {}
            for status, response in sorted(operation.get("responses", {}).items()):
                reference, schema_id = response_schema(openapi, response, schema_ids)
                responses[str(status)] = {
                    "schema_ref": reference,
                    "schema_id": schema_id,
                }
            operations.append(
                {
                    "method": method.upper(),
                    "path_template": path_template,
                    "operation_id": selector,
                    "responses": responses,
                }
            )
    operations.sort(key=lambda row: (row["path_template"], row["method"]))
    return {
        "format_version": 1,
        "generated_from": {
            "openapi_sha256": hashlib.sha256(openapi_bytes).hexdigest(),
            "operation_registry_sha256": hashlib.sha256(operation_registry_bytes).hexdigest(),
            "schema_registry_sha256": hashlib.sha256(schema_registry_bytes).hexdigest(),
        },
        "operations": operations,
        "mock_route_evidence": route_evidence(),
    }


def serialized(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    generated = serialized(generate())
    if args.check:
        current = OUTPUT_PATH.read_text(encoding="utf-8") if OUTPUT_PATH.exists() else ""
        if current != generated:
            print(
                f"{OUTPUT_PATH.relative_to(REPO)} is stale; regenerate with {Path(__file__).name}",
                file=sys.stderr,
            )
            return 1
        print(f"checked {OUTPUT_PATH.relative_to(REPO)}")
        return 0
    OUTPUT_PATH.write_text(generated, encoding="utf-8", newline="\n")
    print(f"generated {OUTPUT_PATH.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
