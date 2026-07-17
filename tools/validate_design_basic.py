#!/usr/bin/env python3
"""Standard-library fallback checks for the APEX design-only repository."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas" / "v1"
errors: list[str] = []
checks = 0


def check(condition: bool, message: str) -> None:
    global checks
    checks += 1
    if not condition:
        errors.append(message)


def resolve_pointer(document: object, fragment: str) -> object:
    value = document
    if not fragment:
        return value
    if not fragment.startswith("/"):
        raise ValueError(f"unsupported fragment #{fragment}")
    for token in fragment[1:].split("/"):
        token = unquote(token).replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or token not in value:
            raise KeyError(token)
        value = value[token]
    return value


required_files = [
    ROOT / "README.md",
    ROOT / "docs" / "ARCHITECTURE.md",
    ROOT / "docs" / "API_INTERFACE.md",
    ROOT / "docs" / "DATABASE_SCHEMA.md",
    ROOT / "docs" / "DIRECTORY_STRUCTURE.md",
    ROOT / "docs" / "IMPLEMENTATION_ROADMAP.md",
    ROOT / "docs" / "JSON_SCHEMAS.md",
    ROOT / "docs" / "MODULE_RESPONSIBILITIES.md",
    ROOT / "docs" / "REQUIREMENTS_TRACEABILITY.md",
    ROOT / "tools" / "validate_design.mjs",
    ROOT / "tools" / "validate_design.sh",
]
for required_file in required_files:
    check(required_file.is_file(), f"missing required file: {required_file.relative_to(ROOT)}")

schemas: dict[Path, object] = {}
for schema_file in sorted(SCHEMA_DIR.glob("*.json")):
    try:
        schema = json.loads(schema_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"{schema_file.relative_to(ROOT)} JSON syntax: {error}")
        continue
    schemas[schema_file.resolve()] = schema
    check(
        schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema",
        f"{schema_file.relative_to(ROOT)} does not declare Draft 2020-12",
    )
    check(
        isinstance(schema.get("$id"), str) and "/v1/" in schema["$id"],
        f"{schema_file.relative_to(ROOT)} has no v1 $id",
    )


def walk_json(value: object):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from walk_json(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_json(child)


for schema_file, schema in schemas.items():
    for node in walk_json(schema):
        if not isinstance(node, dict):
            continue
        ref = node.get("$ref")
        if not isinstance(ref, str) or ref.startswith("#"):
            continue
        file_part, _, fragment = ref.partition("#")
        check(
            not re.match(r"^[a-z]+:", file_part, re.IGNORECASE),
            f"{schema_file.relative_to(ROOT)} uses non-local $ref {ref}",
        )
        target = (schema_file.parent / file_part).resolve()
        try:
            target.relative_to(SCHEMA_DIR.resolve())
            inside_schema_dir = True
        except ValueError:
            inside_schema_dir = False
        check(inside_schema_dir, f"{schema_file.relative_to(ROOT)} $ref escapes schemas/v1: {ref}")
        check(target in schemas, f"{schema_file.relative_to(ROOT)} missing $ref file {file_part}")
        if target in schemas:
            try:
                resolve_pointer(schemas[target], fragment)
            except (KeyError, ValueError) as error:
                errors.append(f"{schema_file.relative_to(ROOT)} unresolved $ref {ref}: {error}")

markdown_files = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
link_pattern = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
for markdown_file in markdown_files:
    markdown = markdown_file.read_text(encoding="utf-8")
    for target in link_pattern.findall(markdown):
        target = target.strip("<>").split("#", 1)[0]
        if not target or target.startswith("#") or re.match(r"^[a-z]+:", target, re.IGNORECASE):
            continue
        check(
            (markdown_file.parent / target).resolve().exists(),
            f"{markdown_file.relative_to(ROOT)} broken link {target}",
        )

traceability = (ROOT / "docs" / "REQUIREMENTS_TRACEABILITY.md").read_text(encoding="utf-8")
requirement_ids = re.findall(r"\|\s*([A-Z]+(?:-[A-Z]+)*-\d{3})\s*\|", traceability)
duplicates = sorted({item for item in requirement_ids if requirement_ids.count(item) > 1})
check(not duplicates, "duplicate requirement IDs: " + ", ".join(duplicates))
for prefix in [
    "CORE", "CTX", "LOC", "RPT", "MCP", "PERF", "COMM", "MEDIA",
    "AI", "AUD", "IDX", "TZ", "KW", "COC", "VIEW", "VAL",
]:
    check(
        re.search(rf"\|\s*{prefix}-\d{{3}}\s*\|", traceability) is not None,
        f"missing {prefix} requirements",
    )

api = (ROOT / "docs" / "API_INTERFACE.md").read_text(encoding="utf-8")
api_rows = re.findall(
    r"\|\s*\x60(GET|POST|PUT|PATCH|DELETE)\x60\s*\|\s*\x60([^\x60]+)\x60\s*\|",
    api,
)
api_keys = [f"{method} {endpoint}" for method, endpoint in api_rows]
api_duplicates = sorted({item for item in api_keys if api_keys.count(item) > 1})
check(not api_duplicates, "duplicate API endpoints: " + ", ".join(api_duplicates))

for forbidden in ("src", "mcp", "prompts"):
    check(not (ROOT / forbidden).exists(), f"forbidden implementation directory exists: {forbidden}")

if errors:
    print(f"Basic design validation failed with {len(errors)} error(s):", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    raise SystemExit(1)

print(
    "Basic design validation passed "
    f"({checks} checks, {len(schemas)} schemas, "
    f"{len(requirement_ids)} requirements, {len(api_rows)} endpoints)."
)
