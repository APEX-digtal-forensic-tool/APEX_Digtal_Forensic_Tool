"""Read-only access to the canonical APEX JSON Schema catalog."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from apex_mcp.errors import DescriptorValidationError, ToolInputValidationError


class SchemaCatalog:
    """Loads and validates canonical schemas without synthesizing DTO fields."""

    def __init__(self, schema_dir: Path) -> None:
        self._schema_dir = schema_dir.resolve()
        self._schemas = self._load(self._schema_dir)
        resources = [
            (str(schema["$id"]), Resource.from_contents(schema))
            for schema in self._schemas.values()
            if isinstance(schema.get("$id"), str)
        ]
        self._registry = Registry().with_resources(resources)

    @property
    def count(self) -> int:
        return len(self._schemas)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._schemas))

    def has(self, schema_name: str) -> bool:
        return schema_name in self._schemas

    def schema(self, schema_name: str) -> dict[str, Any]:
        self._validate_schema_name(schema_name)
        schema = self._schemas.get(schema_name)
        if schema is None:
            raise DescriptorValidationError(
                "A referenced schema is not present in the canonical catalog.",
                target=schema_name,
            )
        return copy.deepcopy(schema)

    def validate(self, schema_name: str, instance: Any) -> None:
        schema = self.schema(schema_name)
        self._validate_with(schema, instance)

    def validate_inline(self, schema: dict[str, Any], instance: Any) -> None:
        self.check_inline(schema)
        self._validate_with(schema, instance)

    @staticmethod
    def check_inline(schema: dict[str, Any]) -> None:
        Draft202012Validator.check_schema(schema)

    def _validate_with(self, schema: dict[str, Any], instance: Any) -> None:
        validator = Draft202012Validator(
            schema,
            registry=self._registry,
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        )
        errors = sorted(validator.iter_errors(instance), key=lambda error: list(error.path))
        if errors:
            first = errors[0]
            target = ".".join(str(part) for part in first.path) or None
            raise ToolInputValidationError(
                f"JSON Schema validation failed: {first.message}",
                target=target,
            )

    @staticmethod
    def _validate_schema_name(schema_name: str) -> None:
        if Path(schema_name).name != schema_name or not schema_name.endswith(".schema.json"):
            raise DescriptorValidationError(
                "Schema references must be catalog file names.",
                target="schema_ref",
            )

    @staticmethod
    def _load(schema_dir: Path) -> dict[str, dict[str, Any]]:
        schemas: dict[str, dict[str, Any]] = {}
        for schema_file in sorted(schema_dir.glob("*.schema.json")):
            value = json.loads(schema_file.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise DescriptorValidationError(
                    "A schema document must be a JSON object.",
                    target=schema_file.name,
                )
            Draft202012Validator.check_schema(value)
            schemas[schema_file.name] = value
        if not schemas:
            raise DescriptorValidationError(
                "No canonical schemas were found.",
                target="schema_dir",
            )
        return schemas
