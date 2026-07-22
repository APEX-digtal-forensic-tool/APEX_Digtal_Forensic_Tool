"""JSON Schema validation adapter for bundled schemas."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from apex_forensic.domain.errors import ValidationError


class JsonSchemaValidator:
    """Validates Phase 1 DTOs against ``schemas/v1`` contracts."""

    def __init__(self, schema_dir: Path) -> None:
        self._schema_dir = schema_dir
        self._schemas = self._load_schemas(schema_dir)
        resources = [
            (str(schema["$id"]), Resource.from_contents(schema))
            for schema in self._schemas.values()
            if isinstance(schema.get("$id"), str)
        ]
        self._registry = Registry().with_resources(resources)

    def validate(self, schema_name: str, instance: Any) -> None:
        """Validate an instance against a schema file."""

        schema = self._schemas.get(schema_name)
        if schema is None:
            raise ValidationError(f"Unknown schema: {schema_name}", target="schema_name")
        validator = Draft202012Validator(
            schema,
            registry=self._registry,
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        )
        errors = sorted(validator.iter_errors(instance), key=lambda error: list(error.path))
        if errors:
            first = errors[0]
            path = ".".join(str(part) for part in first.path)
            raise ValidationError(
                f"JSON Schema validation failed: {first.message}",
                target=path or schema_name,
            )

    def validate_case(self, instance: Any) -> None:
        """Validate a Case DTO."""

        self.validate("case.schema.json", instance)

    def validate_evidence(self, instance: Any) -> None:
        """Validate an Evidence DTO."""

        self.validate("evidence.schema.json", instance)

    def validate_job(self, instance: Any) -> None:
        """Validate a Job DTO."""

        self.validate("job.schema.json", instance)

    def validate_custody_event(self, instance: Any) -> None:
        """Validate a custody event DTO."""

        self.validate("chain-of-custody.schema.json", instance)

    @staticmethod
    def _load_schemas(schema_dir: Path) -> dict[str, dict[str, Any]]:
        schemas: dict[str, dict[str, Any]] = {}
        for schema_file in sorted(schema_dir.glob("*.json")):
            schemas[schema_file.name] = json.loads(schema_file.read_text(encoding="utf-8"))
        return schemas
