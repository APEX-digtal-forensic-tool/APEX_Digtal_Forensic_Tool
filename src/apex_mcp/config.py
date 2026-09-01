"""Configuration boundary for the APEX MCP process."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from apex_forensic.config import AiProviderRuntimeConfig
from apex_forensic.domain.errors import ValidationError
from apex_mcp.errors import McpConfigurationError


@dataclass(frozen=True, slots=True)
class McpConfig:
    """Explicit startup configuration with no implicit evidence path access."""

    database_path: Path
    schema_dir: Path
    allowed_tools: frozenset[str] = field(default_factory=frozenset)
    initialize_database: bool = False
    log_level: str = "INFO"
    ai_provider: AiProviderRuntimeConfig | None = None

    def validate(self) -> McpConfig:
        database_path = self.database_path.expanduser().resolve()
        schema_dir = self.schema_dir.expanduser().resolve()
        if not database_path.exists() and not self.initialize_database:
            raise McpConfigurationError(
                "The configured APEX database does not exist.",
                target="database_path",
            )
        if database_path.exists() and not database_path.is_file():
            raise McpConfigurationError(
                "The configured APEX database is not a regular file.",
                target="database_path",
            )
        if not schema_dir.is_dir():
            raise McpConfigurationError(
                "The configured schema directory does not exist.",
                target="schema_dir",
            )
        if self.log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise McpConfigurationError("Unsupported log level.", target="log_level")
        if self.ai_provider is not None:
            try:
                self.ai_provider.validate()
            except ValidationError as error:
                raise McpConfigurationError(
                    "Invalid AI provider configuration.",
                    target=getattr(error, "target", "ai_provider"),
                ) from error
        return McpConfig(
            database_path=database_path,
            schema_dir=schema_dir,
            allowed_tools=frozenset(self.allowed_tools),
            initialize_database=self.initialize_database,
            log_level=self.log_level,
            ai_provider=self.ai_provider,
        )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> McpConfig:
        values = os.environ if env is None else env
        raw_database = values.get("APEX_MCP_DATABASE")
        if not raw_database:
            raise McpConfigurationError(
                "APEX_MCP_DATABASE must identify an APEX case database.",
                target="APEX_MCP_DATABASE",
            )
        raw_schema_dir = values.get("APEX_MCP_SCHEMA_DIR")
        if not raw_schema_dir:
            raise McpConfigurationError(
                "APEX_MCP_SCHEMA_DIR must identify the canonical schemas/v1 directory.",
                target="APEX_MCP_SCHEMA_DIR",
            )
        allowed_tools = frozenset(
            item.strip()
            for item in values.get("APEX_MCP_ALLOWED_TOOLS", "").split(",")
            if item.strip()
        )
        initialize = values.get("APEX_MCP_INITIALIZE_DATABASE", "false").lower() == "true"
        ai_values = {
            "provider_id": values.get("APEX_MCP_AI_PROVIDER_ID"),
            "base_url": values.get("APEX_MCP_AI_BASE_URL"),
            "model_id": values.get("APEX_MCP_AI_MODEL"),
            "api_key_env": values.get("APEX_MCP_AI_API_KEY_ENV"),
        }
        configured_ai_values = [value for value in ai_values.values() if value]
        if configured_ai_values and len(configured_ai_values) != len(ai_values):
            raise McpConfigurationError(
                "All APEX_MCP_AI_* provider fields must be configured together.",
                target="APEX_MCP_AI_PROVIDER_ID",
            )
        ai_provider = None
        if configured_ai_values:
            try:
                ai_provider = AiProviderRuntimeConfig(
                    provider_id=str(ai_values["provider_id"]),
                    base_url=str(ai_values["base_url"]),
                    model_id=str(ai_values["model_id"]),
                    api_key_env=str(ai_values["api_key_env"]),
                    timeout=float(values.get("APEX_MCP_AI_TIMEOUT", "30")),
                    max_output=int(values.get("APEX_MCP_AI_MAX_OUTPUT", "4096")),
                    temperature=float(values.get("APEX_MCP_AI_TEMPERATURE", "0")),
                    request_policy=values.get(
                        "APEX_MCP_AI_REQUEST_POLICY", "SELECTED_CONTEXT_ONLY"
                    ),
                )
            except ValueError as error:
                raise McpConfigurationError(
                    "AI provider numeric configuration is invalid.",
                    target="APEX_MCP_AI_TIMEOUT",
                ) from error
        return cls(
            database_path=Path(raw_database),
            schema_dir=Path(raw_schema_dir),
            allowed_tools=allowed_tools,
            initialize_database=initialize,
            log_level=values.get("APEX_MCP_LOG_LEVEL", "INFO").upper(),
            ai_provider=ai_provider,
        ).validate()
