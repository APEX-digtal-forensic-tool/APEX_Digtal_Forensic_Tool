"""Public runtime configuration for optional AI provider injection."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from apex_forensic.adapters.ai import OpenAICompatibleConfig, OpenAICompatibleProvider
from apex_forensic.domain.errors import ValidationError
from apex_forensic.ports.ai_assistance import AiAssistanceProviderPort

_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]*$")


@dataclass(frozen=True, slots=True)
class AiProviderRuntimeConfig:
    """Secret-free configuration for an OpenAI-compatible provider endpoint."""

    provider_id: str
    base_url: str
    model_id: str
    api_key_env: str
    timeout: float = 30.0
    max_output: int = 4096
    temperature: float = 0.0
    request_policy: str = "SELECTED_CONTEXT_ONLY"

    def validate(self) -> AiProviderRuntimeConfig:
        parsed = urlparse(self.base_url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
            raise ValidationError(
                "AI provider base URL must be an HTTP or HTTPS URL.",
                target="base_url",
            )
        if not self.provider_id or len(self.provider_id) > 256:
            raise ValidationError("Invalid AI provider id.", target="provider_id")
        if not self.model_id or len(self.model_id) > 256:
            raise ValidationError("Invalid AI provider model id.", target="model_id")
        if not _ENV_NAME.fullmatch(self.api_key_env) or len(self.api_key_env) > 128:
            raise ValidationError(
                "AI provider credentials must be referenced by an environment variable name.",
                target="api_key_env",
            )
        if not 0 < self.timeout <= 600:
            raise ValidationError("Invalid AI provider timeout.", target="timeout")
        if not 1 <= self.max_output <= 200_000:
            raise ValidationError("Invalid AI provider output limit.", target="max_output")
        if not 0 <= self.temperature <= 2:
            raise ValidationError("Invalid AI provider temperature.", target="temperature")
        if self.request_policy not in {
            "SELECTED_CONTEXT_ONLY",
            "NO_RAW_EVIDENCE",
            "CUSTOM",
        }:
            raise ValidationError("Invalid AI provider request policy.", target="request_policy")
        return self


def build_ai_provider(config: AiProviderRuntimeConfig) -> AiAssistanceProviderPort:
    """Construct the optional adapter behind the public Core configuration boundary."""

    validated = config.validate()
    return OpenAICompatibleProvider(
        OpenAICompatibleConfig(
            provider_id=validated.provider_id,
            base_url=validated.base_url,
            model=validated.model_id,
            api_key_env=validated.api_key_env,
            timeout=validated.timeout,
            max_output=validated.max_output,
            temperature=validated.temperature,
            request_policy=validated.request_policy,
        )
    )


__all__ = ["AiProviderRuntimeConfig", "build_ai_provider"]
