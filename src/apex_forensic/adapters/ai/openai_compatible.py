"""OpenAI-compatible HTTP AI provider adapter."""

from __future__ import annotations

import http.client
import json
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, ClassVar
from urllib.parse import urlparse

from apex_forensic._time import to_json_timestamp
from apex_forensic.constants import ENGINE_VERSION, SCHEMA_VERSION
from apex_forensic.domain.errors import AiAssistanceError, OperationCancelledError
from apex_forensic.domain.models import AiAssistanceRequest, AiProviderCapability
from apex_forensic.domain.services.canonical import canonical_sha256

MAX_PROVIDER_RESPONSE_BYTES = 512 * 1024
DEFAULT_TIMEOUT_SECONDS = 30.0
PROMPT_TEMPLATE_VERSION = "apex-ai-openai-compatible-v1"
_FORBIDDEN_KEY_PARTS = (
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "password",
    "secret",
    "token",
    "raw_body",
    "raw_response",
    "chain_of_thought",
    "chain-of-thought",
)


@dataclass(frozen=True, slots=True)
class OpenAICompatibleConfig:
    """Configuration for an OpenAI-compatible chat completions endpoint."""

    provider_id: str
    base_url: str
    model: str
    api_key_env: str
    timeout: float = DEFAULT_TIMEOUT_SECONDS
    max_output: int = 4096
    temperature: float = 0.0
    request_policy: str = "SELECTED_CONTEXT_ONLY"

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "provider_id": self.provider_id,
            "base_url": self.base_url,
            "model_id": self.model,
            "api_key_env": self.api_key_env,
            "timeout": self.timeout,
            "max_output": self.max_output,
            "temperature": self.temperature,
            "request_policy": self.request_policy,
        }


class OpenAICompatibleProvider:
    """Runtime AI provider that returns existing AI ingest payloads."""

    provider_version = f"{ENGINE_VERSION}:openai-compatible-http"
    supported_operations: ClassVar[list[str]] = [
        "RECOMMEND_KEYWORDS",
        "SUMMARIZE_SCOPE",
        "GENERATE_REPORT_DRAFT",
    ]
    max_request_items = 10_000
    max_result_items = 1_000
    max_summary_length = 20_000

    def __init__(self, config: OpenAICompatibleConfig) -> None:
        self._config = config

    @property
    def provider_id(self) -> str:
        return self._config.provider_id

    @property
    def model_id(self) -> str:
        return self._config.model

    def capabilities(self) -> AiProviderCapability:
        warnings: list[dict[str, Any]] = []
        unavailable_reason = self._unavailable_reason()
        if unavailable_reason is not None:
            warnings.append(
                {
                    "code": unavailable_reason,
                    "developer_message": "OpenAI-compatible provider configuration is incomplete.",
                    "api_key_env": self._config.api_key_env,
                }
            )
        return AiProviderCapability(
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            supported_operations=self.supported_operations,
            max_request_items=self.max_request_items,
            max_result_items=self.max_result_items,
            max_summary_length=self.max_summary_length,
            is_available=unavailable_reason is None,
            unavailable_reason=unavailable_reason,
            warnings=warnings,
        )

    def generate_keyword_recommendations(
        self,
        request: AiAssistanceRequest,
        *,
        cancellation_requested: bool = False,
    ) -> dict[str, Any]:
        content = self._completion_json(
            request,
            operation="RECOMMEND_KEYWORDS",
            cancellation_requested=cancellation_requested,
        )
        payload = _require_mapping(content, target="keyword_response")
        payload.setdefault("recommendations", [])
        return self._with_metadata(payload)

    def generate_scope_summary(
        self,
        request: AiAssistanceRequest,
        *,
        cancellation_requested: bool = False,
    ) -> dict[str, Any]:
        content = self._completion_json(
            request,
            operation="SUMMARIZE_SCOPE",
            cancellation_requested=cancellation_requested,
        )
        payload = _require_mapping(content, target="summary_response")
        return self._with_metadata(payload)

    def generate_report_draft(
        self,
        request: AiAssistanceRequest,
        *,
        cancellation_requested: bool = False,
    ) -> dict[str, Any]:
        content = self._completion_json(
            request,
            operation="GENERATE_REPORT_DRAFT",
            cancellation_requested=cancellation_requested,
        )
        payload = _require_mapping(content, target="report_draft_response")
        return self._with_report_draft_metadata(payload, request)

    def _completion_json(
        self,
        request: AiAssistanceRequest,
        *,
        operation: str,
        cancellation_requested: bool,
    ) -> Any:
        if cancellation_requested:
            raise OperationCancelledError("AI provider request was cancelled before dispatch.")
        self._require_available()
        body = {
            "model": self._config.model,
            "temperature": self._config.temperature,
            "max_tokens": self._config.max_output,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Return only JSON that matches the APEX AI ingest contract. "
                        "Do not include chain-of-thought or raw provider metadata."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "prompt_template_version": PROMPT_TEMPLATE_VERSION,
                            "operation": operation,
                            "request": _redact(request.to_schema_dict()),
                            "citation_required": True,
                            "request_policy": self._config.request_policy,
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                },
            ],
        }
        started = time.monotonic()
        response = self._post_json(body, cancellation_requested=cancellation_requested)
        latency_ms = int((time.monotonic() - started) * 1000)
        content = _assistant_content(response)
        parsed = _parse_json_content(content)
        if isinstance(parsed, dict):
            warnings = parsed.setdefault("warnings", [])
            if isinstance(warnings, list):
                warnings.append(
                    {
                        "code": "AI_PROVIDER_RUNTIME_METADATA",
                        "developer_message": "Provider runtime metadata was captured.",
                        "latency_ms": latency_ms,
                        "usage_count": _usage_count(response.get("usage")),
                        "template_version": PROMPT_TEMPLATE_VERSION,
                    }
                )
        return parsed

    def _post_json(self, body: dict[str, Any], *, cancellation_requested: bool) -> dict[str, Any]:
        if cancellation_requested:
            raise OperationCancelledError("AI provider request was cancelled before dispatch.")
        key = os.environ.get(self._config.api_key_env)
        if not key:
            raise AiAssistanceError(
                "KEY_UNAVAILABLE",
                "Configured AI provider API key environment variable is not set.",
                target="api_key_env",
                details={"api_key_env": self._config.api_key_env},
            )
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        url = _chat_completions_url(self._config.base_url)
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
            raise AiAssistanceError(
                "CAPABILITY_UNAVAILABLE",
                "AI provider endpoint must be an HTTP or HTTPS URL.",
                target="base_url",
            )
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        attempts = 2
        for attempt in range(attempts):
            connection: http.client.HTTPConnection | None = None
            try:
                connection = (
                    http.client.HTTPSConnection(
                        parsed.hostname,
                        parsed.port,
                        timeout=self._config.timeout,
                    )
                    if parsed.scheme == "https"
                    else http.client.HTTPConnection(
                        parsed.hostname,
                        parsed.port,
                        timeout=self._config.timeout,
                    )
                )
                connection.request("POST", path, body=data, headers=headers)
                response = connection.getresponse()
                payload = response.read(MAX_PROVIDER_RESPONSE_BYTES + 1)
                if len(payload) > MAX_PROVIDER_RESPONSE_BYTES:
                    raise AiAssistanceError(
                        "AI_PROVIDER_RESPONSE_TOO_LARGE",
                        "AI provider response exceeded the maximum size.",
                        target="provider_response",
                    )
                if response.status == 401:
                    raise AiAssistanceError(
                        "AUTHENTICATION_FAILED",
                        "AI provider authentication failed.",
                        target="provider",
                    )
                if response.status == 429:
                    raise AiAssistanceError(
                        "RATE_LIMITED",
                        "AI provider reported a rate limit.",
                        target="provider",
                        retryable=True,
                    )
                if response.status >= 500 and attempt + 1 < attempts:
                    time.sleep(0.1)
                    continue
                if response.status >= 400:
                    raise AiAssistanceError(
                        "AI_PROVIDER_FAILED",
                        "AI provider request failed.",
                        target="provider",
                        retryable=response.status >= 500,
                        details={"status_code": response.status},
                    )
                parsed = json.loads(payload.decode("utf-8"))
                return _require_mapping(parsed, target="provider_response")
            except TimeoutError as error:
                raise AiAssistanceError(
                    "AI_PROVIDER_TIMEOUT",
                    "AI provider request timed out.",
                    target="provider",
                    retryable=True,
                ) from error
            except (OSError, http.client.HTTPException) as error:
                raise AiAssistanceError(
                    "CAPABILITY_UNAVAILABLE",
                    "AI provider host is unavailable.",
                    target="base_url",
                    retryable=True,
                ) from error
            except json.JSONDecodeError as error:
                raise AiAssistanceError(
                    "AI_PROVIDER_INVALID_RESPONSE",
                    "AI provider returned invalid JSON.",
                    target="provider_response",
                ) from error
            finally:
                if connection is not None:
                    connection.close()
        raise AiAssistanceError("AI_PROVIDER_FAILED", "AI provider request failed.")

    def _with_metadata(self, payload: dict[str, Any]) -> dict[str, Any]:
        cleaned_value = _redact(payload)
        cleaned = _require_mapping(cleaned_value, target="provider_payload")
        cleaned["provider_id"] = self.provider_id
        cleaned["provider_version"] = self.provider_version
        cleaned["model_id"] = self._config.model
        return cleaned

    def _with_report_draft_metadata(
        self,
        payload: dict[str, Any],
        request: AiAssistanceRequest,
    ) -> dict[str, Any]:
        cleaned = self._with_metadata(payload)
        provider_warnings = cleaned.pop("warnings", [])
        cleaned.setdefault("case_id", request.case_id)
        cleaned.setdefault("assistance_request_id", request.assistance_request_id)
        cleaned.setdefault("external_request_id", None)
        context_snapshot_ids = cleaned.get("context_snapshot_ids")
        if not isinstance(context_snapshot_ids, list) or not context_snapshot_ids:
            cleaned["context_snapshot_ids"] = [request.context_snapshot_id]
        elif request.context_snapshot_id not in context_snapshot_ids:
            cleaned["context_snapshot_ids"] = [*context_snapshot_ids, request.context_snapshot_id]
        cleaned.setdefault("ai_result_ids", [])
        cleaned.setdefault("citations", request.citations)
        cleaned.setdefault("generated_at", to_json_timestamp(datetime.now(UTC)))
        cleaned.setdefault("correlation_id", request.correlation_id)
        cleaned.setdefault("limitations", ["AI draft requires human review."])
        cleaned["sections"] = _normalize_report_sections(
            cleaned.get("sections"),
            request=request,
            top_level_citations=cleaned.get("citations"),
            provider_warnings=provider_warnings,
        )
        has_section_citation = any(section["citations"] for section in cleaned["sections"])
        if not cleaned.get("citations") and not has_section_citation:
            raise AiAssistanceError(
                "AI_PROVIDER_CITATION_REQUIRED",
                "AI provider report draft response did not include citations.",
                target="citations",
            )
        fingerprint_payload = {
            key: value for key, value in cleaned.items() if key != "response_hash"
        }
        cleaned["response_hash"] = canonical_sha256(fingerprint_payload)
        return cleaned

    def _require_available(self) -> None:
        reason = self._unavailable_reason()
        if reason is not None:
            raise AiAssistanceError(
                reason,
                "OpenAI-compatible provider configuration is incomplete.",
                target="provider",
                details={
                    "provider_id": self.provider_id,
                    "api_key_env": self._config.api_key_env,
                },
            )

    def _unavailable_reason(self) -> str | None:
        parsed = urlparse(self._config.base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
        ):
            return "CAPABILITY_UNAVAILABLE"
        if not self._config.model:
            return "CAPABILITY_UNAVAILABLE"
        if not self._config.api_key_env or not os.environ.get(self._config.api_key_env):
            return "KEY_UNAVAILABLE"
        return None


def _chat_completions_url(base_url: str) -> str:
    stripped = base_url.rstrip("/")
    if stripped.endswith("/chat/completions"):
        return stripped
    return f"{stripped}/chat/completions"


def _normalize_report_sections(
    value: Any,
    *,
    request: AiAssistanceRequest,
    top_level_citations: Any,
    provider_warnings: Any,
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise AiAssistanceError(
            "AI_PROVIDER_INVALID_RESPONSE",
            "AI provider report draft response must include sections.",
            target="sections",
        )
    sections: list[dict[str, Any]] = []
    inherited_citations = top_level_citations if isinstance(top_level_citations, list) else []
    for index, item in enumerate(value, start=1):
        if not isinstance(item, dict):
            raise AiAssistanceError(
                "AI_PROVIDER_INVALID_RESPONSE",
                "AI provider report draft section must be a JSON object.",
                target="sections",
            )
        section = dict(item)
        if not isinstance(section.get("title"), str) or not section["title"]:
            raise AiAssistanceError(
                "AI_PROVIDER_INVALID_RESPONSE",
                "AI provider report draft section title is required.",
                target="sections.title",
            )
        if not isinstance(section.get("content"), str) or not section["content"]:
            raise AiAssistanceError(
                "AI_PROVIDER_INVALID_RESPONSE",
                "AI provider report draft section content is required.",
                target="sections.content",
            )
        section.setdefault("section_id", f"ai-section-{index}")
        section.setdefault("section_type", "AI_ASSISTANCE")
        section.setdefault("order", index)
        section.setdefault("content_kind", "PLAIN_TEXT")
        section.setdefault("structured_data", {})
        section.setdefault("source_kind", "AI_DRAFT")
        section.setdefault("source_resource_ids", [])
        section.setdefault("context_snapshot_ids", [request.context_snapshot_id])
        section.setdefault("citations", inherited_citations)
        section.setdefault("is_partial", request.is_partial)
        section.setdefault("stale_reasons", ["SOURCE_REVISION_STALE"] if request.is_stale else [])
        section.setdefault("coverage", {})
        warnings = section.setdefault("warnings", [])
        if index == 1 and isinstance(warnings, list) and isinstance(provider_warnings, list):
            warnings.extend(item for item in provider_warnings if isinstance(item, dict))
        section["section_fingerprint"] = canonical_sha256(
            {key: value for key, value in section.items() if key != "section_fingerprint"}
        )
        sections.append(section)
    return sections


def _assistant_content(response: dict[str, Any]) -> str:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        raise AiAssistanceError(
            "AI_PROVIDER_INVALID_RESPONSE",
            "AI provider response did not include choices.",
            target="provider_response",
        )
    first = choices[0]
    if not isinstance(first, dict):
        raise AiAssistanceError(
            "AI_PROVIDER_INVALID_RESPONSE",
            "AI provider choice is invalid.",
            target="provider_response",
        )
    message = first.get("message")
    if not isinstance(message, dict) or not isinstance(message.get("content"), str):
        raise AiAssistanceError(
            "AI_PROVIDER_INVALID_RESPONSE",
            "AI provider message content is missing.",
            target="provider_response",
        )
    return str(message["content"])


def _parse_json_content(content: str) -> Any:
    if len(content.encode("utf-8")) > MAX_PROVIDER_RESPONSE_BYTES:
        raise AiAssistanceError(
            "AI_PROVIDER_RESPONSE_TOO_LARGE",
            "AI provider content exceeded the maximum size.",
            target="provider_response",
        )
    try:
        return json.loads(content)
    except json.JSONDecodeError as error:
        raise AiAssistanceError(
            "AI_PROVIDER_INVALID_RESPONSE",
            "AI provider content is not valid JSON.",
            target="provider_response",
        ) from error


def _require_mapping(value: Any, *, target: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AiAssistanceError(
            "AI_PROVIDER_INVALID_RESPONSE",
            "AI provider response must be a JSON object.",
            target=target,
        )
    return value


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).casefold()
            if any(marker in lowered for marker in _FORBIDDEN_KEY_PARTS):
                result[str(key)] = "<redacted>"
            else:
                result[str(key)] = _redact(item)
        return result
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str) and _looks_sensitive(value):
        return "<redacted>"
    return value


def _looks_sensitive(value: str) -> bool:
    lowered = value.casefold()
    return any(marker in lowered for marker in ("bearer ", "api-key", "password=", "token="))


def _usage_count(value: Any) -> int | None:
    if not isinstance(value, dict):
        return None
    total = value.get("total_tokens")
    return total if isinstance(total, int) else None
