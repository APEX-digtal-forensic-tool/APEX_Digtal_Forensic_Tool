"""Desktop AI connection using Core snapshots, policy checks and validated results."""

import json
import os
from typing import Any

from apex_forensic.adapters.ai.openai_compatible import (
    OpenAICompatibleConfig,
    OpenAICompatibleProvider,
)
from apex_forensic.config import AiProviderRuntimeConfig, ServiceBundle
from apex_forensic.domain.enums import (
    AiDataForm,
    AiDataSourceType,
    AiDestinationCategory,
    AiEgressDecision,
    DataClassification,
)
from apex_forensic.domain.errors import ApexError, ValidationError
from apex_forensic.domain.models import AiAssistanceRequest
from apex_forensic.domain.models.ai_governance import AiEgressData
from apex_forensic.domain.services.ai_projection import ai_data_reference

from .ai_content import excerpt


def provider_config() -> OpenAICompatibleConfig | None:
    raw = os.environ.get("APEX_DESKTOP_AI_CONFIG")
    if not raw:
        return None
    try:
        config = AiProviderRuntimeConfig(**json.loads(raw)).validate()
    except (TypeError, ValueError) as error:
        raise ValidationError("Invalid desktop AI configuration.") from error
    return OpenAICompatibleConfig(
        provider_id=config.provider_id,
        base_url=config.base_url,
        model=config.model_id,
        api_key_env=config.api_key_env,
        timeout=config.timeout,
        max_output=config.max_output,
        temperature=config.temperature,
        request_policy=config.request_policy,
    )


def runtime(services: ServiceBundle) -> dict[str, Any]:
    config = provider_config()
    result = services.ai.capabilities()
    if config is not None:
        result["runtime_capability"] = (
            OpenAICompatibleProvider(config).capabilities().to_schema_dict()
        )
        if result["runtime_capability"]["is_available"]:
            result["engine_capabilities"].append("RUNTIME_LLM_PROVIDER")
            result["unavailable_capabilities"].remove("RUNTIME_LLM_PROVIDER")
    return result


class GovernedDesktopProvider(OpenAICompatibleProvider):
    """Send exactly the policy-approved projection or explicitly reviewed excerpt.

    Both modes retain local citations and classify generated results as AI inference.
    """

    def __init__(
        self,
        config: OpenAICompatibleConfig,
        services: ServiceBundle,
        content: dict[str, Any] | None = None,
    ) -> None:
        self.services = services
        self.audit: Any = None
        self.projection: Any = None
        self.content = content
        super().__init__(config, request_payload=self._approved_payload)

    def _approved_payload(self, request: AiAssistanceRequest) -> dict[str, Any]:
        if self.content is not None:
            self.audit = self.services.ai_egress.evaluate(
                AiEgressData(
                    source=ai_data_reference(request),
                    classification=DataClassification.SECRET,
                    contains_secrets=False,
                    data_form=AiDataForm.REDACTED,
                    content_fingerprint=self.content["fingerprint"],
                ),
                destination=AiDestinationCategory.EXTERNAL,
            )
            if self.audit.result.decision is not AiEgressDecision.ALLOW:
                raise ApexError("AI_EGRESS_DENIED", "error.ai_egress_denied")
            return dict(self.content["payload"])
        self.projection = self.services.ai_projections.create(
            case_id=request.case_id,
            source_id=request.assistance_request_id,
            source_type=AiDataSourceType.AI_ASSISTANCE_REQUEST,
            classification=DataClassification.SENSITIVE,
            # Free text can contain unknown secrets. Projection removes that text,
            # while the original SECRET classification remains unchanged.
            contains_secrets=True,
        )
        # Conservatively treat every configured endpoint as external, including
        # localhost proxies that may forward requests to an external model.
        self.audit = self.services.ai_egress.evaluate_projection(
            self.projection,
            destination=AiDestinationCategory.EXTERNAL,
        )
        if self.audit.result.decision is not AiEgressDecision.ALLOW:
            raise ApexError("AI_EGRESS_DENIED", "error.ai_egress_denied")
        return dict(self.projection.to_schema_dict())

    def generate_scope_summary(self, request: AiAssistanceRequest, **kwargs: Any) -> dict[str, Any]:
        result = super().generate_scope_summary(request, **kwargs)
        result["citations"] = request.citations
        result["scope_context_id"] = request.scope_context_ids[0]
        result["referenced_resource_ids"] = []
        result.setdefault("warnings", []).append(
            {
                "code": "AI_REVIEWED_EXCERPT" if self.content else "AI_STRUCTURAL_PROJECTION_ONLY",
                "developer_message": (
                    "A locally reviewed, bounded excerpt was analyzed; this is AI inference."
                    if self.content
                    else "Only structural policy-approved fields were sent. "
                    "Local citations identify the selected sources, "
                    "not evidence text read by the model."
                ),
            }
        )
        return result


def analyze(
    services: ServiceBundle,
    *,
    case_id: str,
    resource_type: str,
    resource_id: str,
    actor: str,
    mode: str = "STRUCTURE",
    reviewed_fingerprint: str | None = None,
    prepare_only: bool = False,
) -> dict[str, Any]:
    resources = {
        "FILE_SYSTEM_NODE",
        "ARTIFACT",
        "TIMELINE_EVENT",
        "SEARCH_RESULT",
        "MACHINE_CANDIDATE",
    }
    if resource_type not in resources:
        raise ValidationError("Select a file or analysis result for AI assistance.")
    snapshot = services.contexts.build_from_selection(
        case_id=case_id,
        actor_id=actor,
        purpose="AI_REQUEST",
        resources={resource_type: [resource_id]},
    )
    content = (
        excerpt(services, case_id=case_id, resource_type=resource_type, resource_id=resource_id)
        if mode == "CONTENT"
        else None
    )
    request = services.ai.create_request_from_context_snapshot(
        case_id=case_id,
        context_snapshot_id=snapshot.context_snapshot_id,
        requested_operations=["SUMMARIZE_SCOPE"],
        payload_fingerprint=content["fingerprint"] if content else None,
    )
    response: dict[str, Any] = {"request": request.to_schema_dict(), "execution": None}
    if content is not None:
        response.update(preview=content, mode=mode)
        if prepare_only or reviewed_fingerprint != content["fingerprint"]:
            return {**response, "status": "REVIEW_REQUIRED"}
    elif mode != "STRUCTURE":
        raise ValidationError("Unknown AI analysis mode.")
    elif prepare_only:
        return {**response, "status": "PREPARED"}
    config = provider_config()
    if config is None:
        return {**response, "status": "CONFIGURATION_REQUIRED"}
    provider = GovernedDesktopProvider(config, services, content=content)
    try:
        execution = services.ai.execute_request(
            assistance_request_id=request.assistance_request_id,
            operation="SUMMARIZE_SCOPE",
            provider=provider,
        )
    except ApexError as error:
        if error.code != "AI_EGRESS_DENIED":
            raise
        return {**response, "status": "POLICY_DENIED", "audit": provider.audit.to_schema_dict()}
    return {
        **response,
        "status": "COMPLETED",
        "execution": execution,
        # Core may replay a saved result without calling this provider. In that
        # case there was no new egress decision or outgoing projection.
        "audit": provider.audit.to_schema_dict() if provider.audit is not None else None,
        "projection": (
            provider.projection.to_schema_dict() if provider.projection is not None else None
        ),
    }
