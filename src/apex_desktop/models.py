"""Bounded, explicit desktop transport inputs (not replacements for Core DTOs)."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Empty(Input):
    pass


class CaseInput(Input):
    case_id: str = Field(min_length=1, max_length=255)


class CreateCase(Input):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=8192)
    investigator: str | None = Field(default=None, max_length=255)
    locale: str = Field(default="ko-KR", pattern=r"^[a-z]{2,3}(?:-[A-Z]{2})?$")
    timezone: str = Field(default="Asia/Seoul", max_length=100)


class EvidenceInput(CaseInput):
    evidence_id: str = Field(min_length=1, max_length=255)


class RegisterEvidence(CaseInput):
    source_path: str = Field(min_length=1, max_length=32767)
    display_name: str | None = Field(default=None, max_length=255)


class PageInput(CaseInput):
    evidence_id: str | None = None
    cursor: str | None = Field(default=None, max_length=16384)
    limit: int = Field(default=100, ge=1, le=1000)


class Files(PageInput):
    evidence_id: str
    parent_node_id: str | None = None
    directories_only: bool = False
    all_nodes: bool = False
    extension: str | None = Field(default=None, max_length=100)
    name_or_path: str | None = Field(default=None, max_length=4096)


class Artifacts(PageInput):
    artifact_type: str | None = None
    analyzer_id: str | None = None


class Search(PageInput):
    query_text: str = Field(min_length=1, max_length=4096)
    query_mode: Literal["TERM", "PHRASE", "PREFIX", "EXACT", "REGEX_METADATA"] = "TERM"


class View(CaseInput):
    resource_type: str = Field(max_length=100)
    resource_id: str = Field(min_length=1, max_length=255)
    view_mode: Literal["SIMPLE", "DETAILED", "RAW"] = "SIMPLE"


class Raw(View):
    offset: int = Field(default=0, ge=0)
    length: int = Field(default=4096, ge=1, le=1048576)


class ImageInspect(CaseInput):
    resource_type: Literal["FILE_SYSTEM_NODE", "ARTIFACT"]
    resource_id: str = Field(min_length=1, max_length=255)
    action: Literal["PREVIEW", "EXTRACT"] = "PREVIEW"
    channel: Literal["RGB", "R", "G", "B", "A"] = "RGB"
    bit: int | None = Field(default=None, ge=0, le=7)
    channels: str = Field(default="RGB", min_length=1, max_length=4, pattern=r"^[RGBA]+$")
    bit_order: Literal["MSB_FIRST", "LSB_FIRST"] = "MSB_FIRST"
    pixel_offset: int = Field(default=0, ge=0, lt=25_000_000)
    byte_limit: int = Field(default=512, ge=1, le=65536)
    max_dimension: int = Field(default=1536, ge=256, le=4096)


class ContextCreate(CaseInput):
    pass


class ContextUpdate(CaseInput):
    session_context_id: str
    expected_revision: int = Field(ge=1)
    patch: dict[str, Any]


class ContextGet(CaseInput):
    session_context_id: str


class Analysis(EvidenceInput):
    kind: Literal["FILES", "ARTIFACTS", "SEARCH", "TIMELINE", "HASH", "VERIFY"]
    profile_type: Literal["QUICK_TRIAGE", "FULL_ANALYSIS"] = "QUICK_TRIAGE"
    algorithm: Literal["SHA256", "SHA1", "MD5"] = "SHA256"


class CandidateReview(CaseInput):
    candidate_id: str
    review_status: Literal["ACCEPTED", "REJECTED", "CORRECTED"]
    correction_text: str | None = Field(default=None, max_length=100000)
    reason: str = Field(min_length=1, max_length=4096)


class CustodyAdd(EvidenceInput):
    action: str = Field(min_length=1, max_length=4096)
    reason: str = Field(min_length=1, max_length=4096)
    event_type: str = "ANALYZED"
    correction_of_event_id: str | None = None


class ReportCreate(CaseInput):
    title: str = Field(min_length=1, max_length=255)


class ReportGet(CaseInput):
    report_id: str


class ReportVersion(ReportGet):
    title: str = Field(min_length=1, max_length=255)
    executive_summary: str = Field(max_length=100000)
    sections: list[dict[str, Any]] = Field(min_length=1, max_length=100)
    limitations: list[str] = Field(default_factory=list, max_length=100)
    evidence_ids: list[str] = Field(default_factory=list, max_length=100)
    citations: list[dict[str, Any]] = Field(default_factory=list, max_length=1000)


class ReportAction(CaseInput):
    report_version_id: str
    action: Literal[
        "submit",
        "accept_section",
        "request_changes",
        "complete",
        "approve",
        "reject",
        "reopen",
        "revoke",
    ]
    reason: str = Field(min_length=1, max_length=4096)
    section_id: str | None = None
    expected_review_revision: int = Field(ge=0)
    expected_approval_revision: int | None = Field(default=None, ge=0)


class ReportExport(CaseInput):
    report_version_id: str
    format: Literal["HTML", "PDF"]
    filename: str = Field(min_length=1, max_length=200, pattern=r"^[^\\/:*?\"<>|]+$")
    stale_confirmed: bool = False


class Policy(CaseInput):
    expected_revision: int = Field(ge=0)
    ai_enabled: bool = False
    external_allowed: bool = False
    local_only: bool = True
    allowed_classifications: list[str] = Field(default=["PUBLIC", "INTERNAL"], max_length=10)
    secret_handling: str = "DENY"
    raw_allowed: bool = False
    redaction_required: bool = True
    projection_required: bool = True


class TaskAction(CaseInput):
    task_id: str
