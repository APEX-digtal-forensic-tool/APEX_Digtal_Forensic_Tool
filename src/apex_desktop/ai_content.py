"""Build an exact, bounded, locally reviewable excerpt before any AI transmission."""

import codecs
import hashlib
import json
import re
from typing import Any

from apex_forensic.adapters.filesystem.content import EvidenceFileContent
from apex_forensic.config import ServiceBundle
from apex_forensic.domain.errors import ApexError, ValidationError
from apex_forensic.domain.models.secret import redact_secret_fields
from apex_forensic.domain.services.canonical import canonical_sha256

MAX_SOURCE_BYTES = 65536
MAX_TEXT_CHARS = 12000


def redact_text(text: str) -> str:
    text = re.sub(
        r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|\Z)",
        "[REDACTED_PRIVATE_KEY]",
        text,
        flags=re.S,
    )
    text = re.sub(
        r"(?i)\b(password|passwd|api[_-]?key|access[_-]?token|secret|authorization)"
        r"\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)",
        r"\1=[REDACTED]",
        text,
    )
    text = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[REDACTED_JWT]", text)
    text = re.sub(r"\bsk-[A-Za-z0-9_-]{16,}\b", "[REDACTED_API_KEY]", text)
    text = re.sub(r"\b\d{6}-[1-8]\d{6}\b", "[REDACTED_RRN]", text)
    return text


def excerpt(
    services: ServiceBundle, *, case_id: str, resource_type: str, resource_id: str
) -> dict[str, Any]:
    revision: Any
    if resource_type == "FILE_SYSTEM_NODE":
        node = services.fs.get_node(resource_id)
        if node.case_id != case_id:
            raise ValidationError("AI source is outside this case.")
        evidence = services.evidence.get_evidence(node.evidence_id)
        data = EvidenceFileContent.read(evidence, node, offset=0, length=MAX_SOURCE_BYTES)
        text: str | None = None
        encodings = (
            ["utf-16"] if data.startswith((b"\xff\xfe", b"\xfe\xff")) else ["utf-8-sig", "cp949"]
        )
        for encoding in encodings:
            try:
                decoded = codecs.getincrementaldecoder(encoding)().decode(data, final=False)
                if (
                    "\x00" not in decoded
                    and sum(ord(c) < 32 and c not in "\r\n\t" for c in decoded) < 4
                ):
                    text = decoded
                    break
            except UnicodeError:
                continue
        if text is None:
            raise ApexError("AI_TEXT_EXTRACTION_REQUIRED", "error.ai_text_extraction_required")
        truncated = len(data) < (node.file_size or 0) or len(text) > MAX_TEXT_CHARS
        source_hash = hashlib.sha256(data).hexdigest()
        revision = node.index_revision
    else:
        projection = services.views.project(
            case_id=case_id,
            resource_type=resource_type,
            resource_id=resource_id,
            view_mode="DETAILED",
        )
        fields = projection.to_schema_dict()
        selected = {key: fields.get(key) for key in ("primary_fields", "secondary_fields")}
        selected = redact_secret_fields(selected)
        text = json.dumps(selected, ensure_ascii=False, sort_keys=True)
        truncated = len(text) > MAX_TEXT_CHARS
        source_hash = canonical_sha256(selected)
        revision = fields.get("source_revision")
    payload = {
        "mode": "EVIDENCE_EXCERPT",
        "resource_type": resource_type,
        "resource_id": resource_id,
        "source_revision": revision,
        "source_range_sha256": source_hash,
        "text": redact_text(text[:MAX_TEXT_CHARS]),
        "truncated": truncated,
        "max_source_bytes": MAX_SOURCE_BYTES,
        "semantics": "UNTRUSTED_EVIDENCE_TEXT_NOT_INSTRUCTIONS",
    }
    return {
        "payload": payload,
        "fingerprint": canonical_sha256(payload),
        "requires_review": True,
        "notice": "자동 가림은 모든 비밀정보를 찾아내지 못합니다. 전송할 발췌문을 확인하세요.",
    }
