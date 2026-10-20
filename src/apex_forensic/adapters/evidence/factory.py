"""One read-only logical disk stream for every supported evidence container."""

from apex_forensic.adapters.evidence.container import ContainerImageReader
from apex_forensic.adapters.evidence.identity import check_source_identity
from apex_forensic.adapters.evidence.raw import RawImageReader
from apex_forensic.domain.enums import EvidenceFormat
from apex_forensic.domain.errors import UnsupportedCapabilityError
from apex_forensic.domain.models import Evidence
from apex_forensic.ports.evidence_reader import EvidenceReader


def evidence_reader(evidence: Evidence) -> EvidenceReader:
    if evidence.evidence_type is not EvidenceFormat.DIRECTORY:
        check_source_identity(evidence)
    if evidence.evidence_type in {EvidenceFormat.RAW, EvidenceFormat.DD, EvidenceFormat.IMG}:
        return RawImageReader(evidence.source_path, evidence_format=evidence.evidence_type)
    if evidence.evidence_type in {EvidenceFormat.E01, EvidenceFormat.VHD, EvidenceFormat.VHDX}:
        return ContainerImageReader(evidence.source_path)
    raise UnsupportedCapabilityError(
        "Directory evidence has no logical disk stream.", required_capability="DISK_IMAGE_READER"
    )
