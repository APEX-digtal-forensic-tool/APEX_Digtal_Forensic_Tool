"""Evidence reader adapters."""

from apex_forensic.adapters.evidence.ewf import EwfEvidenceReader
from apex_forensic.adapters.evidence.partitions import PartitionParser
from apex_forensic.adapters.evidence.raw import RawImageReader
from apex_forensic.adapters.evidence.virtual_disk import VirtualDiskEvidenceReader

__all__ = [
    "EwfEvidenceReader",
    "PartitionParser",
    "RawImageReader",
    "VirtualDiskEvidenceReader",
]
