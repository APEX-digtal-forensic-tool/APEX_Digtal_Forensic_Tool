"""Apply one persisted-source boundary to TSK, ranges, recovery and carving."""

from copy import deepcopy
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from apex_forensic.adapters.evidence.container import ContainerImageReader
from apex_forensic.adapters.evidence.partitions import PartitionParser
from apex_forensic.adapters.evidence.raw import RawImageReader
from apex_forensic.adapters.evidence.source_identity import (
    SOURCE_IDENTITY_KEY,
    assert_source_identity,
)
from apex_forensic.domain.models import Evidence, EvidenceVolume
from apex_forensic.ports.evidence_reader import (
    EvidenceProbeResult,
    EvidenceReader,
    EvidenceReaderCapabilityStatement,
)


class GuardedEvidenceReader:
    """Check metadata before/after every range; never hash an image per small read."""

    def __init__(self, reader: EvidenceReader, evidence: Evidence) -> None:
        self._reader = reader
        self._path = evidence.source_path
        self._format = evidence.evidence_type
        self._identity = deepcopy(evidence.metadata.get(SOURCE_IDENTITY_KEY))
        self.reader_id = reader.reader_id
        self.reader_version = reader.reader_version

    @classmethod
    def probe(cls, path: Path) -> EvidenceProbeResult:
        if path.suffix.lower() in {".e01", ".vhd", ".vhdx"}:
            return ContainerImageReader.probe(path)
        return RawImageReader.probe(path)

    def check_source(self) -> None:
        assert_source_identity(self._path, self._format, self._identity)

    def open_readonly(self) -> Self:
        self.check_source()
        try:
            self._reader.open_readonly()
            self.check_source()
        except BaseException:
            self._reader.close()
            raise
        return self

    @property
    def size(self) -> int:
        return self._reader.size

    @property
    def sector_size(self) -> int:
        return self._reader.sector_size

    @property
    def source_fingerprint(self) -> dict[str, Any]:
        self.check_source()
        result = self._reader.source_fingerprint
        self.check_source()
        return result

    def capabilities(self) -> tuple[EvidenceReaderCapabilityStatement, ...]:
        return self._reader.capabilities()

    def volumes(self, *, case_id: str, evidence_id: str) -> list[EvidenceVolume]:
        self.check_source()
        result = PartitionParser().parse(self, case_id=case_id, evidence_id=evidence_id)
        self.check_source()
        return result

    def read_at(self, offset: int, length: int) -> bytes:
        self.check_source()
        result = self._reader.read_at(offset, length)
        self.check_source()
        return result

    def close(self) -> None:
        # Cleanup also runs from TSK destructors; validation must not raise here.
        self._reader.close()

    def __enter__(self) -> Self:
        return self.open_readonly()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            if exc_type is None:
                self.check_source()
        finally:
            self.close()
