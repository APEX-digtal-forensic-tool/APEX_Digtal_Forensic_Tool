"""Adapt a container's logical disk bytes to TSK, retaining explicit ownership."""

from types import ModuleType
from typing import Any

from apex_forensic.adapters.evidence.factory import evidence_reader
from apex_forensic.domain.models import Evidence
from apex_forensic.ports.evidence_reader import MAX_EVIDENCE_READ_SIZE


def open_tsk_image(module: ModuleType, evidence: Evidence) -> Any:
    reader = evidence_reader(evidence).open_readonly()

    class LogicalImage(module.Img_Info):  # type: ignore[misc, name-defined]
        def __init__(self) -> None:
            self.reader = reader
            self.closed = False
            super().__init__(url="", type=module.TSK_IMG_TYPE_EXTERNAL)

        def get_size(self) -> int:
            return int(self.reader.size)

        def read(self, offset: int, size: int) -> bytes:
            result = bytearray()
            while len(result) < size:
                chunk = self.reader.read_at(
                    offset + len(result), min(size - len(result), MAX_EVIDENCE_READ_SIZE)
                )
                if not chunk:
                    break
                result.extend(chunk)
            return bytes(result)

        def close(self) -> None:
            if not self.closed:
                self.closed = True
                self.reader.close()

    try:
        return LogicalImage()
    except BaseException:
        reader.close()
        raise


class ManagedFileSystem:
    """Keep the external image alive until all filesystem operations finish."""

    def __init__(self, module: ModuleType, evidence: Evidence, offset: int) -> None:
        self.image: Any = None
        self.filesystem: Any = None
        self.image = open_tsk_image(module, evidence)
        try:
            self.filesystem = module.FS_Info(self.image, offset=offset)
        except BaseException:
            self.image.close()
            raise

    def __getattr__(self, name: str) -> Any:
        return getattr(self.filesystem, name)

    def close(self) -> None:
        if self.image is not None:
            self.image.close()

    def __del__(self) -> None:
        if self.image is not None:
            self.image.close()
