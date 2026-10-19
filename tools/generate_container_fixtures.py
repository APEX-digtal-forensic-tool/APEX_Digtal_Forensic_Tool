"""Rebuild synthetic portable fixtures using ewfacquire, qemu-img and ntfs-3g tools."""

import base64
import gzip
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "tests" / "unit"))
    from test_advanced_runtime_machine_extraction import _write_ocr_fixture
    from test_image_content import write_content_image

    with TemporaryDirectory(prefix="apex-generated-fixtures-") as temporary:
        directory = Path(temporary)
        raw = directory / "source.img"
        write_content_image(raw, {"문서.txt": "E01 가상 디스크의 실제 내용".encode()})
        subprocess.run(
            ["ewfacquire", "-u", "-q", "-c", "best", "-t", str(directory / "compressed"), str(raw)],
            check=True,
        )
        for kind, suffix in (("vpc", "vhd"), ("vhdx", "vhdx")):
            subprocess.run(
                [
                    "qemu-img",
                    "convert",
                    "-f",
                    "raw",
                    "-O",
                    kind,
                    str(raw),
                    str(directory / f"disk.{suffix}"),
                ],
                check=True,
            )
        ntfs = directory / "streams.img"
        with ntfs.open("wb") as handle:
            handle.truncate(32 * 1024 * 1024)
        subprocess.run(["mkntfs", "-F", "-Q", str(ntfs)], check=True)
        for name, content in (
            ("", b"normal file body"),
            ("hidden", b"ADS secret forensic stream"),
            ("large", bytes(range(256)) * 256),
        ):
            source = directory / "stream.bin"
            source.write_bytes(content)
            subprocess.run(
                [
                    "ntfscp",
                    *(["-N", name] if name else []),
                    str(ntfs),
                    str(source),
                    "/document.txt",
                ],
                check=True,
            )
        _write_ocr_fixture(directory / "ocr.png")
        entries = {}
        for name in ("compressed.E01", "disk.vhd", "disk.vhdx", "streams.img", "ocr.png"):
            data = (directory / name).read_bytes()
            entries[name] = {
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "gzip_base64": base64.b64encode(gzip.compress(data, mtime=0)).decode(),
            }
        (root / "tests" / "fixtures" / "container-images.json").write_text(
            json.dumps(entries, indent=2) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()
