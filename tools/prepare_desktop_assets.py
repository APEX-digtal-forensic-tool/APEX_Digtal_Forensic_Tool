"""Build-time only: download pinned public assets, verify, then stage an offline bundle."""

import argparse
import hashlib
import json
import platform
import shutil
import stat
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

import httpx


def sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def download(client, url, destination, expected):
    if (
        destination.is_file()
        and destination.stat().st_size == expected["size"]
        and sha256(destination) == expected["sha256"]
    ):
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".partial")
    try:
        with client.stream("GET", url) as response:
            response.raise_for_status()
            size = 0
            with temporary.open("wb") as handle:
                for chunk in response.iter_bytes(1024 * 1024):
                    size += len(chunk)
                    if size > expected["size"]:
                        raise ValueError("Asset exceeded its locked size")
                    handle.write(chunk)
        if size != expected["size"] or sha256(temporary) != expected["sha256"]:
            raise ValueError("Asset size or SHA-256 differs from desktop-assets.lock.json")
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)


def extract_media(archive: Path, destination: Path) -> None:
    """Keep upstream notices/docs and shared DLLs; never trust archive member paths."""
    with zipfile.ZipFile(archive) as zipped:
        members = zipped.infolist()
        if len(members) > 5000 or sum(m.file_size for m in members) > 512 * 1024 * 1024:
            raise ValueError("FFmpeg archive exceeds extraction limits")
        for member in members:
            path = PurePosixPath(member.filename)
            if (
                path.is_absolute()
                or ".." in path.parts
                or "\\" in member.filename
                or ":" in member.filename
                or stat.S_ISLNK(member.external_attr >> 16)
            ):
                raise ValueError("Unsafe FFmpeg archive member")
            # The pinned distribution wraps all entries in one directory.
            if len(path.parts) < 2 or member.is_dir():
                continue
            target = destination.joinpath(*path.parts[1:])
            target.parent.mkdir(parents=True, exist_ok=True)
            with zipped.open(member) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
    for name in ("ffmpeg.exe", "ffprobe.exe"):
        if not (destination / "bin" / name).is_file():
            raise ValueError(f"Missing bundled {name}")


def prepare(root: Path, *, windows: bool) -> Path:
    lock = json.loads((root / "tools/desktop-assets.lock.json").read_text())
    cache = root / "build/desktop-downloads"
    cache.mkdir(parents=True, exist_ok=True)
    destination = root / "desktop-assets"
    # Never publish a partially downloaded or extracted model as an available model.
    with tempfile.TemporaryDirectory(prefix="assets-", dir=cache) as temp:
        staging = Path(temp) / "assets"
        model = staging / "models/whisper-base"
        model.mkdir(parents=True)
        with httpx.Client(follow_redirects=True, timeout=120) as client:
            spec = lock["stt"]
            for name, expected in spec["files"].items():
                cached = cache / spec["revision"] / name
                url = (
                    f"https://huggingface.co/{spec['repository']}/resolve/{spec['revision']}/{name}"
                )
                download(client, url, cached, expected)
                shutil.copy2(cached, model / name)
            if windows:
                spec = lock["media_windows_x64"]
                archive = cache / (spec["sha256"] + ".zip")
                download(client, spec["url"], archive, spec)
                extract_media(archive, staging / "media")
        shutil.copy2(root / "tools/desktop-assets.lock.json", staging / "asset-manifest.json")
        shutil.copytree(root / "docs/desktop/third-party", staging / "notices")
        if destination.exists():
            shutil.rmtree(destination)
        shutil.move(str(staging), destination)
    print("Verified offline assets ready:", destination)
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--windows", action="store_true", help="Stage Windows x64 tools")
    args = parser.parse_args()
    windows = args.windows or sys.platform == "win32"
    if windows and platform.machine().lower() not in {"x86_64", "amd64"}:
        raise SystemExit("The pinned FFmpeg build targets Windows x64 only")
    prepare(Path(__file__).resolve().parents[1], windows=windows)
