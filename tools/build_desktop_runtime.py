"""Build a native desktop runtime with the current, locked Python environment."""

import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def main() -> None:
    if sys.platform not in {"win32", "darwin"}:
        raise SystemExit("Build the desktop runtime on Windows or macOS.")
    root = Path(__file__).resolve().parents[1]
    build = root / "desktop-runtime-build"
    command = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir",
        "--name", "apex-local-api", "--paths", "src",
        "--hidden-import", "pytsk3",
        "--distpath", str(build), "--workpath", str(root / "build" / "desktop"),
        "--specpath", str(root / "build" / "desktop"),
    ]
    for package in (
        "apex_forensic", "apex_desktop", "uvicorn", "jsonschema", "referencing",
        "reportlab", "PIL",
    ):
        command.extend(["--collect-all", package])
    if sys.platform == "win32":
        command.extend(["--collect-all", "tzdata"])
    command.append(str(root / "tools" / "desktop_entry.py"))
    subprocess.run(command, cwd=root, check=True)
    runtime = build / "apex-local-api"
    executable = runtime / ("apex-local-api.exe" if sys.platform == "win32" else "apex-local-api")
    if not executable.is_file():
        raise SystemExit("The native runtime executable was not produced.")
    architecture = {"amd64": "x64", "x86_64": "x64", "aarch64": "arm64"}.get(
        platform.machine().lower(), platform.machine().lower(),
    )
    (runtime / "runtime-info.json").write_text(
        json.dumps({"platform": sys.platform, "arch": architecture}), encoding="utf-8",
    )
    destination = root / "desktop-runtime"
    if destination.exists():
        shutil.rmtree(destination)
    shutil.move(str(runtime), destination)
    print(f"Native runtime ready: {destination / executable.name}")


if __name__ == "__main__":
    main()
