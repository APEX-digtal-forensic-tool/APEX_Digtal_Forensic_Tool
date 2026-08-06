"""Shared helpers for runtime verification scripts."""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any


def ensure_source_tree_importable(script_file: str) -> Path:
    """Allow verifier scripts to run directly from a copied source tree."""

    root = Path(script_file).resolve().parents[1]
    src = root / "src"
    if src.is_dir():
        src_text = str(src)
        if src_text not in sys.path:
            sys.path.insert(0, src_text)
    return root


def fixture_path_policy(
    paths: dict[str, str | None],
    *,
    forbidden_roots: Iterable[Path],
) -> dict[str, Any]:
    """Return a structured fixture policy decision without reading fixture contents."""

    rejected = []
    roots = [_resolve_path(root) for root in forbidden_roots if str(root)]
    for name, value in paths.items():
        if not value:
            continue
        path = _resolve_path(Path(value))
        for root in roots:
            if _is_relative_to(path, root):
                rejected.append(
                    {
                        "input": name,
                        "path": str(path),
                        "rejected_root": str(root),
                        "reason": "LIVE_USER_PROFILE_PATH",
                    }
                )
                break
    return {
        "status": "LIVE_USER_PROFILE_REJECTED" if rejected else "ACCEPTED",
        "synthetic_or_redistributable_fixture_required": True,
        "live_user_profile_allowed": False,
        "secret_values_emitted": False,
        "rejected_paths": rejected,
    }


def dpapi_live_profile_roots() -> list[Path]:
    """Known current-user Windows DPAPI and Chromium profile roots."""

    roots: list[Path] = []
    for name in ("APPDATA", "LOCALAPPDATA"):
        base = os.environ.get(name)
        if base:
            roots.append(Path(base) / "Microsoft" / "Protect")
    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        user_root = Path(user_profile)
        roots.extend(
            [
                user_root / "AppData" / "Roaming" / "Microsoft" / "Protect",
                user_root / "AppData" / "Local" / "Microsoft" / "Protect",
                user_root / "AppData" / "Local" / "Google" / "Chrome" / "User Data",
                user_root / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data",
            ]
        )
    home = Path.home()
    if str(home) not in {"", os.sep}:
        roots.extend(
            [
                home / "AppData" / "Roaming" / "Microsoft" / "Protect",
                home / "AppData" / "Local" / "Microsoft" / "Protect",
            ]
        )
    return roots


def nss_live_profile_roots() -> list[Path]:
    """Known current-user Firefox profile roots."""

    roots: list[Path] = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        roots.append(Path(appdata) / "Mozilla" / "Firefox" / "Profiles")
    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        roots.append(Path(user_profile) / "AppData" / "Roaming" / "Mozilla" / "Firefox")
    home = Path.home()
    if str(home) not in {"", os.sep}:
        roots.append(home / ".mozilla" / "firefox")
    return roots


def _resolve_path(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
