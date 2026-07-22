"""Artifact analyzer adapters."""

from apex_forensic.adapters.artifacts.windows import (
    WindowsEventLogAnalyzer,
    WindowsPrefetchAnalyzer,
    WindowsRegistryAnalyzer,
)

__all__ = [
    "WindowsEventLogAnalyzer",
    "WindowsPrefetchAnalyzer",
    "WindowsRegistryAnalyzer",
]
