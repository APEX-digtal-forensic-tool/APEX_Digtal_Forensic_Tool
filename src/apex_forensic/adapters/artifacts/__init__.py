"""Artifact analyzer adapters."""

from apex_forensic.adapters.artifacts.browser import BrowserHistoryAnalyzer
from apex_forensic.adapters.artifacts.media import MediaMetadataAnalyzer
from apex_forensic.adapters.artifacts.windows import (
    WindowsEventLogAnalyzer,
    WindowsPrefetchAnalyzer,
    WindowsRegistryAnalyzer,
)

__all__ = [
    "BrowserHistoryAnalyzer",
    "MediaMetadataAnalyzer",
    "WindowsEventLogAnalyzer",
    "WindowsPrefetchAnalyzer",
    "WindowsRegistryAnalyzer",
]
