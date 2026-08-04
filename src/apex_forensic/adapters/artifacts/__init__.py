"""Artifact analyzer adapters."""

from apex_forensic.adapters.artifacts.browser import BrowserHistoryAnalyzer
from apex_forensic.adapters.artifacts.communication import (
    CommunicationCorePluginAnalyzer,
    DiscordSQLiteFixtureAnalyzer,
    EmailMboxFixtureAnalyzer,
    KakaoTalkEncryptedStoreDiscoveryAnalyzer,
    TelegramSQLiteFixtureAnalyzer,
)
from apex_forensic.adapters.artifacts.media import MediaMetadataAnalyzer
from apex_forensic.adapters.artifacts.windows import (
    WindowsEventLogAnalyzer,
    WindowsEventMessageRenderer,
    WindowsPrefetchAnalyzer,
    WindowsRegistryAnalyzer,
)

__all__ = [
    "BrowserHistoryAnalyzer",
    "CommunicationCorePluginAnalyzer",
    "DiscordSQLiteFixtureAnalyzer",
    "EmailMboxFixtureAnalyzer",
    "KakaoTalkEncryptedStoreDiscoveryAnalyzer",
    "MediaMetadataAnalyzer",
    "TelegramSQLiteFixtureAnalyzer",
    "WindowsEventLogAnalyzer",
    "WindowsEventMessageRenderer",
    "WindowsPrefetchAnalyzer",
    "WindowsRegistryAnalyzer",
]
