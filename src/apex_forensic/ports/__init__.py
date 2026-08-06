"""Port interfaces for Phase 1 dependency inversion."""

from apex_forensic.ports.dpapi_provider import DpapiProviderPort
from apex_forensic.ports.kakaotalk_provider import KakaoTalkProviderPort
from apex_forensic.ports.nss_provider import NssProviderPort
from apex_forensic.ports.raw_reader import SafeRawRangeReaderPort

__all__ = [
    "DpapiProviderPort",
    "KakaoTalkProviderPort",
    "NssProviderPort",
    "SafeRawRangeReaderPort",
]
