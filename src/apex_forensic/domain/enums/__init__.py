"""Domain enums shared across Phase 1 modules."""

from __future__ import annotations

from enum import StrEnum


class CaseStatus(StrEnum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    ARCHIVED = "ARCHIVED"


class EvidenceFormat(StrEnum):
    DIRECTORY = "DIRECTORY"
    RAW = "RAW"
    DD = "DD"
    IMG = "IMG"
    E01 = "E01"
    VHD = "VHD"
    VHDX = "VHDX"


class EvidenceStatus(StrEnum):
    REGISTERED = "REGISTERED"
    HASHING = "HASHING"
    READY = "READY"
    FAILED = "FAILED"


class HashAlgorithm(StrEnum):
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"


class HashVerificationStatus(StrEnum):
    NOT_CHECKED = "NOT_CHECKED"
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    ERROR = "ERROR"


class JobType(StrEnum):
    HASH = "HASH"
    VERIFY = "VERIFY"
    INDEX = "INDEX"


class SchemaJobType(StrEnum):
    HASH = "HASH"
    VERIFY = "VERIFY"
    INDEX = "INDEX"


class JobStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    PAUSING = "PAUSING"
    PAUSED = "PAUSED"
    RESUMING = "RESUMING"
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ProgressUnit(StrEnum):
    BYTES = "BYTES"
    FILES = "FILES"
    TASKS = "TASKS"
    UNKNOWN = "UNKNOWN"


class FileSystemNodeType(StrEnum):
    ROOT = "ROOT"
    DIRECTORY = "DIRECTORY"
    FILE = "FILE"
    SYMLINK = "SYMLINK"
    REPARSE_POINT = "REPARSE_POINT"
    OTHER = "OTHER"


class FileSystemProviderCapability(StrEnum):
    LOGICAL_DIRECTORY = "LOGICAL_DIRECTORY"
    LOGICAL_FILE = "LOGICAL_FILE"
    METADATA_ONLY = "METADATA_ONLY"
    STABLE_RAW_LOCATOR = "STABLE_RAW_LOCATOR"


class IndexCoverageStatus(StrEnum):
    NOT_STARTED = "NOT_STARTED"
    PARTIAL = "PARTIAL"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class AnalysisProfileType(StrEnum):
    QUICK_TRIAGE = "QUICK_TRIAGE"
    SELECTED_SCOPE = "SELECTED_SCOPE"
    FULL_ANALYSIS = "FULL_ANALYSIS"
    CUSTOM = "CUSTOM"


class FollowLinkPolicy(StrEnum):
    NEVER = "NEVER"
    RECORD_ONLY = "RECORD_ONLY"


class CustodyEventType(StrEnum):
    ACQUISITION = "ACQUISITION"
    RECEIVED = "RECEIVED"
    TRANSFERRED = "TRANSFERRED"
    STORED = "STORED"
    OPENED = "OPENED"
    MOUNTED = "MOUNTED"
    ANALYZED = "ANALYZED"
    HASH_VERIFIED = "HASH_VERIFIED"
    COPIED = "COPIED"
    EXPORTED = "EXPORTED"
    RETURNED = "RETURNED"
    RELEASED = "RELEASED"
    ARCHIVED = "ARCHIVED"
    DISPOSED = "DISPOSED"
    CORRECTION = "CORRECTION"
