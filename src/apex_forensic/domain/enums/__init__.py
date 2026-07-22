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


class SchemaJobType(StrEnum):
    HASH = "HASH"


class JobStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ProgressUnit(StrEnum):
    BYTES = "BYTES"
    FILES = "FILES"
    TASKS = "TASKS"
    UNKNOWN = "UNKNOWN"


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
