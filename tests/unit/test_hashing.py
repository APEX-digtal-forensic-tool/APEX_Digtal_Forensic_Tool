from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from apex_forensic.adapters.hashing import HashlibStreamingHashProvider
from apex_forensic.domain.enums import HashAlgorithm
from apex_forensic.domain.errors import EvidenceChangedError, OperationCancelledError
from apex_forensic.jobs import CancellationToken


def test_streaming_md5_sha1_sha256(sample_file: Path) -> None:
    provider = HashlibStreamingHashProvider()
    computation = provider.compute_file(
        sample_file,
        [HashAlgorithm.MD5, HashAlgorithm.SHA1, HashAlgorithm.SHA256],
        chunk_size=17,
    )
    data = sample_file.read_bytes()

    assert computation.bytes_hashed == len(data)
    assert computation.digests[HashAlgorithm.MD5] == hashlib.md5(
        data, usedforsecurity=False
    ).hexdigest()
    assert computation.digests[HashAlgorithm.SHA1] == hashlib.sha1(
        data, usedforsecurity=False
    ).hexdigest()
    assert computation.digests[HashAlgorithm.SHA256] == hashlib.sha256(data).hexdigest()


def test_hash_progress_is_monotonic(sample_file: Path) -> None:
    provider = HashlibStreamingHashProvider()
    updates: list[float] = []

    provider.compute_file(
        sample_file,
        [HashAlgorithm.SHA256],
        chunk_size=31,
        progress_callback=lambda progress: updates.append(progress.progress_percent),
    )

    assert updates
    assert updates == sorted(updates)
    assert updates[-1] == 100.0


def test_hash_cancellation_stops_processing(sample_file: Path) -> None:
    provider = HashlibStreamingHashProvider()
    token = CancellationToken.new()

    def cancel_on_progress(_) -> None:
        token.cancel()

    with pytest.raises(OperationCancelledError):
        provider.compute_file(
            sample_file,
            [HashAlgorithm.SHA256],
            chunk_size=8,
            progress_callback=cancel_on_progress,
            cancellation_token=token,
        )


def test_hash_detects_file_change_during_calculation(tmp_path: Path) -> None:
    path = tmp_path / "changing.bin"
    path.write_bytes(b"a" * 2048)
    provider = HashlibStreamingHashProvider()
    changed = False

    def mutate(_) -> None:
        nonlocal changed
        if not changed:
            path.write_bytes(b"b" * 4096)
            changed = True

    with pytest.raises(EvidenceChangedError):
        provider.compute_file(
            path,
            [HashAlgorithm.SHA256],
            chunk_size=512,
            progress_callback=mutate,
        )
