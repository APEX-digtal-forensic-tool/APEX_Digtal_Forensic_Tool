from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from apex_forensic.domain.enums import EvidenceFormat, HashAlgorithm
from apex_forensic.domain.errors import UnsupportedCapabilityError, ValidationError


def test_file_evidence_registration_is_read_only_and_schema_valid(
    services,
    sample_file: Path,
    schema_validator,
) -> None:
    case = services.cases.create_case(name="Case")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=sample_file)

    assert evidence.read_only is True
    assert evidence.evidence_type is EvidenceFormat.RAW
    assert evidence.source_path == sample_file.resolve()
    assert evidence.fingerprint is not None
    assert evidence.fingerprint.value == hashlib.sha256(sample_file.read_bytes()).hexdigest()
    assert sample_file.read_bytes().endswith("한글 경로".encode())
    schema_validator.validate_evidence(evidence.to_schema_dict())


def test_missing_path_is_rejected(services, tmp_path: Path) -> None:
    case = services.cases.create_case(name="Case")
    with pytest.raises(ValidationError):
        services.evidence.register_evidence(
            case_id=case.case_id,
            source_path=tmp_path / "missing.dd",
        )


def test_symlink_policy_rejects_links(services, sample_file: Path, tmp_path: Path) -> None:
    link = tmp_path / "link.bin"
    try:
        link.symlink_to(sample_file)
    except OSError:
        pytest.skip("symlinks are not supported on this filesystem")
    case = services.cases.create_case(name="Case")
    with pytest.raises(UnsupportedCapabilityError):
        services.evidence.register_evidence(case_id=case.case_id, source_path=link)


def test_directory_registration_allows_metadata_but_hash_is_unsupported(
    services,
    tmp_path: Path,
) -> None:
    case = services.cases.create_case(name="Case")
    directory = tmp_path / "evidence-dir"
    directory.mkdir()
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=directory)

    assert evidence.evidence_type is EvidenceFormat.DIRECTORY
    assert evidence.fingerprint is None
    with pytest.raises(UnsupportedCapabilityError):
        services.evidence.calculate_hash(
            evidence_id=evidence.evidence_id,
            algorithm=HashAlgorithm.SHA256,
        )
