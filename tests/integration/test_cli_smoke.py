from __future__ import annotations

import json
import struct
import subprocess
import sys
from pathlib import Path


def run_cli(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "apex_forensic", *args],
        check=False,
        text=True,
        capture_output=True,
        env=env,
    )


def test_cli_case_to_evidence_verification_smoke(tmp_path: Path, cli_env: dict[str, str]) -> None:
    db_path = tmp_path / "cli.db"
    evidence_path = tmp_path / "증거-cli.bin"
    evidence_path.write_bytes(b"cli smoke" * 100)

    init = run_cli(["init", "--db", str(db_path), "--json"], cli_env)
    assert init.returncode == 0, init.stderr
    assert json.loads(init.stdout)["initialized"] is True

    created = run_cli(
        [
            "--db",
            str(db_path),
            "case",
            "create",
            "--name",
            "테스트 사건",
            "--investigator",
            "권태욱",
            "--description",
            "Phase 1 Test",
            "--json",
        ],
        cli_env,
    )
    assert created.returncode == 0, created.stderr
    case = json.loads(created.stdout)
    assert case["name"] == "테스트 사건"

    added = run_cli(
        [
            "--db",
            str(db_path),
            "evidence",
            "add",
            "--case-id",
            case["id"],
            "--path",
            str(evidence_path),
            "--json",
        ],
        cli_env,
    )
    assert added.returncode == 0, added.stderr
    evidence = json.loads(added.stdout)
    assert evidence["read_only"] is True

    hashed = run_cli(
        [
            "--db",
            str(db_path),
            "evidence",
            "hash",
            "--evidence-id",
            evidence["id"],
            "--algorithm",
            "sha256",
            "--chunk-size",
            "16",
            "--json",
        ],
        cli_env,
    )
    assert hashed.returncode == 0, hashed.stderr
    assert json.loads(hashed.stdout)["hash"]["algorithm"] == "SHA256"

    verified = run_cli(
        [
            "--db",
            str(db_path),
            "evidence",
            "verify",
            "--evidence-id",
            evidence["id"],
            "--json",
        ],
        cli_env,
    )
    assert verified.returncode == 0, verified.stderr
    assert json.loads(verified.stdout)["verification"]["status"] == "MATCH"

    custody = run_cli(
        [
            "--db",
            str(db_path),
            "custody",
            "list",
            "--evidence-id",
            evidence["id"],
            "--json",
        ],
        cli_env,
    )
    assert custody.returncode == 0, custody.stderr
    events = json.loads(custody.stdout)
    assert [event["event_type"] for event in events] == ["RECEIVED", "HASH_VERIFIED"]


def test_cli_directory_hash_returns_clear_error(tmp_path: Path, cli_env: dict[str, str]) -> None:
    db_path = tmp_path / "cli-dir.db"
    directory = tmp_path / "dir-evidence"
    directory.mkdir()
    run_cli(["init", "--db", str(db_path), "--json"], cli_env)
    case = json.loads(
        run_cli(
            ["--db", str(db_path), "case", "create", "--name", "Dir Case", "--json"],
            cli_env,
        ).stdout
    )
    evidence = json.loads(
        run_cli(
            [
                "--db",
                str(db_path),
                "evidence",
                "add",
                "--case-id",
                case["id"],
                "--path",
                str(directory),
                "--json",
            ],
            cli_env,
        ).stdout
    )
    result = run_cli(
        [
            "--db",
            str(db_path),
            "evidence",
            "hash",
            "--evidence-id",
            evidence["id"],
            "--json",
        ],
        cli_env,
    )

    assert result.returncode == 1
    assert json.loads(result.stdout)["errors"][0]["code"] == "CAPABILITY_UNAVAILABLE"


def test_cli_disk_image_volumes_and_bounded_read(tmp_path: Path, cli_env: dict[str, str]) -> None:
    db_path = tmp_path / "cli-image.db"
    image_path = tmp_path / "image.dd"
    image = bytearray(8 * 512)
    image[446:462] = bytes([0, 0, 0, 0, 0x07, 0, 0, 0]) + struct.pack("<II", 1, 2)
    image[510:512] = b"\x55\xaa"
    image[512:516] = b"APEX"
    image_path.write_bytes(image)
    run_cli(["init", "--db", str(db_path), "--json"], cli_env)
    case = json.loads(
        run_cli(
            ["--db", str(db_path), "case", "create", "--name", "Image Case", "--json"],
            cli_env,
        ).stdout
    )
    evidence = json.loads(
        run_cli(
            [
                "--db",
                str(db_path),
                "evidence",
                "add",
                "--case-id",
                case["id"],
                "--path",
                str(image_path),
                "--json",
            ],
            cli_env,
        ).stdout
    )

    volumes = run_cli(
        [
            "--db",
            str(db_path),
            "evidence",
            "volumes",
            "--evidence-id",
            evidence["id"],
            "--json",
        ],
        cli_env,
    )
    assert volumes.returncode == 0, volumes.stderr
    parsed = json.loads(volumes.stdout)
    assert any(item["allocated"] and item["start_lba"] == 1 for item in parsed)

    raw = run_cli(
        [
            "--db",
            str(db_path),
            "evidence",
            "read-range",
            "--evidence-id",
            evidence["id"],
            "--offset",
            "512",
            "--length",
            "4",
            "--json",
        ],
        cli_env,
    )
    assert raw.returncode == 0, raw.stderr
    assert json.loads(raw.stdout)["data"] == "QVBFWA=="
