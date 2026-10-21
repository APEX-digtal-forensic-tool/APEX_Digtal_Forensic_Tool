#!/usr/bin/env python3
"""Run one artifact -> MCP -> live AI provider analysis cycle over stdio."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from mcp.client import Client
from mcp.client.stdio import StdioServerParameters

from apex_forensic.config import build_services
from apex_forensic.domain.enums import AiSecretHandling, AnalysisProfileType, DataClassification
from apex_forensic.domain.models import ArtifactQuery

ROOT = Path(__file__).resolve().parents[1]
_EVENT_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID>
<EventRecordID>1</EventRecordID><TimeCreated SystemTime="2026-09-08T01:23:45Z"/>
<Computer>WS-ANALYST01</Computer></System>
<EventData><Data Name="TargetUserName">kim.analyst</Data><Data Name="LogonType">10</Data>
<Data Name="IpAddress">203.0.113.24</Data><Data Name="WorkstationName">REMOTE-PC</Data></EventData>
</Event>"""


def _seed(workdir: Path) -> dict[str, str]:
    evidence_root = workdir / "증거"
    evidence_root.mkdir()
    (evidence_root / "Security-4624.xml").write_text(_EVENT_XML, encoding="utf-8")
    database_path = workdir / "ai-cycle.db"
    services = build_services(database_path)
    try:
        case = services.cases.create_case(name="MCP AI 사이클 검증")
        evidence = services.evidence.register_evidence(
            case_id=case.case_id, source_path=evidence_root
        )
        services.fs.index_evidence(
            case_id=case.case_id,
            evidence_id=evidence.evidence_id,
            profile_type=AnalysisProfileType.FULL_ANALYSIS,
        )
        services.artifacts.analyze_evidence(case_id=case.case_id, evidence_id=evidence.evidence_id)
        artifact = services.artifacts.list_artifacts(ArtifactQuery(case_id=case.case_id)).items[0]
        services.ai_policies.configure(
            case_id=case.case_id,
            expected_revision=0,
            ai_enabled=True,
            external_allowed=True,
            local_only=False,
            allowed_classifications=tuple(DataClassification),
            secret_handling=AiSecretHandling.REDACT,
        )
        context = services.contexts.create(
            session_id="mcp-ai-cycle",
            case_id=case.case_id,
            actor_id="analyst-ai-cycle",
            selected_artifact_ids=[artifact.artifact_id],
        )
        return {
            "database": str(database_path),
            "case_id": case.case_id,
            "artifact_id": artifact.artifact_id,
            "session_context_id": context.session_context_id,
        }
    finally:
        services.close()


def _data(result: Any, step: str) -> Any:
    content = result.structured_content or {}
    if result.is_error:
        raise RuntimeError(f"{step}: {json.dumps(content.get('errors'), ensure_ascii=False)}")
    return content["data"]


async def _cycle(args: argparse.Namespace, seeded: dict[str, str]) -> dict[str, Any]:
    server_args = [
        "-m", "apex_mcp",
        "--database", seeded["database"],
        "--schema-dir", str(ROOT / "schemas" / "v1"),
        "--ai-provider-id", args.provider_id,
        "--ai-base-url", args.base_url,
        "--ai-model", args.model,
        "--ai-api-key-env", args.api_key_env,
        "--ai-temperature", str(args.temperature),
        "--ai-max-output", str(args.max_output),
        "--ai-timeout", str(args.timeout),
    ]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    params = StdioServerParameters(command=sys.executable, args=server_args, cwd=ROOT, env=env)
    report: dict[str, Any] = {"artifact_id": seeded["artifact_id"]}
    async with Client(params, mode="2026-07-28") as client:
        caps = _data(await client.call_tool("ai.capabilities", {}), "ai.capabilities")
        report["provider_available"] = caps["runtime_capability"]["is_available"]
        snapshot = _data(
            await client.call_tool(
                "apex.context.snapshot",
                {"session_context_id": seeded["session_context_id"], "scopes": [args.scope]},
            ),
            "apex.context.snapshot",
        )
        for purpose, operation in (
            ("SCOPE_SUMMARY", "SUMMARIZE_SCOPE"),
            ("KEYWORD_RECOMMENDATION", "RECOMMEND_KEYWORDS"),
        ):
            request = _data(
                await client.call_tool(
                    "ai.request.create",
                    {
                        "case_id": seeded["case_id"],
                        "context_snapshot_id": snapshot["context_snapshot_id"],
                        "purpose": purpose,
                        "requested_operations": [operation],
                        "requested_scopes": [args.scope],
                        "locale": "ko-KR",
                    },
                ),
                "ai.request.create",
            )
            executed = _data(
                await client.call_tool(
                    "ai.request.execute",
                    {
                        "assistance_request_id": request["assistance_request_id"],
                        "operation": operation,
                    },
                ),
                f"ai.request.execute:{operation}",
            )
            report[operation] = {
                "result_kind": executed.get("result_kind"),
                "observed_fact_status": executed.get("observed_fact_status"),
                "result": executed.get("result"),
            }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider-id", default="moonshot-kimi")
    parser.add_argument("--base-url", default="https://api.moonshot.ai/v1")
    parser.add_argument("--model", default="kimi-k3")
    parser.add_argument("--api-key-env", default="APEX_AI_API_KEY")
    parser.add_argument("--temperature", type=float, default=1.0)
    parser.add_argument("--max-output", type=int, default=16384)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--scope", default="eventlog")
    args = parser.parse_args()
    if not os.environ.get(args.api_key_env):
        print(f"{args.api_key_env} is not set.", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="apex-ai-cycle-") as workdir:
        seeded = _seed(Path(workdir))
        try:
            report = asyncio.run(_cycle(args, seeded))
            status = 0
        except Exception as error:
            while isinstance(error, BaseExceptionGroup) and error.exceptions:
                error = error.exceptions[0]
            report = {"status": "FAILED", "error": f"{type(error).__name__}: {error}"}
            status = 1
    sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
