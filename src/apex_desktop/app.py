"""Per-launch authenticated loopback API independent of cloud account login."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from secrets import compare_digest
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError as InputError
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from apex_forensic.config import build_services
from apex_forensic.domain.errors import ApexError

from .operations import MODELS, invoke
from .tasks import Tasks, encode, public_error


def create_app(data_dir: Path, token: str, *, host: str = "127.0.0.1") -> FastAPI:
    if len(token) < 32:
        raise ValueError("A strong per-launch desktop token is required.")
    data_dir = data_dir.resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    database = data_dir / "apex.db"
    services = build_services(database)
    services.close()
    actor_file = data_dir / "local-actor.txt"
    if not actor_file.exists():
        actor_file.write_text(f"local:{uuid4()}", encoding="utf-8")
    actor = actor_file.read_text(encoding="utf-8").strip()
    session_id = str(uuid4())
    tasks = Tasks(database, data_dir / "tasks.json")

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield
        tasks.close()

    app = FastAPI(
        title="APEX Desktop Local API",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def local_boundary(request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.hostname != host or request.headers.get("origin") is not None:
            return JSONResponse({"ok": False, "error": {"code": "LOCAL_ORIGIN_DENIED"}}, 403)
        if not compare_digest(request.headers.get("authorization", ""), f"Bearer {token}"):
            return JSONResponse({"ok": False, "error": {"code": "LOCAL_SESSION_REQUIRED"}}, 401)
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 1048576:
                return JSONResponse(
                    {"ok": False, "error": {"code": "RESOURCE_LIMIT_EXCEEDED"}}, 413
                )
        request._body = bytes(body)
        return await call_next(request)

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"ok": True, "data": {"ready": True, "transport_version": 1}}

    @app.post("/v1/operations/{operation}")
    async def operation_input(operation: str, request: Request) -> Response:
        from starlette.concurrency import run_in_threadpool

        if operation not in MODELS:
            return JSONResponse({"ok": False, "error": {"code": "OPERATION_UNAVAILABLE"}}, 404)
        try:
            payload = MODELS[operation].model_validate(await request.json()).model_dump()
        except (InputError, ValueError):
            return JSONResponse({"ok": False, "error": {"code": "VALIDATION_ERROR"}}, 422)

        def execute() -> dict[str, Any]:
            bundle = build_services(database, initialize=False)
            try:
                data = invoke(
                    operation,
                    payload,
                    bundle,
                    tasks=tasks,
                    actor=actor,
                    session_id=session_id,
                    exports=data_dir / "exports",
                )
                return {"ok": True, "data": encode(data)}
            finally:
                bundle.close()

        try:
            return JSONResponse(await run_in_threadpool(execute))
        except (ValueError, TypeError):
            return JSONResponse({"ok": False, "error": {"code": "VALIDATION_ERROR"}}, 422)
        except Exception as error:
            return JSONResponse(
                {"ok": False, "error": public_error(error)},
                409 if isinstance(error, ApexError) else 500,
            )

    return app
