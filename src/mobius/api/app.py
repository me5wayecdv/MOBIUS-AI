"""Application factory and RFC 9457 error mapping."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path
import tempfile

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ..services.errors import DomainError
from ..services.intake import MAX_APK_BYTES
from .routes import router

# Multipart headers and boundaries need a small allowance above the raw APK cap.
MAX_HTTP_REQUEST_BYTES = MAX_APK_BYTES + 1024 * 1024


class RequestBodyLimitMiddleware:
    """Enforce a hard HTTP body cap before FastAPI parses multipart form data.

    Content-Length is rejected without reading the body. Requests without a trustworthy
    length (for example chunked transfer) are consumed only up to the same fixed cap.
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int = MAX_HTTP_REQUEST_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return

        # Only the APK upload route accepts a large binary body. Other POST bodies use
        # FastAPI/Pydantic limits and must not inherit the APK allowance.
        path = scope.get("path", "")
        if path != "/api/v1/applications":
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        raw_length = headers.get(b"content-length")
        if raw_length is not None:
            try:
                declared_length = int(raw_length)
            except ValueError:
                await self._too_large(send)
                return
            if declared_length < 0 or declared_length > self.max_bytes:
                await self._too_large(send)
                return

        # Spool bounded bodies to disk after 8 MiB. Concurrent near-limit uploads must
        # not multiply the full APK cap into unbounded process RAM usage.
        body_file = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024, mode="w+b")
        total = 0
        more_body = True
        try:
            while more_body:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                chunk = message.get("body", b"")
                total += len(chunk)
                if total > self.max_bytes:
                    await self._too_large(send)
                    return
                body_file.write(chunk)
                more_body = message.get("more_body", False)

            body_file.seek(0)
            sent_bytes = 0

            async def replay_receive() -> Message:
                nonlocal sent_bytes
                chunk = body_file.read(64 * 1024)
                sent_bytes += len(chunk)
                return {
                    "type": "http.request",
                    "body": chunk,
                    "more_body": sent_bytes < total,
                }

            await self.app(scope, replay_receive, send)
        finally:
            body_file.close()

    @staticmethod
    async def _too_large(send: Send) -> None:
        payload = (
            b'{"type":"about:blank","title":"Request body too large",'
            b'"status":413,"detail":"APK upload request exceeds the configured limit",'
            b'"code":"REQUEST_TOO_LARGE"}'
        )
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/problem+json"),
                (b"content-length", str(len(payload)).encode("ascii")),
            ],
        })
        await send({"type": "http.response.body", "body": payload})


def create_app() -> FastAPI:
    app = FastAPI(
        title="MOBIUS",
        version="0.1.0",
        description=(
            "Evidence-driven Android security investigation. A finding is confirmed by a "
            "deterministic gate over evidence, never by model prose."
        ),
    )
    app.add_middleware(RequestBodyLimitMiddleware)
    app.include_router(router, prefix="/api/v1")

    @app.get("/", include_in_schema=False)
    async def _root() -> RedirectResponse:
        return RedirectResponse("/ui")

    @app.get("/ui", response_class=HTMLResponse, include_in_schema=False)
    async def _war_room() -> HTMLResponse:
        """The War Room.

        Served as one static document with no build step and no framework: every number on
        it comes from `/api/v1`, so a panel that looks empty is a scan that has nothing
        there, not a fixture that was not loaded.
        """
        page = files("mobius.api").joinpath("static/war_room.html").read_text(encoding="utf-8")
        return HTMLResponse(page)


    graph_ui_dir = Path(__file__).parent / "static" / "graph-ui"
    graph_assets = graph_ui_dir / "assets"
    if graph_assets.is_dir():
        app.mount("/ui/graph/assets", StaticFiles(directory=graph_assets), name="attack-graph-assets")

    @app.get("/ui/graph", response_class=HTMLResponse, include_in_schema=False)
    async def _attack_graph_ui() -> HTMLResponse:
        index = graph_ui_dir / "index.html"
        if not index.is_file():
            return HTMLResponse(
                "<h1>Attack graph UI is not built</h1>"
                "<p>Run <code>npm install && npm run build</code> in frontend/.</p>",
                status_code=503,
            )
        return HTMLResponse(index.read_text(encoding="utf-8"))

    @app.exception_handler(DomainError)
    async def _domain_error(_request: Request, exc: DomainError) -> JSONResponse:
        # RFC 9457 problem+json. `code` is the stable machine string from
        # docs/API_SPECIFICATION.md 2; clients branch on it, never on the prose.
        return JSONResponse(
            status_code=exc.http_status,
            content={
                "type": f"https://mobius.local/errors/{exc.code}",
                "title": exc.code,
                "status": exc.http_status,
                "detail": exc.detail,
                "code": exc.code,
            },
        )

    return app


app = create_app()
