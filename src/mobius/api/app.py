"""Application factory and RFC 9457 error mapping."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ..services.errors import DomainError
from .routes import router


def create_app() -> FastAPI:
    app = FastAPI(
        title="MOBIUS",
        version="0.1.0",
        description=(
            "Evidence-driven Android security investigation. A finding is confirmed by a "
            "deterministic gate over evidence, never by model prose."
        ),
    )
    app.include_router(router, prefix="/api/v1")

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
