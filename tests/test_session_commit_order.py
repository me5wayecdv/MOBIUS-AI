"""A write must be committed before its response is sent.

Regression test for the War Room E2E flake where GET /scans, fired immediately after
POST /scans returned 201, listed nothing: the session dependency used the default
"request" scope, so its commit ran in teardown after the response had gone out. The
check is done at the ASGI layer, at the exact moment the response body completes -
an HTTP client cannot observe the window reliably on localhost.
"""

from __future__ import annotations

import asyncio
import json

from conftest import make_apk

from mobius.adapters.models import InvestigationRow
from mobius.api.app import create_app
from mobius.api.config import Settings
from mobius.api.deps import AppContext, set_context


def _asgi_call(app, context, method, path, body):
    payload = json.dumps(body).encode()
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(b"content-type", b"application/json")],
        "client": ("127.0.0.1", 123),
        "server": ("test", 80),
    }
    state = {"messages": [], "visible_at_body": None}
    sent = {"done": False}

    async def receive():
        if not sent["done"]:
            sent["done"] = True
            return {"type": "http.request", "body": payload, "more_body": False}
        await asyncio.sleep(0.05)
        return {"type": "http.disconnect"}

    async def send(message):
        state["messages"].append(message)
        if message["type"] == "http.response.body" and not message.get("more_body"):
            probe = context.session()
            try:
                state["visible_at_body"] = probe.query(InvestigationRow).count()
            finally:
                probe.close()

    async def run():
        await app(scope, receive, send)

    asyncio.run(run())
    status = next(m["status"] for m in state["messages"] if m["type"] == "http.response.start")
    return status, state["visible_at_body"]


def test_post_scan_commits_before_response_is_sent(tmp_path):
    # File-backed SQLite: the in-memory test database pools one connection, which
    # cannot see (or hide) another session's uncommitted rows.
    context = AppContext(
        Settings(
            db_url=f"sqlite+pysqlite:///{tmp_path}/commit-order.db",
            artifact_root=tmp_path / "artifacts",
            env="test",
        )
    )
    set_context(context)
    try:
        setup = context.session()
        try:
            from mobius.services.intake import IntakeService

            service = IntakeService(setup, context.store)
            app_dom, _ = service.create_application(make_apk(), "app.apk", uploaded_by="analyst-1")
            auth = service.create_authorization(
                apk_sha256=app_dom.sha256,
                target_package="com.example",
                scope_text="Static analysis of the supplied artefact only; no execution.",
                statement="I am authorised to analyse this build.",
                max_intensity=0,
                granted_by="analyst-1",
                expires_at="2030-01-01T00:00:00Z",
            )
            setup.commit()
            app_id, auth_id = app_dom.id, auth.id
        finally:
            setup.close()

        status, visible_at_body = _asgi_call(
            create_app(),
            context,
            "POST",
            "/api/v1/scans",
            {
                "application_id": app_id,
                "authorization_id": auth_id,
                "objective": "Commit ordering regression round trip.",
                "intensity": 0,
            },
        )
        assert status == 201
        assert visible_at_body == 1, (
            "POST /scans returned 201 before its commit was visible; "
            "a follow-up GET /scans can read an empty list"
        )
    finally:
        set_context(None)
