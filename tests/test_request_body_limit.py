"""Tests for the pre-parser APK HTTP request body limit."""

from __future__ import annotations

import asyncio

from mobius.api.app import RequestBodyLimitMiddleware


def _run(middleware, *, headers=(), chunks=()):
    sent = []
    app_called = False
    queue = iter(chunks)

    async def app(scope, receive, send):
        nonlocal app_called
        app_called = True
        received = []
        while True:
            message = await receive()
            received.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        sent.append({"received": b"".join(received)})

    async def receive():
        try:
            return next(queue)
        except StopIteration:
            return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/applications",
        "headers": list(headers),
    }
    async def invoke():
        await middleware(scope, receive, send)

    asyncio.run(invoke())
    return sent, app_called


def test_rejects_oversized_content_length_without_invoking_fastapi():
    middleware = RequestBodyLimitMiddleware(lambda *_: None, max_bytes=10)
    sent, called = _run(
        middleware,
        headers=[(b"content-length", b"11")],
    )
    assert called is False
    assert sent[0]["status"] == 413
    assert b"REQUEST_TOO_LARGE" in sent[1]["body"]


def test_rejects_chunked_body_that_crosses_limit():
    middleware = RequestBodyLimitMiddleware(lambda *_: None, max_bytes=10)
    sent, called = _run(
        middleware,
        chunks=[
            {"type": "http.request", "body": b"123456", "more_body": True},
            {"type": "http.request", "body": b"78901", "more_body": False},
        ],
    )
    assert called is False
    assert sent[0]["status"] == 413


def test_replays_bounded_request_chunks_unchanged():
    middleware = RequestBodyLimitMiddleware(lambda *_: None, max_bytes=10)
    sent, called = _run(
        middleware,
        headers=[(b"content-length", b"6")],
        chunks=[
            {"type": "http.request", "body": b"123", "more_body": True},
            {"type": "http.request", "body": b"456", "more_body": False},
        ],
    )
    assert called is True
    assert sent[-1]["received"] == b"123456"


def test_non_upload_routes_are_not_subject_to_apk_allowance():
    middleware = RequestBodyLimitMiddleware(lambda *_: None, max_bytes=1)
    sent, called = _run(
        middleware,
        headers=[(b"content-length", b"999")],
        chunks=[{"type": "http.request", "body": b"{}"}],
    )
    assert called is True
