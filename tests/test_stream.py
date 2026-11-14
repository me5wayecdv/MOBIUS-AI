"""Server-sent events: replay, resume and termination.

A live stream that never ends is untestable and unusable, so the contract includes a
definite end: once the investigation is terminal and every event has been delivered, the
server closes the stream with a `stream_end` event. The client can then stop reconnecting
without guessing.
"""

from __future__ import annotations

import json

from conftest import make_apk


def _scan(client, *, start=True):
    app = client.post(
        "/api/v1/applications",
        files={"file": ("a.apk", make_apk(), "application/vnd.android.package-archive")},
    ).json()
    auth = client.post("/api/v1/authorizations", json={
        "apk_sha256": app["sha256"],
        "target_package": "com.example",
        "scope_text": "Static analysis of the supplied artefact only; no execution.",
        "statement": "s",
        "max_intensity": 2,
        "expires_at": "2030-01-01T00:00:00Z",
    }).json()
    scan = client.post("/api/v1/scans", json={
        "application_id": app["id"],
        "authorization_id": auth["id"],
        "objective": "Determine whether exported components reach a privileged sink.",
        "intensity": 0,
    }).json()
    return scan["id"]


def _collect(client, path, **kwargs):
    """Read a stream to completion and return the parsed event list."""
    events = []
    with client.stream("GET", path, **kwargs) as response:
        assert response.status_code == 200, response.read()
        buf = b""
        for chunk in response.iter_bytes():
            buf += chunk
    for block in buf.decode().split("\n\n"):
        if not block.strip() or block.lstrip().startswith(":"):
            continue
        fields = {}
        for line in block.splitlines():
            key, _, value = line.partition(": ")
            fields[key] = value
        events.append(fields)
    return events


def test_stream_replays_and_closes_on_terminal_state(client):
    scan_id = _scan(client)
    client.post(f"/api/v1/scans/{scan_id}/cancel")

    events = _collect(client, f"/api/v1/scans/{scan_id}/stream")
    ids = [int(e["id"]) for e in events if "id" in e]
    assert ids == [1, 2, 3]
    assert events[0]["event"] == "investigation_started"
    assert events[-1]["event"] == "stream_end"


def test_stream_payloads_are_json(client):
    scan_id = _scan(client)
    client.post(f"/api/v1/scans/{scan_id}/cancel")
    events = _collect(client, f"/api/v1/scans/{scan_id}/stream")
    for event in events:
        if "data" in event and event["data"]:
            json.loads(event["data"])  # must not raise


def test_stream_resumes_from_cursor(client):
    scan_id = _scan(client)
    client.post(f"/api/v1/scans/{scan_id}/cancel")
    events = _collect(client, f"/api/v1/scans/{scan_id}/stream?after=2")
    assert [int(e["id"]) for e in events if "id" in e] == [3]


def test_last_event_id_header_is_honoured(client):
    """The browser reconnect path: EventSource sends Last-Event-ID automatically."""
    scan_id = _scan(client)
    client.post(f"/api/v1/scans/{scan_id}/cancel")
    events = _collect(
        client,
        f"/api/v1/scans/{scan_id}/stream",
        headers={"Last-Event-ID": "2"},
    )
    assert [int(e["id"]) for e in events if "id" in e] == [3]


def test_stream_requires_the_scan_to_exist(client):
    response = client.get("/api/v1/scans/scn_missing/stream")
    assert response.status_code == 404
    assert response.json()["code"] == "NOT_FOUND"


def test_content_type_is_event_stream(client):
    scan_id = _scan(client)
    client.post(f"/api/v1/scans/{scan_id}/cancel")
    with client.stream("GET", f"/api/v1/scans/{scan_id}/stream") as response:
        assert response.headers["content-type"].startswith("text/event-stream")
        assert response.headers["cache-control"] == "no-cache"
