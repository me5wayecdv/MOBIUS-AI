# HTTP request body limits

The FastAPI application installs an outer ASGI middleware for `POST /api/v1/applications`.
It rejects a declared Content-Length above the configured hard cap before FastAPI parses
multipart form data. For requests without Content-Length, it bounds the received body while
consuming chunks and returns HTTP 413 when the cap is crossed. The cap is the service APK
limit (200 MiB) plus 1 MiB for multipart framing and headers.

The middleware spools bounded request data to a temporary file, retaining at most 8 MiB
in memory before rolling over to disk. It replays the bounded body to FastAPI after the
complete request has passed the limit, and closes the temporary file even if downstream
processing fails.

This is an application-level guard, not a replacement for a reverse-proxy or ingress body
limit. Deployments should set an equal or lower cap at the edge, enforce request timeouts,
and configure connection/concurrency limits. FastAPI's multipart parser still processes
the bounded body, and APK parsing/decompilation still must move to an isolated worker.
