#!/usr/bin/env python3
"""D-061 mock origin: the controlled lab backend.

TLS HTTPS server bound to namespace loopback. GET-only: any other method is
refused with 405 (safe-GET replay slice). Every receipt is appended as one
JSON line to the receipts log: timestamp, request id (the `req` query
parameter), path, and a bounded header subset. A second receipt with the same
request id is what request replay means in this harness; we never serve
stored responses as a replay substitute (that would be response replay).
"""
import json
import ssl
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

CERT = sys.argv[1]
KEY = sys.argv[2]
RECEIPTS = sys.argv[3]
PORT = int(sys.argv[4]) if len(sys.argv) > 4 else 8443

SAFE_HEADERS = ("user-agent", "x-d061-fixture", "accept")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _record(self, status: int) -> None:
        parsed = urlparse(self.path)
        req_id = (parse_qs(parsed.query).get("req") or [""])[0]
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "req": req_id,
            "method": self.command,
            "path": parsed.path,
            "status": status,
            "headers": {k.lower(): v for k, v in self.headers.items()
                        if k.lower() in SAFE_HEADERS},
        }
        with open(RECEIPTS, "a") as fh:
            fh.write(json.dumps(entry) + "\n")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        req_id = (parse_qs(parsed.query).get("req") or [""])[0]
        body = json.dumps({"ok": True, "req": req_id, "path": parsed.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self._record(200)

    def do_POST(self) -> None:
        self.send_response(405)
        self.send_header("Content-Length", "0")
        self.end_headers()
        self._record(405)

    do_PUT = do_POST
    do_DELETE = do_POST

    def log_message(self, fmt, *args):  # silence default stderr chatter
        pass


def main() -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    server = HTTPServer(("127.0.0.1", PORT), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print(f"MOCK_ORIGIN_LISTENING port={PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
