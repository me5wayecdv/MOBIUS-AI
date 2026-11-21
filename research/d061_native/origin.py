#!/usr/bin/env python3
"""PREPARATION ONLY: stdlib fixture, standalone toolchain only, never run here."""
import argparse
import hashlib
import http.server
import json
from pathlib import Path
import ssl
import time

p = argparse.ArgumentParser()
p.add_argument('--policy', required=True)
a = p.parse_args()
policy = json.loads(Path(a.policy).read_text())
output = Path(policy['output'])

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        valid = (self.path == '/receipt?nonce=' + policy['nonce']
                 and self.headers.get('X-D061-Nonce') == policy['nonce']
                 and not self.headers.get('Content-Length')
                 and not self.headers.get('Transfer-Encoding'))
        if not valid:
            self.send_error(403)
            return
        receipt = {'nonce':policy['nonce'], 'method':self.command,
                   'path':self.path, 'headers':list(self.headers.raw_items()),
                   'body_bytes':0,'body_sha256':hashlib.sha256(b'').hexdigest(),
                   'timestamp_ns':time.time_ns(), 'peer':self.client_address[0],
                   'tls_version':self.connection.version()}
        with (output / 'backend-receipts.jsonl').open('a') as f:
            f.write(json.dumps(receipt, sort_keys=True) + '\n')
            f.flush()
        body = json.dumps({'nonce':policy['nonce']}).encode()
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, fmt, *args):
        pass

server = http.server.HTTPServer(('127.0.0.1',policy['origin_port']), Handler)
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.minimum_version = ssl.TLSVersion.TLSv1_2
tls.load_cert_chain(str(output/'origin.crt'), str(output/'origin.key'))
server.socket = tls.wrap_socket(server.socket, server_side=True)
server.serve_forever()
