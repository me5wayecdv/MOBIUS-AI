"""HELD stdlib local TLS origin with independent atomic receipts."""
import argparse
import http.server
import json
from pathlib import Path
import ssl
import time

from wire import append_record, canonical

p = argparse.ArgumentParser()
p.add_argument('--policy',required=True)
a = p.parse_args()
policy = json.loads(Path(a.policy).read_text())
out = Path(policy['output'])

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            raw_headers = list(self.headers.raw_items())
            fingerprint = canonical(self.command,self.path,raw_headers,b'',policy)
            receipt = append_record(out/'backend-receipts.json',{
                'receipt_id':policy['nonce']+':'+str(self.server.receipt_count+1),
                'nonce':policy['nonce'],'canonical':fingerprint,
                'raw_headers':raw_headers,'timestamp_ns':time.time_ns(),
                'peer':self.client_address[0],'tls_version':self.connection.version()})
            self.server.receipt_count += 1
            body = json.dumps({'nonce':policy['nonce']}).encode()
            self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            append_record(out/'backend-failures.json',{'class':type(e).__name__})
            self.send_error(403)
    def log_message(self,fmt,*args):pass

server = http.server.HTTPServer(('127.0.0.1',policy['origin_port']),Handler)
server.receipt_count = 0
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.minimum_version = ssl.TLSVersion.TLSv1_2
tls.load_cert_chain(str(out/'origin.crt'),str(out/'origin.key'))
server.socket = tls.wrap_socket(server.socket,server_side=True)
server.serve_forever()
