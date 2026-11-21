#!/usr/bin/env python3
"""Pinned native mitmproxy addon, PREPARATION ONLY, never imported here.

Runs only under separately reviewed standalone runtime. Trusted policy file is
read from harness-generated path, never from flow metadata. Actual captured
HTTPFlow is persisted and its copy queued for native request replay once.
"""
import hashlib
import json
import os
from pathlib import Path
import time

from mitmproxy import ctx, http, io


class Slice:
    def __init__(self):
        self.policy = json.loads(Path(os.environ['D061_NATIVE_POLICY']).read_text())
        self.out = Path(self.policy['output'])
        self.replayed = False
        self.initial_done = False

    def record(self, name, data):
        with (self.out / name).open('a') as f:
            f.write(json.dumps(data, sort_keys=True) + '\n')

    def http_connect(self, flow):
        # Restrict CONNECT destination before TLS/upstream connection handling.
        if (flow.request.host, flow.request.port) != ('127.0.0.1', self.policy['origin_port']):
            flow.response = http.Response.make(403, b'fixture endpoint denied')

    def request(self, flow):
        r = flow.request
        allowed = (
            r.method == 'GET' and r.scheme == 'https'
            and r.host == '127.0.0.1' and r.port == self.policy['origin_port']
            and r.path == '/receipt?nonce=' + self.policy['nonce']
            and r.raw_content in (None, b'')
            and len(r.headers.fields) <= 6
            and all(k.lower() in (b'host', b'accept', b'x-d061-nonce') for k,v in r.headers.fields)
            and all(len(k) <= 64 and len(v) <= 256 for k,v in r.headers.fields)
            and r.headers.get('x-d061-nonce') == self.policy['nonce']
        )
        if not allowed:
            self.record('rejections.jsonl', {'stage':'request','flow':flow.id,'reason':'fixed_policy_mismatch'})
            flow.response = http.Response.make(403, b'fixture request denied')

    def response(self, flow):
        if flow.response.status_code != 200:
            return
        request = flow.request
        body = request.raw_content or b''
        fingerprint = {
            'method':request.method, 'scheme':request.scheme, 'host':request.host,
            'port':request.port, 'path':request.path,
            'headers':[(k.decode('ascii'), v.decode('ascii')) for k,v in request.headers.fields],
            'body_sha256':hashlib.sha256(body).hexdigest(), 'body_bytes':len(body),
        }
        record = {'flow_id':flow.id,'is_replay':flow.is_replay,'request':fingerprint,
                  'status':flow.response.status_code,'nonce':self.policy['nonce'],
                  'upstream_tls':flow.server_conn.tls,
                  'timestamp_start':request.timestamp_start, 'timestamp_end':flow.response.timestamp_end}
        self.record('native-events.jsonl', record)
        if flow.is_replay == 'request':
            self.record('replay-completed.jsonl', {'flow_id':flow.id,'status':200,'nonce':self.policy['nonce']})
            return
        if self.initial_done:
            self.record('rejections.jsonl', {'reason':'extra_initial_success'})
            return
        self.initial_done = True
        capture = self.out / 'initial.native'
        with capture.open('xb') as f:
            io.FlowWriter(f).add(flow)
            f.flush()
            os.fsync(f.fileno())
        self.record('capture-digest.jsonl', {'sha256':hashlib.sha256(capture.read_bytes()).hexdigest(),
                                          'version':'mitmproxy12.3.1','nonce':self.policy['nonce']})
        # Read original native bytes, rather than rebuild from a known URL.
        if capture.stat().st_size > 256*1024:
            raise RuntimeError('capture exceeds bound')
        with capture.open('rb') as f:
            if f.read(4).lstrip(b'\xef\xbb\xbf').startswith(b'{'):
                raise RuntimeError('HAR forbidden')
            f.seek(0)
            flows = list(io.FlowReader(f).stream())
        if len(flows) != 1 or not isinstance(flows[0], http.HTTPFlow):
            raise RuntimeError('one native HTTP capture required')
        replay = flows[0]
        if replay.request.get_state() != request.get_state():
            raise RuntimeError('saved request differs from captured request')
        if self.replayed:
            raise RuntimeError('second replay forbidden')
        self.replayed = True
        ctx.master.commands.call('replay.client', [replay])

    def error(self, flow):
        self.record('native-errors.jsonl', {'flow_id':flow.id,'class':'proxy_flow_error','nonce':self.policy['nonce']})


addons = [Slice()]
