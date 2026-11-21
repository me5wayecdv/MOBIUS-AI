"""HELD pinned-native addon, positive local capture/request replay only."""
import hashlib
import json
import os
from pathlib import Path
import traceback

from mitmproxy import ctx, http, io
from wire import append_record, atomic_json, canonical


class Slice:
    def __init__(self):
        self.policy = json.loads(Path(os.environ['D061_NATIVE_POLICY']).read_text())
        self.out = Path(self.policy['output'])
        self.initial_done = False
        self.started = False
        self.completed = False
        self.failed = False

    def record(self, name, data):
        return append_record(self.out/(name+'.json'),data)

    def fail(self, stage, reason):
        self.failed = True
        self.record('addon-failures',{'stage':stage,'reason':reason})

    def validate(self, flow):
        if not isinstance(flow,http.HTTPFlow) or not flow.request:
            raise ValueError('not_http')
        r = flow.request
        if (r.scheme,r.host,r.port)!=('https','127.0.0.1',self.policy['origin_port']):
            raise ValueError('endpoint')
        if r.trailers or flow.websocket:raise ValueError('trailers_or_websocket')
        return canonical(r.method,r.path,r.headers.fields,r.raw_content,self.policy)

    def http_connect(self, flow):
        if (flow.request.host,flow.request.port)!=('127.0.0.1',self.policy['origin_port']):
            self.fail('connect','endpoint')
            flow.response = http.Response.make(403,b'fixture endpoint denied')

    def request(self, flow):
        try:
            self.validate(flow)
            if flow.is_replay == 'request':
                if not self.started or self.completed:raise ValueError('replay_lifecycle')
                self.record('replay-started',{'flow_id':flow.id,'nonce':self.policy['nonce']})
        except Exception as e:
            self.fail('request',type(e).__name__)
            flow.response = http.Response.make(403,b'fixture request denied')

    def response(self, flow):
        try:self.process_response(flow)
        except Exception as e:
            self.fail('response',type(e).__name__)

    def process_response(self, flow):
        fingerprint = self.validate(flow)
        if flow.response.status_code != 200:raise ValueError('non_200')
        self.record('native-events',{'flow_id':flow.id,'is_replay':flow.is_replay,
            'canonical':fingerprint,'raw_headers':[(k.decode('ascii'),v.decode('ascii')) for k,v in flow.request.headers.fields],
            'status':200,'nonce':self.policy['nonce'],'upstream_tls':flow.server_conn.tls})
        if flow.is_replay == 'request':
            if self.completed:raise ValueError('duplicate_replay_completion')
            self.completed = True
            self.record('replay-completed',{'flow_id':flow.id,'nonce':self.policy['nonce']})
            return
        if self.initial_done:raise ValueError('extra_initial_success')
        self.initial_done = True
        capture = self.out/'initial.native'
        with capture.open('xb') as f:
            io.FlowWriter(f).add(flow)
            f.flush()
            os.fsync(f.fileno())
        atomic_json(self.out/'capture-digest.json',{'sha256':hashlib.sha256(capture.read_bytes()).hexdigest(),
            'version':'mitmproxy12.3.1','nonce':self.policy['nonce']})
        if capture.stat().st_size > 256*1024:raise ValueError('capture_bound')
        with capture.open('rb') as f:
            if f.read(4).lstrip(b'\xef\xbb\xbf').startswith(b'{'):raise ValueError('har')
            f.seek(0)
            flows = list(io.FlowReader(f).stream())
        if len(flows)!=1:raise ValueError('flow_count')
        replay = flows[0]
        if self.validate(replay)!=fingerprint:raise ValueError('loaded_policy')
        if replay.request.get_state()!=flow.request.get_state():raise ValueError('saved_request')
        atomic_json(self.out/'native-proof.json',{'extractor':'mitmproxy.io.FlowReader',
            'version':'12.3.1','wheel_sha256':'87afb808ac8d55383dbe6aa30eadeb0fedaeffd26210e7e23c25c9cd43bdb36a',
            'capture_sha256':hashlib.sha256(capture.read_bytes()).hexdigest(),
            'flow_count':1,'flow_id':replay.id,'canonical':self.validate(replay),
            'loaded_request_state_equal':True,'raw_content_present':replay.request.raw_content is not None})
        playback = ctx.master.addons.get('clientplayback')
        if playback is None:raise ValueError('missing_clientplayback')
        eligibility_error = playback.check(replay)
        if eligibility_error is not None:raise ValueError('native_replay_ineligible')
        if self.started:raise ValueError('second_enqueue')
        self.started = True
        self.record('replay-enqueued',{'flow_id':replay.id,'nonce':self.policy['nonce']})
        ctx.master.commands.call('replay.client',[replay])

    def error(self, flow):
        self.fail('http_flow','positive_flow_error')

    def done(self):
        atomic_json(self.out/'addon-final.json',{'initial_done':self.initial_done,
            'replay_enqueued':self.started,'replay_completed':self.completed,'failed':self.failed})


addons = [Slice()]
