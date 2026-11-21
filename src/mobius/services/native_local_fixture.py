"""Disabled-by-default local native host adapter, never elevates API privileges.

A trusted ephemeral CI host may supply a typed implementation. Product plans
cannot provide argv, paths, URLs or scripts. Existing APK is an authorization
anchor only; this fixture is not APK runtime traffic.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import secrets
from typing import Callable, Mapping

from ..core.schemas import PoCTestPlan
from .poc_runner import PoCAdapterUnavailable, PoCExecutionError

PROFILE = 'trusted-local-positive-v1'
TRAFFIC_SOURCE = 'owned-stdlib-loopback-client-not-apk'
REQUIRED = frozenset({
    'native-proof.json','initial.native','capture-digest.json','backend-receipts.json','native-events.json',
    'replay-enqueued.json','replay-started.json','replay-completed.json','addon-final.json',
    'driver-cleanup.json','wrapper-cleanup.json','emergency-cleanup.json','collector-summary.json',
    'binding.json',
})

@dataclass(frozen=True)
class NativeFixtureRequest:
    investigation_id: str
    plan_id: str
    authorization_id: str
    approval_id: str
    anchor_apk_sha256: str
    anchor_package: str
    plan_sha256: str
    nonce: str
    profile: str = PROFILE
    traffic_source: str = TRAFFIC_SOURCE
    budget_seconds: int = 60

    @classmethod
    def from_plan(cls, plan: PoCTestPlan):
        encoded=json.dumps(plan.model_dump(mode='json',exclude={'approval_id'}),
                           sort_keys=True,separators=(',',':')).encode()
        return cls(plan.investigation_id,plan.id,plan.authorization_id,plan.approval_id or '',
                   plan.target_sha256,plan.target_package,hashlib.sha256(encoded).hexdigest(),
                   secrets.token_hex(16),budget_seconds=plan.steps[0].timeout_seconds)

@dataclass(frozen=True)
class NativeFixtureOutput:
    binding: NativeFixtureRequest
    artifacts: Mapping[str, bytes]
    tool_versions: tuple[str,...]


class NativeLocalFixtureAdapter:
    VERSION = 'mobius-native-local/0.1.0-preparation'

    def __init__(self, host_execute: Callable[[NativeFixtureRequest],NativeFixtureOutput] | None = None):
        self._host_execute=host_execute

    def execute(self, request: NativeFixtureRequest) -> NativeFixtureOutput:
        if self._host_execute is None:
            raise PoCAdapterUnavailable('native local host executor is not configured')
        output=self._host_execute(request)
        self.validate(request,output)
        return output

    @staticmethod
    def validate(request: NativeFixtureRequest, output: NativeFixtureOutput) -> None:
        if output.binding!=request or request.profile!=PROFILE or request.traffic_source!=TRAFFIC_SOURCE:
            raise PoCExecutionError('native host identity/profile mismatch')
        files=output.artifacts
        if (not REQUIRED<=files.keys() or len(files)>40
            or any(name not in REQUIRED|{'policy.json','proxy.log','origin.log'} for name in files)):
            raise PoCExecutionError('native required original evidence missing')
        if any(not isinstance(v,bytes) or len(v)>4*1024*1024 for v in files.values()) or sum(map(len,files.values()))>32*1024*1024:
            raise PoCExecutionError('native evidence bound')
        def read(name):return json.loads(files[name])
        binding=read('binding.json')
        from dataclasses import asdict
        if binding!=asdict(request):raise PoCExecutionError('retained binding differs from host request')
        if not files['initial.native'] or files['initial.native'].lstrip(b'\xef\xbb\xbf').startswith(b'{'):
            raise PoCExecutionError('native capture absent or HAR')
        digest=hashlib.sha256(files['initial.native']).hexdigest()
        if read('capture-digest.json')['sha256']!=digest:raise PoCExecutionError('native digest mismatch')
        receipts,events=read('backend-receipts.json'),read('native-events.json')
        if len(receipts)!=2 or len(events)!=2:raise PoCExecutionError('native final counts')
        if [r['sequence'] for r in receipts]!=[1,2] or len({r['receipt_id'] for r in receipts})!=2:
            raise PoCExecutionError('independent receipt identity')
        if any(r['nonce']!=request.nonce for r in receipts+events):raise PoCExecutionError('native case nonce')
        if events[0]['is_replay'] or events[1]['is_replay']!='request' or events[0]['flow_id']!=events[1]['flow_id']:
            raise PoCExecutionError('native request replay identity')
        canonical=events[0]['canonical']
        if (canonical['method']!='GET' or canonical['path']!='/receipt?nonce='+request.nonce
            or canonical['body_bytes']!=0
            or canonical['body_sha256']!=hashlib.sha256(b'').hexdigest()
            or canonical['headers']!=sorted([['accept','application/json'],['host','127.0.0.1:18443'],['x-d061-nonce',request.nonce]])):
            raise PoCExecutionError('fixed request policy')
        if any(r['canonical']!=canonical for r in receipts+events):raise PoCExecutionError('four-way mismatch')
        if any(not e['upstream_tls'] or e['status']!=200 for e in events) or any(not r['tls_version'] for r in receipts):
            raise PoCExecutionError('positive TLS missing')
        for name in ('replay-enqueued.json','replay-started.json','replay-completed.json'):
            rows=read(name)
            if len(rows)!=1 or rows[0]['nonce']!=request.nonce or rows[0]['flow_id']!=events[0]['flow_id']:
                raise PoCExecutionError('native lifecycle mismatch')
        if read('addon-final.json')!={'initial_done':True,'replay_enqueued':True,'replay_completed':True,'failed':False}:
            raise PoCExecutionError('native terminal state')
        for name in ('driver-cleanup.json','wrapper-cleanup.json','emergency-cleanup.json'):
            state=read(name)
            if state['errors'] or state.get('complete',True) is not True:
                raise PoCExecutionError('native cleanup incomplete')
        if not read('wrapper-cleanup.json')['private_keys_absent'] or not read('driver-cleanup.json')['private_keys_absent']:
            raise PoCExecutionError('native private keys remain')
        if read('wrapper-cleanup.json')['remaining_namespace_members']!=[]:
            raise PoCExecutionError('native namespace members remain')
        collector=read('collector-summary.json')
        if collector['command_rc']!=0 or not collector['success'] or collector['errors']:
            raise PoCExecutionError('native collector failed')
        manifest={row['path']:row for row in collector['copied']}
        for name in REQUIRED-{'collector-summary.json'}:
            if name not in manifest or manifest[name]['sha256']!=hashlib.sha256(files[name]).hexdigest() or manifest[name]['bytes']!=len(files[name]):
                raise PoCExecutionError('native original artifact was not copied/hash-verified')
        if collector.get('binding')!=binding or collector.get('mode')!='product_positive_fixture':
            raise PoCExecutionError('native collector product binding mismatch')
        # Actual native decoding is owned by the exact trusted host/addon,
        # not this stdlib JSON/blob validator. Require its pinned extractor
        # provenance bound to original native bytes and cross-check projections.
        proof=read('native-proof.json')
        if (proof['extractor']!='mitmproxy.io.FlowReader' or proof['version']!='12.3.1'
            or proof['wheel_sha256']!='87afb808ac8d55383dbe6aa30eadeb0fedaeffd26210e7e23c25c9cd43bdb36a'
            or proof['capture_sha256']!=digest or proof['flow_count']!=1
            or proof['flow_id']!=events[0]['flow_id'] or proof['canonical']!=canonical
            or not proof['loaded_request_state_equal'] or not proof['raw_content_present']):
            raise PoCExecutionError('trusted host native extractor provenance mismatch')
