"""Owned Android fixed-fixture product contract, disabled without trusted host injection.

The approved target APK is the intended traffic source, unlike native_local_fixture.
No subprocess, namespace, SDK, device, network, model or approval mutation here.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
import re
import secrets
from typing import Mapping

PROFILE='owned-android-fixed-loopback-v1'
PACKAGE='org.mobius.ownedfixture'

@dataclass(frozen=True)
class OwnedAppRequest:
    apk_sha256: str
    public_ca_sha256: str
    plan_sha256: str
    authorization_id: str
    approval_id: str
    investigation_id: str
    plan_id: str
    nonce: str
    profile: str = PROFILE
    package: str = PACKAGE
    proxy_host: str = '127.0.0.1'
    proxy_port: int = 18080
    origin_host: str = '127.0.0.1'
    origin_port: int = 18443
    operation_seconds: int = 60
    teardown_seconds: int = 60
    collection_seconds: int = 10
    max_evidence_bytes: int = 1048576

    @classmethod
    def from_plan(cls,plan):
        encoded=json.dumps(plan.model_dump(mode='json',exclude={'approval_id'}),sort_keys=True,separators=(',',':')).encode()
        return cls(apk_sha256=plan.target_sha256,public_ca_sha256=plan.steps[0].input_values['public_ca_sha256'],
            plan_sha256=hashlib.sha256(encoded).hexdigest(),authorization_id=plan.authorization_id,
            approval_id=plan.approval_id or '',investigation_id=plan.investigation_id,plan_id=plan.id,
            nonce=secrets.token_hex(16))

    def validate(self):
        if self.profile!=PROFILE or self.package!=PACKAGE:raise ValueError('fixed owned APK profile')
        if (self.proxy_host,self.proxy_port,self.origin_host,self.origin_port)!=('127.0.0.1',18080,'127.0.0.1',18443):
            raise ValueError('fixed owned local endpoints')
        for value in (self.apk_sha256,self.public_ca_sha256,self.plan_sha256):
            if not re.fullmatch('[0-9a-f]{64}',value):raise ValueError('required original digest')
        if not re.fullmatch('[0-9a-f]{32}',self.nonce):raise ValueError('required fixed nonce')
        if not all((self.authorization_id,self.approval_id,self.investigation_id,self.plan_id)):raise ValueError('authority binding required')
        if (self.operation_seconds,self.teardown_seconds,self.collection_seconds)!=(60,60,10):
            raise ValueError('fixed bounded operation and cleanup reserve')
        if self.max_evidence_bytes!=1048576:raise ValueError('fixed output ceiling')
        return self


TRAFFIC_SOURCE='owned-android-app-process-fixed-loopback'
REQUIRED=frozenset({
    'payload-privileges.json','binding.json','build-result.json','owned-app-launch.json','owned-app-socket.json',
    'owned-app-completion.json','initial.native','capture-digest.json','native-proof.json',
    'native-events.json','backend-receipts.json','replay-enqueued.json','replay-started.json',
    'replay-completed.json','addon-final.json','adb-cleanup.json','emulator-cleanup.json',
    'driver-cleanup.json','wrapper-cleanup.json','independent-absence.json','collector-summary.json',
})
DIAGNOSTICS=frozenset({'host-failure.json','product-rejection.json','rejected-host-binding.json',
    'policy.json','proxy.log','origin.log','app-log.json','emulator-readiness.json','namespace-setup.json'})


@dataclass(frozen=True)
class OwnedAppOutput:
    binding: OwnedAppRequest
    artifacts: Mapping[str,bytes]
    tool_versions: tuple[str,...]
    status: str = 'failed'
    failure_code: str | None = 'host_not_executed'


class OwnedAppAdapter:
    VERSION='mobius-owned-android/0.1.0-preparation'

    def __init__(self,execute=None):self._execute=execute

    def execute(self,request,*,cancel_check=None):
        request.validate()
        if self._execute is None:raise RuntimeError('owned APK host adapter disabled/unregistered')
        return self._execute(request,cancel_check=cancel_check)

    @staticmethod
    def validate(request,output):
        request.validate()
        if not isinstance(output,OwnedAppOutput) or output.binding!=request:
            raise ValueError('owned APK output binding/type differs')
        files=output.artifacts
        if (not isinstance(files,dict) or len(files)>40 or set(files)-(REQUIRED|DIAGNOSTICS)
            or any(not isinstance(content,bytes) or len(content)>1048576 for content in files.values())
            or sum(map(len,files.values()))>request.max_evidence_bytes):
            raise ValueError('owned APK evidence names/bytes bound')
        def read(name):
            try:return json.loads(files[name])
            except (KeyError,ValueError,UnicodeError) as error:raise ValueError('missing/malformed original '+name) from error
        if read('binding.json')!=asdict(request):raise ValueError('original binding differs')
        if output.status=='failed':
            if output.failure_code not in {'host_failed','host_timeout','host_cancelled','host_cleanup_failed',
                    'host_collection_failed','product_rejected'}:
                raise ValueError('unknown failure code or no actual attempt')
            name='product-rejection.json' if output.failure_code=='product_rejected' else 'host-failure.json'
            failure=read(name)
            if failure.get('code')!=output.failure_code:raise ValueError('original failure diagnostic differs')
            if output.failure_code=='product_rejected' and failure.get('not_a_capture_or_cleanup_proof') is not True:
                raise ValueError('product rejection is not original host/cleanup proof')
            # Failure is retained as failure, never inferred absence or success.
            return
        if output.status!='passed' or output.failure_code is not None or not REQUIRED<=files.keys():
            raise ValueError('owned APK required original evidence/status missing')
        privileges=read('payload-privileges.json')
        status=privileges.get('status','')
        if ('NoNewPrivs:\t1' not in status
            or not all(re.search(r'^'+key+r':\s+0+$',status,re.M) for key in ('CapEff','CapBnd'))):
            raise ValueError('actual runtime postdrop privilege evidence missing')
        if set(privileges.get('devices',[]))!={'null','random','urandom','kvm','shm'}:
            raise ValueError('runtime exact delegated devices differ')
        interfaces=privileges.get('interfaces','').splitlines()
        if len(interfaces)<3 or [line.strip().split(':')[0] for line in interfaces[2:]]!=['lo']:
            raise ValueError('runtime no-uplink interfaces unverified')
        for target in privileges.get('fds',{}).values():
            if target.startswith('socket:[') or target.startswith(('net:[','mnt:[','pid:[')):
                raise ValueError('inherited broker or namespace descriptor')
        build=read('build-result.json')
        if (build.get('tls_scenario','positive')!='positive'
            or build.get('embedded_public_ca_sha256',request.public_ca_sha256)!=request.public_ca_sha256
            or build.get('apk_sha256')!=request.apk_sha256 or build.get('public_ca_sha256')!=request.public_ca_sha256
            or build.get('package')!=PACKAGE or not re.fullmatch('[0-9a-f]{64}',build.get('signature_sha256',''))
            or build.get('actual_app_network_not_executed_by_build') is not True):
            raise ValueError('owned APK build/package/public-CA/signature identity')
        launch=read('owned-app-launch.json');sock=read('owned-app-socket.json');completion=read('owned-app-completion.json')
        if (launch.get('apk_sha256')!=request.apk_sha256 or launch.get('nonce')!=request.nonce
            or launch.get('package')!=PACKAGE or launch.get('observed_process_cmdline')!=PACKAGE
            or launch.get('request')!=asdict(request)):
            raise ValueError('original APK/process launch binding')
        pid=launch.get('pid');uid=launch.get('guest_uid')
        if type(pid) is not int or pid<=0 or type(uid) is not int or uid<10000:
            raise ValueError('real owned app UID/PID required')
        status=launch.get('observed_process_status','')
        match=re.search(r'(?m)^Uid:\s+([0-9]+)\s',status)
        if match is None or int(match.group(1))!=uid:raise ValueError('observed process UID mismatch')
        for item in (sock,completion):
            if (item.get('pid'),item.get('guest_uid'),item.get('nonce'))!=(pid,uid,request.nonce):
                raise ValueError('app UID/PID/nonce evidence correlation')
        if (sock.get('remote_host'),sock.get('remote_port'))!=('127.0.0.1',18080):
            raise ValueError('app socket destination')
        if type(sock.get('local_port')) is not int or not 1024<=sock['local_port']<=65535:
            raise ValueError('observed app socket source port')
        if sock.get('guest_proc_socket_uid')!=uid or sock.get('guest_proc_socket_inode') in (None,'','0'):
            raise ValueError('guest proc socket-to-app UID binding missing')
        if completion.get('completed_count')!=1 or completion.get('failed_count')!=0:
            raise ValueError('owned app terminal request count')
        if not files['initial.native'] or files['initial.native'].lstrip(b'\xef\xbb\xbf').startswith(b'{'):
            raise ValueError('original native bytes missing or JSON substitute')
        capture_hash=hashlib.sha256(files['initial.native']).hexdigest()
        if read('capture-digest.json').get('sha256')!=capture_hash:raise ValueError('original native digest differs')
        proof=read('native-proof.json');events=read('native-events.json');receipts=read('backend-receipts.json')
        if not isinstance(events,list) or not isinstance(receipts,list) or len(events)!=2 or len(receipts)!=2:
            raise ValueError('exact native/backend count')
        canonical={'method':'GET','path':'/receipt?nonce='+request.nonce,'body_bytes':0,
            'body_sha256':hashlib.sha256(b'').hexdigest(),'headers':sorted([
                ['host','127.0.0.1:18443'],['accept','application/json'],['x-d061-nonce',request.nonce]])}
        if any(item.get('canonical')!=canonical or item.get('nonce')!=request.nonce for item in events+receipts):
            raise ValueError('four-way exact APK request wire contract')
        if (events[0].get('is_replay') or events[1].get('is_replay')!='request'
            or events[0].get('flow_id')!=events[1].get('flow_id') or not events[0].get('flow_id')):
            raise ValueError('captured app flow replay identity')
        if any(e.get('status')!=200 or e.get('upstream_tls') is not True for e in events):
            raise ValueError('upstream TLS response evidence')
        if ([r.get('sequence') for r in receipts]!=[1,2] or len({r.get('receipt_id') for r in receipts})!=2
            or any(not r.get('tls_version') for r in receipts)):
            raise ValueError('independent backend TLS receipt identities')
        if (proof.get('extractor')!='mitmproxy.io.FlowReader' or proof.get('version')!='12.3.1'
            or proof.get('wheel_sha256')!='87afb808ac8d55383dbe6aa30eadeb0fedaeffd26210e7e23c25c9cd43bdb36a'
            or proof.get('capture_sha256')!=capture_hash or proof.get('flow_count')!=1
            or proof.get('flow_id')!=events[0]['flow_id'] or proof.get('canonical')!=canonical
            or proof.get('loaded_request_state_equal') is not True or proof.get('raw_content_present') is not True):
            raise ValueError('original native decode provenance differs')
        for name in ('replay-enqueued.json','replay-started.json','replay-completed.json'):
            rows=read(name)
            if len(rows)!=1 or rows[0].get('flow_id')!=events[0]['flow_id'] or rows[0].get('nonce')!=request.nonce:
                raise ValueError('native replay lifecycle differs')
        if read('addon-final.json')!={'initial_done':True,'replay_enqueued':True,'replay_completed':True,'failed':False}:
            raise ValueError('native terminal state differs')
        for name in ('adb-cleanup.json','emulator-cleanup.json','driver-cleanup.json','wrapper-cleanup.json','independent-absence.json'):
            state=read(name)
            if state.get('complete') is not True or state.get('errors')!=[]:
                raise ValueError('stage cleanup/absence incomplete '+name)
        wrapper=read('wrapper-cleanup.json');absence=read('independent-absence.json')
        if wrapper.get('backend') is not None:
            # Closed backend-aware branch. Jail records carry no tag and keep the jail checks below, untouched.
            keys=('inspect_not_found','cgroup_unpopulated_or_gone','ns_members_empty','handles_absent','leader_exit_observed')
            ab=wrapper.get('absence')
            if (wrapper.get('backend')!='docker' or wrapper.get('role')!='runtime' or wrapper.get('errors')!=[]
                or wrapper.get('verdict')!='VERIFIED_ABSENT_RECORD' or wrapper.get('container_absent') is not True
                or not isinstance(ab,dict) or any(ab.get(k) is not True for k in keys)
                or re.fullmatch('[0-9a-f]{64}',str(wrapper.get('container_id'))) is None
                or re.fullmatch('[0-9a-f]{32}',str(wrapper.get('run_id'))) is None
                or 'jail_absent' in wrapper or 'remaining_namespace_members' in wrapper):
                raise ValueError('docker backend wrapper absence unverified or mixed with jail fields')
        elif (wrapper.get('remaining_namespace_members')!=[] or wrapper.get('jail_absent') is not True):
            raise ValueError('independent stage-aware absence unverified')
        if (absence.get('stage_required_records_complete') is not True or absence.get('private_material_absent') is not True
            or absence.get('remaining_namespace_members')!=[] or absence.get('reverse_mappings')!=[]):
            raise ValueError('independent stage-aware absence unverified')
        collector=read('collector-summary.json')
        if (collector.get('success') is not True or collector.get('errors')!=[]
            or collector.get('binding')!=asdict(request) or collector.get('traffic_source')!=TRAFFIC_SOURCE):
            raise ValueError('owned APK collector provenance differs')
        copied={row['path']:row for row in collector.get('copied',[])}
        for name in REQUIRED-{'collector-summary.json'}:
            row=copied.get(name,{})
            if row.get('sha256')!=hashlib.sha256(files[name]).hexdigest() or row.get('bytes')!=len(files[name]):
                raise ValueError('original evidence copy/hash missing '+name)
