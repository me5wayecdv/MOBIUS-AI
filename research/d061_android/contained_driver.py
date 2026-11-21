"""HELD fixed owned-APK inner runtime driver. No execution on import.

Provisioning is separate from committed action. Only the trusted sibling relay
can publish /control/commit.json. Root owns that read-only mount. This source
cannot grant permission or supply the still-unresolved toolchain/runtime closure.
"""
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time

from handoff_io import read,write,json_write,wait,digest
from handoff_protocol import validate_commit,canonical,READY_VERSION
from mobius.services.owned_android_fixture import OwnedAppRequest,PROFILE,PACKAGE
from adb_scope import FixedPrivateADB
from emulator_scope import PrivateEmulator,validate_listeners,socket_rows

APPROVED_FOR_EXECUTION = False
PYTHON='/runtime/bin/python'
NATIVE=Path('/fixture/native')


class Producers:
    def __init__(self,env):self.env=env;self.rows=[]
    def start(self,argv,name,out):
        log=(out/(name+'.log')).open('xb')
        child=subprocess.Popen(list(map(str,argv)),env=self.env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,close_fds=True,start_new_session=True)
        os.set_blocking(child.stdout.fileno(),False)
        self.rows.append({'name':name,'child':child,'log':log,'bytes':0});return child
    def pump(self):
        for row in self.rows:
            if row.get('closed'):continue
            while True:
                try:data=os.read(row['child'].stdout.fileno(),4096)
                except BlockingIOError:break
                if not data:break
                left=65536-row['bytes'];row['log'].write(data[:left]);row['bytes']+=min(left,len(data));row['log'].flush()
                if len(data)>left:raise ValueError('fixed producer log ceiling')
    def stop(self):
        errors=[]
        for row in reversed(self.rows):
            if row.get('closed'):continue
            child=row['child']
            try:
                if child.poll() is None:
                    os.killpg(child.pid,signal.SIGINT if row['name']=='proxy' else signal.SIGTERM)
                    try:child.wait(timeout=3)
                    except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=3)
            except BaseException as error:errors.append(type(error).__name__)
        try:self.pump()
        except BaseException as error:errors.append(type(error).__name__)
        for row in self.rows:
            if not row.get('closed'):
                row['log'].close();row['child'].stdout.close();row['closed']=True
        if errors:raise RuntimeError('producer cleanup errors '+','.join(errors))


def owned_listener(port,pid):
    inodes={r['inode'] for r in socket_rows() if r['state']=='0A' and r['address']=='0100007F' and r['port']==port}
    fds=set()
    for fd in Path('/proc/'+str(pid)+'/fd').iterdir():
        try:target=os.readlink(fd)
        except FileNotFoundError:continue
        if target.startswith('socket:['):fds.add(target[8:-1])
    return bool(inodes) and inodes<=fds


def proxy_argv(home,out):
    return ['/runtime/bin/mitmdump','--mode','regular','--listen-host','127.0.0.1','--listen-port','18080',
        '--set','confdir='+str(home/'proxy-conf'),'--set','ssl_verify_upstream_trusted_ca='+str(out/'origin.crt'),
        '--set','connection_strategy=lazy','--set','http2=false','--set','client_replay_concurrency=1',
        '-s',str(NATIVE/'addon.py')]


def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('HELD complete sibling source/closure/lifecycle review required')
    if os.geteuid()==0:raise RuntimeError('unprivileged runtime payload required')
    status=Path('/proc/self/status').read_text()
    if ('NoNewPrivs:\t1' not in status or not all(re.search(r'^'+x+r':\s+0+$',status,re.M) for x in ('CapEff','CapBnd'))):
        raise RuntimeError('actual postdrop capability/no-new-privs mismatch')
    work=Path('/work');out=work/'evidence';out.mkdir(mode=0o700)
    ctx=json.loads(read('/control/context.json',65536))
    json_write(out/'payload-privileges.json',{'status':status,'namespace':os.readlink('/proc/self/ns/net'),
        'fds':{p.name:os.readlink(p) for p in Path('/proc/self/fd').iterdir() if p.exists()},
        'mountinfo':Path('/proc/self/mountinfo').read_text(),
        'interfaces':Path('/proc/net/dev').read_text(),'routes4':Path('/proc/net/route').read_text(),'devices':sorted(p.name for p in Path('/dev').iterdir())})
    started=time.monotonic();provision_deadline=started+240
    home=out/'home';home.mkdir(mode=0o700)
    env={'PATH':'/runtime/bin:/usr/bin:/bin','HOME':str(home),'LANG':'C.UTF-8','TMPDIR':'/tmp',
        'PYTHONPATH':str(NATIVE),'D061_NATIVE_POLICY':str(out/'policy.json')}
    emulator=None;adb=None;producers=Producers(env);request=None;failure=None;cleanup_errors=[];operation_started=None
    def pump():
        producers.pump()
        if emulator is not None:emulator.drain_logs()
    try:
        # No app request/probe. Local certificate generation only, no CA private
        # material is put into the APK/public snapshot.
        subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(out/'origin.key'),
            '-out',str(out/'origin.crt'),'-days','1','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'],
            env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,check=True,timeout=15)
        policy={'output':str(out),'origin_port':18443,'proxy_port':18080,'nonce':'0'*32,
            'profile':PROFILE,'traffic_source':'owned-android-app-process-fixed-loopback'}
        json_write(out/'policy.json',policy)
        proxy=producers.start(proxy_argv(home,out),'proxy',out)
        ca=home/'proxy-conf/mitmproxy-ca-cert.pem'
        while not (ca.is_file() and owned_listener(18080,proxy.pid)):
            pump()
            if time.monotonic()>min(provision_deadline,started+20) or proxy.poll() is not None:
                raise TimeoutError('proxy public CA/listener provisioning failed')
            time.sleep(.05)
        producers.stop()
        # Provisioning addon terminal record is not an operation original. Keep
        # it separately and require empty request/origin ledgers before handoff.
        if (out/'initial.native').exists() or (out/'backend-receipts.json').exists():raise ValueError('unexpected preapproval traffic')
        if (out/'addon-final.json').exists():(out/'addon-final.json').rename(out/'provision-addon-final.json')
        (out/'proxy.log').rename(out/'provision-proxy.log')
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        public_ca=x509.load_pem_x509_certificate(read(ca,16384)).public_bytes(Encoding.DER)
        public_path=work/'public-ca.der';write(public_path,public_ca)
        subprocess.run([PYTHON,'/fixture/build_owned.py','--toolchain-root','/opt/android',
            '--toolchain-lock','/fixture/build-lock.json','--public-proxy-ca',str(public_path),
            '--public-ca-sha256',digest(public_ca),'--output',str(work/'build')],env=env,
            stdin=subprocess.DEVNULL,close_fds=True,check=True,timeout=min(120,max(.1,provision_deadline-time.monotonic())))
        build_bytes=read(work/'build/build-result.json',65536);build=json.loads(build_bytes)
        apk=read(work/'build/owned-fixture.apk',4*1024**2)
        adb_home=Path('/home/fixture/adb-home');adb_home.mkdir(mode=0o700)
        adb=FixedPrivateADB('/opt/android/platform-tools/adb',None,private_home=adb_home,output=out,host_netns=ctx['host_netns'])
        emulator=PrivateEmulator(out,host_netns=ctx['host_netns']);emulator.boot(adb)
        if time.monotonic()>provision_deadline:raise TimeoutError('fixed whole provisioning deadline')
        existing=adb.command(['shell','pm','path',PACKAGE],check=False)
        if existing.strip() or adb.records[-1]['rc'] not in (0,1):raise ValueError('owned package not absent before ready')
        if (out/'initial.native').exists() or (out/'backend-receipts.json').exists():raise ValueError('preapproval original/receipt appeared')
        json_write(out/'provision-zero-state.json',{'owned_package_query':existing,'owned_package_query_rc':adb.records[-1]['rc'],
            'owned_package_absent':True,'native_original_absent':True,'origin_receipts_absent':True,
            'source':'observed fixed readiness and on-disk inventories, no app launch'})
        ready={'version':READY_VERSION,'profile':PROFILE,'package':PACKAGE,'apk_sha256':digest(apk),
            'public_ca_sha256':digest(public_ca),'build_json_sha256':digest(build_bytes),
            'source_manifest_sha256':ctx['source_manifest_sha256'],'run_id':ctx['run_id'],
            'provisioning_id':ctx['provisioning_id'],'closure_sha256':ctx['closure_sha256'],
            'original_count':0,'origin_receipt_count':0,'apk_installed':False,'apk_launched':False}
        public=work/'provision';public.mkdir(mode=0o755)
        write(public/'owned-fixture.apk',apk);write(public/'public-ca.der',public_ca)
        write(public/'build-result.json',build_bytes);json_write(public/'ready.json',ready)
        # Root must snapshot public bytes before they become an approved input.
        raw=wait('/control/commit.json',deadline=time.monotonic()+30,pump=pump)
        commit=json.loads(raw);expected=OwnedAppRequest(**commit['request'])
        request=validate_commit(commit,ready_metadata=ready,expected_request=expected)
        operation_started=time.monotonic();adb.bind_request(request)
        # Policy nonce is service-created after approval; no source/model/client URL.
        (out/'policy.json').unlink();policy['nonce']=request.nonce;json_write(out/'policy.json',policy)
        write(out/'binding.json',canonical(commit['request']));write(out/'build-result.json',build_bytes)
        producers=Producers(env)
        origin=producers.start([PYTHON,NATIVE/'origin.py','--policy',out/'policy.json'],'origin',out)
        proxy=producers.start(proxy_argv(home,out),'proxy',out)
        for port,process in ((18443,origin),(18080,proxy)):
            while not owned_listener(port,process.pid):
                pump()
                if process.poll() is not None or time.monotonic()-operation_started>10:raise RuntimeError('owned operation listener missing')
                time.sleep(.05)
        validate_listeners(socket_rows(),proxy_origin_ready=True)
        launch=adb.launch_owned(work/'build/owned-fixture.apk');adb.commit_owned(launch)
        adb.attribute_socket_and_release(launch)
        wait(out/'replay-completed.json',deadline=operation_started+60,pump=pump)
        adb.completion(launch)
        if time.monotonic()-operation_started>60:raise TimeoutError('fixed operation60 exceeded')
        json_write(out/'operation-returned.json',{'elapsed_seconds':time.monotonic()-operation_started,
            'request':commit['request'],'operation_completed':True})
    except BaseException as error:
        failure=error
        json_write(out/'host-failure.json',{'code':'host_timeout' if isinstance(error,TimeoutError) else 'host_failed',
            'original_error':type(error).__name__,'request_bound':request is not None,'not_a_cleanup_proof':True})
    finally:
        teardown=time.monotonic()
        for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,signal.SIG_IGN)
        if adb is not None and request is not None:
            try:adb.cleanup()
            except BaseException as error:cleanup_errors.append({'stage':'adb','class':type(error).__name__})
        try:producers.stop()
        except BaseException as error:cleanup_errors.append({'stage':'producers','class':type(error).__name__})
        if emulator is not None:
            try:emulator.cleanup()
            except BaseException as error:cleanup_errors.append({'stage':'emulator','class':type(error).__name__})
        for sensitive in (home,work/'build/private-build-home',out/'origin.key'):
            try:
                if sensitive.is_dir():shutil.rmtree(sensitive)
                else:sensitive.unlink(missing_ok=True)
            except BaseException as error:cleanup_errors.append({'stage':'private_material','class':type(error).__name__})
        if time.monotonic()-teardown>60:cleanup_errors.append({'stage':'teardown','class':'TimeoutError'})
        json_write(out/'driver-cleanup.json',{'complete':not cleanup_errors,'errors':cleanup_errors,
            'private_keys_absent':not home.exists() and not (out/'origin.key').exists(),
            'operation_elapsed_seconds':None if operation_started is None else time.monotonic()-operation_started,
            'runtime_namespace_absence':'REQUIRES_TRUSTED_OUTER_CHECK'})
    if failure:raise failure
    if cleanup_errors:raise RuntimeError('runtime cleanup incomplete')


if __name__=='__main__':main()
