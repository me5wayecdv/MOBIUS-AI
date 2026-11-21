"""HELD positive-only native capture/request replay driver, never run here."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import time

from wire import atomic_json
from cleanup import attempt, error_record, ordinary_signals_ignored

APPROVED_FOR_EXECUTION = False

def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('HELD: exact installer/wrapper/harness review required')
    if len(sys.argv)!=3:raise SystemExit('usage: driver.py FRESH_OUTPUT ISOLATED_VENV')
    if os.geteuid()==0:raise RuntimeError('nonroot required')
    status = Path('/proc/self/status').read_text()
    if (not re.search(r'^CapEff:\s+0+$',status,re.M)
        or not re.search(r'^CapBnd:\s+0+$',status,re.M) or 'NoNewPrivs:\t1' not in status):
        raise RuntimeError('capability/no-new-privs guard')
    out,venv = (Path(x).resolve() for x in sys.argv[1:])
    out.mkdir(mode=0o700,parents=False,exist_ok=False)
    os.umask(0o077)
    home = out/'home'
    home.mkdir(mode=0o700)
    root = Path(__file__).resolve().parent
    policy = {'output':str(out),'origin_port':18443,'proxy_port':18080,
              'nonce':secrets.token_hex(16),'profile':'trusted-local-positive-v1',
              'target':'owned-loopback-fixture'}
    product_binding=Path('/work/binding.json')
    if product_binding.exists():
        binding=json.loads(product_binding.read_text())
        if (binding.get('profile')!=policy['profile']
            or binding.get('traffic_source')!='owned-stdlib-loopback-client-not-apk'
            or not re.fullmatch('[0-9a-f]{32}',binding.get('nonce',''))):
            raise RuntimeError('trusted product binding mismatch')
        policy['nonce']=binding['nonce']
        policy['product_binding']=binding
        atomic_json(out/'binding.json',binding)
    policy_path = out/'policy.json'
    atomic_json(policy_path,policy)
    env = {'PATH':str(venv/'bin')+':/usr/bin:/bin','LANG':'C.UTF-8',
           'HOME':str(home),'D061_NATIVE_POLICY':str(policy_path)}
    processes = []
    quiesced = False
    def interrupted(signum,frame):raise SystemExit(128+signum)
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,interrupted)
    def start(argv,name):
        with (out/(name+'.log')).open('xb') as log:
            p = subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                env=env,cwd=out,close_fds=True,start_new_session=True)
        processes.append((name,p))
        return p
    def stop(original=None):
        cleanup = {'processes':[],'errors':[],'original_error':error_record(original)}
        errors=cleanup['errors']
        with ordinary_signals_ignored():
            for name,p in reversed(processes):
                if p.poll() is None:
                    attempt(errors,'signal:'+name,lambda p=p,name=name:os.killpg(p.pid,signal.SIGINT if name=='proxy' else signal.SIGTERM))
                attempt(errors,'wait:'+name,lambda p=p:p.wait(timeout=5))
                if p.poll() is None:
                    attempt(errors,'kill:'+name,lambda p=p:os.killpg(p.pid,signal.SIGKILL))
                    attempt(errors,'reap:'+name,lambda p=p:p.wait(timeout=3))
                cleanup['processes'].append({'name':name,'pid':p.pid,'exit_code':p.poll()})
                if p.poll() is None:errors.append({'stage':name,'class':'process_remains'})
            import shutil
            attempt(errors,'remove_origin_key',lambda:(out/'origin.key').unlink(missing_ok=True))
            if home.exists():attempt(errors,'remove_private_home',lambda:shutil.rmtree(home))
            cleanup['private_keys_absent']=not ((out/'origin.key').exists() or home.exists())
            if not cleanup['private_keys_absent']:errors.append({'stage':'keys','class':'private_keys_remain'})
            attempt(errors,'write_driver_cleanup',lambda:atomic_json(out/'driver-cleanup.json',cleanup))
        return cleanup
    def read(name):return json.loads((out/(name+'.json')).read_text())
    def listener_owned(port,pid):
        inodes=set()
        for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
            fields=line.split()
            if fields[1]=='0100007F:'+format(port,'04X') and fields[3]=='0A':inodes.add(fields[9])
        owned=set()
        for fd in Path('/proc/'+str(pid)+'/fd').iterdir():
            try:target=os.readlink(fd)
            except FileNotFoundError:continue
            if target.startswith('socket:['):owned.add(target[8:-1])
        return bool(inodes) and inodes<=owned
    try:
        subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes',
            '-keyout',str(out/'origin.key'),'-out',str(out/'origin.crt'),'-days','1',
            '-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'],
            env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            close_fds=True,check=True,timeout=15)
        origin=start([str(venv/'bin/python'),str(root/'origin.py'),'--policy',str(policy_path)],'origin')
        conf=home/'proxy-conf'
        proxy=start([str(venv/'bin/mitmdump'),'--mode','regular',
            '--listen-host','127.0.0.1','--listen-port','18080',
            '--set','confdir='+str(conf),'--set','ssl_verify_upstream_trusted_ca='+str(out/'origin.crt'),
            '--set','connection_strategy=lazy','--set','http2=false',
            '--set','client_replay_concurrency=1','-s',str(root/'addon.py')],'proxy')
        ca=conf/'mitmproxy-ca-cert.pem'
        for port,p in ((18443,origin),(18080,proxy)):
            deadline=time.monotonic()+15
            while True:
                if origin.poll() is not None or proxy.poll() is not None:raise RuntimeError('premature fixture exit')
                if listener_owned(port,p.pid) and ca.is_file():break
                if time.monotonic()>deadline:raise TimeoutError('owned listener/CA readiness')
                time.sleep(0.1)
        # /proc ownership readiness makes no TCP/TLS abort probes at all.
        atomic_json(out/'owned-listeners.json',{'origin_pid':origin.pid,'proxy_pid':proxy.pid,'ports':[18443,18080]})
        client=http.client.HTTPSConnection('127.0.0.1',18080,
            context=ssl.create_default_context(cafile=str(ca)),timeout=5)
        client.set_tunnel('127.0.0.1',18443)
        client.putrequest('GET','/receipt?nonce='+policy['nonce'],skip_accept_encoding=True)
        client.putheader('Accept','application/json')
        client.putheader('X-D061-Nonce',policy['nonce'])
        client.endheaders()
        response=client.getresponse()
        body=response.read(4096)
        client.close()
        if response.status!=200 or json.loads(body).get('nonce')!=policy['nonce']:raise RuntimeError('initial response')
        deadline=time.monotonic()+10
        while not (out/'replay-completed.json').exists():
            if (out/'addon-failures.json').exists():raise RuntimeError('addon positive failure')
            if proxy.poll() is not None:raise RuntimeError('proxy exited')
            if time.monotonic()>deadline:raise TimeoutError('native request replay')
            time.sleep(0.1)
        cleanup=stop()
        quiesced=True
        if cleanup['errors']:raise RuntimeError('driver cleanup incomplete')
        # All producers stopped before exact counts and durable terminal state.
        receipts,events=read('backend-receipts'),read('native-events')
        final=read('addon-final')
        if final!={'initial_done':True,'replay_enqueued':True,'replay_completed':True,'failed':False}:
            raise RuntimeError('addon terminal evidence')
        if len(receipts)!=2 or len(events)!=2:raise RuntimeError('exact final count')
        if len({r['receipt_id'] for r in receipts})!=2 or [r['sequence'] for r in receipts]!=[1,2]:
            raise RuntimeError('receipt identity/order')
        if events[0]['is_replay'] or events[1]['is_replay']!='request':raise RuntimeError('replay classification')
        if not all(e['upstream_tls'] for e in events):raise RuntimeError('upstream TLS missing')
        canonical_request=events[0]['canonical']
        if any(x['canonical']!=canonical_request for x in events+receipts):raise RuntimeError('four-way wire mismatch')
        if not all(r['nonce']==policy['nonce'] and r['tls_version'] for r in receipts):raise RuntimeError('receipt TLS/nonce')
        for name in ('replay-enqueued','replay-started','replay-completed'):
            if len(read(name))!=1:raise RuntimeError('replay lifecycle count')
        for name in ('addon-failures','backend-failures'):
            if (out/(name+'.json')).exists():raise RuntimeError('positive fixture failure')
        logs=(out/'proxy.log').read_text()+(out/'origin.log').read_text()
        if re.search(r'\b(error|exception|traceback)\b',logs,re.I):raise RuntimeError('positive proxy/origin log error')
        atomic_json(out/'candidate-result.json',{'status':'POSITIVE_LOCAL_FIXTURE_ONLY',
            'tls_negative_controls':'UNTESTED','profile':policy['profile'],'nonce':policy['nonce'],
            'receipts':2,'cleanup_complete':True,
            'capture_sha256':hashlib.sha256((out/'initial.native').read_bytes()).hexdigest()})
    except BaseException as original:
        with ordinary_signals_ignored():
            failure={'original_error':error_record(original),'cleanup_errors':[]}
            if not quiesced:
                cleanup=attempt(failure['cleanup_errors'],'driver_stop',lambda:stop(original))
                if cleanup is not None:failure['cleanup_errors'].extend(cleanup['errors'])
            attempt(failure['cleanup_errors'],'write_failure',lambda:atomic_json(out/'driver-failure.json',failure))
            attempt(failure['cleanup_errors'],'invalidate_candidate',lambda:(out/'candidate-result.json').unlink(missing_ok=True))
        raise

if __name__=='__main__':main()
