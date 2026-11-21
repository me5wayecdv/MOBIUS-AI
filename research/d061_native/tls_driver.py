"""HELD isolated untrusted-proxy-chain negative control, no positive replay."""
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import time

from cleanup import attempt,ordinary_signals_ignored
from wire import atomic_json
from tls_controls import untrusted_proxy_chain,finalize_untrusted_proxy

APPROVED_FOR_EXECUTION = False


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


def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('HELD: exact TLS control harness review required')
    if len(sys.argv)!=3:raise SystemExit('usage: tls_driver.py NEW_OUTPUT ISOLATED_VENV')
    if os.geteuid()==0:raise RuntimeError('nonroot only')
    status=Path('/proc/self/status').read_text()
    if not re.search(r'^CapEff:\s+0+$',status,re.M) or not re.search(r'^CapBnd:\s+0+$',status,re.M) or 'NoNewPrivs:\t1' not in status:
        raise RuntimeError('TLS child capability guard')
    out,venv=(Path(x).resolve() for x in sys.argv[1:])
    out.mkdir(mode=0o700,exist_ok=False);os.umask(0o077)
    home=out/'home';home.mkdir(mode=0o700)
    source=Path(__file__).resolve().parent
    policy={'output':str(out),'origin_port':18443,'proxy_port':18080,'nonce':secrets.token_hex(16),
        'profile':'tls-untrusted-proxy-chain-v1','target':'owned-loopback-fixture'}
    policy_path=out/'policy.json';atomic_json(policy_path,policy)
    # Initialize empty ledger before any service: absence is never taken as zero.
    atomic_json(out/'backend-receipts.json',[])
    env={'PATH':str(venv/'bin')+':/usr/bin:/bin','LANG':'C.UTF-8','HOME':str(home)}
    processes=[];errors=[];control=None;original=None
    def interrupted(signum,frame):raise SystemExit(128+signum)
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,interrupted)
    def start(argv,name):
        with (out/(name+'.log')).open('xb') as log:
            p=subprocess.Popen(argv,env=env,cwd=out,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                close_fds=True,start_new_session=True)
        processes.append((name,p));return p
    try:
        subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-keyout',str(out/'origin.key'),'-out',str(out/'origin.crt'),'-subj','/CN=127.0.0.1',
            '-addext','subjectAltName=IP:127.0.0.1'],env=env,stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,check=True,timeout=15)
        origin=start([str(venv/'bin/python'),str(source/'origin.py'),'--policy',str(policy_path)],'origin')
        conf=home/'proxy-conf'
        proxy=start([str(venv/'bin/mitmdump'),'--mode','regular','--listen-host','127.0.0.1','--listen-port','18080',
            '--set','confdir='+str(conf),'--set','connection_strategy=lazy','--set','http2=false',
            '--set','ssl_verify_upstream_trusted_ca='+str(out/'origin.crt')],'proxy')
        deadline=time.monotonic()+15
        while not all(listener_owned(port,p.pid) for port,p in ((18443,origin),(18080,proxy))) or not (conf/'mitmproxy-ca-cert.pem').is_file():
            if any(p.poll() is not None for _,p in processes):raise RuntimeError('TLS service exited before readiness')
            if time.monotonic()>deadline:raise TimeoutError('TLS listener readiness')
            time.sleep(0.1)
        atomic_json(out/'owned-listeners.json',{'origin_pid':origin.pid,'proxy_pid':proxy.pid,'ports':[18443,18080]})
        control=untrusted_proxy_chain(positive_policy=policy,output=out)
    except BaseException as exc:
        original=exc
    finally:
        with ordinary_signals_ignored():
            for name,p in reversed(processes):
                if p.poll() is None:attempt(errors,'TERM:'+name,lambda p=p:os.killpg(p.pid,signal.SIGTERM))
                attempt(errors,'wait:'+name,lambda p=p:p.wait(timeout=5))
                if p.poll() is None:attempt(errors,'KILL:'+name,lambda p=p:os.killpg(p.pid,signal.SIGKILL))
                attempt(errors,'reap:'+name,lambda p=p:p.wait(timeout=3))
            import shutil
            attempt(errors,'origin_key',lambda:(out/'origin.key').unlink(missing_ok=True))
            if home.exists():attempt(errors,'private_home',lambda:shutil.rmtree(home))
            atomic_json(out/'driver-cleanup.json',{'errors':errors,'private_keys_absent':not (out/'origin.key').exists() and not home.exists(),
                'original_error_class':None if original is None else type(original).__name__})
    if original is not None:raise original
    if errors:raise RuntimeError('TLS control cleanup failed')
    if control is None:raise RuntimeError('TLS control never reached request')
    # Origin/proxy have quiesced. Final explicit retained ledger must remain0.
    if not (out/'backend-receipts.json').is_file():raise RuntimeError('TLS ledger missing')
    finalize_untrusted_proxy(control,output=out)

if __name__=='__main__':main()
