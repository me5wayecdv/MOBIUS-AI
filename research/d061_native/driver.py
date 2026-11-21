#!/usr/bin/env python3
"""Disabled standalone local fixture driver. Preparation, NOT executed evidence.

Requires later source-specific reviewed activation patch. No environment flag
bypasses this file's operational hold. No product imports or target adapters.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import time

APPROVED_FOR_EXECUTION = False

def main():
    if not APPROVED_FOR_EXECUTION:
        raise SystemExit('HELD: concrete toolchain and harness review required')
    if len(sys.argv) != 3:
        raise SystemExit('usage: driver.py FRESH_OUTPUT_DIR ISOLATED_VENV')
    out = Path(sys.argv[1]).resolve()
    venv = Path(sys.argv[2]).resolve()
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.umask(0o077)
    root = Path(__file__).resolve().parent
    policy = {'output':str(out), 'origin_port':18443, 'proxy_port':18080,
              'nonce':secrets.token_hex(16), 'profile':'trusted-fixed-local-tls-v1',
              'target':'standalone-owned-loopback-fixture'}
    policy_path = out/'policy.json'
    policy_path.write_text(json.dumps(policy, sort_keys=True)+'\n')
    processes = []
    result = None
    def start(argv, name, env=None):
        log = (out/(name+'.log')).open('xb')
        p = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,
                             env=env, start_new_session=True)
        log.close()
        processes.append(p)
        return p
    try:
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes',
            '-keyout',str(out/'origin.key'),'-out',str(out/'origin.crt'),
            '-days','1','-subj','/CN=127.0.0.1',
            '-addext','subjectAltName=IP:127.0.0.1'],check=True,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
        origin = start([str(venv/'bin/python'),str(root/'origin.py'),
                        '--policy',str(policy_path)],'origin')
        conf = out/'proxy-conf'
        env = {k:v for k,v in os.environ.items() if k in ('PATH','LANG','LC_ALL')}
        env.update({'HOME':str(out),'D061_NATIVE_POLICY':str(policy_path)})
        proxy = start([str(venv/'bin/mitmdump'),'--listen-host','127.0.0.1',
             '--listen-port','18080','--set','confdir='+str(conf),
             '--set','ssl_verify_upstream_trusted_ca='+str(out/'origin.crt'),
             '--set','connection_strategy=lazy','--set','http2=false',
             '--set','client_replay_concurrency=1','-s',str(root/'addon.py')], 'proxy',env)
        ca = conf/'mitmproxy-ca-cert.pem'
        deadline = time.monotonic()+15
        while not ca.is_file():
            if proxy.poll() is not None or origin.poll() is not None:
                raise RuntimeError('fixture process exited before ready')
            if time.monotonic()>deadline:raise TimeoutError('CA readiness')
            time.sleep(0.1)
        # TCP-only readiness, never an application probe or successful request.
        for port in (18443,18080):
            deadline = time.monotonic()+5
            while True:
                if proxy.poll() is not None or origin.poll() is not None:
                    raise RuntimeError('fixture process exited before socket ready')
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=0.2):
                        break
                except OSError:
                    if time.monotonic()>deadline:raise TimeoutError('fixture listener readiness')
                    time.sleep(0.1)
        # One initial request. A failure stays failed, no model or client retries.
        context = ssl.create_default_context(cafile=str(ca))
        client = http.client.HTTPSConnection('127.0.0.1',18080,context=context,timeout=5)
        client.set_tunnel('127.0.0.1',18443)
        client.putrequest('GET','/receipt?nonce='+policy['nonce'], skip_accept_encoding=True)
        client.putheader('Accept','application/json')
        client.putheader('X-D061-Nonce',policy['nonce'])
        client.endheaders()
        response = client.getresponse()
        body = response.read(4096)
        client.close()
        if response.status != 200 or json.loads(body).get('nonce') != policy['nonce']:
            raise RuntimeError('initial response mismatch')
        deadline = time.monotonic()+10
        done = out/'replay-completed.jsonl'
        while not done.exists():
            if time.monotonic()>deadline:raise TimeoutError('native request replay')
            if proxy.poll() is not None:raise RuntimeError('proxy exited')
            time.sleep(0.1)
        receipts = [json.loads(x) for x in (out/'backend-receipts.jsonl').read_text().splitlines()]
        events = [json.loads(x) for x in (out/'native-events.jsonl').read_text().splitlines()]
        if len(receipts)!=2 or len(events)!=2:raise RuntimeError('exactly two independent receipts and events required')
        if events[1]['is_replay']!='request' or events[0]['is_replay']:
            raise RuntimeError('native replay classification mismatch')
        if events[0]['request']!=events[1]['request']:raise RuntimeError('native replay request differs')
        if not all(e['upstream_tls'] for e in events):raise RuntimeError('upstream TLS missing')
        if not all(r['nonce']==policy['nonce'] and r['tls_version'] for r in receipts):
            raise RuntimeError('independent backend receipt mismatch')
        def canonical_headers(items):
            return sorted((k.lower(),v) for k,v in items)
        for receipt,event in zip(receipts,events):
            req = event['request']
            if (receipt['method'] != req['method'] or receipt['path'] != req['path']
                or receipt['body_sha256'] != req['body_sha256']
                or receipt['body_bytes'] != req['body_bytes']
                or canonical_headers(receipt['headers']) != canonical_headers(req['headers'])):
                raise RuntimeError('independent backend/native request fingerprint mismatch')
        if receipts[1]['timestamp_ns'] <= receipts[0]['timestamp_ns']:
            raise RuntimeError('backend receipt order mismatch')
        if (out/'native-errors.jsonl').exists() or (out/'rejections.jsonl').exists():
            raise RuntimeError('proxy errors/rejections recorded')
        result = {'status':'LOCAL_FIXTURE_ONLY',
            'profile':policy['profile'],'nonce':policy['nonce'], 'receipts':2,
            'capture_sha256':hashlib.sha256((out/'initial.native').read_bytes()).hexdigest()}
    finally:
        cleanup = {'processes':[], 'errors':[]}
        for p in reversed(processes):
            try:
                if p.poll() is None:os.killpg(p.pid,signal.SIGTERM)
            except OSError as e:
                cleanup['errors'].append(type(e).__name__)
        for p in processes:
            try:p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(p.pid,signal.SIGKILL)
                    p.wait(timeout=3)
                except (OSError,subprocess.TimeoutExpired) as e:
                    cleanup['errors'].append(type(e).__name__)
            cleanup['processes'].append({'pid':p.pid,'exit_code':p.poll()})
            if p.poll() is None:cleanup['errors'].append('process_remains')
        # Remove all ephemeral signing keys before any publishable result.
        import shutil
        try:
            (out/'origin.key').unlink(missing_ok=True)
            if (out/'proxy-conf').exists():shutil.rmtree(out/'proxy-conf')
        except OSError as e:
            cleanup['errors'].append(type(e).__name__)
        cleanup['private_keys_absent'] = not ((out/'origin.key').exists() or (out/'proxy-conf').exists())
        if not cleanup['private_keys_absent']:cleanup['errors'].append('private_keys_remain')
        (out/'cleanup.json').write_text(json.dumps(cleanup,sort_keys=True)+'\n')
        if cleanup['errors']:raise RuntimeError('cleanup incomplete, see cleanup.json')
    if result is not None:
        result['cleanup_complete'] = True
        (out/'candidate-result.json').write_text(json.dumps(result,sort_keys=True)+'\n')

if __name__ == '__main__':
    main()
