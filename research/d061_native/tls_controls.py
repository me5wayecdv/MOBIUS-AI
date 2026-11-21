"""HELD local TLS controls, separate from positive native receipt ledger.

Invoked only inside the same reviewed namespace and after explicit scope review.
Never disables certificate verification. No socket outside fixed loopback port.
"""
import http.client
import json
from pathlib import Path
import ssl
import subprocess
import sys
import time

from wire import atomic_json

APPROVED_FOR_EXECUTION = False


def untrusted_proxy_chain(*, positive_policy: dict, output: Path):
    if not APPROVED_FOR_EXECUTION:raise RuntimeError('TLS control execution HELD')
    ledger=output/'backend-receipts.json'
    before=json.loads(ledger.read_text()) if ledger.exists() else []
    control={'id':'untrusted-proxy-chain','nonce':positive_policy['nonce'],
             'expected_stage':'client-verifies-proxy-chain','before_receipts':len(before),
             'verification_enabled':True,'result':'failed','exception':None}
    # SSLContext(PROTOCOL_TLS_CLIENT) checks certificates+hostname but has no
    # loaded trust anchors. Generated proxyCA is deliberately absent.
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    assert context.verify_mode==ssl.CERT_REQUIRED and context.check_hostname
    client=http.client.HTTPSConnection('127.0.0.1',18080,context=context,timeout=5)
    client.set_tunnel('127.0.0.1',18443)
    try:
        client.putrequest('GET','/receipt?nonce='+positive_policy['nonce'],skip_accept_encoding=True)
        client.putheader('Accept','application/json')
        client.putheader('X-D061-Nonce',positive_policy['nonce'])
        client.endheaders()
        response=client.getresponse()
        response.read(4096)
        control['unexpected_status']=response.status
    except ssl.SSLCertVerificationError as e:
        control['exception']={'class':type(e).__name__,'verify_code':e.verify_code,'verify_message':e.verify_message}
    finally:client.close()
    # Caller must quiesce its separately scoped origin/proxy before finalizing
    # and reread ledger there. This function alone must not claim PASS.
    control['result']='awaiting_quiesced_backend_readback'
    atomic_json(output/'tls-untrusted-proxy-pending.json',control)
    return control


def finalize_untrusted_proxy(control: dict, *, output: Path):
    if not APPROVED_FOR_EXECUTION:raise RuntimeError('TLS control execution HELD')
    ledger=output/'backend-receipts.json'
    after=json.loads(ledger.read_text()) if ledger.exists() else []
    control=dict(control,after_receipts=len(after),delta=len(after)-control['before_receipts'])
    passed=bool(control['exception']) and control['delta']==0 and not control.get('unexpected_status')
    control['result']='passed' if passed else 'failed'
    atomic_json(output/'tls-untrusted-proxy-final.json',control)
    if not passed:raise RuntimeError('untrusted proxy-chain rejection control failed')
    return control

# Hostname mismatch and untrusted origin chain remain defined in
# D061_PRODUCT_ADAPTER_PREPARATION.md. They need separate local TLS origin key,
# trust profiles/proxy instances/ledgers and exact log+delta0 validators, not an
# unsafe change to the reviewed positive proxy options or an expected exception
# hidden in its normal positive logs. No executor invokes these controls yet.
