"""PROPOSED OFFLINE CONTRACT, not a capture adapter or proof of authenticity.

JSON records below are hypothetical normalized evidence. A future reviewed
runtime must extract them from real mitmproxy flows, origin receipts, verified
TLS probes and product authorization/run rows. Hashes bind bytes, they do NOT
authenticate their author or prove that network/TLS events occurred.
"""
from __future__ import annotations

import hashlib
import json


class ContractRejected(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ContractRejected(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(record) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(',', ':')).encode()


def validate(bundle: dict, artifacts: dict[str, bytes]) -> dict:
    """Offline structural acceptance only; no shell/network/product mutation."""
    require(bundle.get('evidence_scope') == 'substitute_fixture', 'scope label required')
    inv = bundle['investigation_id']
    nonce = bundle['run_nonce']
    require(isinstance(nonce, str) and len(nonce) >= 16, 'fresh run nonce required')
    require(bundle['approval']['state'] == 'granted', 'approval not granted')
    require(bundle['approval']['investigation_id'] == inv, 'cross-investigation approval')
    require(bundle['approval']['plan_sha256'] == digest(artifacts['plan']), 'plan binding mismatch')
    plan = json.loads(artifacts['plan'])
    require(plan['method'] == 'GET' and plan['max_replays'] == 1, 'safe GET single replay only')
    require(plan['endpoint_scope'] == 'no_uplink_loopback_fixture', 'endpoint scope mismatch')
    for name in ('flow', 'receipts', 'tls_checks', 'plan'):
        require(bundle['artifact_sha256'][name] == digest(artifacts[name]), 'artifact bytes mismatch: '+name)
    auths = {a['id']: a for a in bundle['authorizations']}
    for target in bundle['targets']:
        auth = auths[target['authorization_id']]
        require(auth['investigation_id'] == inv and auth['package'] == target['package']
                and auth['apk_sha256'] == target['apk_sha256'], 'target authorization mismatch')
        require(auth['active'] is True, 'revoked or expired target authorization')
    require(len({t['package'] for t in bundle['targets']}) == len(bundle['targets']), 'duplicate target')

    flow = json.loads(artifacts['flow'])
    require(flow['investigation_id'] == inv and flow['nonce'] == nonce, 'flow context mismatch')
    require(flow['method'] == 'GET' and flow['url'] == plan['url'], 'captured request scope mismatch')
    require(flow['response_status'] == 200 and flow['source'] == 'real_proxy_capture', 'capture record missing')
    # Request hash includes method, exact URL, bounded permitted headers and body.
    # A runtime cannot substitute reissuing a known URL for replaying this record.
    request = {k: flow[k] for k in ('method', 'url', 'headers', 'body_sha256')}
    request_hash = digest(canonical(request))
    replay = bundle['replay']
    require(replay['kind'] == 'request_replay', 'response replay is not request replay')
    require(replay['captured_flow_sha256'] == digest(artifacts['flow']), 'replay not bound to capture')
    require(replay['request_sha256'] == request_hash, 'replay request differs from captured request')
    receipts = json.loads(artifacts['receipts'])
    require(len(receipts) == 2, 'exactly initial plus one replay receipt required')
    require([r['sequence'] for r in receipts] == [1, 2], 'receipt sequence mismatch')
    require(len({r['receipt_id'] for r in receipts}) == 2, 'duplicate origin receipt')
    for receipt in receipts:
        require(receipt['investigation_id'] == inv and receipt['nonce'] == nonce, 'receipt context mismatch')
        require(receipt['method'] == 'GET' and receipt['request_sha256'] == request_hash
                and receipt['status'] == 200, 'origin request/response mismatch')
    require(receipts[1]['phase'] == 'replay' and receipts[0]['phase'] == 'initial', 'receipt phases mismatch')

    checks = json.loads(artifacts['tls_checks'])
    expected = {
        'trusted_positive': ('accepted', 'validated_chain_and_hostname'),
        'untrusted_ca': ('rejected', 'untrusted_chain'),
        'wrong_hostname': ('rejected', 'hostname_mismatch'),
        'upstream_valid': ('accepted', 'validated_chain_and_hostname'),
        'upstream_untrusted': ('rejected', 'untrusted_chain'),
    }
    require(set(checks) == set(expected), 'TLS controls incomplete')
    for name, (outcome, reason) in expected.items():
        check = checks[name]
        require(check['outcome'] == outcome and check['reason'] == reason, 'wrong TLS rejection reason: '+name)
        require(check['verification_enabled'] is True, 'TLS verification disabled')
        require(check['investigation_id'] == inv and check['nonce'] == nonce, 'TLS evidence context mismatch')
    require(checks['wrong_hostname']['chain_trusted'] is True, 'hostname control confounded by chain failure')
    return {'structural_contract': 'accepted', 'runtime_capability': 'NOT_ESTABLISHED',
            'authenticity': 'NOT_ESTABLISHED_BY_HASHES', 'scope': 'substitute_fixture'}
