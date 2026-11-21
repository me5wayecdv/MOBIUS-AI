"""PROPOSED OFFLINE CONTRACT, not a capture adapter or proof of authenticity.

JSON records below are hypothetical normalized evidence. A future reviewed
runtime must extract them from real mitmproxy flows, origin receipts, verified
TLS probes and product authorization/run rows. Hashes bind bytes, they do NOT
authenticate their author or prove that network/TLS events occurred.
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit


class ContractRejected(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ContractRejected(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(record) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(',', ':')).encode()


def validate(bundle: dict, artifacts: dict[str, bytes], *, fixture_policy: dict) -> dict:
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
    require(bool(bundle['targets']), 'nonempty targets required')
    required = fixture_policy['required_targets']
    require(bool(required) and {t['package']:t['apk_sha256'] for t in bundle['targets']} == required, 'required target identities mismatch')
    require(len({a['id'] for a in bundle['authorizations']}) == len(bundle['authorizations']), 'duplicate authorization IDs')
    auths = {a['id']: a for a in bundle['authorizations']}
    for target in bundle['targets']:
        auth = auths[target['authorization_id']]
        require(auth['investigation_id'] == inv and auth['package'] == target['package']
                and auth['apk_sha256'] == target['apk_sha256'], 'target authorization mismatch')
        require(auth['active'] is True, 'revoked or expired target authorization')
    require(len({t['package'] for t in bundle['targets']}) == len(bundle['targets']), 'duplicate target')

    plan_hash = digest(artifacts['plan'])
    def identity(record):
        require(record['plan_sha256'] == plan_hash, 'operation plan mismatch')
        require(required.get(record['package']) == record['apk_sha256'], 'operation target mismatch')
        require(record['package'] == fixture_policy['profiles'][record['profile']], 'TLS/operation profile mismatch')
    require(plan['url'] in fixture_policy['allowed_urls'], 'endpoint not independently allowed')
    parsed = urlsplit(plan['url'])
    require(parsed.scheme == 'https' and not parsed.username and not parsed.password and not parsed.fragment, 'unsafe URL shape')
    flow = json.loads(artifacts['flow'])
    identity(flow)
    require(isinstance(flow['headers'], dict) and len(flow['headers']) <= 4, 'header bound')
    require(set(flow['headers']) <= {'x-test', 'accept'}, 'credential/cookie/unknown header forbidden')
    require(all(isinstance(v,str) and len(v)<=256 and '\r' not in v and '\n' not in v for v in flow['headers'].values()), 'header value bound')
    require(flow['body_sha256'] == digest(b''), 'GET body forbidden')
    require(flow.get('redirects_followed') == 0, 'redirect policy unresolved: redirects forbidden')
    require(flow['investigation_id'] == inv and flow['nonce'] == nonce, 'flow context mismatch')
    require(flow['method'] == 'GET' and flow['url'] == plan['url'], 'captured request scope mismatch')
    require(flow['response_status'] == 200 and flow['source'] == 'real_proxy_capture', 'capture record missing')
    # Request hash includes method, exact URL, bounded permitted headers and body.
    # A runtime cannot substitute reissuing a known URL for replaying this record.
    request = {k: flow[k] for k in ('method', 'url', 'headers', 'body_sha256')}
    request_hash = digest(canonical(request))
    replay = bundle['replay']
    identity(replay)
    require(replay['kind'] == 'request_replay', 'response replay is not request replay')
    require(replay['captured_flow_sha256'] == digest(artifacts['flow']), 'replay not bound to capture')
    require(replay['request_sha256'] == request_hash, 'replay request differs from captured request')
    receipts = json.loads(artifacts['receipts'])
    require(len(receipts) == 2, 'exactly initial plus one replay receipt required')
    require([r['sequence'] for r in receipts] == [1, 2], 'receipt sequence mismatch')
    require(len({r['receipt_id'] for r in receipts}) == 2, 'duplicate origin receipt')
    for receipt in receipts:
        identity(receipt)
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
        identity(check)
        require(check['outcome'] == outcome and check['reason'] == reason, 'wrong TLS rejection reason: '+name)
        require(check['verification_enabled'] is True, 'TLS verification disabled')
        require(check['investigation_id'] == inv and check['nonce'] == nonce, 'TLS evidence context mismatch')
    require(checks['wrong_hostname']['chain_trusted'] is True, 'hostname control confounded by chain failure')
    return {'structural_contract': 'accepted', 'runtime_capability': 'NOT_ESTABLISHED',
            'authenticity': 'NOT_ESTABLISHED_BY_HASHES', 'scope': 'substitute_fixture'}
