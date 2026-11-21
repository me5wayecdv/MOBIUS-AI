"""HELD pure evaluator for owned-app TLS negative runs. Reads supplied evidence only; runs nothing, opens no device or socket.

A negative PASSES only when the app's own logged attribution (same nonce, same pid/uid across lines) shows the expected
refusal point AND the independent ledgers show nothing reached the origin. A green parse of fabricated or host-side logs is
not evidence: the caller must supply logcat captured from the installed owned APK process. Not an attestation.
"""
import re

APPROVED_FOR_EXECUTION = False
TAG = 'OWNED_FIXTURE'
LINE = re.compile(r'(OWNED_FIXTURE_[A-Z_]+|REFUSED)\b(.*)')
KV = re.compile(r'(\w+)=(\S+)')
SCENARIOS = {
    # scenario: (lines that MUST appear, lines that MUST NOT appear, allowed failure classes)
    'untrusted-ca': (('PREPARED', 'SOCKET', 'TLS_BEGIN', 'FAILED'), ('TLS_ESTABLISHED', 'REQUEST_COMPLETED'),
                     {'SSLHandshakeException', 'SSLPeerUnverifiedException'}),
    'wrong-hostname': (('PREPARED', 'SOCKET', 'TLS_BEGIN', 'FAILED'), ('TLS_ESTABLISHED', 'REQUEST_COMPLETED'),
                       {'SSLHandshakeException', 'SSLPeerUnverifiedException'}),
    # upstream-origin untrusted: the owned proxy refuses its upstream chain, so the app never reaches TLS.
    'untrusted-origin': (('PREPARED', 'SOCKET', 'FAILED'), ('TLS_BEGIN', 'TLS_ESTABLISHED', 'REQUEST_COMPLETED'),
                         {'IOException', 'SocketTimeoutException'}),
}


def parse(text):
    rows = []
    for raw in text.splitlines():
        m = LINE.search(raw)
        if m:
            rows.append((m.group(1).replace('OWNED_FIXTURE_', ''), dict(KV.findall(m.group(2)))))
    return rows


def evaluate(scenario, logcat_text, *, nonce, native_request_ledger, origin_receipts, proxy_upstream_refusals=None,
             teardown_absence_verified=False, apk_sha256=None, expected_apk_sha256=None):
    """Returns {'passed': bool, 'reasons': [...]}. Fail closed on any missing or contradictory evidence."""
    if scenario not in SCENARIOS:
        raise ValueError('closed negative scenario required')
    must, must_not, classes = SCENARIOS[scenario]
    reasons = []
    if not re.fullmatch('[0-9a-f]{32}', nonce or ''):
        reasons.append('nonce form')
    rows = parse(logcat_text)
    mine = [(k, kv) for k, kv in rows if kv.get('nonce') == nonce]
    if len(mine) != len([1 for k, kv in rows if 'nonce' in kv]):
        reasons.append('log lines for a different nonce present')
    kinds = [k for k, _ in mine]
    for need in must:
        if kinds.count(need) != 1:
            reasons.append('expected exactly one %s line' % need)
    for bad in must_not:
        if bad in kinds:
            reasons.append('forbidden %s line present' % bad)
    order = [k for k in ('PREPARED', 'SOCKET', 'TLS_BEGIN', 'FAILED') if k in kinds]
    if [k for k in kinds if k in order] != order:
        reasons.append('log lines out of order')
    ids = {(kv.get('pid'), kv.get('uid')) for k, kv in mine if k != 'REQUEST_COMPLETED' and 'pid' in kv and 'uid' in kv}
    if len(ids) != 1 or None in {x for pair in ids for x in pair}:
        reasons.append('app pid/uid not a single consistent identity')
    failed = [kv for k, kv in mine if k == 'FAILED']
    if failed and failed[0].get('class') not in classes:
        reasons.append('failure class outside the expected refusal for this scenario')
    if native_request_ledger != 0 or origin_receipts != 0:
        reasons.append('request reached native or origin ledger')
    if scenario == 'untrusted-origin' and (not isinstance(proxy_upstream_refusals, int) or proxy_upstream_refusals < 1):
        reasons.append('proxy upstream refusal not evidenced')
    if not apk_sha256 or apk_sha256 != expected_apk_sha256:
        reasons.append('fresh negative APK identity not bound')
    if teardown_absence_verified is not True:
        reasons.append('independent teardown absence not verified')
    return {'passed': not reasons, 'reasons': reasons, 'scenario': scenario, 'not_attestation': True}
