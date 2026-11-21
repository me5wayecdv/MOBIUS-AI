"""HELD pure evaluator for owned-app TLS negative runs. Validates SUPPLIED records only; runs nothing, opens no device/socket.

It cannot create provenance. The caller must supply: logcat (threadtime format) captured from the installed owned APK
process, the independently observed app pid/uid, the build record binding the APK hash to this scenario, trust/hostname
premises, and typed complete ledgers with run/nonce/window attribution. A pass means the supplied records are mutually
consistent with the expected refusal. It does NOT establish the handshake refusal REASON: the app logs only an exception
class, so the verdict states a generic handshake refusal under the bound premises. Not an attestation.
"""
import re

from app_negative_preparation import WRONG_PEER

APPROVED_FOR_EXECUTION = False
TAG = 'MobiusOwnedFixture'
HEX64 = re.compile('[0-9a-f]{64}')
NONCE = re.compile('[0-9a-f]{32}')
# adb logcat -v threadtime:  MM-DD HH:MM:SS.mmm  PID  TID L Tag: message
THREADTIME = re.compile(r'^\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}\s+(\d+)\s+(\d+)\s+([VDIWEF])\s+(\S+?)\s*: (.*)$')
MARKER = re.compile(r'^(OWNED_FIXTURE_[A-Z_]+|REFUSED)\b(.*)$')
KV = re.compile(r'(\w+)=(\S+)')
CLASSES = {'untrusted-ca': {'SSLHandshakeException', 'SSLPeerUnverifiedException'},
           'wrong-hostname': {'SSLHandshakeException', 'SSLPeerUnverifiedException'},
           'untrusted-origin': {'IOException', 'SocketTimeoutException'}}
MUST = {'untrusted-ca': ('PREPARED', 'SOCKET', 'TLS_BEGIN', 'FAILED'), 'wrong-hostname': ('PREPARED', 'SOCKET', 'TLS_BEGIN', 'FAILED'),
        'untrusted-origin': ('PREPARED', 'SOCKET', 'FAILED')}
ORDER = ('PREPARED', 'SOCKET', 'TLS_BEGIN', 'FAILED')


def _int(v):
    return type(v) is int and v >= 0


def _hex(v, rx=HEX64):
    return isinstance(v, str) and rx.fullmatch(v) is not None


def parse(text, expected_pid, expected_uid):
    """Strict parse. Returns (rows, problems). Any marker text outside the exact app tag, any marker line without numeric
    nonce/pid/uid matching the externally observed app identity, duplicate keys, or REFUSED lines are problems."""
    rows, problems = [], []
    for raw in text.splitlines():
        if 'OWNED_FIXTURE_' not in raw and 'REFUSED' not in raw:
            continue
        m = THREADTIME.match(raw)
        if not m:
            problems.append('marker text in a line that is not threadtime-formatted')
            continue
        lpid, _tid, _lvl, tag, msg = m.groups()
        if tag != TAG:
            problems.append('marker text under a different log tag')
            continue
        mk = MARKER.match(msg)
        if not mk:
            problems.append('unparseable marker message')
            continue
        pairs = KV.findall(mk.group(2))
        kv = dict(pairs)
        if len(kv) != len(pairs):
            problems.append('duplicate key in marker')
            continue
        kind = mk.group(1).replace('OWNED_FIXTURE_', '')
        if kind == 'REFUSED':
            problems.append('app refusal marker present')
            continue
        if not (kv.get('pid', '').isdigit() and kv.get('uid', '').isdigit() and _hex(kv.get('nonce'), NONCE)):
            problems.append('%s marker lacks numeric pid/uid or nonce' % kind)
            continue
        if int(kv['pid']) != expected_pid or int(kv['uid']) != expected_uid or int(lpid) != expected_pid:
            problems.append('%s marker identity differs from the independently observed app' % kind)
            continue
        rows.append((kind, kv))
    return rows, problems


def _ledger(rec, scenario, nonce):
    keys = {'scenario', 'nonce', 'window_start', 'window_end', 'complete', 'count'}
    return (isinstance(rec, dict) and set(rec) == keys and rec['scenario'] == scenario and rec['nonce'] == nonce
            and rec['complete'] is True and _int(rec['window_start']) and _int(rec['window_end'])
            and rec['window_start'] < rec['window_end'] and _int(rec['count']))


def _premises_problem(scenario, p):
    if not isinstance(p, dict):
        return 'premises missing'
    if scenario == 'untrusted-ca':
        if set(p) != {'embedded_anchor_sha256', 'origin_chain_anchor_sha256'} or not all(_hex(v) for v in p.values()):
            return 'untrusted-ca premises malformed'
        if p['embedded_anchor_sha256'] == p['origin_chain_anchor_sha256']:
            return 'untrusted-ca premise: embedded anchor must differ from the presented chain anchor'
    elif scenario == 'wrong-hostname':
        if set(p) != {'peer_name', 'presented_cert_names', 'chain_anchor_trusted'}:
            return 'wrong-hostname premises malformed'
        if (p['peer_name'] != WRONG_PEER.split('"')[1] or not isinstance(p['presented_cert_names'], list)
                or not p['presented_cert_names'] or p['peer_name'] in p['presented_cert_names'] or p['chain_anchor_trusted'] is not True):
            return 'wrong-hostname premise: trusted chain required and the peer name must be absent from the certificate names'
    else:
        if set(p) != {'upstream_chain_anchor_sha256', 'proxy_upstream_trust_sha256'} or not all(_hex(v) for v in p.values()):
            return 'untrusted-origin premises malformed'
        if p['upstream_chain_anchor_sha256'] == p['proxy_upstream_trust_sha256']:
            return 'untrusted-origin premise: upstream chain anchor must differ from the proxy trust anchor'
    return None


def evaluate(scenario, logcat_text, *, nonce, expected_app, build_record, premises, native_ledger, origin_ledger,
             proxy_refusal=None, teardown_absence_verified=None):
    if scenario not in CLASSES:
        raise ValueError('closed negative scenario required')
    reasons = []
    if not _hex(nonce, NONCE):
        reasons.append('nonce form')
    if not (isinstance(expected_app, dict) and set(expected_app) == {'pid', 'uid'} and _int(expected_app['pid']) and _int(expected_app['uid'])):
        reasons.append('independently observed app pid/uid required')
        return {'passed': False, 'reasons': reasons, 'scenario': scenario, 'not_attestation': True}
    if not (isinstance(build_record, dict) and set(build_record) == {'scenario', 'apk_sha256', 'installed_apk_sha256'}
            and build_record['scenario'] == scenario and _hex(build_record['apk_sha256'])
            and build_record['apk_sha256'] == build_record['installed_apk_sha256']):
        reasons.append('scenario-bound fresh APK identity (built == installed, exact sha256) required')
    problem = _premises_problem(scenario, premises)
    if problem:
        reasons.append(problem)
    rows, problems = parse(logcat_text, expected_app['pid'], expected_app['uid'])
    reasons += problems
    kinds = [k for k, _ in rows]
    if any(kv['nonce'] != nonce for _, kv in rows):
        reasons.append('marker for a different nonce present')
    for need in MUST[scenario]:
        if kinds.count(need) != 1:
            reasons.append('expected exactly one %s marker' % need)
    extra = set(kinds) - set(ORDER)
    if extra:
        reasons.append('unexpected or success marker present: ' + ','.join(sorted(extra)))
    if scenario == 'untrusted-origin' and 'TLS_BEGIN' in kinds:
        reasons.append('app reached TLS in the untrusted-origin case')
    if [k for k in kinds if k in ORDER] != [k for k in ORDER if k in kinds]:
        reasons.append('markers out of order')
    failed = [kv for k, kv in rows if k == 'FAILED']
    if failed and failed[0].get('class') not in CLASSES[scenario]:
        reasons.append('failure class outside the expected refusal for this scenario')
    for name, rec in (('native', native_ledger), ('origin', origin_ledger)):
        if not _ledger(rec, scenario, nonce):
            reasons.append('%s ledger must be typed, complete and scenario/nonce/window-bound' % name)
        elif rec['count'] != 0:
            reasons.append('request reached the %s ledger' % name)
    if scenario == 'untrusted-origin':
        keys = {'scenario', 'nonce', 'upstream', 'reason', 'count'}
        if not (isinstance(proxy_refusal, dict) and set(proxy_refusal) == keys and proxy_refusal['scenario'] == scenario
                and proxy_refusal['nonce'] == nonce and isinstance(proxy_refusal['upstream'], str) and proxy_refusal['upstream']
                and isinstance(proxy_refusal['reason'], str) and proxy_refusal['reason'] and _int(proxy_refusal['count'])
                and proxy_refusal['count'] >= 1):
            reasons.append('typed nonce-bound proxy upstream refusal record required')
    if teardown_absence_verified is not True:
        reasons.append('independent teardown absence not verified')
    return {'passed': not reasons, 'reasons': reasons, 'scenario': scenario, 'refusal_reason_established': False,
            'claim': 'generic refusal under the bound premises; the app logs only an exception class', 'not_attestation': True}
