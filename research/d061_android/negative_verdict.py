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


EXPECTED_UPSTREAM = '127.0.0.1:18443'  # reviewed fixed origin from README; the proxy refusal record must name exactly this
REFUSAL_REASONS = {'certificate_verify_failed'}


def _certs(blobs, minimum=1):
    from cryptography import x509
    if not isinstance(blobs, list) or not minimum <= len(blobs) <= 4 or not all(isinstance(b, bytes) for b in blobs):
        raise ValueError('bounded DER certificate chain required')
    out = []
    for b in blobs:
        cert = x509.load_der_x509_certificate(b)
        if cert.public_bytes(_der()) != b:
            raise ValueError('canonical DER certificate required')
        out.append(cert)
    return out


def _der():
    from cryptography.hazmat.primitives.serialization import Encoding
    return Encoding.DER


def _spki(cert):
    from cryptography.hazmat.primitives.serialization import PublicFormat
    return cert.public_key().public_bytes(_der(), PublicFormat.SubjectPublicKeyInfo)


def _issued_by(child, parent):
    try:
        child.verify_directly_issued_by(parent)
        return True
    except Exception:
        return False


def _chain_consistent(chain):
    return all(_issued_by(chain[k], chain[k + 1]) for k in range(len(chain) - 1))


def _anchored_by(chain, anchor):
    """True if the presented chain would be trusted by `anchor`: a member IS the anchor key, or the top is issued by it."""
    a = _spki(anchor)
    if any(_spki(c) == a for c in chain):
        return True
    return any(_issued_by(c, anchor) for c in chain)


def _ca_ok(cert):
    from cryptography import x509
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    except Exception:
        return False


def _premises_problem(scenario, p, build):
    """Validates ACTUAL canonical DER certificates and chain relations, not unrelated digest strings."""
    from cryptography import x509
    import ipaddress
    import hashlib
    try:
        if not isinstance(p, dict):
            return 'premises missing'
        if scenario in ('untrusted-ca', 'untrusted-origin'):
            keys = {'trust_anchor_der', 'presented_chain_der'}
            if set(p) != keys:
                return 'premises malformed'
            anchor = _certs([p['trust_anchor_der']])[0]
            chain = _certs(p['presented_chain_der'])
            if not _ca_ok(anchor) or not _chain_consistent(chain):
                return 'anchor must be a CA and the presented chain internally consistent'
            if _anchored_by(chain, anchor):
                return 'presented chain is anchored by the trust anchor, so refusal would not be an untrusted-chain case'
            bound = build.get('embedded_anchor_sha256') if scenario == 'untrusted-ca' else build.get('proxy_upstream_trust_sha256')
            if bound != hashlib.sha256(p['trust_anchor_der']).hexdigest():
                return 'trust anchor is not the one bound to the build record'
        else:
            if set(p) != {'trust_anchor_der', 'presented_chain_der', 'peer_name'}:
                return 'wrong-hostname premises malformed'
            anchor = _certs([p['trust_anchor_der']])[0]
            chain = _certs(p['presented_chain_der'])
            if not _ca_ok(anchor) or not _chain_consistent(chain) or not _anchored_by(chain, anchor):
                return 'wrong-hostname requires a consistent chain TRUSTED by the embedded anchor'
            if build.get('embedded_anchor_sha256') != hashlib.sha256(p['trust_anchor_der']).hexdigest():
                return 'trust anchor is not the one bound to the build record'
            if p['peer_name'] != WRONG_PEER.split('"')[1]:
                return 'peer name must be the reviewed fixed mismatch name'
            san = chain[0].extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            names = [n for n in san]
            # Conservative: ONLY the exact reviewed loopback IP SAN; no DNS names, no wildcards, no other types, no CN fallback.
            if len(names) != 1 or not isinstance(names[0], x509.IPAddress) or names[0].value != ipaddress.ip_address('127.0.0.1'):
                return 'leaf SAN must be exactly the reviewed loopback IP'
    except Exception as error:
        return 'premise certificate validation failed: ' + error.__class__.__name__
    return None


def _window_ok(rec):
    return _int(rec.get('window_start')) and _int(rec.get('window_end')) and rec['window_start'] < rec['window_end']


def _ledger(rec, scenario, nonce, run_id, app):
    keys = {'run_id', 'scenario', 'nonce', 'window_start', 'window_end', 'complete', 'count'}
    return (isinstance(rec, dict) and set(rec) == keys and rec['run_id'] == run_id and rec['scenario'] == scenario
            and rec['nonce'] == nonce and rec['complete'] is True and _window_ok(rec) and _int(rec['count'])
            and rec['window_start'] <= app['start'] and rec['window_end'] >= app['end'])


def evaluate(scenario, logcat_text, *, nonce, run_id, app_window, expected_app, build_record, premises, native_ledger, origin_ledger,
             proxy_refusal=None, teardown_absence_verified=None):
    if scenario not in CLASSES:
        raise ValueError('closed negative scenario required')
    reasons = []
    if not _hex(nonce, NONCE):
        reasons.append('nonce form')
    if not (isinstance(expected_app, dict) and set(expected_app) == {'pid', 'uid'} and _int(expected_app['pid']) and _int(expected_app['uid'])):
        reasons.append('independently observed app pid/uid required')
        return {'passed': False, 'reasons': reasons, 'scenario': scenario, 'not_attestation': True}
    if not (isinstance(app_window, dict) and set(app_window) == {'start', 'end'} and _int(app_window['start'])
            and _int(app_window['end']) and app_window['start'] < app_window['end']):
        reasons.append('witnessed app attempt window required')
        return {'passed': False, 'reasons': reasons, 'scenario': scenario, 'not_attestation': True}
    bkeys = {'run_id', 'scenario', 'apk_sha256', 'installed_apk_sha256', 'embedded_anchor_sha256', 'proxy_upstream_trust_sha256'}
    if not (isinstance(build_record, dict) and set(build_record) == bkeys and build_record['run_id'] == run_id
            and build_record['scenario'] == scenario and _hex(build_record['apk_sha256'])
            and build_record['apk_sha256'] == build_record['installed_apk_sha256']
            and _hex(build_record['embedded_anchor_sha256']) and _hex(build_record['proxy_upstream_trust_sha256'])):
        reasons.append('same-run scenario-bound fresh APK/trust identity (built == installed, exact sha256) required')
        build_record = build_record if isinstance(build_record, dict) else {}
    problem = _premises_problem(scenario, premises, build_record)
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
        if not _ledger(rec, scenario, nonce, run_id, app_window):
            reasons.append('%s ledger must be typed, complete, same-run, scenario/nonce-bound and cover the witnessed app window' % name)
        elif rec['count'] != 0:
            reasons.append('request reached the %s ledger' % name)
    if scenario == 'untrusted-origin':
        import hashlib
        keys = {'run_id', 'scenario', 'nonce', 'upstream', 'upstream_leaf_sha256', 'reason', 'observed_at', 'count'}
        leaf_ok = False
        try:
            leaf_ok = proxy_refusal['upstream_leaf_sha256'] == hashlib.sha256(premises['presented_chain_der'][0]).hexdigest()
        except Exception:
            pass
        if not (isinstance(proxy_refusal, dict) and set(proxy_refusal) == keys and proxy_refusal['run_id'] == run_id
                and proxy_refusal['scenario'] == scenario and proxy_refusal['nonce'] == nonce
                and proxy_refusal['upstream'] == EXPECTED_UPSTREAM and proxy_refusal['reason'] in REFUSAL_REASONS
                and leaf_ok and _int(proxy_refusal['observed_at']) and app_window['start'] <= proxy_refusal['observed_at'] <= app_window['end']
                and _int(proxy_refusal['count']) and proxy_refusal['count'] >= 1):
            reasons.append('typed same-run proxy refusal bound to the fixed upstream, presented leaf digest, reason set and app window required')
    if teardown_absence_verified is not True:
        reasons.append('independent teardown absence not verified')
    return {'passed': not reasons, 'reasons': reasons, 'scenario': scenario, 'refusal_reason_established': False,
            'claim': 'generic refusal under the bound premises; the app logs only an exception class', 'not_attestation': True}
