"""Synthetic offline contract tests only. No capture or TLS events occur."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('contract', Path(__file__).parents[1]/'research/d061_capture_contract.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def fixture():
    inv, nonce = 'test-investigation', 'synthetic-run-nonce-001'
    plan = {'method': 'GET', 'max_replays': 1, 'endpoint_scope': 'no_uplink_loopback_fixture',
            'url': 'https://lab.invalid/fixture?nonce='+nonce}
    flow = {'investigation_id': inv, 'nonce': nonce, 'source': 'real_proxy_capture',
            'method': 'GET', 'url': plan['url'], 'headers': {'x-test': nonce},
            'body_sha256': c.digest(b''), 'response_status': 200}
    req_hash = c.digest(c.canonical({k:flow[k] for k in ('method','url','headers','body_sha256')}))
    receipts = [{'receipt_id': str(i), 'sequence': i, 'phase': phase,
                 'investigation_id': inv, 'nonce': nonce, 'method': 'GET',
                 'request_sha256': req_hash, 'status': 200}
                for i,phase in ((1,'initial'),(2,'replay'))]
    checks = {}
    for name,outcome,reason in (
        ('trusted_positive','accepted','validated_chain_and_hostname'),
        ('untrusted_ca','rejected','untrusted_chain'),
        ('wrong_hostname','rejected','hostname_mismatch'),
        ('upstream_valid','accepted','validated_chain_and_hostname'),
        ('upstream_untrusted','rejected','untrusted_chain')):
        checks[name] = {'outcome':outcome,'reason':reason,'verification_enabled':True,
                        'investigation_id':inv,'nonce':nonce,'chain_trusted':True}
    artifacts = {k:c.canonical(v) for k,v in {'plan':plan,'flow':flow,'receipts':receipts,'tls_checks':checks}.items()}
    targets = [{'package':pkg,'apk_sha256':c.digest(pkg.encode()),'authorization_id':'a'+str(i)}
               for i,pkg in enumerate(('fixture.trusted','fixture.untrusted'))]
    bundle = {'evidence_scope':'substitute_fixture','investigation_id':inv,'run_nonce':nonce,
              'approval':{'state':'granted','investigation_id':inv,'plan_sha256':c.digest(artifacts['plan'])},
              'artifact_sha256':{k:c.digest(v) for k,v in artifacts.items()},
              'targets':targets,'authorizations':[dict(t,id=t['authorization_id'],investigation_id=inv,active=True) for t in targets],
              'replay':{'kind':'request_replay','captured_flow_sha256':c.digest(artifacts['flow']),'request_sha256':req_hash}}
    return bundle,artifacts


class ProposedCaptureContractTests(unittest.TestCase):
    def test_structural_acceptance_never_claims_runtime_or_authenticity(self):
        result = c.validate(*fixture())
        self.assertEqual(result['runtime_capability'], 'NOT_ESTABLISHED')
        self.assertEqual(result['authenticity'], 'NOT_ESTABLISHED_BY_HASHES')

    def test_missing_capture_receipt_only_is_rejected(self):
        b,a=fixture(); del a['flow']
        with self.assertRaises((KeyError,c.ContractRejected)): c.validate(b,a)

    def test_bundle_mutations_rejected(self):
        for mutation in (
            lambda b:b.update(evidence_scope='Allsafe_verified'),
            lambda b:b['approval'].update(state='pending'),
            lambda b:b['approval'].update(investigation_id='other'),
            lambda b:b['targets'][1].update(authorization_id=b['targets'][0]['authorization_id']),
            lambda b:b['replay'].update(kind='response_replay'),
            lambda b:b['replay'].update(captured_flow_sha256='0'*64),
            lambda b:b['replay'].update(request_sha256='0'*64),
        ):
            b,a=fixture();mutation(b)
            with self.subTest(mutation=mutation),self.assertRaises(c.ContractRejected):c.validate(b,a)

    def test_receipt_tls_and_flow_mutations_rejected_even_with_new_hash(self):
        cases = [
            ('receipts', lambda v:v.pop()),
            ('receipts', lambda v:v.append(copy.deepcopy(v[-1]))),
            ('receipts', lambda v:v[1].update(receipt_id=v[0]['receipt_id'])),
            ('receipts', lambda v:v[1].update(nonce='previous-run')),
            ('receipts', lambda v:v[1].update(request_sha256='0'*64)),
            ('tls_checks', lambda v:v['wrong_hostname'].update(reason='untrusted_chain')),
            ('tls_checks', lambda v:v['wrong_hostname'].update(chain_trusted=False)),
            ('tls_checks', lambda v:v['upstream_valid'].update(verification_enabled=False)),
            ('flow', lambda v:v.update(method='POST')),
            ('flow', lambda v:v.update(source='receipt_only_guess')),
        ]
        for name,mutate in cases:
            b,a=fixture();v=json.loads(a[name]);mutate(v);a[name]=c.canonical(v);b['artifact_sha256'][name]=c.digest(a[name])
            with self.subTest(name=name,mutate=mutate),self.assertRaises(c.ContractRejected):c.validate(b,a)

    def test_unbound_changed_artifact_bytes_rejected(self):
        b,a=fixture();a['flow']+=b' '
        with self.assertRaises(c.ContractRejected):c.validate(b,a)
