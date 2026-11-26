"""Closed, proposal-only provider read investigation. No execution, model calls or verdict changes.

A trusted host supplies a reviewed lab contract keyed by exact APK digest. The
contract is configuration, never model output or an inferred URI. Without one,
there is no proposal. A proposal collects bounded read evidence for a hypothesis;
it does NOT validate arbitrary prose or claim whole-agent readiness.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
import hashlib
import json
import re
import xml.etree.ElementTree as ET

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..adapters.models import ApplicationRow, EvidenceRow, HypothesisRow, InvestigationRow, ObservationRow
from ..core.schemas import PoCTestPlan, PoCStep, ProviderProbeBinding
from .artifacts import ArtifactStore
from .poc_runner import SafePoCRunner, PoCScopeRejected

ANDROID = '{http://schemas.android.com/apk/res/android}'


@dataclass(frozen=True)
class ProviderReadContract:
    """Independent reviewed host config. Not accepted from API/model input.

    Paths are known fixture routes, not claims derived from class-name guessing.
    Fixture source review is identified by its immutable review digest. The
    reviewed negative route must belong to a non-exported provider of this APK.
    No contract is registered by default.
    """
    apk_sha256: str
    source_review_sha256: str
    package: str
    provider: str
    authority: str
    path: str
    negative_provider: str
    negative_authority: str
    negative_path: str
    emulator_serial: str

    def __post_init__(self):
        if re.fullmatch(r"emulator-[0-9]{1,8}",self.emulator_serial) is None:raise ValueError("explicit emulator serial required")
        for value in (self.apk_sha256, self.source_review_sha256):
            if re.fullmatch(r'[0-9a-f]{64}',value) is None: raise ValueError('reviewed immutable digests required')
        for value in (self.package,self.provider,self.authority,self.negative_provider,self.negative_authority):
            if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]{0,249}',value) is None: raise ValueError('invalid contract identifier')
        for value in (self.path,self.negative_path):
            if re.fullmatch(r'[A-Za-z0-9_-]{1,64}',value) is None: raise ValueError('one reviewed literal path required')
        if self.authority==self.negative_authority or self.provider==self.negative_provider:
            raise ValueError('independent negative provider required')
        if any(not a.startswith(self.package+'.') for a in (self.authority,self.negative_authority)):
            raise ValueError('authorities must fit existing same-package probe scope')


class ProviderReadProposal:
    def __init__(self, session:Session, store:ArtifactStore, contracts:tuple[ProviderReadContract,...]=()):
        self.session,self.store=session,store
        self.contracts={c.apk_sha256:c for c in contracts}
        if len(self.contracts)!=len(contracts):raise ValueError('ambiguous contract registration')

    def propose(self, investigation_id:str, hypothesis_id:str, *, analyst_id:str)->dict:
        scan=self.session.get(InvestigationRow,investigation_id)
        if scan is None or scan.created_by!=analyst_id:raise PoCScopeRejected('investigation ownership required')
        app=self.session.get(ApplicationRow,scan.application_id)
        hyp=self.session.get(HypothesisRow,hypothesis_id)
        if app is None or hyp is None or hyp.investigation_id!=scan.id:raise PoCScopeRejected('same-investigation hypothesis required')
        c=self.contracts.get(app.sha256)
        if c is None:raise PoCScopeRejected('no independently reviewed exact-APK provider-read contract')
        if scan.paused_at is not None:raise PoCScopeRejected('investigation is paused')
        if hyp.status!='open':raise PoCScopeRejected('open hypothesis required')
        if app.package_name!=c.package:raise PoCScopeRejected('parsed package differs from reviewed contract')
        derived=list(hyp.derived_from or [])
        observations=list(self.session.execute(select(ObservationRow).where(
            ObservationRow.id.in_(derived),ObservationRow.investigation_id==scan.id,
            ObservationRow.agent=='SPECTRE',ObservationRow.subject_ref==c.provider,
            ObservationRow.kind=='inference',ObservationRow.fidelity=='decompiled',ObservationRow.subject_type=='component')).scalars())
        candidates=[o for o in observations if (o.attributes or {}).get('operation')=='read'
                    and (o.attributes or {}).get('method_references') and o.evidence_refs]
        if len(candidates)!=1:raise PoCScopeRejected('one cited persisted provider-read flow observation required')
        obs=candidates[0]
        # Require actual matching detector evidence, not a hand-entered observation.
        verified=[]
        flow_sha256=None
        for eid in obs.evidence_refs:
            e=self.session.get(EvidenceRow,eid)
            if e is None or e.investigation_id!=scan.id or e.produced_by!='SPECTRE' or e.kind!='tool-output':continue
            if e.truncated or e.byte_size>4*1024*1024:raise PoCScopeRejected('complete bounded flow evidence required')
            raw=self.store.get(e.object_key)
            if len(raw)>4*1024*1024 or hashlib.sha256(raw).hexdigest()!=e.sha256:raise PoCScopeRejected('flow evidence integrity')
            try:d=json.loads(raw)
            except (ValueError,UnicodeError):continue
            if not isinstance(d,dict):continue
            flows=d.get('sink_flows')
            if not isinstance(flows,list) or not flows:continue
            methods={f.get('method') for f in flows if isinstance(f,dict) and isinstance(f.get('method'),str)}
            refs=obs.attributes['method_references']
            if not isinstance(refs,list) or not all(isinstance(r,str) and r in methods for r in refs):continue
            if d.get('provider')==c.provider and d.get('operation')=='read':
                verified.append(e.id)
                flow_sha256=e.sha256
        if len(verified)!=1:raise PoCScopeRejected('one hash-verified detector read-flow document required')
        manifests=list(self.session.execute(select(EvidenceRow).where(
            EvidenceRow.investigation_id==scan.id,EvidenceRow.kind=='manifest',EvidenceRow.produced_by=='RECON')).scalars())
        if len(manifests)!=1:raise PoCScopeRejected('unambiguous persisted manifest required')
        ev=manifests[0]
        if ev.truncated or ev.byte_size>1024*1024:raise PoCScopeRejected('complete bounded manifest required')
        raw=self.store.get(ev.object_key)
        if len(raw)>1024*1024 or hashlib.sha256(raw).hexdigest()!=ev.sha256:raise PoCScopeRejected('manifest integrity')
        if b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():raise PoCScopeRejected('manifest extensions unsupported')
        try:root=ET.fromstring(raw)
        except ET.ParseError as exc:raise PoCScopeRejected('invalid manifest XML') from exc
        if root.get('package')!=c.package:raise PoCScopeRejected('manifest package mismatch')
        applications=root.findall('./application')
        if len(applications)!=1 or applications[0].get(ANDROID+'enabled','true')!='true':
            raise PoCScopeRejected('one enabled manifest application required')
        providers=applications[0].findall('./provider')
        def bound(name,authority,exported):
            matches=[]
            for p in providers:
                n=p.get(ANDROID+'name','')
                n=c.package+n if n.startswith('.') else n if '.' in n else c.package+'.'+n
                authorities=p.get(ANDROID+'authorities','').split(';')
                if n==name and authority in authorities:matches.append(p)
            return len(matches)==1 and matches[0].get(ANDROID+'exported')==exported and matches[0].get(ANDROID+'enabled','true')=='true'
        if not bound(c.provider,c.authority,'true') or not bound(c.negative_provider,c.negative_authority,'false'):
            raise PoCScopeRejected('reviewed positive/negative manifest bindings not established')
        plan=PoCTestPlan(investigation_id=scan.id,authorization_id=scan.authorization_id,
            target_sha256=app.sha256,target_package=c.package,target_kind='emulator',hypothesis_ids=(hyp.id,),
            prerequisites=('Reviewed exact-APK fixture and verified emulator; no external targets.',
                'Read-only query may return lab data; approved evidence audience required.'),
            steps=(PoCStep(action='assert_emulator_package_present',target_ref=c.package,expected_value=True,timeout_seconds=60),
                   PoCStep(action='assert_emulator_provider_permission_denied',target_ref=c.negative_authority+'/'+c.negative_path,expected_value=True,timeout_seconds=60),
                   PoCStep(action='assert_emulator_provider_rows',target_ref=c.authority+'/'+c.path,expected_value=1,timeout_seconds=60)),
            expected_outcome='Collect evidence whether adb shell can read at least one reviewed lab row after explicit denial on the private control. This does not establish ordinary application UID access or validate the full model claim.',
            provider_probe_binding=ProviderProbeBinding(
                contract_sha256=hashlib.sha256(json.dumps(asdict(c),sort_keys=True,separators=(',',':')).encode()).hexdigest(),
                source_review_sha256=c.source_review_sha256,manifest_sha256=ev.sha256,flow_sha256=flow_sha256,
                observation_id=obs.id,manifest_evidence_id=ev.id,flow_evidence_id=verified[0],
                emulator_serial=c.emulator_serial),
            safety_class='read_only',requires_approval=True,max_duration_seconds=180,max_output_bytes=8192)
        # Existing authority checks without demanding a grant on a not-yet-approved proposal.
        SafePoCRunner(self.session)._validate_scope(plan)
        return {'plan':plan.model_dump(mode='json'), 'flow_observation_id':obs.id,
                'flow_evidence_id':verified[0], 'manifest_evidence_id':ev.id,
                'source_review_sha256':c.source_review_sha256,
                'negative_control':{'target_ref':c.negative_authority+'/'+c.negative_path,
                    'required_result':'explicit permission denial, never generic failure/timeout',
                    'implemented':True},
                'ready_for_execution':False,
                'limitations':['An independent matching approved plan and verified emulator are required before execution.',
                    'The probe caller is adb shell, NOT an ordinary third-party application UID.',
                    'Proposal only; no execution or hypothesis/finding verdict change.',
                    'A positive read does not prove the full model claim or broader agent readiness.']}
