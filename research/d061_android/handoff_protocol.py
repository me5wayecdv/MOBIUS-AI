"""Pure closed provisioning/commit handoff protocol, no authorization by records.

No process launch, network, file writes, SDK or APK execution. Public provisioning
bytes travel child -> trusted controller; fixed typed commit travels controller ->
child. Caller must establish actual committed product authority and root-owned
read-only control mount. These records never grant owner permission themselves.
"""
from dataclasses import asdict
import hashlib
import json
import re

from mobius.services.owned_android_fixture import OwnedAppRequest,PACKAGE,PROFILE

READY_VERSION='owned-android-ready/1'
COMMIT_VERSION='owned-android-commit/1'
MAX_APK=4*1024**2
MAX_METADATA=65536
MAX_READY=MAX_APK+2*MAX_METADATA+16384


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()

def digest(value):return hashlib.sha256(value).hexdigest()


def validate_digest(value):
    if not isinstance(value,str) or re.fullmatch('[0-9a-f]{64}',value) is None:
        raise ValueError('original lowercase SHA256 required')
    return value


def validate_ready_fields(metadata):
    if not isinstance(metadata,dict) or set(metadata)!={
        'version','profile','package','apk_sha256','public_ca_sha256','build_json_sha256',
        'source_manifest_sha256','run_id','provisioning_id','closure_sha256','original_count','origin_receipt_count','apk_installed','apk_launched'}:
        raise ValueError('closed provisioning metadata keys required')
    if (metadata['version'],metadata['profile'],metadata['package'])!=(READY_VERSION,PROFILE,PACKAGE):
        raise ValueError('fixed provisioning profile/package/version')
    for name in ('apk_sha256','public_ca_sha256','build_json_sha256','source_manifest_sha256','closure_sha256'):
        validate_digest(metadata[name])
    for name in ('run_id','provisioning_id'):
        if not isinstance(metadata[name],str) or re.fullmatch('[0-9a-f]{32}',metadata[name]) is None:
            raise ValueError('unique fixed run/provisioning identifier required')
    if (type(metadata['original_count']) is not int or metadata['original_count']!=0
        or type(metadata['origin_receipt_count']) is not int or metadata['origin_receipt_count']!=0
        or metadata['apk_installed'] is not False or metadata['apk_launched'] is not False):
        raise ValueError('provisioning must not consume app operation')
    return metadata


def validate_provisioned(metadata,*,apk,public_ca_der,build_json,expected_source_manifest_sha256):
    # This parser cannot establish that a binary was built or a device booted.
    # Its caller separately retains original build/boot evidence and provenance.
    validate_ready_fields(metadata)
    for value,limit in ((apk,MAX_APK),(public_ca_der,16384),(build_json,MAX_METADATA)):
        if not isinstance(value,bytes) or not 0<len(value)<=limit:raise ValueError('bounded public provisioning bytes')
    if metadata['source_manifest_sha256']!=validate_digest(expected_source_manifest_sha256):
        raise ValueError('provisioning reviewed source identity differs')
    for name,value in (('apk_sha256',apk),('public_ca_sha256',public_ca_der),('build_json_sha256',build_json)):
        if metadata[name]!=digest(value):raise ValueError('public provisioning bytes substituted')
    # Parse exact one public CA without accepting a PEM/private-key bundle or
    # trailing bytes. Runtime cryptography belongs in the exact closure.
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    cert=x509.load_der_x509_certificate(public_ca_der)
    if cert.public_bytes(Encoding.DER)!=public_ca_der or not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError('single public CA DER required')
    build=json.loads(build_json)
    if (build.get('apk_sha256')!=metadata['apk_sha256'] or build.get('public_ca_sha256')!=metadata['public_ca_sha256']
        or build.get('package')!=PACKAGE or build.get('actual_app_network_not_executed_by_build') is not True):
        raise ValueError('public build identity differs from handoff')
    validate_digest(build.get('signature_sha256'))
    if len(canonical(metadata))+len(apk)+len(public_ca_der)+len(build_json)>MAX_READY:
        raise ValueError('total public provisioning handoff bound')
    return build


def make_commit(request,*,ready_metadata,ready_metadata_sha256):
    # Conversion only, NOT an approval issuance. Product host must already have
    # validated fresh committed grant and exact actual APK/CA against its plan.
    request.validate()
    validate_ready_fields(ready_metadata)
    if digest(canonical(ready_metadata))!=validate_digest(ready_metadata_sha256):
        raise ValueError('fixed provisioning metadata digest')
    if (request.apk_sha256,request.public_ca_sha256)!=(ready_metadata['apk_sha256'],ready_metadata['public_ca_sha256']):
        raise ValueError('approved request differs from provisioned public bytes')
    return {'version':COMMIT_VERSION,'ready_metadata_sha256':ready_metadata_sha256,'request':asdict(request)}


def validate_commit(record,*,ready_metadata,expected_request):
    if not isinstance(record,dict) or set(record)!={'version','ready_metadata_sha256','request'}:
        raise ValueError('closed fixed commit record keys')
    if record['version']!=COMMIT_VERSION or len(canonical(record))>MAX_METADATA:
        raise ValueError('fixed bounded commit version')
    request=OwnedAppRequest(**record['request']);request.validate()
    if request!=expected_request:raise ValueError('control commit differs from fresh product host request')
    if record!=make_commit(request,ready_metadata=ready_metadata,ready_metadata_sha256=record['ready_metadata_sha256']):
        raise ValueError('control commit provenance differs')
    return request


class LifecycleState:
    """Pure stage accounting, records intent/result without performing any work."""
    def __init__(self):self.stage='new';self.failure=None;self.records=[]

    def advance(self,event,*,seconds,originals=0,receipts=0):
        if self.failure is not None:raise ValueError('failed lifecycle cannot retry into success')
        try:return self._advance(event,seconds=seconds,originals=originals,receipts=receipts)
        except BaseException as error:
            self.failure={'stage':self.stage,'class':type(error).__name__}
            raise

    def _advance(self,event,*,seconds,originals,receipts):
        # Runtime supervisor supplies elapsed values from its own monotonic clock,
        # never from child data. Any invalid transition terminal-fails this object.
        if type(seconds) not in (int,float) or not 0<=seconds<100000:raise ValueError('elapsed seconds required')
        if type(originals) is not int or type(receipts) is not int or originals<0 or receipts<0:
            raise ValueError('actual nonnegative evidence counts required')
        order={'new':('provisioned','ready',240),'ready':('committed','committed',30),
            'committed':('operation_returned','operation_returned',60),
            'operation_returned':('runtime_absent','runtime_absent',60),
            'runtime_absent':('collected','collected',10)}
        if self.stage not in order or order[self.stage][0]!=event:raise ValueError('out-of-order or duplicate lifecycle event')
        required,new,limit=order[self.stage]
        if seconds>limit:raise ValueError('separate stage ceiling exceeded')
        if self.stage in ('new','ready') and (originals or receipts):raise ValueError('traffic before approved operation')
        self.records.append({'stage':self.stage,'event':event,'seconds':seconds,'originals':originals,'receipts':receipts})
        self.stage=new
        return self.stage

    def fail(self,error_class):
        if not isinstance(error_class,str) or re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,79}',error_class) is None:
            raise ValueError('bounded failure class required')
        self.failure={'stage':self.stage,'class':error_class};return self.failure


class ExpectedContext:
    """Root-owned relay object, never reconstructed from a client record."""
    def __init__(self,*,run_id,provisioning_id,closure_sha256,source_manifest_sha256):
        self.run_id=run_id;self.provisioning_id=provisioning_id
        self.closure_sha256=validate_digest(closure_sha256)
        self.source_manifest_sha256=validate_digest(source_manifest_sha256)
        for value in (run_id,provisioning_id):
            if re.fullmatch('[0-9a-f]{32}',value) is None:raise ValueError('unique root context required')
        self.ready=None;self.used=False;self.failed=False

    def accept_ready(self,metadata):
        try:
            if self.ready is not None or self.used or self.failed:raise ValueError('ready already consumed or failed')
            validate_ready_fields(metadata)
            for key in ('run_id','provisioning_id','closure_sha256','source_manifest_sha256'):
                if metadata[key]!=getattr(self,key):raise ValueError('cross-run provisioning context differs')
            self.ready=json.loads(canonical(metadata));return self.ready
        except BaseException:self.failed=True;raise

    def consume(self,record):
        try:
            if self.failed or self.used or self.ready is None:raise ValueError('one-shot relay context unavailable')
            self.used=True
            request=OwnedAppRequest(**record['request']);request.validate()
            validate_commit(record,ready_metadata=self.ready,expected_request=request)
            return request
        except BaseException:self.failed=True;raise
