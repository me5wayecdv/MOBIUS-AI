"""Pure held owned-APK profile. Not registered in product schema/runner."""
from dataclasses import dataclass
import re

PROFILE='owned-android-fixed-loopback-v1'
PACKAGE='org.mobius.ownedfixture'
APPROVED_FOR_BUILD = False
APPROVED_FOR_EXECUTION = False


@dataclass(frozen=True)
class OwnedAppRequest:
    apk_sha256: str
    public_ca_sha256: str
    plan_sha256: str
    authorization_id: str
    approval_id: str
    investigation_id: str
    nonce: str
    profile: str = PROFILE
    package: str = PACKAGE
    proxy_host: str = '127.0.0.1'
    proxy_port: int = 18080
    origin_host: str = '127.0.0.1'
    origin_port: int = 18443
    operation_seconds: int = 60
    teardown_seconds: int = 60
    collection_seconds: int = 10
    max_evidence_bytes: int = 1048576

    def validate(self):
        if self.profile!=PROFILE or self.package!=PACKAGE:raise ValueError('fixed owned APK profile')
        if (self.proxy_host,self.proxy_port,self.origin_host,self.origin_port)!=('127.0.0.1',18080,'127.0.0.1',18443):
            raise ValueError('fixed owned local endpoints')
        for value in (self.apk_sha256,self.public_ca_sha256,self.plan_sha256):
            if not re.fullmatch('[0-9a-f]{64}',value):raise ValueError('required original digest')
        if not re.fullmatch('[0-9a-f]{32}',self.nonce):raise ValueError('required fixed nonce')
        if not all((self.authorization_id,self.approval_id,self.investigation_id)):raise ValueError('authority binding required')
        if (self.operation_seconds,self.teardown_seconds,self.collection_seconds)!=(60,60,10):
            raise ValueError('fixed bounded operation and cleanup reserve')
        if self.max_evidence_bytes!=1048576:raise ValueError('fixed output ceiling')
        return self
