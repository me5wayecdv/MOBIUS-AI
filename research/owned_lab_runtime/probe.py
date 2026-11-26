"""Held, exact owned-lab read probes. No boot, target discovery, install or writes.

Only a separately reviewed supervisor may call this after exact artifact/installed
APK hash checks, approved shell identity and explicit disposable-device authority.
"""
from __future__ import annotations
import hashlib
import re
from pathlib import Path

APPROVED_FOR_EXECUTION=False
SIGNED_SHA256='6b7081010eb6dfb2b90e27b94a761020528e4ea8b17d300bdd372e0b130deca8'
CERT_SHA256='197ce8054d16f0c8bded9802c0ada2a4908ed0f7fd1b923decb7d37c1074f75c'
PACKAGE='com.mobius.ownedlab'


def classify(text: str, returncode: int, *, private: bool) -> str:
    # Exact success requires a known seeded row. A generic Row: substring is
    # insufficient. Private denial requires explicit permission denial, not error.
    if len(text.encode())>262144:return 'unclassified'
    if private:
        if re.search(r'Permission Denial:.*not exported',text,re.S) and 'Row:' not in text:
            return 'permission_denied'
        return 'unclassified'
    if returncode==0 and re.fullmatch(r'Row: 0 _id=1, body=MOBIUS_SYNTHETIC_LAB_ROW\s*',text):
        return 'synthetic_row_read'
    return 'unclassified'


def run(adb: str, serial: str, artifact: Path, *, invoke=None) -> dict:
    if not APPROVED_FOR_EXECUTION:raise RuntimeError('HELD: runtime permission and independent supervisor review required')
    if not Path(adb).is_absolute() or not re.fullmatch(r'emulator-[0-9]{4,8}',serial):raise ValueError('explicit adb and emulator serial required')
    if artifact.is_symlink() or hashlib.sha256(artifact.read_bytes()).hexdigest()!=SIGNED_SHA256:raise ValueError('exact signed artifact required')
    def cmd(*args):
        if invoke is None:
            from .collector import collect
            result=collect([adb,'-s',serial,*args],timeout=45,limit=262144)
        else:
            result=invoke([adb,'-s',serial,*args],timeout=45,limit=262144)
        if result.status!='completed':raise RuntimeError('bounded adb transport failed')
        return result
    uid=cmd('shell','id','-u')
    if uid.returncode or uid.stdout.strip()!='2000':raise RuntimeError('shell UID2000 required')
    path=cmd('shell','pm','path',PACKAGE)
    if path.returncode or not re.fullmatch(r'package:/data/app/[A-Za-z0-9_~+=./-]+/base\.apk\s*',path.stdout):raise RuntimeError('one installed base APK required')
    remote=path.stdout.strip()[8:]
    digest=cmd('shell','sha256sum',remote)
    if digest.returncode or digest.stdout.split()[:1]!=[SIGNED_SHA256]:raise RuntimeError('installed APK hash mismatch')
    negative=cmd('shell','content','query','--uri','content://com.mobius.ownedlab.private/note')
    if classify(negative.stdout+negative.stderr,negative.returncode,private=True)!='permission_denied':raise RuntimeError('private denial not established')
    positive=cmd('shell','content','query','--uri','content://com.mobius.ownedlab.notes/note')
    if classify(positive.stdout+positive.stderr,positive.returncode,private=False)!='synthetic_row_read':raise RuntimeError('fixed synthetic row not established')
    return {'status':'owned_lab_plain_read_and_private_denial','apk_sha256':SIGNED_SHA256,
            'certificate_sha256':CERT_SHA256,'caller_uid':2000,
            'selection_injection_proven':False,'ordinary_app_uid_proven':False}


if __name__=='__main__':
    raise SystemExit('HELD: no CLI execution route until reviewed supervisor, transfer and runtime approval')
