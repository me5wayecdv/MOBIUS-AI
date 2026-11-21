"""HELD offline owned-APK build, no fetch/Gradle/SDK resolution/private user key.

Only invoked after separate exact build/toolchain review. The toolchain manifest
must contain actual SHA256-pinned regular files, not metadata candidate hashes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import selectors
import time
import zipfile

APPROVED_FOR_BUILD = False
PACKAGE='org.mobius.ownedfixture'


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def regular(path):
    if not path.is_file() or path.is_symlink():raise ValueError('regular toolchain/source file required')
    current=path.absolute()
    for parent in current.parents:
        if parent.is_symlink():raise ValueError('symlink toolchain parent')
    return path


def verify_toolchain(root,lock):
    required={'aapt2','d8','zipalign','apksigner','android.jar','java','javac','keytool'}
    rows=lock.get('files',{})
    if lock.get('status')!='RESOLVED_REVIEWED_OFFLINE_LOCK' or set(rows)!=required:
        raise ValueError('unresolved offline build toolchain')
    paths={}
    for name,row in rows.items():
        relative=Path(row['relative_path'])
        if relative.is_absolute() or '..' in relative.parts:raise ValueError('toolchain path')
        path=regular(root/relative)
        if not re.fullmatch('[0-9a-f]{64}',row.get('sha256','')) or digest(path)!=row['sha256']:
            raise ValueError('toolchain digest')
        paths[name]=path
    # Launchers can load other libraries. Whole closure must be listed separately;
    # executable/jar hashes alone are NOT dependency-closure verification.
    closure=lock.get('closure_files',[])
    if not closure:raise ValueError('toolchain runtime closure manifest required')
    for row in closure:
        relative=Path(row['relative_path'])
        if relative.is_absolute() or '..' in relative.parts:raise ValueError('closure path')
        path=regular(root/relative)
        if digest(path)!=row['sha256']:raise ValueError('toolchain closure digest')
    return paths


def main():
    if not APPROVED_FOR_BUILD:raise SystemExit('HELD: exact offline toolchain/build review required')
    p=argparse.ArgumentParser()
    p.add_argument('--toolchain-root',type=Path,required=True)
    p.add_argument('--toolchain-lock',type=Path,required=True)
    p.add_argument('--public-proxy-ca',type=Path,required=True)
    p.add_argument('--public-ca-sha256',required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    # Runs only in the later reviewed no-uplink child, never root/host shell.
    if os.geteuid()==0:raise RuntimeError('nonroot offline build child required')
    tools=verify_toolchain(a.toolchain_root,json.loads(a.toolchain_lock.read_text()))
    ca=regular(a.public_proxy_ca)
    if not re.fullmatch('[0-9a-f]{64}',a.public_ca_sha256) or digest(ca)!=a.public_ca_sha256:
        raise ValueError('this-run public proxy CA digest differs')
    if ca.stat().st_size>16384:raise ValueError('public certificate bound')
    # Parse exactly one public CA certificate, not a DER-looking byte prefix.
    # cryptography itself must belong to the reviewed offline runtime closure.
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    certificate=x509.load_der_x509_certificate(ca.read_bytes())
    if certificate.public_bytes(Encoding.DER)!=ca.read_bytes():raise ValueError('noncanonical DER or trailing bytes')
    if not certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError('explicit app anchor must be a public CA certificate')
    out=a.output;out.mkdir(mode=0o700,exist_ok=False)
    source=Path(__file__).resolve().parent/'app'
    app=out/'app';shutil.copytree(source,app,symlinks=False)
    raw=app/'res/raw';raw.mkdir(exist_ok=False);shutil.copyfile(ca,raw/'fixture_proxy_ca.der')
    classes=out/'classes';classes.mkdir()
    dex=out/'dex';dex.mkdir()
    generated=out/'generated';generated.mkdir()
    home=out/'private-build-home';home.mkdir(mode=0o700)
    java_home=tools['java'].parent.parent
    if tools['javac'].parent.parent!=java_home or tools['keytool'].parent.parent!=java_home:
        raise ValueError('one pinned JDK closure required')
    env={'PATH':str(java_home/'bin')+':/usr/bin:/bin','JAVA_HOME':str(java_home),
        'LANG':'C.UTF-8','HOME':str(home),'TMPDIR':str(out)}
    commands=[]
    build_started=time.monotonic()
    def run(argv,name):
        commands.append({'stage':name,'argv':list(map(str,argv))})
        remaining=120-(time.monotonic()-build_started)
        if remaining<=0:raise TimeoutError('fixed whole offline build ceiling')
        deadline=time.monotonic()+min(60,remaining)
        process=None
        with (out/(name+'.log')).open('xb') as log:
            try:
                process=subprocess.Popen(list(map(str,argv)),env=env,cwd=out,stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,stderr=subprocess.STDOUT,close_fds=True)
                os.set_blocking(process.stdout.fileno(),False)
                total=0
                with selectors.DefaultSelector() as poller:
                    poller.register(process.stdout,selectors.EVENT_READ)
                    eof=False
                    while not eof:
                        if time.monotonic()>deadline:raise TimeoutError('fixed build stage deadline')
                        for key,events in poller.select(timeout=min(.1,max(0,deadline-time.monotonic()))):
                            data=os.read(process.stdout.fileno(),4096)
                            if not data:eof=True;break
                            total+=len(data)
                            if total>65536:raise ValueError('build stage diagnostic output bound')
                            log.write(data)
                process.wait(timeout=max(.1,deadline-time.monotonic()))
                result=process
            finally:
                if process is not None:
                    if process.poll() is None:process.kill();process.wait(timeout=5)
                    process.stdout.close()
        commands[-1]['rc']=result.returncode
        (out/'build-commands.json').write_text(json.dumps(commands,sort_keys=True))
        if result.returncode:raise RuntimeError('actual offline build stage failed:'+name)
    run([tools['aapt2'],'compile','--dir',app/'res','-o',out/'compiled.zip'],'resources')
    run([tools['aapt2'],'link','--manifest',app/'AndroidManifest.xml','-I',tools['android.jar'],
        '--java',generated,'-o',out/'unsigned-res.apk',out/'compiled.zip'],'resource-link')
    java=sorted(app.rglob('*.java'))+sorted(generated.rglob('*.java'))
    run([tools['javac'],'-source','8','-target','8','-bootclasspath',tools['android.jar'],
        '-d',classes,*java],'java')
    # D8 accepts one deterministic classes JAR, not shell-expanded argv patterns.
    jar=out/'classes.jar'
    with zipfile.ZipFile(jar,'x',zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(classes.rglob('*.class')):archive.write(path,path.relative_to(classes))
    run([tools['d8'],'--min-api','26','--lib',tools['android.jar'],'--output',dex,jar],'dex')
    unsigned=out/'unsigned.apk';shutil.copyfile(out/'unsigned-res.apk',unsigned)
    with zipfile.ZipFile(unsigned,'a',zipfile.ZIP_DEFLATED) as archive:
        archive.write(dex/'classes.dex','classes.dex')
    run([tools['zipalign'],'-p','4',unsigned,out/'aligned.apk'],'align')
    key=home/'disposable-signing.p12'
    # Fixed throwaway password is not a user credential, never reused. The
    # private key is local test material and is excluded from uploaded evidence.
    run([tools['keytool'],'-genkeypair','-keystore',key,'-storetype','PKCS12',
        '-storepass','android','-keypass','android','-alias','owned-fixture','-keyalg','RSA','-keysize','2048',
        '-validity','1','-dname','CN=Mobius Owned Disposable Fixture'],'disposable-signing-key')
    apk=out/'owned-fixture.apk'
    run([tools['apksigner'],'sign','--ks',key,'--ks-pass','pass:android','--key-pass','pass:android',
        '--ks-key-alias','owned-fixture','--out',apk,out/'aligned.apk'],'sign')
    run([tools['apksigner'],'verify','--verbose','--print-certs',apk],'verify-signature')
    run([tools['aapt2'],'dump','badging',apk],'verify-package')
    if "package: name='"+PACKAGE+"'" not in (out/'verify-package.log').read_text():raise ValueError('actual APK package differs')
    with zipfile.ZipFile(apk) as archive:
        names=archive.namelist()
        if len(names)!=len(set(names)):raise ValueError('duplicate APK entries')
        if archive.read('res/raw/fixture_proxy_ca.der')!=ca.read_bytes():raise ValueError('APK public CA differs')
    signature=re.findall(r'(?m)^Signer #1 certificate SHA-256 digest: ([0-9a-f]{64})$',(out/'verify-signature.log').read_text())
    if len(signature)!=1:raise ValueError('exact single APK signer certificate identity required')
    record={'signature_sha256':signature[0],'apk_sha256':digest(apk),'public_ca_sha256':digest(ca),'package':PACKAGE,
        'source_files':[{ 'path':str(path.relative_to(source)),'sha256':digest(path)} for path in sorted(source.rglob('*')) if path.is_file()],
        'toolchain_lock_sha256':digest(a.toolchain_lock),'disposable_key_not_for_upload':True,
        'actual_app_network_not_executed_by_build':True}
    (out/'build-result.json').write_text(json.dumps(record,sort_keys=True))
    # Independent outer sanitizer still required on every failure path.
    shutil.rmtree(home)

if __name__=='__main__':main()
