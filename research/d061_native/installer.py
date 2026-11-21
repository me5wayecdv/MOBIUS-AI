"""HELD wheel-only no-index isolated installer. Does not fetch or build."""
import hashlib
import json
import os
from pathlib import Path
import platform
import ssl
import subprocess
import sys
import zipfile

APPROVED_FOR_EXECUTION = False

def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('HELD: exact installer/wrapper/harness review required')
    if os.geteuid()!=0:raise RuntimeError('ephemeral isolated CI root staging required')
    if sys.version_info[:2]!=(3,12) or platform.machine()!='x86_64':raise RuntimeError('wrong interpreter/platform')
    libc,version=platform.libc_ver()
    if libc!='glibc' or tuple(map(int,version.split('.')[:2]))<(2,28):raise RuntimeError('glibc target mismatch')
    if len(sys.argv)!=2:raise SystemExit('usage: installer.py PREPOPULATED_WHEELHOUSE')
    wheelhouse=Path(sys.argv[1]).resolve()
    source=Path(__file__).resolve().parent
    lock=json.loads((source/'wheel-lock.json').read_text())
    bootstrap=json.loads((source/'bootstrap-lock.json').read_text())
    rows=lock['wheels']+[bootstrap]
    for row in rows:
        path=wheelhouse/row['filename']
        if path.is_symlink() or not path.is_file() or path.suffix!='.whl':raise RuntimeError('not regular wheel')
        if hashlib.sha256(path.read_bytes()).hexdigest()!=row['sha256']:raise RuntimeError('wheel hash mismatch')
        with zipfile.ZipFile(path) as z:
            if z.testzip() is not None:raise RuntimeError('corrupt wheel')
    root=Path('/opt/d061-runtime')
    root.mkdir(mode=0o755,exist_ok=False)
    env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','HOME':str(root),
         'PIP_NO_INDEX':'1','PIP_DISABLE_PIP_VERSION_CHECK':'1','PYTHONDONTWRITEBYTECODE':'1'}
    def run(argv,extra=None):
        e=dict(env)
        if extra:e.update(extra)
        subprocess.run(argv,env=e,stdin=subprocess.DEVNULL,close_fds=True,check=True,timeout=120)
    venv=root/'venv'
    run([sys.executable,'-I','-m','venv','--without-pip',str(venv)])
    # Import the separately hash-verified bootstrap wheel only inside the future
    # reviewed isolated install phase, never during present preparation.
    run([str(venv/'bin/python'),'-m','pip','install','--no-index','--no-deps',
         '--only-binary=:all:','--require-hashes','--no-compile',
         '--find-links',str(wheelhouse),'-r',str(source/'requirements.lock')],
        {'PYTHONPATH':str(wheelhouse/bootstrap['filename'])})
    # No deps flag is intentional: the separately resolved hash-closed42 lock
    # lists every distribution explicitly. Post-install consistency still checked.
    run([str(venv/'bin/python'),'-m','pip','check'],
        {'PYTHONPATH':str(wheelhouse/bootstrap['filename'])})
    runtime={'interpreter':sys.version,'executable':sys.executable,'base_prefix':sys.base_prefix,
             'glibc':platform.libc_ver(),'openssl':ssl.OPENSSL_VERSION,
             'kernel':platform.release(),'os_release':Path('/etc/os-release').read_text(),
             'provider_reported_image_os':os.environ.get('ImageOS'),
             'provider_reported_image_version':os.environ.get('ImageVersion'),
             'image_digest':'not provided by hosted runner, no invented digest',
             'runtime_wheels':len(lock['wheels']),'bootstrap_pip':bootstrap['version']}
    (root/'runtime-record.json').write_text(json.dumps(runtime,sort_keys=True)+'\n')
    # Root-owned/read-only to the later fixture UID, no runtime wheel downloads.
    for path in root.rglob('*'):
        if not path.is_symlink():
            os.chown(path,0,0)
            path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
    print(json.dumps({'status':'ISOLATED_INSTALL_ONLY','record':str(root/'runtime-record.json')}))

if __name__=='__main__':main()
