"""Held workflow orchestrator. Review install and positive modes independently."""
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ALLOW_INSTALL_ONLY = False
ALLOW_POSITIVE_FIXTURE = False

def main():
    if len(sys.argv)!=4:raise SystemExit('usage: activate.py MODE NEW_RAW_ROOT WHEELHOUSE')
    mode,raw,wheelhouse=sys.argv[1],Path(sys.argv[2]).resolve(),Path(sys.argv[3]).resolve()
    if mode not in ('install_only','positive_fixture'):raise RuntimeError('unknown mode')
    if not ALLOW_INSTALL_ONLY:raise SystemExit('INSTALL MODE HELD: exact review required')
    if mode=='positive_fixture' and not ALLOW_POSITIVE_FIXTURE:raise SystemExit('POSITIVE RUNTIME HELD')
    if os.geteuid()!=0:raise RuntimeError('ephemeral CI root orchestrator required')
    source=Path(__file__).resolve().parent
    raw.mkdir(mode=0o700,exist_ok=False)
    stage=Path('/opt/d061-reviewed-source')
    stage.mkdir(mode=0o755,exist_ok=False)
    manifest=[]
    names=('installer.py','wrapper.py','driver.py','origin.py','addon.py','wire.py','cleanup.py',
           'wheel-lock.json','requirements.lock','bootstrap-lock.json')
    for name in names:
        content=(source/name).read_bytes()
        manifest.append({'path':name,'sha256':hashlib.sha256(content).hexdigest()})
        if name=='installer.py' or mode=='positive_fixture' and name in ('wrapper.py','driver.py'):
            text=content.decode()
            marker='APPROVED_FOR_EXECUTION = False'
            if text.count(marker)!=1:raise RuntimeError('unexpected activation source')
            text=text.replace(marker,'APPROVED_FOR_EXECUTION = True')
            ast.parse(text)
            content=text.encode()
        (stage/name).write_bytes(content)
        (stage/name).chmod(0o644)
    manifest_record={'mode':mode,'reviewed_checkout_sha':os.environ.get('D061_REVIEWED_SHA'),
                     'source_files':manifest,'staged_dir':str(stage),'no_product_changes':True}
    (raw/'activation-record.json').write_text(json.dumps(manifest_record,sort_keys=True)+'\n')
    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','HOME':'/nonexistent',
         'ImageOS':os.environ.get('ImageOS',''),'ImageVersion':os.environ.get('ImageVersion','')}
    def command(argv,name):
        with (raw/(name+'.log')).open('xb') as log:
            p=subprocess.run(argv,env=env,stdin=subprocess.DEVNULL,stdout=log,
                stderr=subprocess.STDOUT,close_fds=True,timeout=180)
        (raw/'workflow-command.json').write_text(json.dumps({'mode':mode,'stage':name,
            'argv':argv,'rc':p.returncode})+'\n')
        if p.returncode:raise subprocess.CalledProcessError(p.returncode,argv)
    shutil.copyfile(wheelhouse/'staging-manifest.json',raw/'staging-manifest.json')
    command([sys.executable,str(stage/'installer.py'),str(wheelhouse)],'install')
    shutil.copyfile('/opt/d061-runtime/runtime-record.json',raw/'runtime-record.json')
    if mode=='positive_fixture':
        command([sys.executable,str(stage/'wrapper.py'),'--source',str(stage),
            '--runtime','/opt/d061-runtime','--base-prefix',sys.base_prefix,
            '--output',str(raw/'fixture')],'fixture')

if __name__=='__main__':main()
