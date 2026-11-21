"""HELD exact-source staging, no import/install/runtime side effect until review."""
import ast
import hashlib
import json
import os
from pathlib import Path
import sys

APPROVED_FOR_EXECUTION = False


def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('HELD: consolidated product workflow/source review required')
    if os.geteuid()!=0:raise RuntimeError('ephemeral CI staging only')
    source=Path(__file__).resolve().parent
    stage=Path('/opt/d061-reviewed-source');stage.mkdir(mode=0o755,exist_ok=False)
    names=('installer.py','wrapper.py','driver.py','origin.py','addon.py','wire.py','cleanup.py','lifecycle.py',
        'emergency.py','absence.py','tls_controls.py','tls_driver.py','product_host.py','product_setup.py',
        'product_http_journey.py','run_product_owned.py','product_collect.py','wheel-lock.json','requirements.lock','bootstrap-lock.json')
    activated={'installer.py','wrapper.py','driver.py','tls_controls.py','tls_driver.py','product_host.py','product_setup.py','product_http_journey.py','run_product_owned.py'}
    manifest=[]
    for name in names:
        content=(source/name).read_bytes()
        row={'path':name,'original_sha256':hashlib.sha256(content).hexdigest(),'gate_activated':name in activated}
        if name in activated:
            text=content.decode();marker='APPROVED_FOR_EXECUTION = False'
            if text.count(marker)!=1:raise ValueError('unexpected exact source activation marker:'+name)
            text=text.replace(marker,'APPROVED_FOR_EXECUTION = True');ast.parse(text);content=text.encode()
        (stage/name).write_bytes(content);(stage/name).chmod(0o644)
        row['staged_sha256']=hashlib.sha256(content).hexdigest();manifest.append(row)
    # Separate isolated TLS namespace uses identical reviewed wrapper mechanics.
    # Only its two fixed child-driver literals differ. No request-selected code.
    wrapper=(stage/'wrapper.py').read_text()
    if wrapper.count('/fixture/driver.py')!=2:raise ValueError('unexpected wrapper fixed child-driver count')
    tls=wrapper.replace('/fixture/driver.py','/fixture/tls_driver.py')
    ast.parse(tls);(stage/'tls_wrapper.py').write_text(tls)
    manifest.append({'path':'tls_wrapper.py','derived_from':'wrapper.py','fixed_replacements':2,
        'staged_sha256':hashlib.sha256(tls.encode()).hexdigest()})
    Path(sys.argv[1]).write_text(json.dumps({'reviewed_sha':os.environ['D061_REVIEWED_SHA'],'files':manifest},sort_keys=True))

if __name__=='__main__':main()
