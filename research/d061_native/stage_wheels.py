"""Download-only staging, verify all locked wheels, never import/install."""
import hashlib
import json
from pathlib import Path
import sys
import urllib.parse
import urllib.request

if len(sys.argv)!=2:raise SystemExit('usage: stage_wheels.py NEW_WHEELHOUSE')
root=Path(__file__).resolve().parent
out=Path(sys.argv[1]).resolve()
out.mkdir(mode=0o700,parents=False,exist_ok=False)
rows=json.loads((root/'wheel-lock.json').read_text())['wheels']
rows.append(json.loads((root/'bootstrap-lock.json').read_text()))
manifest=[]
for row in rows:
    url=urllib.parse.urlsplit(row['url'])
    if url.scheme!='https' or url.netloc!='files.pythonhosted.org':raise RuntimeError('wheel source')
    filename=row['filename']
    if Path(filename).name!=filename or not filename.endswith('.whl'):raise RuntimeError('wheel filename')
    path=out/filename
    with urllib.request.urlopen(row['url'],timeout=30) as response:
        if urllib.parse.urlsplit(response.url).netloc!='files.pythonhosted.org':raise RuntimeError('wheel redirect host')
        data=response.read(64*1024*1024+1)
    if len(data)>64*1024*1024:raise RuntimeError('wheel size')
    digest=hashlib.sha256(data).hexdigest()
    if digest!=row['sha256']:raise RuntimeError('wheel digest')
    path.write_bytes(data)
    manifest.append({'filename':filename,'sha256':digest,'bytes':len(data),'source_url':row['url']})
(out/'staging-manifest.json').write_text(json.dumps(manifest,sort_keys=True)+'\n')
