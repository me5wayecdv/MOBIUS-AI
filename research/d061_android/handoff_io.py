"""Fixed bounded regular-file handoff IO. No shell, launch, or arbitrary tree copy."""
import hashlib
import json
import os
from pathlib import Path
import stat
import time


def read(path,limit=1048576):
    path=Path(path)
    for parent in path.parents:
        if parent.is_symlink():raise ValueError('symlink handoff ancestor')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        meta=os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_size>limit:raise ValueError('regular handoff size bound')
        with os.fdopen(fd,'rb',closefd=False) as stream:data=stream.read(limit+1)
        if len(data)>limit:raise ValueError('handoff grew beyond bound')
        return data
    finally:os.close(fd)


def write(path,data,*,mode=0o444):
    path=Path(path)
    if not isinstance(data,bytes):raise TypeError('exact byte snapshot required')
    tmp=path.with_name('.'+path.name+'.partial')
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb',closefd=False) as output:output.write(data);output.flush();os.fsync(fd)
        os.fchmod(fd,mode)
    finally:os.close(fd)
    # One-shot destination. No overwrite/rebind when a previous handoff exists.
    os.link(tmp,path,follow_symlinks=False);tmp.unlink()
    directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(directory)
    finally:os.close(directory)


def json_write(path,value,*,mode=0o444):
    write(path,json.dumps(value,sort_keys=True,separators=(',',':')).encode(),mode=mode)


def wait(path,*,deadline,child=None,pump=None,limit=65536):
    # Root/driver owns absolute monotonic deadline, never child-provided elapsed.
    while True:
        if time.monotonic()>deadline:raise TimeoutError('fixed handoff deadline')
        if pump:pump()
        if Path(path).exists():return read(path,limit)
        if child is not None and child.poll() is not None:raise RuntimeError('handoff producer exited early')
        time.sleep(.05)


def digest(data):return hashlib.sha256(data).hexdigest()
