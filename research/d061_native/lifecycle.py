"""Linux lifecycle helpers, called only during a reviewed future execution."""
import ctypes
import os
from pathlib import Path
import signal
import stat
import select
import time


def lexical(path, leaf_missing=False):
    if '..' in Path(path).parts:raise ValueError('parent component')
    path=Path(os.path.abspath(os.fspath(path)))
    current=Path(path.anchor)
    for i,part in enumerate(path.parts[1:]):
        current=current/part
        try:info=current.lstat()
        except FileNotFoundError:
            if leaf_missing and i==len(path.parts)-2:return path
            raise
        if stat.S_ISLNK(info.st_mode):raise ValueError('symlink path component')
    return path


def parent_death(expected_parent, sig=signal.SIGKILL):
    def arm():
        libc=ctypes.CDLL(None,use_errno=True)
        if libc.prctl(1,int(sig),0,0,0)!=0:os._exit(126)
        if os.getppid()!=expected_parent:os._exit(125)
    return arm


def identity(pid):
    content=Path('/proc/'+str(pid)+'/stat').read_text()
    return {'pid':pid,'starttime':content[content.rindex(')')+2:].split()[19],
            'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def matches(record):
    try:return identity(record['pid'])==record
    except (FileNotFoundError,ProcessLookupError):return False


def terminate_identity(record, seconds=8):
    # pidfd avoids signalling a reused numeric PID after identity validation.
    if not matches(record):return {'state':'already_absent_or_identity_changed'}
    fd=os.pidfd_open(record['pid'])
    try:
        if not matches(record):return {'state':'identity_changed_before_signal'}
        signal.pidfd_send_signal(fd,signal.SIGKILL)
        deadline=time.monotonic()+seconds
        while not select.select([fd],[],[],0.1)[0]:
            if time.monotonic()>deadline:raise TimeoutError('identity remains after kill')
        return {'state':'terminated'}
    finally:os.close(fd)
