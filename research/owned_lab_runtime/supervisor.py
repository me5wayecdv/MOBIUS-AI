"""Held supervisor foundation, not an emulator launcher.

A retained Popen owner and pidfd can stop/reap its exact direct child. This does
not prove descendant absence or independent cancellation recovery. Activation
must stay held until a reviewed containment mechanism closes those gaps.
"""
from __future__ import annotations
import os
from pathlib import Path
import signal
import subprocess

APPROVED_FOR_EXECUTION=False


def identity(pid):
    raw=Path(f'/proc/{pid}/stat').read_text()
    fields=raw[raw.rindex(')')+2:].split()
    executable=Path(f'/proc/{pid}/exe').stat()
    return {'pid':pid,'starttime':fields[19],'pgid':int(fields[2]),
            'sid':int(fields[3]),'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'exe_device':executable.st_dev,'exe_inode':executable.st_ino}


class OwnershipUnavailable(RuntimeError):
    """Exact retained owner could not be established."""


class RetainedChild:
    def __init__(self, process):
        self.process=process
        if process.poll() is not None:
            raise OwnershipUnavailable('child_already_reaped')
        try:self.fd=os.pidfd_open(process.pid)
        except ProcessLookupError:raise OwnershipUnavailable('child_already_absent') from None
        try:self.record=identity(process.pid)
        except (FileNotFoundError,ProcessLookupError):
            os.close(self.fd)
            raise OwnershipUnavailable('child_identity_unavailable') from None
        if self.record['pgid']!=process.pid or self.record['sid']!=process.pid:
            os.close(self.fd);raise ValueError('dedicated session required')

    def close(self):
        p=self.process
        try:
            if p.poll() is None:
                try:current=identity(p.pid)
                except (FileNotFoundError,ProcessLookupError):current=None
                if current!=self.record:
                    return {'owner_state':'UNVERIFIED','descendants':'UNVERIFIED'}
                try:signal.pidfd_send_signal(self.fd,signal.SIGTERM)
                except ProcessLookupError:pass
                try:p.wait(timeout=.5)
                except subprocess.TimeoutExpired:
                    try:signal.pidfd_send_signal(self.fd,signal.SIGKILL)
                    except ProcessLookupError:pass
                    try:p.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        return {'owner_state':'UNVERIFIED','descendants':'UNVERIFIED'}
            else:p.wait(timeout=2)
            return {'owner_state':'reaped','descendants':'UNVERIFIED'}
        finally:
            os.close(self.fd)


def launch_emulator(*args,**kwargs):
    raise RuntimeError('HELD: transfer, runtime authority, network containment and descendant cleanup unresolved')
