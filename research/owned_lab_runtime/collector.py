"""Bounded local child transport. No Android command is selected here.

pidfds bind signals to the retained child, not a reused PID. Descendant/group
cleanup is deliberately NOT claimed. The future emulator supervisor must own
its containment group and prove absence independently before runtime activation.
"""
from __future__ import annotations
from dataclasses import dataclass
import os
import selectors
import signal
import subprocess
import time

@dataclass(frozen=True)
class Result:
    returncode:int
    stdout:str
    stderr:str
    status:str
    descendant_cleanup:str='UNVERIFIED'


def collect(argv, *, timeout=45, limit=262144):
    if not argv or not os.path.isabs(argv[0]):raise ValueError('absolute executable required')
    if not 0<timeout<=180 or not 0<limit<=262144:raise ValueError('bounded limits required')
    if not hasattr(os,'pidfd_open') or not hasattr(signal,'pidfd_send_signal'):
        raise RuntimeError('pidfd capability required')
    p=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    fd=os.pidfd_open(p.pid)
    sel=selectors.DefaultSelector();streams={};total=0;status='completed';deadline=time.monotonic()+timeout
    for pipe in (p.stdout,p.stderr):
        os.set_blocking(pipe.fileno(),False);sel.register(pipe,selectors.EVENT_READ);streams[pipe]=bytearray()
    def stop():
        # Always signal through pidfd, never recycled PID/process-name search.
        try:signal.pidfd_send_signal(fd,signal.SIGTERM)
        except ProcessLookupError:pass
        try:p.wait(timeout=.5)
        except subprocess.TimeoutExpired:
            try:signal.pidfd_send_signal(fd,signal.SIGKILL)
            except ProcessLookupError:pass
            try:p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                raise RuntimeError('child_reap_unverified') from None
    try:
        while sel.get_map():
            remaining=deadline-time.monotonic()
            if remaining<=0:status='timeout';stop();break
            for key,_ in sel.select(min(remaining,.1)):
                try:data=os.read(key.fileobj.fileno(),min(65536,limit-total+1))
                except BlockingIOError:continue
                if not data:sel.unregister(key.fileobj);continue
                total+=len(data)
                if total>limit:status='output_limit';stop();break
                streams[key.fileobj].extend(data)
            if status!='completed':break
        if status=='completed':
            try:p.wait(timeout=max(.001,deadline-time.monotonic()))
            except subprocess.TimeoutExpired:status='timeout';stop()
        return Result(p.returncode,streams[p.stdout].decode('utf-8','replace'),
                      streams[p.stderr].decode('utf-8','replace'),status)
    finally:
        if p.poll() is None:stop()
        sel.close();p.stdout.close();p.stderr.close();os.close(fd)
