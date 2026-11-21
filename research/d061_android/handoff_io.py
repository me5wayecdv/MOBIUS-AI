"""Directory-FD anchored bounded handoff IO, no shell or path-following cleanup."""
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import secrets
import shutil
from contextlib import contextmanager


@contextmanager
def parent_fd(path):
    # Every component is opened relative to the descriptor already checked.
    # Renaming a live payload-owned ancestor cannot redirect this traversal;
    # replacing it with a symlink refuses rather than following its target.
    if '..' in Path(path).parts:raise ValueError('parent traversal prohibited')
    path=Path(os.path.abspath(path))
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            meta=os.fstat(child)
            if not stat.S_ISDIR(meta.st_mode) or meta.st_uid not in (0,os.geteuid(),65534):
                os.close(child);raise ValueError('unexpected handoff directory owner/type')
            os.close(fd);fd=child
        yield fd,path.name
    finally:os.close(fd)


def read(path,limit=1048576):
    if type(limit) is not int or limit<0:raise ValueError('nonnegative read limit')
    with parent_fd(path) as (directory,name):
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        try:
            meta=os.fstat(fd)
            if (not stat.S_ISREG(meta.st_mode) or meta.st_size>limit
                or meta.st_uid not in (0,os.geteuid(),65534)):
                raise ValueError('regular owned handoff size/type bound')
            with os.fdopen(fd,'rb',closefd=False) as stream:data=stream.read(limit+1)
            if len(data)>limit:raise ValueError('handoff grew beyond bound')
            return data
        finally:os.close(fd)


def exists(path):
    try:
        with parent_fd(path) as (directory,name):
            meta=os.stat(name,dir_fd=directory,follow_symlinks=False)
            if stat.S_ISLNK(meta.st_mode):raise ValueError('linked handoff leaf')
            return True
    except FileNotFoundError:return False


def write(path,data,*,mode=0o444,replace=False):
    if not isinstance(data,bytes):raise TypeError('exact byte snapshot required')
    with parent_fd(path) as (directory,name):
        # Publications only into our own directories. Runtime writable source
        # acquisition uses read(), never publication through a writable ancestor.
        if os.fstat(directory).st_uid!=os.geteuid():raise ValueError('publisher must own output directory')
        tmp='.'+name+'.'+secrets.token_hex(8)+'.partial'
        fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
        try:
            with os.fdopen(fd,'wb',closefd=False) as output:output.write(data);output.flush();os.fsync(fd)
            os.fchmod(fd,mode)
        finally:os.close(fd)
        try:
            if replace:os.replace(tmp,name,src_dir_fd=directory,dst_dir_fd=directory)
            else:
                os.link(tmp,name,src_dir_fd=directory,dst_dir_fd=directory,follow_symlinks=False)
                os.unlink(tmp,dir_fd=directory)
            os.fsync(directory)
        finally:
            try:os.unlink(tmp,dir_fd=directory)
            except FileNotFoundError:pass


def mkdir(path,mode=0o755):
    with parent_fd(path) as (directory,name):
        if os.fstat(directory).st_uid!=os.geteuid():raise ValueError('root-owned publication parent required')
        os.mkdir(name,mode,dir_fd=directory)


def remove(path):
    with parent_fd(path) as (directory,name):
        try:meta=os.stat(name,dir_fd=directory,follow_symlinks=False)
        except FileNotFoundError:return
        if stat.S_ISDIR(meta.st_mode):
            if not shutil.rmtree.avoids_symlink_attacks:raise RuntimeError('FD-safe recursive removal required')
            shutil.rmtree(name,dir_fd=directory)
        else:os.unlink(name,dir_fd=directory)


def publish_directory(staged,destination):
    # Both locations belong to the root relay, not either payload. Rename is
    # descriptor-relative and atomic. No success result was visible before this.
    with parent_fd(staged) as (source,name),parent_fd(destination) as (dest,leaf):
        staged_fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=source)
        try:
            if os.fstat(staged_fd).st_uid!=os.geteuid():raise ValueError('staged snapshot root owner')
        finally:os.close(staged_fd)
        if os.fstat(source).st_uid!=os.geteuid() or os.fstat(dest).st_uid!=os.geteuid():
            raise ValueError('immutable publication parents required')
        try:os.stat(leaf,dir_fd=dest,follow_symlinks=False)
        except FileNotFoundError:pass
        else:raise FileExistsError('one-shot result destination exists')
        os.rename(name,leaf,src_dir_fd=source,dst_dir_fd=dest);os.fsync(dest)


def json_write(path,value,*,mode=0o444,replace=False):
    write(path,json.dumps(value,sort_keys=True,separators=(',',':')).encode(),mode=mode,replace=replace)


def wait(path,*,deadline,child=None,pump=None,limit=65536):
    while True:
        if time.monotonic()>deadline:raise TimeoutError('fixed handoff deadline')
        if pump:pump()
        if exists(path):return read(path,limit)
        if child is not None and child.poll() is not None:raise RuntimeError('handoff producer exited early')
        time.sleep(.05)


def digest(data):return hashlib.sha256(data).hexdigest()


def public_directory(path):
    # Deliberately traversable root-owned RO inbox subtree. chmod is explicit
    # because outer umask077 must not turn the mounted subtree into0700.
    mkdir(path,mode=0o700)
    with parent_fd(path) as (directory,name):
        fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
        try:
            if os.fstat(fd).st_uid!=os.geteuid():raise ValueError('public subtree owner differs')
            os.fchmod(fd,0o755)
        finally:os.close(fd)
