"""HELD, unwired: DATA-only member hash inspection of known official archives.

Not extraction, install, license acceptance or execution. One verified read-only
fd per archive: the container sha256 is computed from that same fd, members are
streamed through decompression into sha256 only (no member write, link
creation, import, subprocess, sdkmanager). ZIP: bounded classic-directory
preflight first, then zipfile on the same fd. TAR.GZ: sequential stream mode,
no getmembers() pre-pass. Output: names/modes/sizes/sha256/link text only.
Outer limits are applied before the archive is opened: RLIMIT_AS/CPU/FSIZE/NOFILE
and a wall-clock alarm. Requires the reviewed APPROVED flag to run as a CLI.
Caller must still pin expected container sha256/size from committed candidates.
"""
import argparse,hashlib,json,os,resource,signal,stat,sys,tarfile,zipfile
from pathlib import PurePosixPath
from zip_preflight import preflight

APPROVED_FOR_EXECUTION=False
MAX_FILES=50000;MAX_MEMBER=4*1024**3;MAX_TOTAL=16*1024**3;MAX_LINK=4096
LIMITS={'as':3*1024**3,'cpu':900,'wall':1200,'nofile':16}


def apply_outer_limits(limits=LIMITS):
    resource.setrlimit(resource.RLIMIT_AS,(limits['as'],limits['as']))
    resource.setrlimit(resource.RLIMIT_CPU,(limits['cpu'],limits['cpu']))
    resource.setrlimit(resource.RLIMIT_FSIZE,(0,0))
    resource.setrlimit(resource.RLIMIT_NOFILE,(limits['nofile'],limits['nofile']))
    signal.signal(signal.SIGALRM,lambda *a:os._exit(70));signal.alarm(limits['wall'])


def canon(name):
    name=name.rstrip('/');p=PurePosixPath(name)
    if (not name or len(name)>1024 or p.is_absolute() or '..' in p.parts or '\\' in name
        or str(p)!=name or any(ord(c)<32 or ord(c)==127 for c in name)):
        raise ValueError('canonical relative member path required')
    return name


class Hashing:
    def __init__(self,f):self.f=f;self.h=hashlib.sha256();self.n=0
    def read(self,n=-1):
        d=self.f.read(n);self.h.update(d);self.n+=len(d);return d
    def drain(self):
        while self.read(1048576):pass


def digest(stream,size):
    h=hashlib.sha256();n=0
    while d:=stream.read(min(1048576,size-n+1)):
        n+=len(d)
        if n>size:raise ValueError('member grew beyond declared size')
        h.update(d)
    if n!=size:raise ValueError('member incomplete')
    return h.hexdigest()


class Book:
    def __init__(self):self.rows=[];self.seen=set();self.total=0
    def add(self,name,size,kind,mode,target=None):
        name=canon(name)
        if name in self.seen:raise ValueError('duplicate member path')
        self.seen.add(name)
        if (len(self.seen)>MAX_FILES or not 0<=size<=MAX_MEMBER or mode&0o7000):raise ValueError('member bound or special bits')
        self.total+=size
        if self.total>MAX_TOTAL:raise ValueError('expanded bound')
        row={'path':name,'size':size,'kind':kind,'mode':mode}
        if target is not None:
            if len(target)>MAX_LINK:raise ValueError('link bound')
            row['target']=target
        self.rows.append(row);return row


def inspect_fd(fd,expected_sha256=None,expected_size=None):
    st=os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):raise ValueError('regular file fd required')
    f=os.fdopen(os.dup(fd),'rb');book=Book()
    try:
        head=f.read(4);f.seek(0)
        if head[:2]==b'PK':
            h=hashlib.sha256()
            while d:=f.read(1048576):h.update(d)
            container=h.hexdigest();f.seek(0)
            preflight(f);f.seek(0)
            with zipfile.ZipFile(f) as z:
                items=z.infolist()
                for it in items:
                    if it.flag_bits&1:raise ValueError('encrypted')
                    mode=(it.external_attr>>16)&0o177777;k=mode&0o170000
                    if it.is_dir():kind='directory'
                    elif k==0o120000:kind='symlink'
                    elif k in (0,0o100000):kind='regular'
                    else:raise ValueError('special member')
                    if kind=='symlink' and it.file_size>MAX_LINK:raise ValueError('link bound')
                    book.add(it.filename,it.file_size,kind,mode&0o7777)
                for it,row in zip(items,book.rows):
                    if row['kind']=='directory':continue
                    with z.open(it) as s:
                        if row['kind']=='symlink':
                            data=s.read(MAX_LINK+1)
                            if len(data)!=row['size']:raise ValueError('link size')
                            row['target']=data.decode('utf-8');row['sha256']=hashlib.sha256(data).hexdigest()
                        else:row['sha256']=digest(s,row['size'])
            size=st.st_size
        elif head[:2]==b'\x1f\x8b':
            hr=Hashing(f)
            with tarfile.open(fileobj=hr,mode='r|gz') as t:
                for it in t:
                    if it.issparse() or it.ischr() or it.isblk() or it.isfifo() or it.isdev():raise ValueError('special member')
                    if it.isdir():book.add(it.name,0,'directory',it.mode)
                    elif it.isfile():
                        row=book.add(it.name,it.size,'regular',it.mode)
                        with t.extractfile(it) as s:row['sha256']=digest(s,it.size)
                    elif it.issym():book.add(it.name,0,'symlink',it.mode,it.linkname)
                    elif it.islnk():book.add(it.name,0,'hardlink',it.mode,it.linkname)
                    else:raise ValueError('special member')
            hr.drain();container=hr.h.hexdigest();size=hr.n
        else:raise ValueError('unsupported container')
        if size!=st.st_size:raise ValueError('container size changed during read')
        if expected_sha256 and container!=expected_sha256:raise ValueError('container sha256 differs from pinned value')
        if expected_size is not None and size!=expected_size:raise ValueError('container size differs from pinned value')
        return {'container_sha256':container,'container_bytes':size,'member_count':len(book.rows),
            'declared_expanded_bytes':book.total,'members':book.rows,'inspection':'data_only_streaming_hash',
            'member_written':False,'package_code_executed':False,'license_accepted':False,
            'runtime_closure_resolved':False,'provenance_note':'hashes of supplied bytes only'}
    finally:f.close()


def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('held: exact program not reviewed/approved')
    p=argparse.ArgumentParser();p.add_argument('archive');p.add_argument('--sha256',required=True);p.add_argument('--size',type=int,required=True)
    a=p.parse_args();apply_outer_limits()
    fd=os.open(a.archive,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    json.dump(inspect_fd(fd,a.sha256,a.size),sys.stdout,sort_keys=True)


if __name__=='__main__':main()
