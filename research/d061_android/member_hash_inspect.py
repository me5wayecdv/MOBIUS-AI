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
import argparse,hashlib,json,os,re,resource,select,signal,stat,subprocess,sys,tarfile,time,zipfile
from pathlib import PurePosixPath
from zip_preflight import preflight

APPROVED_FOR_EXECUTION=False
MAX_FILES=50000;MAX_MEMBER=4*1024**3;MAX_TOTAL=16*1024**3;MAX_LINK=4096
MAX_CONTAINER=2*1024**3;MAX_OUTPUT=64*1024**2
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


def identity(st):
    return (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns,st.st_nlink,st.st_uid,st.st_mode)


def open_anchored(path):
    """Every component opened with O_NOFOLLOW from '/'; every directory and the
    leaf must be owned by root or the effective user and not group/other writable."""
    path=os.fspath(path)
    if not path.startswith('/') or '//' in path or '\x00' in path:raise ValueError('absolute canonical path required')
    parts=[x for x in path.split('/') if x]
    if not parts or any(x in ('.','..') for x in parts):raise ValueError('canonical path required')
    cur=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for i,part in enumerate(parts):
            last=i==len(parts)-1
            flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|(os.O_NONBLOCK if last else os.O_DIRECTORY)
            nxt=os.open(part,flags,dir_fd=cur);os.close(cur);cur=nxt
            st=os.fstat(cur)
            sticky_root=stat.S_ISDIR(st.st_mode) and st.st_mode&stat.S_ISVTX and st.st_uid==0
            if st.st_uid not in (0,os.geteuid()) or (st.st_mode&0o022 and not sticky_root):raise ValueError('immutable-owner/mode required on every component')
        if not stat.S_ISREG(os.fstat(cur).st_mode) or os.fstat(cur).st_nlink!=1:raise ValueError('single-link regular file required')
        out=cur;cur=None;return out
    finally:
        if cur is not None:os.close(cur)


def inspect_fd(fd,expected_sha256,expected_size):
    if not (isinstance(expected_sha256,str) and re.fullmatch('[0-9a-f]{64}',expected_sha256)):raise ValueError('pinned canonical sha256 required')
    if not (isinstance(expected_size,int) and not isinstance(expected_size,bool) and 0<expected_size<=MAX_CONTAINER):raise ValueError('pinned bounded size required')
    st=os.fstat(fd);ident=identity(st)
    if not stat.S_ISREG(st.st_mode) or st.st_size!=expected_size:raise ValueError('regular file of pinned size required')
    h=hashlib.sha256();n=0;off=0
    while n<expected_size+1:
        d=os.pread(fd,1048576,off)
        if not d:break
        n+=len(d);off+=len(d);h.update(d)
        if n>expected_size:raise ValueError('container larger than pinned size')
    if n!=expected_size or h.hexdigest()!=expected_sha256:raise ValueError('container differs from pinned sha256/size BEFORE parsing')
    if identity(os.fstat(fd))!=ident:raise ValueError('input changed during pre-hash')
    try:return _parse(fd,st,expected_sha256,expected_size,ident)
    finally:pass


def _parse(fd,st,expected_sha256,expected_size,ident):
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
        if container!=expected_sha256 or size!=expected_size:raise ValueError('container differs from pinned value during parse')
        if identity(os.fstat(fd))!=ident:raise ValueError('input changed during parse')
        return {'container_sha256':container,'container_bytes':size,'member_count':len(book.rows),
            'declared_expanded_bytes':book.total,'members':book.rows,'inspection':'data_only_streaming_hash',
            'member_written':False,'package_code_executed':False,'license_accepted':False,
            'runtime_closure_resolved':False,'provenance_note':'hashes of supplied bytes only'}
    finally:f.close()


class CaptureError(Exception):
    def __init__(self,kind):super().__init__(kind);self.kind=kind


KINDS={'deadline','output_bound','nonzero_exit','bad_json','bad_schema','spawn','pidfd','read_error','reap_timeout'}
ENVELOPE={'container_sha256','container_bytes','member_count','declared_expanded_bytes','members',
    'inspection','member_written','package_code_executed','license_accepted','runtime_closure_resolved','provenance_note'}
ROW_KEYS={'regular':{'path','size','kind','mode','sha256'},'directory':{'path','size','kind','mode'},
    'symlink':{'path','size','kind','mode','target'},'hardlink':{'path','size','kind','mode','target'}}
HEX=re.compile('[0-9a-f]{64}')


def is_int(x):return type(x) is int


def validate_inventory(out,sha256,size):
    bad=lambda:CaptureError('bad_schema')
    if not isinstance(out,dict) or set(out)!=ENVELOPE:raise bad()
    if (out['container_sha256']!=sha256 or not is_int(out['container_bytes']) or out['container_bytes']!=size
        or out['inspection']!='data_only_streaming_hash' or out['member_written'] is not False
        or out['package_code_executed'] is not False or out['license_accepted'] is not False
        or out['runtime_closure_resolved'] is not False or not isinstance(out['provenance_note'],str) or len(out['provenance_note'])>200):raise bad()
    rows=out['members']
    if (not isinstance(rows,list) or not is_int(out['member_count']) or out['member_count']!=len(rows) or len(rows)>MAX_FILES
        or not is_int(out['declared_expanded_bytes'])):raise bad()
    total=0;seen=set()
    for r in rows:
        if not isinstance(r,dict) or r.get('kind') not in ROW_KEYS or set(r)!=ROW_KEYS[r['kind']]:raise bad()
        path=r['path']
        if not isinstance(path,str):raise bad()
        try:
            if canon(path)!=path:raise bad()
        except ValueError:raise bad()
        if path in seen:raise bad()
        if not is_int(r['size']) or not 0<=r['size']<=MAX_MEMBER or not is_int(r['mode']) or not 0<=r['mode']<=0o777:raise bad()
        k=r['kind']
        if k=='regular' and not (isinstance(r['sha256'],str) and HEX.fullmatch(r['sha256'])):raise bad()
        if k in ('directory','symlink','hardlink') and k!='regular' and k!='symlink' and r['size']!=0:raise bad()
        if k in ('symlink','hardlink'):
            t=r['target']
            if not isinstance(t,str) or not 0<len(t)<=MAX_LINK or '\x00' in t:raise bad()
        seen.add(path);total+=r['size']
    if total!=out['declared_expanded_bytes'] or total>MAX_TOTAL:raise bad()
    return out


def run_child(path,sha256,size,*,wall=1300,cmd=None,_pidfd_open=None):
    """Parent capture. One direct child, no group signalling. Everything after spawn
    is inside one ownership scope: the unreaped direct child is killed through a
    pidfd when we have one, else through Popen.kill() while still unreaped.
    Every failure maps to a closed CaptureError kind."""
    argv=cmd or [sys.executable,os.path.abspath(__file__),path,'--sha256',sha256,'--size',str(size)]
    try:
        p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,close_fds=True,env={})
    except OSError:raise CaptureError('spawn')
    pidfd=None;buf=bytearray();kind=None
    def kill():
        if p.poll() is not None:return
        try:
            if pidfd is not None:signal.pidfd_send_signal(pidfd,signal.SIGKILL)
            else:p.kill()
        except OSError:pass
    def reap():
        try:p.wait(timeout=5);return True
        except subprocess.TimeoutExpired:return False
    try:
        try:pidfd=(_pidfd_open or os.pidfd_open)(p.pid)
        except OSError:
            kind='pidfd'
        end=time.monotonic()+wall
        while kind is None:
            left=end-time.monotonic()
            if left<=0:kind='deadline';break
            try:
                if not select.select([p.stdout],[],[],min(left,1))[0]:continue
                d=os.read(p.stdout.fileno(),65536)
            except (OSError,ValueError):kind='read_error';break
            if not d:break
            buf+=d
            if len(buf)>MAX_OUTPUT:kind='output_bound'
        if kind:
            kill()
            if not reap():kill();reap();kind='reap_timeout' if kind not in ('pidfd',) else kind
            raise CaptureError(kind)
        try:rc=p.wait(timeout=max(1,end-time.monotonic()))
        except subprocess.TimeoutExpired:
            kill()
            if not reap():raise CaptureError('reap_timeout')
            raise CaptureError('deadline')
        if rc!=0:raise CaptureError('nonzero_exit')
        try:out=json.loads(bytes(buf))
        except ValueError:raise CaptureError('bad_json')
        return validate_inventory(out,sha256,size)
    except BaseException:
        kill();reap()
        raise
    finally:
        try:p.stdout.close()
        except OSError:pass
        if pidfd is not None:os.close(pidfd)


def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('held: exact program not reviewed/approved')
    p=argparse.ArgumentParser();p.add_argument('archive');p.add_argument('--sha256',required=True);p.add_argument('--size',type=int,required=True)
    a=p.parse_args();apply_outer_limits()
    fd=open_anchored(a.archive)
    try:result=inspect_fd(fd,a.sha256,a.size)
    finally:os.close(fd)
    json.dump(result,sys.stdout,sort_keys=True)


if __name__=='__main__':main()
