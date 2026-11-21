"""HELD exact-member archive staging with retained verified container sessions.

No SDK manager, license acceptance, binary execution or dependency inference.
A separately reviewed complete transitive runtime/control/source lock is required.
"""
from contextlib import contextmanager,ExitStack
import argparse
import hashlib
import json
import os
from pathlib import Path,PurePosixPath
import re
import stat
import tarfile
import time
import zipfile

from handoff_io import read,json_write,mkdir,digest,public_directory,parent_fd
from namespace_supervisor import validate_manifest,ROLES

APPROVED_FOR_EXECUTION = False
MAX_FILES=100000
MAX_BYTES=24*1024**3
MAX_SECONDS=900
MAX_ARCHIVE_FILES=50000


def relative(value):
    path=PurePosixPath(value)
    if not value or value=='.' or path.is_absolute() or '..' in path.parts or str(path)!=value or '\\' in value:
        raise ValueError('exact canonical relative archive path required')
    return value


class Budget:
    def __init__(self,clock=time.monotonic):
        self.clock=clock;self.deadline=clock()+MAX_SECONDS;self.files=0;self.bytes=0
    def check(self,*,files=0,bytes=0):
        self.files+=files;self.bytes+=bytes
        if self.clock()>self.deadline:raise TimeoutError('whole bounded staging session deadline')
        if self.files>MAX_FILES or self.bytes>MAX_BYTES:raise ValueError('aggregate staged file/byte ceiling')


def archive_rows(lock):
    rows=lock.get('archives',[]);seen=set();total=0
    if not rows or len(rows)>64:raise ValueError('bounded exact archive set required')
    for row in rows:
        if set(row)!={'name','bytes','sha256'} or type(row['bytes']) is not int or not 0<row['bytes']<=4*1024**3:
            raise ValueError('exact archive row schema and bounded byte count required')
        name=relative(row['name'])
        if '/' in name or name in seen:raise ValueError('fixed unique archive basename')
        seen.add(name);total+=row['bytes']
        if total>32*1024**3:raise ValueError('aggregate archive size ceiling')
        if not isinstance(row['sha256'],str) or re.fullmatch('[0-9a-f]{64}',row['sha256']) is None:
            raise ValueError('exact reviewed archive digest required')
    return rows


def immutable_identity(meta,expected):
    if (not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o222
        or meta.st_nlink!=1 or meta.st_size!=expected['bytes']):
        raise ValueError('immutable root-owned regular single-link archive required')
    return (meta.st_dev,meta.st_ino,meta.st_size,meta.st_mtime_ns,meta.st_ctime_ns)


class Container:
    """One verified FD/hash and one retained reader/index per archive session."""
    def __init__(self,path,expected,budget,stack):
        self.budget=budget;self.expected=expected
        with parent_fd(path) as (parent,leaf):
            parent_meta=os.fstat(parent)
            if parent_meta.st_uid!=0 or parent_meta.st_mode&0o022:raise ValueError('immutable root-owned archive directory required')
            fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        self.source=stack.enter_context(os.fdopen(fd,'rb'))
        self.identity=immutable_identity(os.fstat(fd),expected)
        h=hashlib.sha256()
        while block:=self.source.read(1048576):budget.check();h.update(block)
        if h.hexdigest()!=expected['sha256']:raise ValueError('reviewed archive digest differs')
        self.check();self.source.seek(0);self.members={}
        if zipfile.is_zipfile(self.source):
            self.source.seek(0);self.kind='zip';self.reader=stack.enter_context(zipfile.ZipFile(self.source))
            members=self.reader.infolist()
        else:
            self.source.seek(0);self.kind='tar';self.reader=stack.enter_context(tarfile.open(fileobj=self.source,mode='r:*'))
            members=self.reader
        for index,item in enumerate(members):
            budget.check()
            if index>=MAX_ARCHIVE_FILES:raise ValueError('bounded archive member index required')
            name=item.filename if self.kind=='zip' else item.name
            # Directory entries can carry a trailing slash. Regular lookup below
            # still requires the exact canonical reviewed member spelling.
            if name in self.members:raise ValueError('duplicate archive member')
            self.members[name]=item
        self.check()

    def check(self):
        self.budget.check()
        if immutable_identity(os.fstat(self.source.fileno()),self.expected)!=self.identity:
            raise ValueError('verified archive descriptor changed during session')

    def order(self,name):
        item=self.members[relative(name)]
        return item.header_offset if self.kind=='zip' else item.offset_data

    @contextmanager
    def stream(self,name,size):
        self.check();item=self.members.get(relative(name))
        if item is None:raise ValueError('exact archive member absent')
        if self.kind=='zip':
            mode=item.external_attr>>16
            if (item.is_dir() or item.flag_bits&1 or item.file_size!=size
                or stat.S_IFMT(mode) not in (0,stat.S_IFREG)):raise ValueError('exact regular unencrypted ZIP member required')
            source=self.reader.open(item)
        else:
            if not item.isfile() or item.size!=size:raise ValueError('exact regular TAR member required, no link resolution')
            source=self.reader.extractfile(item)
        with source as stream:yield stream
        self.check()


@contextmanager
def verify_archives(directory,lock,*,budget=None):
    budget=budget or Budget();rows=archive_rows(lock)
    with ExitStack() as stack:
        result={row['name']:Container(Path(directory)/row['name'],row,budget,stack) for row in rows}
        yield result,budget


@contextmanager
def member_stream(archive,name,size,*,expected=None):
    """Small-source inspection helper, not the production per-file staging path."""
    if expected is not None:
        with ExitStack() as stack:
            container=Container(archive,expected,Budget(),stack)
            with container.stream(name,size) as stream:yield stream
        return
    # Synthetic unit inspection still refuses FIFO/device leaves before parsing.
    with parent_fd(archive) as (parent,leaf):
        fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
    with os.fdopen(fd,'rb') as source:
        if not stat.S_ISREG(os.fstat(fd).st_mode):raise ValueError('regular archive descriptor required')
        if zipfile.is_zipfile(source):
            source.seek(0)
            with zipfile.ZipFile(source) as reader:
                items=[item for item in reader.infolist() if item.filename==relative(name)]
                if len(items)!=1:raise ValueError('missing/duplicate exact ZIP member')
                item=items[0];mode=item.external_attr>>16
                if item.is_dir() or item.flag_bits&1 or item.file_size!=size or stat.S_IFMT(mode) not in (0,stat.S_IFREG):raise ValueError('regular exact ZIP member required')
                with reader.open(item) as stream:yield stream
        else:
            source.seek(0)
            with tarfile.open(fileobj=source,mode='r:*') as reader:
                items=[]
                for index,item in enumerate(reader):
                    if index>=MAX_ARCHIVE_FILES:raise ValueError('bounded member index')
                    if item.name==relative(name):items.append(item)
                if len(items)!=1 or not items[0].isfile() or items[0].size!=size:raise ValueError('regular exact TAR member required')
                with reader.extractfile(items[0]) as stream:yield stream


def stage_role(role,lock,archives,budget):
    if lock.get('status')!='EXACT_REVIEWED_SIBLING_STAGE_LOCK':raise ValueError('unresolved sibling staging lock')
    if lock.get('sdk_license_reviewed') is not True:raise ValueError('explicit scoped license review missing')
    manifest=lock['roles'][role];validate_manifest(manifest,role)
    # Group aliases so each archive member is decompressed ONCE per role. The
    # archive offsets are processed in order, avoiding repeated gzip rewinds.
    groups={};seen=set()
    for row in manifest['files']:
        archive=row.get('archive');member=relative(row['member']);source=relative(row['source'])
        if archive not in archives or source in seen:raise ValueError('unique exact source archive/path required')
        seen.add(source);key=(archive,member);group=groups.setdefault(key,[]);group.append(row)
        if len(group)>16:raise ValueError('bounded exact member alias fanout required')
        if any((x['size'],x['sha256'],x['mode'])!=(row['size'],row['sha256'],row['mode']) for x in group):
            raise ValueError('member aliases must have identical content/mode')
    budget.check()
    if budget.files+len(manifest['files'])>MAX_FILES or budget.bytes+sum(x['size'] for x in manifest['files'])>MAX_BYTES:
        raise ValueError('aggregate staging declarations exceed session ceiling')
    root=Path(ROLES[role][0]);mkdir(root,0o700)
    for (archive,member),rows in sorted(groups.items(),key=lambda item:(item[0][0],archives[item[0][0]].order(item[0][1]))):
        budget.check(files=len(rows));first=rows[0]
        with ExitStack() as stack:
            destinations=[]
            for row in rows:
                destination=root/relative(row['source']);current=root
                for part in destination.relative_to(root).parts[:-1]:
                    current=current/part
                    if not current.exists():public_directory(current)
                    elif current.is_symlink():raise ValueError('staging ancestor link')
                parent,leaf=stack.enter_context(parent_fd(destination));temporary='.'+leaf+'.staging'
                fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
                stack.callback(os.close,fd)
                def unlink_partial(parent=parent,temporary=temporary):
                    try:os.unlink(temporary,dir_fd=parent)
                    except FileNotFoundError:pass
                stack.callback(unlink_partial)
                destinations.append((parent,leaf,temporary,fd,row['mode']))
            count=0;h=hashlib.sha256()
            with archives[archive].stream(member,first['size']) as source:
                while block:=source.read(min(1048576,first['size']-count+1)):
                    count+=len(block)
                    if count>first['size']:raise ValueError('expanded member exceeded exact size')
                    budget.check(bytes=len(block)*len(destinations));h.update(block)
                    for parent,leaf,temporary,fd,mode in destinations:
                        view=memoryview(block)
                        while view:
                            written=os.write(fd,view)
                            if written<=0:raise OSError('staging write made no progress')
                            view=view[written:]
            if count!=first['size'] or h.hexdigest()!=first['sha256']:raise ValueError('materialized member identity differs')
            for parent,leaf,temporary,fd,mode in destinations:
                budget.check();os.fsync(fd);os.fchmod(fd,mode)
                os.link(temporary,leaf,src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False)
                os.unlink(temporary,dir_fd=parent);os.fsync(parent)
    budget.check();json_write(root/'closure-lock.json',manifest)
    with parent_fd(root) as (parent,leaf):
        fd=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        try:os.fchmod(fd,0o755)
        finally:os.close(fd)
    return {'role':role,'root':str(root),'file_count':len(manifest['files']),
        'closure_sha256':digest(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()),
        'staging_only_no_code_executed':True}


def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('HELD complete archive/library/source closure and license review required')
    if os.geteuid()!=0:raise RuntimeError('disposable root staging only')
    parser=argparse.ArgumentParser();parser.add_argument('--archives',type=Path,required=True)
    parser.add_argument('--lock',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();lock=json.loads(read(args.lock,16*1024**2))
    if lock.get('status')!='EXACT_REVIEWED_SIBLING_STAGE_LOCK':raise ValueError('unresolved staging lock')
    with verify_archives(args.archives,lock) as (archives,budget):
        results=[stage_role(role,lock,archives,budget) for role in ('runtime','control')]
        budget.check()
        json_write(args.output,{'results':results,'no_code_executed':True,'runtime_still_requires_exact_activation':True,
            'materialized_files':budget.files,'materialized_bytes':budget.bytes,'whole_session_seconds_limit':MAX_SECONDS})


if __name__=='__main__':main()
