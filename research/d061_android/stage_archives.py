"""HELD exact-member archive staging for reviewed immutable sibling closures.

No SDK manager, license acceptance, Gradle, extraction helper subprocess or code
execution. Every materialized regular byte stream must have an approved manifest
entry. Archive links are not followed. Runtime/library dependency resolution is
NOT performed or inferred here: missing reviewed closure locks refuse staging.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path,PurePosixPath
import stat
import tarfile
import zipfile
from contextlib import contextmanager

from handoff_io import read,write,json_write,mkdir,digest
from namespace_supervisor import validate_manifest,ROLES

APPROVED_FOR_EXECUTION = False


def relative(value):
    path=PurePosixPath(value)
    if not value or path.is_absolute() or '..' in path.parts or str(path)!=value or '\\' in value:
        raise ValueError('exact canonical relative archive path required')
    return value


@contextmanager
def member_stream(archive,name,size):
    from handoff_io import parent_fd
    name=relative(name)
    with parent_fd(archive) as (parent,leaf):
        fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
        meta=os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode):os.close(fd);raise ValueError('regular archive FD required')
        with os.fdopen(fd,'rb') as container:
            if zipfile.is_zipfile(container):
                container.seek(0)
                with zipfile.ZipFile(container) as source:
                    items=[x for x in source.infolist() if x.filename==name]
                    if len(items)!=1:raise ValueError('missing/duplicate exact ZIP member')
                    item=items[0];mode=item.external_attr>>16
                    if (item.is_dir() or item.flag_bits&1 or item.file_size!=size
                        or stat.S_IFMT(mode) not in (0,stat.S_IFREG)):
                        raise ValueError('regular exact unencrypted ZIP member required')
                    with source.open(item) as stream:yield stream
            else:
                container.seek(0)
                with tarfile.open(fileobj=container,mode='r:*') as source:
                    items=[x for x in source.getmembers() if x.name==name]
                    if len(items)!=1 or not items[0].isfile() or items[0].size!=size:
                        raise ValueError('regular exact TAR member required, no link resolution')
                    with source.extractfile(items[0]) as stream:yield stream


def verify_archives(directory,lock):
    rows=lock.get('archives',[]);result={}
    if not rows or len(rows)>64:raise ValueError('bounded exact archive set required')
    for row in rows:
        name=relative(row['name'])
        if '/' in name or name in result:raise ValueError('fixed unique archive basename')
        path=directory/name
        if row['bytes']>4*1024**3:raise ValueError('archive size bound')
        # Streaming hash avoids buffering Android system image containers.
        from handoff_io import parent_fd
        with parent_fd(path) as (parent,leaf):
            fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
            try:
                meta=os.fstat(fd)
                if not stat.S_ISREG(meta.st_mode) or meta.st_size!=row['bytes']:raise ValueError('archive type/size differs')
                h=hashlib.sha256()
                with os.fdopen(fd,'rb',closefd=False) as stream:
                    while block:=stream.read(1048576):h.update(block)
                if h.hexdigest()!=row['sha256']:raise ValueError('reviewed archive digest differs')
            finally:os.close(fd)
        result[name]=path
    return result


def stage_role(role,lock,archives):
    # A lock must enumerate all actual SDK/JDK/Python/ELF loader/shared libs and
    # source files, not only launchers. No broad /usr,/lib or host-home copy.
    if lock.get('status')!='EXACT_REVIEWED_SIBLING_STAGE_LOCK':raise ValueError('unresolved sibling staging lock')
    if lock.get('sdk_license_reviewed') is not True:raise ValueError('explicit scoped license review missing')
    manifest=lock['roles'][role]
    validate_manifest(manifest,role)
    root=Path(ROLES[role][0]);mkdir(root,0o700)
    for row in manifest['files']:
        archive_name=row.get('archive')
        if archive_name not in archives:raise ValueError('reviewed source archive absent')
        member=relative(row['member']);size=row['size']
        if size>4*1024**3:raise ValueError('regular staging file size bound')
        destination=root/relative(row['source'])
        current=root
        for part in destination.relative_to(root).parts[:-1]:
            current=current/part
            if not current.exists():mkdir(current,0o755)
            elif current.is_symlink():raise ValueError('staging ancestor link')
        from handoff_io import parent_fd
        with member_stream(archives[archive_name],member,size) as source,parent_fd(destination) as (parent,leaf):
            temporary='.'+leaf+'.staging'
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
            count=0;h=hashlib.sha256()
            try:
                with os.fdopen(fd,'wb',closefd=False) as output:
                    while block:=source.read(min(1048576,size-count+1)):
                        count+=len(block)
                        if count>size:raise ValueError('expanded member exceeded approved exact size')
                        output.write(block);h.update(block)
                    output.flush();os.fsync(fd)
                if count!=size or h.hexdigest()!=row['sha256']:raise ValueError('materialized member identity differs')
                os.fchmod(fd,row['mode'])
                os.link(temporary,leaf,src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False)
                os.unlink(temporary,dir_fd=parent);os.fsync(parent)
            finally:
                os.close(fd)
                try:os.unlink(temporary,dir_fd=parent)
                except FileNotFoundError:pass
    json_write(root/'closure-lock.json',manifest)
    root.chmod(0o755)
    return {'role':role,'root':str(root),'file_count':len(manifest['files']),
        'closure_sha256':digest(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()),
        'staging_only_no_code_executed':True}


def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('HELD reviewed archive/library/source closure and license review required')
    if os.geteuid()!=0:raise RuntimeError('disposable root staging only')
    parser=argparse.ArgumentParser();parser.add_argument('--archives',type=Path,required=True)
    parser.add_argument('--lock',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    lock=json.loads(read(args.lock,16*1024**2))
    if lock.get('status')!='EXACT_REVIEWED_SIBLING_STAGE_LOCK':raise ValueError('unresolved staging lock')
    archives=verify_archives(args.archives,lock)
    results=[stage_role(role,lock,archives) for role in ('runtime','control')]
    json_write(args.output,{'results':results,'no_code_executed':True,'runtime_still_requires_exact_activation':True})


if __name__=='__main__':main()
