"""Archive-byte inventory only. Does not extract/install/execute package code.

This establishes member names/sizes/digests for subsequent staging review, NOT
an executable closure or license acceptance. CLI accepts known local archive
bytes; no network retrieval or subprocess calls are implemented here.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
import zipfile

MAX_FILES=50000
MAX_FILE=4*1024**3
MAX_TOTAL=16*1024**3


def member_name(name):
    name=name.rstrip('/')
    p=PurePosixPath(name)
    if not name or p.is_absolute() or '..' in p.parts or '\\' in name or str(p)!=name:
        raise ValueError('archive member must have a canonical relative path')
    if len(name)>1024 or any(ord(x)<32 or ord(x)==127 for x in name):raise ValueError('archive name bound')
    return name


def stream_digest(stream,size):
    count=0;h=hashlib.sha256()
    while data:=stream.read(min(1048576,size-count+1)):
        count+=len(data)
        if count>size:raise ValueError('archive member grew beyond declared size')
        h.update(data)
    if count!=size:raise ValueError('archive member incomplete')
    return h.hexdigest()


def inventory(path):
    path=Path(path);rows=[];seen=set();total=0
    def start(name,size,kind,mode):
        nonlocal total
        name=member_name(name)
        if name in seen:raise ValueError('duplicate archive path')
        seen.add(name)
        if len(seen)>MAX_FILES or size<0 or size>MAX_FILE:raise ValueError('archive file/count bound')
        total+=size
        if total>MAX_TOTAL:raise ValueError('archive expanded-size bound')
        if mode & 0o7000:raise ValueError('special permission bits prohibited')
        row={'path':name,'size':size,'kind':kind,'mode':mode};rows.append(row)
        return row
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            # Preflight full declarations before reading any decompressed bytes.
            members=archive.infolist()
            for item in members:
                if item.flag_bits&1:raise ValueError('encrypted archive unsupported')
                mode=(item.external_attr>>16)&0o177777;kind=mode&0o170000
                if item.is_dir():kind_name='directory'
                elif kind==0o120000:kind_name='symlink'
                elif kind in (0,0o100000):kind_name='regular'
                else:raise ValueError('special archive member prohibited')
                start(item.filename,item.file_size,kind_name,mode&0o7777)
            for item,row in zip(members,rows):
                if row['kind']=='directory':continue
                if row['kind']=='symlink' and row['size']>4096:raise ValueError('symlink target bound')
                with archive.open(item) as stream:row['sha256']=stream_digest(stream,row['size'])
                if row['kind']=='symlink':
                    row['target']=archive.read(item).decode('utf-8')
    else:
        with tarfile.open(path,'r:*') as archive:
            members=archive.getmembers()
            for item in members:
                if item.isdir():kind='directory'
                elif item.isfile():kind='regular'
                elif item.issym():kind='symlink'
                elif item.islnk():kind='hardlink'
                else:raise ValueError('special tar member prohibited')
                row=start(item.name,item.size,kind,item.mode)
                if kind in ('symlink','hardlink'):
                    if len(item.linkname)>4096:raise ValueError('link target bound')
                    row['target']=item.linkname
            for item,row in zip(members,rows):
                if row['kind']!='regular':continue
                with archive.extractfile(item) as stream:row['sha256']=stream_digest(stream,row['size'])
    # Links are recorded but NEVER followed/extracted. Future staging must resolve
    # each link within its package root and review the resulting immutable file.
    with path.open('rb') as source:container_hash=stream_digest(source,path.stat().st_size)
    return {'archive_sha256':container_hash,'archive_bytes':path.stat().st_size,
        'member_count':len(rows),'declared_expanded_bytes':total,'members':rows,
        'archive_extracted':False,'package_code_executed':False,'runtime_closure_resolved':False}


def main():
    p=argparse.ArgumentParser();p.add_argument('archive',type=Path);p.add_argument('output',type=Path)
    a=p.parse_args();result=inventory(a.archive)
    with a.output.open('x') as output:json.dump(result,output,sort_keys=True)


if __name__=='__main__':main()
