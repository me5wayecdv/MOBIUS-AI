"""Bounded classic-ZIP central-directory preflight before ZipFile allocation.

ZIP64/multidisk/encrypted/non-deflate variants refuse pending separate review.
This bounds metadata declarations, not decompression CPU, filesystem stalls or
Python allocator behavior. A trusted outer watchdog/resource cap is still needed.
"""
import struct

MAX_DIRECTORY=32*1024**2
MAX_ENTRIES=50000
MAX_NAME=1024
MAX_EXTRA=4096
MAX_COMMENT=4096


def preflight(source,*,check=lambda **kwargs:None):
    source.seek(0,2);size=source.tell();tail_size=min(size,65557)
    source.seek(size-tail_size);tail=source.read(tail_size)
    cursor=len(tail);end=None
    while True:
        index=tail.rfind(b'PK\x05\x06',0,cursor)
        if index<0:raise ValueError('exact bounded classic ZIP EOCD required')
        if index+22<=len(tail):
            values=struct.unpack_from('<4s4H2IH',tail,index)
            if index+22+values[-1]==len(tail):end=size-tail_size+index;break
        cursor=index
    _,disk,cd_disk,count_disk,count,cd_bytes,cd_offset,comment=values
    if (disk or cd_disk or count_disk!=count or count==65535 or cd_bytes==0xffffffff
        or cd_offset==0xffffffff or not 0<count<=MAX_ENTRIES or cd_bytes>MAX_DIRECTORY):
        raise ValueError('bounded single-disk classic ZIP directory required, no ZIP64')
    if cd_offset+cd_bytes!=end:raise ValueError('exact bounded central-directory extent required')
    if end>=20:
        source.seek(end-20)
        if source.read(4)==b'PK\x06\x07':raise ValueError('ZIP64 locator requires separate review')
    check(index_files=count,index_bytes=cd_bytes)
    source.seek(cd_offset);total=0;expanded=0
    for _ in range(count):
        check();header=source.read(46);total+=len(header)
        if len(header)!=46:raise ValueError('truncated ZIP directory header')
        row=struct.unpack('<4s6H3I5H2I',header)
        signature,version,flags,compression=row[0],row[2],row[3],row[4]
        compressed,uncompressed=row[8],row[9]
        name,extra,comment,disk_start=row[10:14];local_offset=row[16]
        if (signature!=b'PK\x01\x02' or version>=45 or flags&1 or compression not in (0,8)
            or disk_start or not 0<name<=MAX_NAME or extra>MAX_EXTRA or comment>MAX_COMMENT
            or max(compressed,uncompressed,local_offset)==0xffffffff or local_offset+30>cd_offset):
            raise ValueError('unsupported/unbounded central-directory entry')
        expanded+=uncompressed
        if uncompressed>4*1024**3 or expanded>16*1024**3:raise ValueError('bounded expanded ZIP declarations required')
        variable=name+extra+comment;total+=variable
        if total>cd_bytes or len(source.read(variable))!=variable:raise ValueError('central-directory variable extent differs')
    if total!=cd_bytes or source.tell()!=end:raise ValueError('ZIP directory count/extent differs')
    source.seek(0)
    return {'entries':count,'directory_bytes':cd_bytes,'expanded_declaration_bytes':expanded,
        'metadata_preflight_only':True,'hard_resource_or_elapsed_bound':False}
