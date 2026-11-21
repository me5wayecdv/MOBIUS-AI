"""Read ELF64 little-endian metadata as DATA, never load or execute the object.

DT_NEEDED is only a dependency lead. dlopen, interpreters, plugins, NSS, Python,
JDK modules, shell launcher behavior and compatibility still require review.
"""
import hashlib
import struct

MAX_BYTES=256*1024**2


def inspect(data):
    if not isinstance(data,bytes) or len(data)>MAX_BYTES:raise ValueError('bounded exact byte object required')
    result={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
        'object_executed':False,'dependency_closure_resolved':False}
    if data.startswith(b'#!'):
        line=data.split(b'\n',1)[0]
        if len(line)>256:raise ValueError('bounded launcher interpreter')
        return {**result,'kind':'script','shebang':line.decode('ascii')}
    if not data.startswith(b'\x7fELF'):return {**result,'kind':'non-ELF'}
    def unpack(fmt,offset):
        size=struct.calcsize(fmt)
        if offset<0 or offset+size>len(data):raise ValueError('ELF structure outside object')
        return struct.unpack_from(fmt,data,offset)
    if data[4:7]!=bytes([2,1,1]):raise ValueError('only ELF64 little-endian v1 is reviewed')
    header=unpack('<16sHHIQQQIHHHHHH',0)
    if header[2]!=62:raise ValueError('only host x86_64 metadata is reviewed')
    phoff,phentsize,phnum=header[5],header[9],header[10]
    if phentsize!=56 or phnum>1024:raise ValueError('bounded exact ELF program header table')
    loads=[];dynamic=[];interpreters=[]
    for index in range(phnum):
        kind,flags,offset,address,physical,size,memory,align=unpack('<IIQQQQQQ',phoff+index*phentsize)
        if offset+size>len(data):raise ValueError('ELF segment outside object')
        if kind==1:loads.append((address,offset,size))
        if kind==2:
            if size%16 or size>1024**2:raise ValueError('bounded exact ELF dynamic entries')
            terminated=False
            for at in range(offset,offset+size,16):
                tag,value=unpack('<qQ',at)
                if tag==0:terminated=True;break
                dynamic.append((tag,value))
            if not terminated:raise ValueError('unterminated ELF dynamic table')
        if kind==3:
            raw=data[offset:offset+size]
            if not raw.endswith(b'\x00') or b'\x00' in raw[:-1] or len(raw)>4096:raise ValueError('exact ELF interpreter')
            interpreters.append(raw[:-1].decode('ascii'))
    if len(interpreters)>1:raise ValueError('duplicate ELF interpreter')
    strings={tag:[value for current,value in dynamic if current==tag] for tag in (5,10)}
    fields={1:[],14:[],15:[],29:[]}
    wanted=[(tag,value) for tag,value in dynamic if tag in fields]
    if wanted:
        if len(strings[5])!=1 or len(strings[10])!=1:raise ValueError('unique ELF string table required')
        address,size=strings[5][0],strings[10][0]
        if size>16*1024**2:raise ValueError('bounded ELF string table')
        offsets=[offset+address-base for base,offset,length in loads if base<=address and address+size<=base+length]
        if len(offsets)!=1:raise ValueError('unambiguous file-backed ELF string table')
        table=data[offsets[0]:offsets[0]+size]
        for tag,offset in wanted:
            if offset>=len(table):raise ValueError('ELF dynamic string outside table')
            end=table.find(b'\x00',offset)
            if end<0 or end-offset>4096:raise ValueError('bounded terminated ELF dynamic string')
            fields[tag].append(table[offset:end].decode('ascii'))
    return {**result,'kind':'ELF64-x86_64','interpreter':interpreters[0] if interpreters else None,
        'needed':fields[1],'soname':fields[14],'rpath':fields[15],'runpath':fields[29]}
