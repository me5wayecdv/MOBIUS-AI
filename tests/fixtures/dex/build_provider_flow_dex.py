"""Deterministic hand-assembled static provider fixture, NOT installable/runnable.

Public query has the Android ContentProvider descriptor and passes its selection
argument to SQLiteDatabase.rawQuery. negative uses a constant query instead.
The database receiver is null; these methods intentionally cannot execute. This
fixture tests real bytecode adaptation and bounded may-flow evidence only, never
runtime exposure, app UID access or a usable provider route/control contract.
"""
import hashlib
import struct
import zlib

def uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def build(*, caller_controlled: bool = True) -> bytes:
    OBJ="Landroid/content/ContentProvider;"
    DB="Landroid/database/sqlite/SQLiteDatabase;"
    STRING="Ljava/lang/String;"
    ARRAY="[Ljava/lang/String;"
    URI="Landroid/net/Uri;"
    CURSOR="Landroid/database/Cursor;"
    CLS="Lcom/example/demo/NotesProvider;"
    params=[URI,ARRAY,STRING,ARRAY,STRING]
    strings=sorted({OBJ,DB,STRING,ARRAY,URI,CURSOR,CLS,"L", "LLL", "LLLLLL", "query", "negative", "rawQuery", "SELECT 1"})
    S={s:i for i,s in enumerate(strings)}
    types=sorted([OBJ,DB,STRING,ARRAY,URI,CURSOR,CLS],key=lambda t:S[t])
    T={t:i for i,t in enumerate(types)}
    protos=[("LLL",CURSOR,[STRING,ARRAY]),("LLLLLL",CURSOR,params)]
    protos.sort(key=lambda p:(T[p[1]],[T[x] for x in p[2]]))
    P={(p[1],tuple(p[2])):i for i,p in enumerate(protos)}
    pk=lambda ret,params:P[(ret,tuple(params))]
    app=["query","negative"]
    mids=[(DB,"rawQuery",pk(CURSOR,[STRING,ARRAY]))]
    mids += [(CLS,n,pk(CURSOR,params)) for n in app]
    mids.sort(key=lambda m:(T[m[0]],S[m[1]],m[2]))
    M={(m[0],m[1]):i for i,m in enumerate(mids)}
    sink=M[(DB,"rawQuery")]
    # v0 null DB, v1 result; v2=this; v3..v7 are the five query args.
    code={
        "query":[0x0012,0x306e,sink,0x0650,0x010c,0x0111],
        "negative":[0x0012,0x011a,S["SELECT 1"],0x306e,sink,0x0610,0x010c,0x0111],
    }
    if not caller_controlled:
        code["query"]=code["negative"]

    # DEX header and fixed-size identifier sections.
    hdr = 0x70
    off_str = hdr
    off_type = off_str + 4 * len(strings)
    off_proto = off_type + 4 * len(types)
    off_meth = off_proto + 12 * len(protos)
    off_cls = off_meth + 8 * len(mids)
    data = bytearray()
    data_off = off_cls + 32

    def at():
        return data_off + len(data)

    def align(n):
        while at() % n:
            data.append(0)

    str_off = []
    for value in strings:
        str_off.append(at())
        encoded = value.encode()
        data += uleb(len(value)) + encoded + b"\0"

    align(4)
    type_list_offsets = {}
    for proto in protos:
        if proto[2]:
            key = (proto[1], tuple(proto[2]))
            type_list_offsets[key] = at()
            data += struct.pack("<I", len(proto[2]))
            data += b"".join(struct.pack("<H", T[x]) for x in proto[2])
            align(4)

    code_offsets = {}
    code_first = None
    for name in app:
        align(4)
        code_offsets[name] = at()
        if code_first is None:
            code_first = at()
        instructions = code[name]
        data += struct.pack(
            "<HHHHII", 8, 6, 3, 0, 0, len(instructions)
        )
        data += b"".join(struct.pack("<H", x) for x in instructions)

    align(4)
    class_data_off = at()
    direct = sorted(app, key=lambda name: M[(CLS, name)])
    class_data = uleb(0) + uleb(0) + uleb(0) + uleb(len(direct))
    previous = 0
    for name in direct:
        method_idx = M[(CLS, name)]
        class_data += uleb(method_idx - previous) + uleb(0x1) + uleb(code_offsets[name])
        previous = method_idx
    data += class_data

    align(4)
    map_off = at()
    map_entries = [
        (0x0000, 1, 0),
        (0x0001, len(strings), off_str),
        (0x0002, len(types), off_type),
        (0x0003, len(protos), off_proto),
        (0x0005, len(mids), off_meth),
        (0x0006, 1, off_cls),
        (0x2002, len(strings), str_off[0]),
        (0x1001, len(type_list_offsets), min(type_list_offsets.values())),
        (0x2001, len(app), code_first),
        (0x2000, 1, class_data_off),
        (0x1000, 1, map_off),
    ]
    data += struct.pack("<I", len(map_entries))
    data += b"".join(
        struct.pack("<HHII", item_type, 0, count, offset)
        for item_type, count, offset in map_entries
    )

    fixed = bytearray()
    fixed += struct.pack("<" + "I" * len(strings), *str_off)
    fixed += struct.pack("<" + "I" * len(types), *[S[t] for t in types])
    for shorty, return_type, params in protos:
        fixed += struct.pack(
            "<III",
            S[shorty],
            T[return_type],
            type_list_offsets.get((return_type, tuple(params)), 0),
        )
    for class_type, name, proto_idx in mids:
        fixed += struct.pack("<HHI", T[class_type], proto_idx, S[name])
    fixed += struct.pack(
        "<IIIIIIII",
        T[CLS], 1, T[OBJ], 0, 0xFFFFFFFF, 0, class_data_off, 0,
    )

    body = bytes(fixed) + bytes(data)
    file_size = hdr + len(body)
    header = bytearray(b"dex\n035\0" + b"\0" * 24)
    header += struct.pack(
        "<IIIIII", file_size, hdr, 0x12345678, 0, 0, map_off
    )
    header += struct.pack("<II", len(strings), off_str)
    header += struct.pack("<II", len(types), off_type)
    header += struct.pack("<II", len(protos), off_proto)
    header += struct.pack("<II", 0, 0)
    header += struct.pack("<II", len(mids), off_meth)
    header += struct.pack("<II", 1, off_cls)
    header += struct.pack("<II", len(data), data_off)
    assert len(header) == hdr, len(header)

    raw = bytes(header) + body
    signature = hashlib.sha1(raw[32:]).digest()
    raw = raw[:12] + signature + raw[32:]
    checksum = zlib.adler32(raw[12:]) & 0xFFFFFFFF
    return raw[:8] + struct.pack("<I", checksum) + raw[12:]


if __name__ == "__main__":
    import sys
    with open(sys.argv[1], "wb") as output:
        output.write(build())
