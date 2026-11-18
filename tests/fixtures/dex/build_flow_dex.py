"""Hand-assembles a tiny DEX (no javac/d8 needed) for real-DEX data-flow tests.

Methods (all public static void m(Intent, WebView)):
  positive:        getStringExtra -> loadUrl on one straight-line block
  branching:       source assigned on one branch of an if, sink after the join
  negative:        constant URL reaches loadUrl, no source
  negative_branch: same CFG as branching, but the source result goes to an
                   unrelated register, so the sink argument stays constant
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


def build() -> bytes:
    OBJ, INTENT, WEBVIEW, STRING, CLS = (
        "Ljava/lang/Object;",
        "Landroid/content/Intent;",
        "Landroid/webkit/WebView;",
        "Ljava/lang/String;",
        "LFlowTest;",
    )
    strings = sorted({
        OBJ, INTENT, WEBVIEW, STRING, CLS, "V", "VL", "VLL", "LL",
        "default", "https://example.com", "url", "getStringExtra", "loadUrl",
        "positive", "branching", "negative", "negative_branch",
    })
    S = {s: i for i, s in enumerate(strings)}
    types = sorted([OBJ, INTENT, WEBVIEW, STRING, CLS, "V"], key=lambda t: S[t])
    T = {t: i for i, t in enumerate(types)}

    # Protos sorted by (return type index, parameter type indices).
    protos = [
        ("LL", STRING, [STRING]),
        ("VL", "V", [STRING]),
        ("VLL", "V", [INTENT, WEBVIEW]),
    ]
    protos.sort(key=lambda p: (T[p[1]], [T[x] for x in p[2]]))
    P = {(p[1], tuple(p[2])): i for i, p in enumerate(protos)}
    pk = lambda ret, params: P[(ret, tuple(params))]

    app = ["positive", "branching", "negative", "negative_branch"]
    mids = [
        (INTENT, "getStringExtra", pk(STRING, [STRING])),
        (WEBVIEW, "loadUrl", pk("V", [STRING])),
    ]
    mids += [(CLS, n, pk("V", [INTENT, WEBVIEW])) for n in app]
    mids.sort(key=lambda m: (T[m[0]], S[m[1]], m[2]))
    M = {(m[0], m[1]): i for i, m in enumerate(mids)}
    src = M[(INTENT, "getStringExtra")]
    sink = M[(WEBVIEW, "loadUrl")]

    const_string = lambda reg, value: [0x001A | (reg << 8), S[value]]
    invoke = lambda mid, receiver, arg: [0x206E, mid, (arg << 4) | receiver]
    ret_void = [0x000E]
    code = {
        "positive": (
            const_string(0, "url") + invoke(src, 2, 0) + [0x010C]
            + invoke(sink, 3, 1) + ret_void
        ),
        "negative": (
            const_string(0, "https://example.com")
            + invoke(sink, 3, 0) + ret_void
        ),
        "branching": (
            const_string(0, "default") + [0x0238, 6]
            + invoke(src, 2, 0) + [0x000C]
            + invoke(sink, 3, 0) + ret_void
        ),
        "negative_branch": (
            const_string(0, "default") + [0x0238, 6]
            + invoke(src, 2, 0) + [0x010C]
            + invoke(sink, 3, 0) + ret_void
        ),
    }

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
            "<HHHHII", 4, 2, 2, 0, 0, len(instructions)
        )
        data += b"".join(struct.pack("<H", x) for x in instructions)

    align(4)
    class_data_off = at()
    direct = sorted(app, key=lambda name: M[(CLS, name)])
    class_data = uleb(0) + uleb(0) + uleb(len(direct)) + uleb(0)
    previous = 0
    for name in direct:
        method_idx = M[(CLS, name)]
        class_data += uleb(method_idx - previous) + uleb(0x9) + uleb(code_offsets[name])
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
