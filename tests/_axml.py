"""Minimal Android binary-XML (AXML) encoder, for tests only.

Why this exists: the binary-manifest path is the one that runs on real APKs, and no sample
APK is available in this environment to test it against. Hand-encoding the format gives a
fixture that androguard - an independent, mature implementation - must also be able to
decode. If both agree, the decoder path is exercised for real rather than assumed.

This is not a general-purpose encoder. It writes the chunk subset a manifest needs: string
pool, empty resource map, namespace markers, and elements with string/int/boolean
attributes. No styling, no CDATA, no UTF-16 strings.

Format reference: Android's `ResChunk_header` / `ResXMLTree_*` structures in
frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h.
"""

from __future__ import annotations

import struct

ANDROID_NS = "http://schemas.android.com/apk/res/android"
ANDROID_PREFIX = "android"

RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103

UTF8_FLAG = 0x00000100
NO_ENTRY = 0xFFFFFFFF

TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12


class El:
    """An element: name, attributes as (ns, name, type, value), and children."""

    def __init__(self, tag: str, attrs=(), children=()):
        self.tag = tag
        self.attrs = list(attrs)
        self.children = list(children)


def _utf8_len(value: str) -> bytes:
    raw = value.encode("utf-8")
    # length of the UTF-16 form matters for some readers; ASCII here, so it equals len(raw)
    return raw


def _encode_utf16_string(value: str) -> bytes:
    """UTF-16LE with a u16 length prefix. aapt's legacy format, and unambiguous."""
    raw = value.encode("utf-16-le")
    length = len(raw) // 2
    out = bytearray()
    if length > 0x7FFF:
        out += struct.pack("<HH", (length >> 16) | 0x8000, length & 0xFFFF)
    else:
        out += struct.pack("<H", length)
    out += raw
    out += b"\x00\x00"
    return bytes(out)


def _encode_utf8_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    utf16_len = len(value)
    out = bytearray()
    for length in (utf16_len, len(raw)):
        if length > 0x7F:
            out += bytes([(length >> 8) | 0x80, length & 0xFF])
        else:
            out.append(length)
    out += raw
    out.append(0)
    return bytes(out)


def _string_pool(strings: list[str]) -> bytes:
    offsets: list[int] = []
    data = bytearray()
    for value in strings:
        offsets.append(len(data))
        data += _encode_utf16_string(value)
    while len(data) % 4:
        data.append(0)

    header_size = 28
    strings_start = header_size + 4 * len(strings)
    size = strings_start + len(data)

    out = bytearray()
    out += struct.pack("<HHIIIIII", RES_STRING_POOL_TYPE, header_size, size,
                       len(strings), 0, 0, strings_start, 0)
    for offset in offsets:
        out += struct.pack("<I", offset)
    out += data
    return bytes(out)


def _resource_map(strings: list[str]) -> bytes:
    # Empty map: every attribute name is present as a real string, so nothing needs
    # resolving by resource id. A real aapt output would populate this.
    return struct.pack("<HHI", RES_XML_RESOURCE_MAP_TYPE, 8, 8)


def _start_namespace(prefix_idx: int, uri_idx: int) -> bytes:
    return struct.pack("<HHIIIII", RES_XML_START_NAMESPACE_TYPE, 16, 24,
                       1, NO_ENTRY, prefix_idx, uri_idx)


def _end_namespace(prefix_idx: int, uri_idx: int) -> bytes:
    return struct.pack("<HHIIIII", RES_XML_END_NAMESPACE_TYPE, 16, 24,
                       1, NO_ENTRY, prefix_idx, uri_idx)


def _attr_value(attr_type: int, value, index_of) -> tuple[int, int]:
    """Return (rawValue, data) for an attribute."""
    if attr_type == TYPE_STRING:
        # aapt sets rawValue to the same pool index for string attributes; androguard reads
        # the raw value first and returns empty if it is NO_ENTRY.
        idx = index_of(str(value))
        return idx, idx
    if attr_type == TYPE_INT_BOOLEAN:
        return NO_ENTRY, 0xFFFFFFFF if value is True else 0
    return NO_ENTRY, int(value)


def _start_element(tag_idx: int, ns_idx: int, attrs, index_of) -> bytes:
    body = bytearray()
    for ns, name, attr_type, value in attrs:
        raw, data = _attr_value(attr_type, value, index_of)
        body += struct.pack("<IIIHBBI",
                            ns_idx if ns == ANDROID_NS else NO_ENTRY,
                            index_of(name), raw, 8, 0, attr_type, data)
    # ResXMLTree_node (8 header + 4 line + 4 comment = 16) + ResXMLTree_attrExt (20)
    # + one ResXMLTree_attribute (20) per attribute.
    size = 36 + len(body)
    return (
        struct.pack("<HHIII", RES_XML_START_ELEMENT_TYPE, 16, size, 1, NO_ENTRY)
        + struct.pack("<IIHHHHHH", ns_idx, tag_idx, 20, 20, len(attrs), 0, 0, 0)
        + bytes(body)
    )


def _end_element(tag_idx: int, ns_idx: int) -> bytes:
    return struct.pack("<HHIIIII", RES_XML_END_ELEMENT_TYPE, 16, 24,
                       1, NO_ENTRY, ns_idx, tag_idx)


def encode(root: El) -> bytes:
    strings: list[str] = []
    index: dict[str, int] = {}

    def intern(value: str) -> int:
        if value not in index:
            index[value] = len(strings)
            strings.append(value)
        return index[value]

    intern("")  # index 0 is conventionally the empty string
    intern(ANDROID_PREFIX)
    intern(ANDROID_NS)

    elements: list[bytes] = []
    android_ns_idx = index[ANDROID_NS]

    def visit(element: El) -> None:
        tag_idx = intern(element.tag)
        elements.append(_start_element(tag_idx, NO_ENTRY, element.attrs, intern))
        for child in element.children:
            visit(child)
        elements.append(_end_element(tag_idx, NO_ENTRY))

    # Intern all names before emitting, so the pool is stable while writing.
    for _, name, _, _ in root.attrs:
        intern(name)
    visit(root)

    chunks = (
        _string_pool(strings)
        + _resource_map(strings)
        + _start_namespace(index[ANDROID_PREFIX], android_ns_idx)
        + b"".join(elements)
        + _end_namespace(index[ANDROID_PREFIX], android_ns_idx)
    )
    return struct.pack("<HHI", RES_XML_TYPE, 8, 8 + len(chunks)) + chunks


def manifest_xml() -> El:
    """A manifest with the properties the tests care about."""
    A = ANDROID_NS
    return El(
        "manifest",
        attrs=[("", "package", TYPE_STRING, "com.example.demo"),
               (A, "versionCode", TYPE_INT_DEC, 7),
               (A, "versionName", TYPE_STRING, "1.2.3")],
        children=[
            El("uses-sdk", attrs=[(A, "minSdkVersion", TYPE_INT_DEC, 24),
                                  (A, "targetSdkVersion", TYPE_INT_DEC, 34)]),
            El("uses-permission", attrs=[(A, "name", TYPE_STRING, "android.permission.INTERNET")]),
            El("uses-permission", attrs=[(A, "name", TYPE_STRING, "android.permission.READ_CONTACTS")]),
            El("application",
               attrs=[(A, "allowBackup", TYPE_INT_BOOLEAN, True),
                      (A, "debuggable", TYPE_INT_BOOLEAN, False),
                      (A, "usesCleartextTraffic", TYPE_INT_BOOLEAN, True)],
               children=[
                   El("activity",
                      attrs=[(A, "name", TYPE_STRING, ".MainActivity"),
                             (A, "exported", TYPE_INT_BOOLEAN, True)],
                      children=[
                          El("intent-filter", children=[
                              El("action", attrs=[(A, "name", TYPE_STRING, "android.intent.action.MAIN")]),
                              El("category", attrs=[(A, "name", TYPE_STRING, "android.intent.category.LAUNCHER")]),
                          ])
                      ]),
                   El("activity",
                      attrs=[(A, "name", TYPE_STRING, ".ExportActivity"),
                             (A, "exported", TYPE_INT_BOOLEAN, True)]),
                   El("service",
                      attrs=[(A, "name", TYPE_STRING, ".SyncService"),
                             (A, "exported", TYPE_INT_BOOLEAN, True),
                             (A, "permission", TYPE_STRING, "com.example.demo.BIND_SYNC")]),
                   El("receiver",
                      attrs=[(A, "name", TYPE_STRING, "com.example.demo.BootReceiver")],
                      children=[
                          El("intent-filter", children=[
                              El("action", attrs=[(A, "name", TYPE_STRING, "android.intent.action.BOOT_COMPLETED")]),
                          ])
                      ]),
                   El("provider",
                      attrs=[(A, "name", TYPE_STRING, ".FilesProvider"),
                             (A, "authorities", TYPE_STRING, "com.example.demo.files"),
                             (A, "exported", TYPE_INT_BOOLEAN, False)]),
               ]),
        ],
    )
