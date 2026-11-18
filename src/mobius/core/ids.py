"""ULID generation.

IDs are ULIDs (Universally Unique Lexicographically Sortable Identifiers) with a type
prefix, matching the contract in docs/API_SPECIFICATION.md 1:

    app_01J8ZQ3K7Y...

A ULID is 26 characters of Crockford base32: a 48-bit millisecond timestamp followed by
80 bits of randomness. Sorting by ID therefore sorts by creation time, which lets the API
paginate on IDs instead of offsets without a separate cursor column.
"""

from __future__ import annotations

import secrets
import time

# Crockford base32: no I, L, O or U, so the alphabet cannot spell ambiguous words.
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_TS_CHARS = 10
_RAND_CHARS = 16
ULID_LENGTH = _TS_CHARS + _RAND_CHARS


class IdPrefix:
    APPLICATION = "app"
    INVESTIGATION = "scn"
    OBSERVATION = "obs"
    HYPOTHESIS = "hyp"
    DECISION = "dec"
    FINDING = "fnd"
    EVIDENCE = "ev"
    VERDICT = "vrd"
    APPROVAL = "apr"
    EVENT = "evt"
    GRAPH_NODE = "gph"
    GRAPH_EDGE = "ged"
    POC_PLAN = "poc"
    POC_RUN = "pcr"
    FRONTIER = "fro"
    AUTHORIZATION = "ath"


def ulid(now_ms: int | None = None) -> str:
    """Return a 26-character ULID.

    ``now_ms`` is injectable so tests can produce deterministic, ordered IDs without
    sleeping.
    """
    ts = int(time.time() * 1000) if now_ms is None else now_ms
    if ts < 0 or ts >= 1 << 48:
        raise ValueError("timestamp out of range for a 48-bit ULID field")

    ts_part = ["0"] * _TS_CHARS
    for i in range(_TS_CHARS - 1, -1, -1):
        ts_part[i] = _CROCKFORD[ts & 0x1F]
        ts >>= 5

    rand_part = "".join(secrets.choice(_CROCKFORD) for _ in range(_RAND_CHARS))
    return "".join(ts_part) + rand_part


def new_id(prefix: str, now_ms: int | None = None) -> str:
    """Return a prefixed ULID, e.g. ``scn_01J8ZR4M2P...``."""
    if not prefix or not prefix.isalnum():
        raise ValueError(f"invalid id prefix: {prefix!r}")
    return f"{prefix}_{ulid(now_ms)}"
