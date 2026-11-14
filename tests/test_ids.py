from __future__ import annotations

import re

import pytest

from mobius.core.ids import ULID_LENGTH, new_id, ulid

_PATTERN = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")


def test_ulid_has_expected_shape():
    value = ulid()
    assert len(value) == ULID_LENGTH == 26
    assert _PATTERN.match(value)


def test_ulid_excludes_ambiguous_letters():
    # Crockford base32 omits I, L, O and U so an ID cannot spell a confusing word.
    sample = "".join(ulid() for _ in range(50))
    assert not set("ILOU") & set(sample)


def test_prefixed_ids_are_unique():
    ids = {new_id("obs") for _ in range(500)}
    assert len(ids) == 500


def test_ulids_sort_by_time():
    earlier = ulid(now_ms=1_700_000_000_000)
    later = ulid(now_ms=1_700_000_000_001)
    assert earlier < later


def test_rejects_empty_prefix():
    with pytest.raises(ValueError):
        new_id("")


def test_rejects_out_of_range_timestamp():
    with pytest.raises(ValueError):
        ulid(now_ms=1 << 48)
