"""Versioned Android source/sink/guard catalogue.

The YAML catalogue is data, not executable policy. Entries identify API references only;
reachability is not taint flow and a catalogue match is never a vulnerability verdict.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from types import MappingProxyType
from typing import Mapping

import yaml

_ID = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_DESCRIPTOR = re.compile(r"^L[^;]+;$")
_MASWE = re.compile(r"^MASWE-[0-9]{4}$")
_MASVS = re.compile(r"^MASVS-[A-Z]+-[0-9]+$")


@dataclass(frozen=True, slots=True)
class Source:
    """An API that may introduce data across a trust boundary."""

    id: str
    class_descriptor: str
    method: str
    descriptor: str
    family: str
    trust_boundary: str
    maswe: tuple[str, ...]
    masvs: tuple[str, ...]
    confidence: str
    description: str
    references: tuple[str, ...]

    @property
    def key(self) -> tuple[str, str]:
        return (self.class_descriptor, self.method)


@dataclass(frozen=True, slots=True)
class Sink:
    """A security-relevant operation, identified as a dex method reference."""

    id: str
    class_descriptor: str
    method: str
    family: str
    maswe: tuple[str, ...]
    description: str
    masvs: tuple[str, ...] = ()
    confidence: str = "low"
    impact: str = "unknown"
    references: tuple[str, ...] = ()

    @property
    def key(self) -> tuple[str, str]:
        return (self.class_descriptor, self.method)


@dataclass(frozen=True, slots=True)
class Guard:
    """A call that may indicate a caller check; it does not prove safety."""

    id: str
    class_descriptor: str
    method: str
    description: str

    @property
    def key(self) -> tuple[str, str]:
        return (self.class_descriptor, self.method)


@dataclass(frozen=True, slots=True)
class Catalogue:
    version: int
    catalogue_id: str
    sources: tuple[Source, ...]
    sinks: tuple[Sink, ...]
    guards: tuple[Guard, ...]


def _strings(value: object, field: str, pattern: re.Pattern[str]) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{field} must be a non-empty list")
    values = tuple(value)
    if any(not isinstance(item, str) or not pattern.fullmatch(item) for item in values):
        raise ValueError(f"{field} contains an invalid identifier")
    if pattern is _MASWE and any(not 1 <= int(item[-4:]) <= 78 for item in values):
        raise ValueError(f"{field} contains an unknown MASWE v1.0.0 identifier")
    if len(values) != len(set(values)):
        raise ValueError(f"{field} contains duplicate identifiers")
    return values


def _record_list(data: object, name: str) -> list[dict[str, object]]:
    if not isinstance(data, list):
        raise ValueError(f"{name} must be a list")
    records: list[dict[str, object]] = []
    for item in data:
        if not isinstance(item, dict):
            raise ValueError(f"{name} entries must be mappings")
        records.append(item)
    return records


def _base(item: dict[str, object], kind: str) -> tuple[str, str, str, str]:
    identifier = item.get("id")
    class_descriptor = item.get("class_descriptor")
    method = item.get("method")
    description = item.get("description")
    if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
        raise ValueError(f"{kind} has invalid id")
    if not isinstance(class_descriptor, str) or not _DESCRIPTOR.fullmatch(class_descriptor):
        raise ValueError(f"{kind} {identifier} has invalid class descriptor")
    if not isinstance(method, str) or not method or len(method) > 128:
        raise ValueError(f"{kind} {identifier} has invalid method")
    if not isinstance(description, str) or not description.strip():
        raise ValueError(f"{kind} {identifier} has no description")
    return identifier, class_descriptor, method, description


def load_catalogue(path: str | Path) -> Catalogue:
    """Load and validate a catalogue file; invalid or ambiguous data fails closed."""
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("platform") != "android":
        raise ValueError("catalogue must be an Android mapping")
    version = raw.get("version")
    catalogue_id = raw.get("catalogue_id")
    if not isinstance(version, int) or version < 1:
        raise ValueError("catalogue version must be a positive integer")
    if not isinstance(catalogue_id, str) or not catalogue_id.strip():
        raise ValueError("catalogue_id is required")

    sources: list[Source] = []
    for item in _record_list(raw.get("sources"), "sources"):
        identifier, cls, method, description = _base(item, "source")
        descriptor = item.get("descriptor")
        family, trust = item.get("family"), item.get("trust_boundary")
        confidence = item.get("confidence")
        if not isinstance(descriptor, str) or len(descriptor) > 256 or not descriptor.startswith("("):
            raise ValueError(f"source {identifier} has invalid method descriptor")
        if not isinstance(family, str) or not family or not isinstance(trust, str) or not trust:
            raise ValueError(f"source {identifier} needs family and trust_boundary")
        if confidence not in {"low", "medium", "high"}:
            raise ValueError(f"source {identifier} has invalid confidence")
        references = item.get("references", [])
        if not isinstance(references, list) or any(not isinstance(v, str) or not v for v in references):
            raise ValueError(f"source {identifier} has invalid references")
        sources.append(Source(
            identifier, cls, method, descriptor, family, trust,
            _strings(item.get("maswe"), f"{identifier}.maswe", _MASWE),
            _strings(item.get("masvs"), f"{identifier}.masvs", _MASVS),
            confidence, description, tuple(references),
        ))

    sinks: list[Sink] = []
    for item in _record_list(raw.get("sinks"), "sinks"):
        identifier, cls, method, description = _base(item, "sink")
        family, confidence, impact = item.get("family"), item.get("confidence"), item.get("impact")
        if not isinstance(family, str) or not family:
            raise ValueError(f"sink {identifier} needs family")
        if confidence not in {"low", "medium", "high"}:
            raise ValueError(f"sink {identifier} has invalid confidence")
        if impact not in {"confidentiality", "integrity", "availability", "unknown"}:
            raise ValueError(f"sink {identifier} has invalid impact")
        references = item.get("references", [])
        if not isinstance(references, list) or any(not isinstance(v, str) or not v for v in references):
            raise ValueError(f"sink {identifier} has invalid references")
        sinks.append(Sink(
            identifier, cls, method, family,
            _strings(item.get("maswe"), f"{identifier}.maswe", _MASWE),
            description,
            _strings(item.get("masvs"), f"{identifier}.masvs", _MASVS),
            confidence, impact, tuple(references),
        ))

    guards: list[Guard] = []
    for item in _record_list(raw.get("guards"), "guards"):
        identifier, cls, method, description = _base(item, "guard")
        guards.append(Guard(identifier, cls, method, description))

    for kind, records in (("source", sources), ("sink", sinks), ("guard", guards)):
        ids = [record.id for record in records]
        if len(ids) != len(set(ids)):
            raise ValueError(f"duplicate {kind} id")
        keys = [record.key for record in records]
        if len(keys) != len(set(keys)):
            raise ValueError(f"duplicate {kind} API key")

    return Catalogue(version, catalogue_id, tuple(sources), tuple(sinks), tuple(guards))


_CATALOGUE = load_catalogue(
    Path(__file__).resolve().parents[1] / "data" / "android_source_sink_catalogue.yaml"
)
CATALOGUE_VERSION = _CATALOGUE.version
SOURCES: Mapping[tuple[str, str], Source] = MappingProxyType({item.key: item for item in _CATALOGUE.sources})
SINKS: Mapping[tuple[str, str], Sink] = MappingProxyType({item.key: item for item in _CATALOGUE.sinks})
GUARDS: Mapping[tuple[str, str], Guard] = MappingProxyType({item.key: item for item in _CATALOGUE.guards})


# Lifecycle and entry-point methods exposed by Android component kinds.
ENTRY_POINTS: Mapping[str, tuple[str, ...]] = MappingProxyType({
    "activity": ("onCreate", "onStart", "onResume", "onNewIntent", "onActivityResult"),
    "service": ("onCreate", "onStartCommand", "onStart", "onBind", "handleMessage", "onHandleIntent"),
    "receiver": ("onReceive",),
    "provider": ("query", "insert", "update", "delete", "call", "openFile", "getType", "bulkInsert"),
})


def source_for(class_descriptor: str, method: str) -> Source | None:
    return SOURCES.get((class_descriptor, method))


def sink_for(class_descriptor: str, method: str) -> Sink | None:
    return SINKS.get((class_descriptor, method))


def guard_for(class_descriptor: str, method: str) -> Guard | None:
    return GUARDS.get((class_descriptor, method))


def entry_methods_for(kind: str) -> tuple[str, ...]:
    return ENTRY_POINTS.get(kind, ())
