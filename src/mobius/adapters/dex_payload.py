"""Versioned, bounded wire format for transferring DEX indexes from isolated workers."""
from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..core.reachability import CallGraph, CallTarget, MethodRef
from ..core.dataflow import DataFlowFinding
from .dex import CodeIndex, DexCoverage

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_INDEX_JSON_BYTES = 19 * 1024 * 1024


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class MethodDTO(StrictModel):
    class_name: str = Field(min_length=1, max_length=500)
    name: str = Field(min_length=1, max_length=300)
    descriptor: str = Field(default="", max_length=4000)

    def to_ref(self) -> MethodRef:
        return MethodRef(self.class_name, self.name, self.descriptor)


class CoverageDTO(StrictModel):
    entry: str = Field(min_length=1, max_length=256)
    status: str
    size_bytes: int = Field(ge=0, le=64 * 1024 * 1024)
    classes: int = Field(default=0, ge=0, le=100000)
    methods: int = Field(default=0, ge=0, le=50000)
    error: str | None = Field(default=None, max_length=2000)


class EdgeDTO(StrictModel):
    caller: MethodDTO
    callees: list[MethodDTO] = Field(default_factory=list, max_length=50000)
    strings: list[str] = Field(default_factory=list, max_length=25)


class BoundaryCallDTO(StrictModel):
    class_descriptor: str = Field(min_length=1, max_length=1000)
    method: str = Field(min_length=1, max_length=500)


class BoundaryDTO(StrictModel):
    caller: MethodDTO
    calls: list[BoundaryCallDTO] = Field(default_factory=list, max_length=50000)


class MethodSourcesDTO(StrictModel):
    method: MethodDTO
    sources: list[str] = Field(default_factory=list, max_length=128)


class DataFlowDTO(StrictModel):
    method: MethodDTO
    source_id: str = Field(min_length=1, max_length=128)
    sink_id: str = Field(min_length=1, max_length=128)
    source_offset: int = Field(ge=0, le=10_000_000)
    sink_offset: int = Field(ge=0, le=10_000_000)
    sink_register: int = Field(ge=0, le=65535)
    guard_ids_before: list[str] = Field(default_factory=list, max_length=32)
    guard_ids_after: list[str] = Field(default_factory=list, max_length=32)
    guard_dominates_sink: bool = False
    guard_outcome_verified: bool = False
    assertion: str = "may-flow"


class DexIndexDTO(StrictModel):
    schema_version: int = Field(ge=1, le=1)
    artifact_sha256: str
    classes: list[str] = Field(max_length=100000)
    methods: int = Field(ge=0, le=50000)
    truncated: bool
    dex_coverage: list[CoverageDTO] = Field(min_length=1, max_length=64)
    edges: list[EdgeDTO] = Field(max_length=50000)
    boundary: list[BoundaryDTO] = Field(max_length=50000)
    class_sources: dict[str, list[str]]
    method_sources: list[MethodSourcesDTO]
    data_flows: list[DataFlowDTO] = Field(default_factory=list, max_length=1000)
    data_flow_methods: int = Field(default=0, ge=0, le=50000)
    data_flow_truncated_methods: int = Field(default=0, ge=0, le=50000)
    data_flow_complete: bool = False
    data_flow_limitations: list[str] = Field(default_factory=list, max_length=100)

    def to_code_index(self) -> CodeIndex:
        refs: dict[tuple[str, str, str], MethodRef] = {}

        def ref(dto: MethodDTO) -> MethodRef:
            key = (dto.class_name, dto.name, dto.descriptor)
            if key not in refs:
                refs[key] = dto.to_ref()
            return refs[key]

        edges: dict[MethodRef, tuple[MethodRef, ...]] = {}
        strings: dict[MethodRef, tuple[str, ...]] = {}
        for item in self.edges:
            caller = ref(item.caller)
            if caller in edges:
                raise ValueError("duplicate caller in DEX graph payload")
            edges[caller] = tuple(sorted({ref(callee) for callee in item.callees}))
            if item.strings:
                strings[caller] = tuple(dict.fromkeys(item.strings))

        boundary = {}
        for item in self.boundary:
            caller = ref(item.caller)
            if caller in boundary:
                raise ValueError("duplicate caller in DEX boundary payload")
            boundary[caller] = tuple(
                sorted({CallTarget(call.class_descriptor, call.method) for call in item.calls},
                       key=lambda call: (call.class_descriptor, call.method))
            )

        method_sources = {}
        for item in self.method_sources:
            method = ref(item.method)
            if method in method_sources:
                raise ValueError("duplicate method provenance in DEX payload")
            method_sources[method] = tuple(sorted(set(item.sources)))

        coverage = tuple(
            DexCoverage(
                entry=item.entry,
                status=item.status,
                size_bytes=item.size_bytes,
                classes=item.classes,
                methods=item.methods,
                error=item.error,
            )
            for item in self.dex_coverage
        )
        allowed = {"indexed", "failed", "skipped", "truncated"}
        if any(item.status not in allowed for item in coverage):
            raise ValueError("unknown DEX coverage status")
        if len({item.entry for item in coverage}) != len(coverage):
            raise ValueError("duplicate DEX coverage entry")

        data_flows = []
        for item in self.data_flows:
            if item.assertion != "may-flow" or item.guard_outcome_verified:
                raise ValueError("DEX data-flow payload contains an unsupported assertion")
            data_flows.append(DataFlowFinding(
                method=ref(item.method),
                source_id=item.source_id,
                sink_id=item.sink_id,
                source_offset=item.source_offset,
                sink_offset=item.sink_offset,
                sink_register=item.sink_register,
                guard_ids_before=tuple(item.guard_ids_before),
                guard_ids_after=tuple(item.guard_ids_after),
                guard_dominates_sink=item.guard_dominates_sink,
                guard_outcome_verified=False,
            ))

        return CodeIndex(
            graph=CallGraph(edges=edges, strings=strings),
            boundary=boundary,
            classes=tuple(self.classes),
            methods=self.methods,
            truncated=self.truncated,
            strings=strings,
            dex_coverage=coverage,
            class_sources={key: tuple(sorted(set(value))) for key, value in self.class_sources.items()},
            method_sources=method_sources,
            data_flows=tuple(data_flows),
            data_flow_methods=self.data_flow_methods,
            data_flow_truncated_methods=self.data_flow_truncated_methods,
            data_flow_complete=self.data_flow_complete,
            data_flow_limitations=tuple(self.data_flow_limitations),
        )


def code_index_payload(index: CodeIndex, artifact_sha256: str) -> dict[str, Any]:
    if not _SHA256.fullmatch(artifact_sha256):
        raise ValueError("artifact SHA-256 must be lowercase hexadecimal")
    methods = []
    for caller in sorted(index.graph.edges):
        methods.append({
            "caller": _method_dict(caller),
            "callees": [_method_dict(item) for item in index.graph.callees(caller)],
            "strings": list(index.strings.get(caller, ()))[:25],
        })
    boundary = [
        {
            "caller": _method_dict(caller),
            "calls": [
                {"class_descriptor": item.class_descriptor, "method": item.method}
                for item in calls
            ],
        }
        for caller, calls in sorted(index.boundary.items())
    ]
    return {
        "schema_version": 1,
        "artifact_sha256": artifact_sha256,
        "classes": list(index.classes),
        "methods": index.methods,
        "truncated": index.truncated,
        "dex_coverage": [item.describe() for item in index.dex_coverage],
        "edges": methods,
        "boundary": boundary,
        "class_sources": {key: list(value) for key, value in index.class_sources.items()},
        "method_sources": [
            {"method": _method_dict(method), "sources": list(sources)}
            for method, sources in sorted(index.method_sources.items())
        ],
        "data_flows": [
            item.describe() for item in index.data_flows
        ],
        "data_flow_methods": index.data_flow_methods,
        "data_flow_truncated_methods": index.data_flow_truncated_methods,
        "data_flow_complete": index.data_flow_complete,
        "data_flow_limitations": list(index.data_flow_limitations),
    }


def validate_dex_index_payload(raw: bytes, expected_sha256: str) -> CodeIndex:
    if len(raw) > MAX_INDEX_JSON_BYTES:
        raise ValueError("DEX index worker output exceeds the API size limit")
    try:
        import json
        decoded = json.loads(raw)
        dto = DexIndexDTO.model_validate(decoded)
    except (UnicodeDecodeError, ValueError, ValidationError) as exc:
        raise ValueError("DEX index worker returned an invalid schema payload") from exc
    if not _SHA256.fullmatch(dto.artifact_sha256) or dto.artifact_sha256 != expected_sha256:
        raise ValueError("DEX index result is not bound to the authorized APK SHA-256")
    return dto.to_code_index()


def _method_dict(method: MethodRef) -> dict[str, str]:
    return {
        "class_name": method.class_name,
        "name": method.name,
        "descriptor": method.descriptor,
    }
