"""Investigation-scoped read-only lookup over verified JADX cache entries.

Decompilation is an explicit POST operation. Lookup endpoints only read a verified cache;
they never trigger tool execution or fall back to guessed/bytecode-only source.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..adapters.models import ApplicationRow, InvestigationRow
from ..adapters.jadx import JadxAdapter, JadxError, JadxResult, SourceSnippet
from ..services.artifacts import ArtifactStore
from ..services.tool_runner import ToolRunner
from .errors import NotFound

_MAX_CLASSES = 5000
_MAX_METHODS = 500
_JAVA_METHOD = re.compile(
    r"""(?m)^\s*(?:(?:public|protected|private|static|final|synchronized|native|abstract|default|strictfp)\s+)*"""
    r"""(?:[\w.$<>?,\[\]@]+\s+)+(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<args>[^;{}]*)\)\s*(?:throws\s+[^{}]+)?\s*\{"""
)
_SMALI_METHOD = re.compile(r"(?m)^\s*\.method\s+(?P<flags>.*?)\s+(?P<name>[\w$<>]+)(?P<descriptor>\([^\r\n]*?)\s*$")


@dataclass(frozen=True, slots=True)
class CodeMethod:
    class_name: str
    name: str
    signature: str
    path: str
    start_line: int
    fidelity: str


class JadxCodeLookup:
    """Resolve classes, methods and bounded source from a scan's digest/version cache."""

    def __init__(
        self,
        *,
        session,
        store: ArtifactStore,
        cache_root: Path,
        runner: ToolRunner,
        tool_version: str = "1.5.6",
    ) -> None:
        self.session = session
        self.store = store
        self.cache_root = Path(cache_root)
        self.adapter = JadxAdapter(
            runner=runner, cache_root=self.cache_root, tool_version=tool_version
        )

    def _identity(self, investigation_id: str) -> tuple[InvestigationRow, ApplicationRow]:
        investigation = self.session.get(InvestigationRow, investigation_id)
        if investigation is None:
            raise NotFound(f"investigation {investigation_id} not found")
        application = self.session.get(ApplicationRow, investigation.application_id)
        if application is None:
            raise NotFound(f"application for investigation {investigation_id} not found")
        return investigation, application

    def decompile(self, investigation_id: str) -> dict[str, Any]:
        _, application = self._identity(investigation_id)
        artifact = self.store.get(application.artifact_key)
        result = self.adapter.decompile(
            investigation_id=investigation_id,
            artifact=artifact,
            expected_sha256=application.sha256,
            artifact_name="input.apk",
        )
        return self._result_body(result)

    def cached_result(self, investigation_id: str) -> JadxResult:
        _, application = self._identity(investigation_id)
        digest_root = self.cache_root / application.sha256
        entry = digest_root / self.adapter.tool_version
        result = self.adapter._read_cache(entry, application.sha256)
        if result is None:
            raise JadxError("source_unavailable", "no verified JADX cache exists for this APK digest and tool version")
        return result

    @staticmethod
    def _result_body(result: JadxResult) -> dict[str, Any]:
        return {
            "apk_sha256": result.apk_sha256,
            "tool_version": result.tool_version,
            "cached": result.cached,
            "source_file_count": len(result.source_files),
            "source_files": list(result.source_files[:_MAX_CLASSES]),
            "fidelity": result.fidelity,
        }

    def classes(self, investigation_id: str, *, prefix: str | None = None, limit: int = 200) -> dict[str, Any]:
        result = self.cached_result(investigation_id)
        if not 1 <= limit <= _MAX_CLASSES:
            raise JadxError("invalid_limit", "class limit must be between 1 and 5000")
        by_class: dict[str, dict[str, str]] = {}
        for path in result.source_files:
            if not (path.endswith(".java") or path.endswith(".smali")):
                continue
            suffix = ".java" if path.endswith(".java") else ".smali"
            class_name = path[:-len(suffix)].replace("/", ".")
            if prefix and not class_name.startswith(prefix):
                continue
            item = {
                "class_name": class_name,
                "path": path,
                "fidelity": "decompiled" if suffix == ".java" else "smali",
            }
            current = by_class.get(class_name)
            if current is None or (current["fidelity"] == "smali" and suffix == ".java"):
                by_class[class_name] = item
        items = sorted(by_class.values(), key=lambda item: item["class_name"])
        return {
            "investigation_id": investigation_id,
            "apk_sha256": result.apk_sha256,
            "tool_version": result.tool_version,
            "items": items[:limit],
            "truncated": len(items) > limit,
            "total": len(items),
            "limitations": ["Class names are derived from JADX output paths; inner/anonymous class names follow JADX file naming."],
        }

    def methods(self, investigation_id: str, *, class_name: str, limit: int = 200) -> dict[str, Any]:
        if not class_name or len(class_name) > 500:
            raise JadxError("invalid_class", "class_name must contain 1 to 500 characters")
        if not 1 <= limit <= _MAX_METHODS:
            raise JadxError("invalid_limit", "method limit must be between 1 and 500")
        result = self.cached_result(investigation_id)
        path = self._class_path(result, class_name)
        source = self._read_text(result, path)
        methods = self._parse_methods(class_name, path, source)
        return {
            "investigation_id": investigation_id,
            "class_name": class_name,
            "path": path,
            "fidelity": "decompiled" if path.endswith(".java") else "smali",
            "items": [method.__dict__ if hasattr(method, "__dict__") else {
                "class_name": method.class_name, "name": method.name,
                "signature": method.signature, "path": method.path,
                "start_line": method.start_line, "fidelity": method.fidelity,
            } for method in methods[:limit]],
            "total": len(methods),
            "truncated": len(methods) > limit,
        }

    def source(
        self, investigation_id: str, *, path: str, start_line: int = 1,
        end_line: int = 40,
    ) -> dict[str, Any]:
        result = self.cached_result(investigation_id)
        snippet = self.adapter.resolve_source(
            result, relative_path=path, start_line=start_line, end_line=end_line
        )
        return {
            "investigation_id": investigation_id,
            "apk_sha256": result.apk_sha256,
            "tool_version": result.tool_version,
            "path": snippet.path,
            "start_line": snippet.start_line,
            "end_line": snippet.end_line,
            "text": snippet.text,
            "fidelity": snippet.fidelity,
            "truncated": False,
        }

    def method_excerpt(
        self,
        investigation_id: str,
        *,
        class_name: str,
        method_name: str,
        max_lines: int = 40,
    ) -> dict[str, Any]:
        """Resolve one unambiguous method to a verified, at-most-40-line excerpt."""
        if not 1 <= max_lines <= 40:
            raise JadxError("invalid_limit", "method excerpt limit must be between 1 and 40 lines")
        if not method_name or len(method_name) > 200:
            raise JadxError("invalid_method", "method_name must contain 1 to 200 characters")
        result = self.cached_result(investigation_id)
        path = self._class_path(result, class_name)
        source_text = self._read_text(result, path)
        matches = [
            method for method in self._parse_methods(class_name, path, source_text)
            if method.name == method_name
        ]
        if not matches:
            raise JadxError("method_not_found", f"method {method_name!r} is not present in {class_name!r}")
        if len(matches) != 1:
            raise JadxError("method_ambiguous", f"method {method_name!r} has multiple declarations in {class_name!r}")
        method = matches[0]
        lines = source_text.splitlines()
        start_line = method.start_line
        end_line = min(len(lines), start_line + max_lines - 1)
        snippet = self.adapter.resolve_source(
            result, relative_path=path, start_line=start_line, end_line=end_line
        )
        return {
            "apk_sha256": result.apk_sha256,
            "tool_version": result.tool_version,
            "method_reference": f"{class_name}->{method.name}{method.signature[len(method.name):]}",
            "path": snippet.path,
            "start_line": snippet.start_line,
            "end_line": snippet.end_line,
            "text": snippet.text,
            "fidelity": snippet.fidelity,
        }

    @staticmethod
    def _class_path(result: JadxResult, class_name: str) -> str:
        expected = class_name.replace(".", "/")
        matches = [
            path for path in result.source_files
            if path in {expected + ".java", expected + ".smali"}
        ]
        if not matches:
            raise JadxError("class_not_found", f"class {class_name!r} is not present in the verified JADX output")
        return sorted(matches)[0]

    @staticmethod
    def _read_text(result: JadxResult, path: str) -> str:
        # resolve_source validates manifest membership, containment and file integrity.
        JadxAdapter.resolve_source(result, relative_path=path, start_line=1, end_line=1)
        source_path = result.cache_dir / path
        # resolve_source already validates manifest membership and file integrity.
        data = source_path.read_bytes()
        try:
            return data.decode("utf-8")
        except UnicodeError as exc:
            raise JadxError("source_unreadable", "cached source is not valid UTF-8") from exc

    @staticmethod
    def _parse_methods(class_name: str, path: str, source: str) -> list[CodeMethod]:
        found: list[CodeMethod] = []
        if path.endswith(".smali"):
            for match in _SMALI_METHOD.finditer(source):
                line = source.count("\n", 0, match.start()) + 1
                found.append(CodeMethod(
                    class_name, match.group("name"),
                    match.group("name") + match.group("descriptor"),
                    path, line, "smali",
                ))
        else:
            for match in _JAVA_METHOD.finditer(source):
                line = source.count("\n", 0, match.start()) + 1
                signature = " ".join(match.group(0).strip().split())
                found.append(CodeMethod(
                    class_name, match.group("name"), signature, path, line, "decompiled"
                ))
        return sorted(found, key=lambda method: (method.name, method.start_line))
