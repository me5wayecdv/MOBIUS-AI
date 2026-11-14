"""Architectural fitness function.

Layer 1 (``mobius.core``) must be importable with no database, no web framework and no
model client. That property is what makes the domain testable and what keeps the
reasoning rules from drifting into whatever the persistence layer finds convenient. A
comment cannot enforce it; this test can.
"""

from __future__ import annotations

import ast
import pathlib

CORE = pathlib.Path(__file__).resolve().parents[1] / "src" / "mobius" / "core"

FORBIDDEN = (
    "sqlalchemy",
    "fastapi",
    "starlette",
    "pydantic_settings",
    "httpx",
    "redis",
    "anthropic",
    "openai",
    "mobius.adapters",
    "mobius.services",
    "mobius.api",
)


def _imported_modules(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
    return found


def test_core_is_pure():
    violations: list[str] = []
    for path in sorted(CORE.glob("*.py")):
        for module in _imported_modules(path):
            if any(module == f or module.startswith(f + ".") for f in FORBIDDEN):
                violations.append(f"{path.name} imports {module}")
    assert not violations, "Layer 1 must not depend on outer layers:\n" + "\n".join(violations)


def test_services_do_not_import_the_api():
    services = CORE.parent / "services"
    for path in sorted(services.glob("*.py")):
        for module in _imported_modules(path):
            assert not module.startswith("mobius.api"), f"{path.name} imports {module}"


def test_core_does_not_expose_mutable_global_state():
    """The domain must be pure functions over data.

    Module-level mutable containers are what make a "pure" module stop being pure: a caller
    mutates the dict and every later decision changes. Constants are fine (uppercase or
    underscore-prefixed, conventionally frozen by review); type aliases are fine (they are
    values of ``Subscript``/``Call``, not containers). A bare lowercase dict/list/set is a
    bug.
    """
    problems: list[str] = []
    for path in sorted(CORE.glob("*.py")):
        tree = ast.parse(path.read_text())
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            if not isinstance(node.value, (ast.Dict, ast.List, ast.Set)):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and not (target.id.isupper() or target.id.startswith("_")):
                    problems.append(f"{path.name}:{node.lineno} mutable global {target.id}")
    assert not problems, "\n".join(problems)
