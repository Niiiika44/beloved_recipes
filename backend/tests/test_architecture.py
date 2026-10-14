import ast
import dataclasses
import importlib
import inspect
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

BACKEND = Path(__file__).resolve().parents[1]
MODULES = BACKEND / "app" / "modules"
MODULE_NAMES = sorted(
    path.name for path in MODULES.iterdir() if path.is_dir() and (path / "__init__.py").exists()
)

SERVICE_FORBIDDEN = (
    "sqlalchemy",
    "fastapi",
    "starlette",
    "pydantic",
    "pydantic_settings",
    "redis",
    "httpx",
    "app.core.db",
    "app.core.redis",
)
INFRASTRUCTURE_FORBIDDEN = ("fastapi", "starlette")


def _module_name(path: Path) -> str:
    parts = path.relative_to(BACKEND).with_suffix("").parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _imported_names(path: Path) -> set[str]:
    module = _module_name(path)
    package = module if path.name == "__init__.py" else module.rsplit(".", 1)[0]
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base_parts = package.split(".")
                base = ".".join(base_parts[: len(base_parts) - node.level + 1])
                source = f"{base}.{node.module}" if node.module else base
            else:
                source = node.module or ""
            names.add(source)
            names.update(f"{source}.{alias.name}" for alias in node.names)
    return names


def _matches(name: str, prefixes: Iterable[str]) -> bool:
    return any(name == prefix or name.startswith(f"{prefix}.") for prefix in prefixes)


def _layer_files(module: str, layer: str) -> list[Path]:
    return sorted((MODULES / module / layer).rglob("*.py"))


def _violations(files: Iterable[Path], forbidden: Iterable[str]) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for path in files:
        bad = sorted(name for name in _imported_names(path) if _matches(name, forbidden))
        if bad:
            found[str(path.relative_to(BACKEND))] = bad
    return found


@pytest.mark.parametrize("module", MODULE_NAMES)
def test_domain_imports_only_stdlib_and_core_exceptions(module: str) -> None:
    own_domain = f"app.modules.{module}.domain"
    found: dict[str, list[str]] = {}
    for path in _layer_files(module, "domain"):
        bad = sorted(
            name
            for name in _imported_names(path)
            if name.split(".")[0] not in sys.stdlib_module_names
            and not _matches(name, ("app.core.exceptions", own_domain))
        )
        if bad:
            found[str(path.relative_to(BACKEND))] = bad

    assert found == {}


@pytest.mark.parametrize("module", MODULE_NAMES)
def test_service_knows_nothing_about_frameworks_and_outer_layers(module: str) -> None:
    forbidden = (
        *SERVICE_FORBIDDEN,
        f"app.modules.{module}.infrastructure",
        f"app.modules.{module}.routes",
    )

    assert _violations(_layer_files(module, "service"), forbidden) == {}


@pytest.mark.parametrize("module", MODULE_NAMES)
def test_infrastructure_does_not_depend_on_http_layer(module: str) -> None:
    forbidden = (*INFRASTRUCTURE_FORBIDDEN, f"app.modules.{module}.routes")

    assert _violations(_layer_files(module, "infrastructure"), forbidden) == {}


@pytest.mark.parametrize("module", MODULE_NAMES)
def test_routes_reach_infrastructure_only_through_dependencies(module: str) -> None:
    files = [path for path in _layer_files(module, "routes") if path.name != "dependencies.py"]

    assert _violations(files, (f"app.modules.{module}.infrastructure",)) == {}


def _accepts_assignment(dto: type[Any]) -> bool:
    instance = object.__new__(dto)
    field_name = dataclasses.fields(instance)[0].name
    try:
        setattr(instance, field_name, None)
    except dataclasses.FrozenInstanceError:
        return False
    return True


@pytest.mark.parametrize("module", MODULE_NAMES)
def test_service_dtos_are_frozen(module: str) -> None:
    if not (MODULES / module / "service" / "dto.py").exists():
        pytest.skip("module has no DTOs yet")
    dto_module = importlib.import_module(f"app.modules.{module}.service.dto")
    dtos = [
        member
        for _, member in inspect.getmembers(dto_module, inspect.isclass)
        if member.__module__ == dto_module.__name__ and dataclasses.is_dataclass(member)
    ]

    assert dtos
    assert [dto.__name__ for dto in dtos if _accepts_assignment(dto)] == []
