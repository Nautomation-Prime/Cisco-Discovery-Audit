"""Version helpers for Nautomation Prime Cisco Discovery Audit."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef]

_ROOT = Path(__file__).resolve().parent.parent
_PYPROJECT_FILE = _ROOT / "pyproject.toml"
_APP_NAME = "Nautomation Prime Cisco Discovery Audit"
_PACKAGE_NAME = "nautomation-prime-cisco-discovery-audit"


def _read_project_metadata() -> dict:
    try:
        data = tomllib.loads(_PYPROJECT_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}

    project = data.get("project")
    return project if isinstance(project, dict) else {}


def get_version() -> str:
    """Return installed metadata, falling back to source-tree metadata."""
    try:
        installed = package_version(_PACKAGE_NAME)
        if installed.strip():
            return installed.strip()
    except PackageNotFoundError:
        pass

    project = _read_project_metadata()
    version = project.get("version")
    if isinstance(version, str) and version.strip():
        return version.strip()
    return "unknown"


def get_version_info() -> str:
    """Return a user-facing version summary."""
    return "\n".join([_APP_NAME, f"Version: {get_version()}"])
