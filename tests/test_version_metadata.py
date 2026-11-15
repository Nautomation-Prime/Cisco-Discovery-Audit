from __future__ import annotations

from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef]

import cdp_audit
from cdp_audit import __about__
from cdp_audit.version import get_version, get_version_info


def test_runtime_version_matches_pyproject() -> None:
    root = Path(__file__).resolve().parents[1]
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project_version = pyproject["project"]["version"]

    assert get_version() == project_version
    assert cdp_audit.__version__ == project_version
    assert __about__.__version__ == project_version


def test_version_info_includes_core_summary_lines() -> None:
    info = get_version_info()

    assert "Nautomation Prime Cisco Discovery Audit" in info
    assert f"Version: {get_version()}" in info
