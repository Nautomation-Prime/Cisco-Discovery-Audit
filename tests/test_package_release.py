from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

from scripts.package_release import EXECUTABLE_NAME, create_release


def test_release_packaging_creates_website_handoff_files(tmp_path: Path) -> None:
    dist_directory = tmp_path / "dist"
    dist_directory.mkdir()
    (dist_directory / EXECUTABLE_NAME).write_bytes(b"placeholder executable")
    (dist_directory / "_internal").mkdir()
    (dist_directory / "_internal" / "runtime.dll").write_bytes(b"runtime")

    artifacts = create_release(
        dist_directory,
        tmp_path / "release",
        include_runtime_licenses=False,
        staging_parent=tmp_path / "staging",
    )

    archive_path = artifacts["archive"]
    manifest = json.loads(artifacts["manifest"].read_text(encoding="utf-8"))
    actual_checksum = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    assert manifest["artifact"]["sha256"] == actual_checksum
    assert manifest["default_discovery_protocol"] == "cdp"
    assert manifest["discovery_protocols"] == ["cdp", "lldp", "both"]
    assert artifacts["checksum"].read_text(encoding="ascii").startswith(
        actual_checksum
    )

    with zipfile.ZipFile(archive_path) as archive:
        names = set(archive.namelist())
    archive_root = (
        "NautomationPrimeCiscoDiscoveryAudit-1.0.0-windows-x64"
    )
    assert f"{archive_root}/{EXECUTABLE_NAME}" in names
    assert f"{archive_root}/config.yaml" in names
    assert f"{archive_root}/NOTICE" in names
    assert (
        f"{archive_root}/assets/textfsm/"
        "cisco_ios_show_lldp_neighbors_detail.textfsm"
    ) in names
    assert not any(name.endswith(".py") for name in names)


def test_release_packaging_rejects_python_sources(tmp_path: Path) -> None:
    dist_directory = tmp_path / "dist"
    dist_directory.mkdir()
    (dist_directory / EXECUTABLE_NAME).write_bytes(b"placeholder executable")
    (dist_directory / "source.py").write_text("secret = True\n", encoding="utf-8")

    import pytest

    with pytest.raises(RuntimeError, match="contains Python source files"):
        create_release(
            dist_directory,
            tmp_path / "release",
            include_runtime_licenses=False,
            staging_parent=tmp_path / "staging",
        )


def test_release_packaging_removes_stale_handoff_files(tmp_path: Path) -> None:
    dist_directory = tmp_path / "dist"
    dist_directory.mkdir()
    (dist_directory / EXECUTABLE_NAME).write_bytes(b"placeholder executable")
    output_directory = tmp_path / "release"
    output_directory.mkdir()
    stale = output_directory / "old-version.zip"
    stale.write_bytes(b"stale")

    create_release(
        dist_directory,
        output_directory,
        include_runtime_licenses=False,
        staging_parent=tmp_path / "staging",
    )

    assert not stale.exists()
