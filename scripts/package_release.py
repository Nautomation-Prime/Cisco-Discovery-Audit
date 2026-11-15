"""Create the website-ready Windows premium release artifacts."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import stat
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from packaging.requirements import Requirement

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]


ROOT = Path(__file__).resolve().parents[1]
PROJECT_DISTRIBUTION = "nautomation-prime-cisco-discovery-audit"
EXECUTABLE_NAME = "NautomationPrimeCiscoDiscoveryAudit.exe"


def project_metadata() -> dict:
    return tomllib.loads(
        (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]


def runtime_distributions(root_name: str) -> list[importlib.metadata.Distribution]:
    """Resolve installed runtime dependencies while ignoring optional extras."""
    resolved: dict[str, importlib.metadata.Distribution] = {}
    pending = [root_name]
    while pending:
        requested_name = pending.pop()
        distribution = importlib.metadata.distribution(requested_name)
        canonical_name = _canonical_name(distribution.metadata["Name"])
        if canonical_name in resolved:
            continue
        resolved[canonical_name] = distribution

        for requirement_text in distribution.requires or []:
            requirement = Requirement(requirement_text)
            if requirement.marker and not requirement.marker.evaluate({"extra": ""}):
                continue
            pending.append(requirement.name)
    return sorted(
        resolved.values(),
        key=lambda distribution: distribution.metadata["Name"].lower(),
    )


def copy_runtime_licenses(destination: Path) -> list[str]:
    """Copy complete licence texts for the runtime and bundled components."""
    destination.mkdir(parents=True, exist_ok=True)
    overrides = ROOT / "third_party_licenses"
    if overrides.exists():
        shutil.copytree(overrides, destination, dirs_exist_ok=True)

    copied_distributions: list[str] = []
    for distribution in runtime_distributions(PROJECT_DISTRIBUTION):
        name = distribution.metadata["Name"]
        if _canonical_name(name) == _canonical_name(PROJECT_DISTRIBUTION):
            continue

        target_dir = destination / _canonical_name(name)
        target_dir.mkdir(parents=True, exist_ok=True)
        _copy_distribution_licenses(distribution, target_dir)
        if not any(path.is_file() for path in target_dir.rglob("*")):
            raise RuntimeError(
                f"No complete licence text is available for {name} "
                f"{distribution.version}"
            )
        copied_distributions.append(f"{name} {distribution.version}")

    python_license = next(
        (
            candidate
            for candidate in (
                Path(sys.base_prefix) / "LICENSE.txt",
                Path(sys.base_prefix) / "LICENSE",
                Path(sys.executable).resolve().parent / "LICENSE.txt",
            )
            if candidate.is_file()
        ),
        None,
    )
    if python_license is None:
        raise RuntimeError("The CPython licence file could not be located")
    python_target = destination / "cpython"
    python_target.mkdir(exist_ok=True)
    shutil.copy2(python_license, python_target / python_license.name)
    copied_distributions.insert(0, f"CPython {platform.python_version()}")

    pyinstaller = importlib.metadata.distribution("pyinstaller")
    pyinstaller_target = destination / "pyinstaller"
    pyinstaller_target.mkdir(exist_ok=True)
    _copy_distribution_licenses(pyinstaller, pyinstaller_target)
    if not any(path.is_file() for path in pyinstaller_target.rglob("*")):
        raise RuntimeError("The PyInstaller licence file could not be located")
    copied_distributions.append(
        f"PyInstaller bootloader {pyinstaller.version}"
    )
    return copied_distributions


def _copy_distribution_licenses(
    distribution: importlib.metadata.Distribution,
    target_dir: Path,
) -> int:
    copied = 0
    for relative_file in distribution.files or []:
        basename = Path(str(relative_file)).name.lower()
        if not basename.startswith(("license", "licence", "copying", "notice")):
            continue
        source = Path(distribution.locate_file(relative_file))
        if not source.is_file():
            continue
        target = target_dir / Path(str(relative_file)).name
        if target.exists():
            target = target_dir / f"{copied}-{target.name}"
        shutil.copy2(source, target)
        copied += 1
    return copied


def create_release(
    dist_directory: Path,
    output_directory: Path,
    *,
    include_runtime_licenses: bool = True,
    staging_parent: Path | None = None,
) -> dict:
    """Build the staging tree, ZIP, checksum, and website product manifest."""
    metadata = project_metadata()
    version = metadata["version"]
    archive_stem = (
        f"NautomationPrimeCiscoDiscoveryAudit-{version}-windows-x64"
    )
    release_staging_parent = (
        staging_parent or ROOT / "build" / "package-release"
    )
    staging_root = release_staging_parent / archive_stem

    if release_staging_parent.exists():
        _remove_tree(release_staging_parent)
    staging_root.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(dist_directory, staging_root)
    source_files = list(staging_root.rglob("*.py"))
    if source_files:
        sample = ", ".join(str(path.relative_to(staging_root)) for path in source_files[:5])
        raise RuntimeError(
            f"Release staging contains Python source files: {sample}"
        )

    for filename in (
        "config.yaml",
        "LICENSE",
        "NOTICE",
        "THIRD_PARTY_NOTICES.md",
        "README.md",
        "RELEASE_NOTES.md",
    ):
        shutil.copy2(ROOT / filename, staging_root / filename)
    shutil.copytree(ROOT / "assets", staging_root / "assets")
    (staging_root / "logs").mkdir(exist_ok=True)
    (staging_root / "output").mkdir(exist_ok=True)

    included_distributions: list[str] = []
    if include_runtime_licenses:
        included_distributions = copy_runtime_licenses(
            staging_root / "third_party_licenses"
        )

    product_info = {
        "product": "Nautomation Prime Cisco Discovery Audit",
        "version": version,
        "edition": "Premium",
        "platform": "Windows 10/11 x64",
        "supported_devices": ["Cisco IOS", "Cisco IOS-XE"],
        "discovery_protocols": ["cdp", "lldp", "both"],
        "default_discovery_protocol": "cdp",
        "runtime_activation_required": False,
        "included_runtime_distributions": included_distributions,
    }
    (staging_root / "product-info.json").write_text(
        json.dumps(product_info, indent=2) + "\n",
        encoding="utf-8",
    )

    output_directory = _prepare_output_directory(output_directory)
    archive_path = output_directory / f"{archive_stem}.zip"
    if archive_path.exists():
        archive_path.unlink()
    with zipfile.ZipFile(
        archive_path,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for path in sorted(staging_root.rglob("*")):
            if path.is_file():
                archive.write(
                    path,
                    Path(archive_stem) / path.relative_to(staging_root),
                )

    checksum = _sha256(archive_path)
    checksum_path = output_directory / f"{archive_path.name}.sha256"
    checksum_path.write_text(
        f"{checksum}  {archive_path.name}\n",
        encoding="ascii",
    )
    release_notes_path = output_directory / f"release-notes-{version}.md"
    shutil.copy2(ROOT / "RELEASE_NOTES.md", release_notes_path)

    manifest = {
        **product_info,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "artifact": {
            "filename": archive_path.name,
            "size_bytes": archive_path.stat().st_size,
            "sha256": checksum,
            "checksum_filename": checksum_path.name,
        },
        "release_notes_filename": release_notes_path.name,
    }
    manifest_path = output_directory / "product-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    return {
        "archive": archive_path,
        "checksum": checksum_path,
        "manifest": manifest_path,
        "release_notes": release_notes_path,
        "staging_root": staging_root,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_handle:
        for block in iter(lambda: file_handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _remove_tree(path: Path) -> None:
    """Remove one resolved staging tree, clearing Windows read-only attributes."""
    resolved = path.resolve()
    expected_root = (ROOT / "build").resolve()
    if expected_root not in resolved.parents and "pytest-" not in str(resolved):
        raise ValueError(f"Refusing to remove unexpected staging path: {resolved}")

    _rmtree(resolved)


def _prepare_output_directory(path: Path) -> Path:
    """Create an empty, narrowly scoped website-handoff directory."""
    resolved = path.resolve()
    expected = (ROOT / "release").resolve()
    if resolved != expected and "pytest-" not in str(resolved):
        raise ValueError(f"Refusing to clean unexpected release path: {resolved}")
    if resolved.exists():
        _rmtree(resolved)
    resolved.mkdir(parents=True)
    return resolved


def _rmtree(path: Path) -> None:
    def clear_readonly(function, item, _error) -> None:
        os.chmod(item, stat.S_IWRITE)
        function(item)

    shutil.rmtree(path, onerror=clear_readonly)


def _canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dist-directory",
        type=Path,
        default=ROOT / "dist" / "NautomationPrimeCiscoDiscoveryAudit",
    )
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=ROOT / "release",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    executable = args.dist_directory / EXECUTABLE_NAME
    if not executable.exists():
        parser.error(f"Packaged executable not found: {executable}")
    artifacts = create_release(args.dist_directory, args.output_directory)
    print(json.dumps({key: str(value) for key, value in artifacts.items()}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
