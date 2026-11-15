from __future__ import annotations

import socket

import pytest

from cdp_audit import validators


def test_seed_order_is_preserved_so_primary_seed_is_stable() -> None:
    """hosts[0] is stamped as 'Primary Seed' in the report, so order matters."""
    seeds = ["192.0.2.20", "192.0.2.10", "192.0.2.30"]

    assert validators.normalize_seeds(seeds) == seeds


def test_duplicate_seeds_are_removed_keeping_first_occurrence() -> None:
    result = validators.normalize_seeds(
        ["10.0.0.2", "10.0.0.1", "10.0.0.2", "10.0.0.1"]
    )

    assert result == ["10.0.0.2", "10.0.0.1"]


def test_unresolvable_seed_is_skipped_not_fatal(monkeypatch) -> None:
    def fail_to_resolve(name: str) -> str:
        raise socket.gaierror(f"cannot resolve {name}")

    monkeypatch.setattr(validators.socket, "gethostbyname", fail_to_resolve)

    result = validators.normalize_seeds(["10.0.0.1", "typo-hostname", "10.0.0.2"])

    assert result == ["10.0.0.1", "10.0.0.2"]


def test_run_aborts_only_when_no_seed_survives(monkeypatch) -> None:
    def fail_to_resolve(name: str) -> str:
        raise socket.gaierror(f"cannot resolve {name}")

    monkeypatch.setattr(validators.socket, "gethostbyname", fail_to_resolve)

    with pytest.raises(SystemExit):
        validators.normalize_seeds(["typo-one", "typo-two"])


def test_hostnames_are_resolved_to_addresses(monkeypatch) -> None:
    monkeypatch.setattr(
        validators.socket, "gethostbyname", lambda name: "192.0.2.55"
    )

    assert validators.normalize_seeds(["core-sw-01"]) == ["192.0.2.55"]
