from __future__ import annotations

from pathlib import Path

import pytest

from cdp_audit.config_loader import Config, ConfigError

PROJECT_CONFIG = Path(__file__).resolve().parents[1] / "config.yaml"


def _config(tmp_path: Path, text: str) -> Config:
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return Config(str(path))


def test_shipped_config_is_valid() -> None:
    loaded = Config(str(PROJECT_CONFIG))

    assert loaded.DEFAULT_LIMIT >= 1
    assert loaded.EXCEL_CELL_SITE_NAME == "B4"


def test_empty_file_and_empty_sections_use_defaults(tmp_path: Path) -> None:
    assert _config(tmp_path, "").SSH_PORT == 22
    loaded = _config(tmp_path, "network:\nexcel:\n  sheets:\n")
    assert loaded.DEFAULT_TIMEOUT == 10
    assert loaded.EXCEL_SHEET_AUDIT == "Audit"


@pytest.mark.parametrize(
    "yaml_text,expected",
    [
        ("network:\n  default_limit: 0\n", "network.default_limit"),
        ("network:\n  max_retry_attempts: 0\n", "network.max_retry_attempts"),
        ("network:\n  ssh_port: 70000\n", "network.ssh_port"),
        ("network:\n  default_timeout: ten\n", "network.default_timeout"),
        ("network:\n  device_type: cisco_iso\n", "Did you mean"),
        ("network:\n  jump_host: admin@bastion\n", "user@host"),
        ("network:\n  jump_host: 10.0.0.1:2222\n", "host:port"),
        ("network:\n  jump_host: 0.0.0.0\n", "unspecified"),
        ("network:\n  defualt_timeout: 30\n", "network.defualt_timeout"),
        ("network:\n  dns_min_workers: 40\n  dns_max_workers: 8\n", "dns_min_workers"),
        ("excel:\n  metadata_cells:\n    date: 5B\n", "excel.metadata_cells.date"),
        ("excel:\n  metadata_cells:\n    date: B4\n", "overlap"),
        ("excel:\n  sheets:\n    dns: 'DNS/Resolved'\n", "excel.sheets.dns"),
        ("excel:\n  sheets:\n    dns: audit\n", "distinct"),
        ("excel:\n  columns_audit: [LOCAL_HOST, LOCL_IP]\n", "LOCL_IP"),
        ("excel:\n  columns_inventory: [IP, IP]\n", "duplicate"),
        ("discovery:\n  protocol: auto\n", "discovery.protocol"),
    ],
)
def test_invalid_settings_are_reported_with_their_yaml_path(
    tmp_path: Path, yaml_text: str, expected: str
) -> None:
    with pytest.raises(ConfigError, match=expected.replace(".", r"\.")):
        _config(tmp_path, yaml_text)


def test_all_problems_are_reported_together(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as caught:
        _config(tmp_path, "network:\n  default_limit: 0\n  ssh_port: 0\n")

    assert "network.default_limit" in str(caught.value)
    assert "network.ssh_port" in str(caught.value)


def test_string_booleans_are_parsed_not_truthy(tmp_path: Path) -> None:
    # bool("false") is True; the old loader would have enabled strict mode.
    assert _config(tmp_path, 'network:\n  strict_host_keys: "false"\n').STRICT_HOST_KEYS is False
    assert _config(tmp_path, "network:\n  strict_host_keys: yes\n").STRICT_HOST_KEYS is True


def test_null_jump_host_means_direct(tmp_path: Path) -> None:
    assert _config(tmp_path, "network:\n  jump_host: null\n").JUMP_HOST == ""


def test_cell_references_are_upper_cased(tmp_path: Path) -> None:
    loaded = _config(tmp_path, "excel:\n  metadata_cells:\n    site_name: c4\n")

    assert loaded.EXCEL_CELL_SITE_NAME == "C4"


def test_env_override_is_validated_and_named(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CDP_LIMIT", "lots")

    with pytest.raises(ConfigError, match="CDP_LIMIT"):
        _config(tmp_path, "network:\n  default_limit: 10\n")


def test_env_override_applies(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CDP_TIMEOUT", " 30 ")
    monkeypatch.setenv("CDP_JUMP_SERVER", "bastion.example.test")

    loaded = _config(tmp_path, "network:\n  default_timeout: 10\n")

    assert loaded.DEFAULT_TIMEOUT == 30
    assert loaded.JUMP_HOST == "bastion.example.test"


def test_blank_env_override_is_ignored(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CDP_LIMIT", "  ")

    assert _config(tmp_path, "network:\n  default_limit: 7\n").DEFAULT_LIMIT == 7


def test_non_mapping_yaml_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="mapping"):
        _config(tmp_path, "- just\n- a list\n")
