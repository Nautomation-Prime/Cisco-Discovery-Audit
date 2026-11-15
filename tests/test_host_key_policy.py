from __future__ import annotations

from pathlib import Path

import paramiko
import pytest

from cdp_audit.app_config import config
from cdp_audit.config_loader import Config
from cdp_audit.discovery import NetworkDiscoverer

ROOT = Path(__file__).resolve().parents[1]
CDP_TEMPLATE = ROOT / "assets/textfsm/cisco_ios_show_cdp_neighbors_detail.textfsm"
LLDP_TEMPLATE = ROOT / "assets/textfsm/cisco_ios_show_lldp_neighbors_detail.textfsm"
VERSION_TEMPLATE = ROOT / "assets/textfsm/cisco_ios_show_version.textfsm"


class RecordingClient:
    """Stands in for paramiko.SSHClient to capture the configured policy."""

    def __init__(self) -> None:
        self.policy = None
        self.loaded_system_keys = False

    def load_system_host_keys(self, *args, **kwargs) -> None:
        self.loaded_system_keys = True

    def set_missing_host_key_policy(self, policy) -> None:
        self.policy = policy

    def connect(self, *args, **kwargs) -> None:
        pass

    def get_transport(self):
        return None


def make_discoverer() -> NetworkDiscoverer:
    return NetworkDiscoverer(
        timeout=1,
        limit=1,
        cdp_template=CDP_TEMPLATE,
        lldp_template=LLDP_TEMPLATE,
        ver_template=VERSION_TEMPLATE,
    )


def _client_for(monkeypatch, strict: bool) -> RecordingClient:
    recorded = RecordingClient()
    monkeypatch.setattr(paramiko, "SSHClient", lambda: recorded)
    monkeypatch.setattr(
        type(config), "STRICT_HOST_KEYS", property(lambda self: strict)
    )
    make_discoverer()._paramiko_jump_client("bastion", "user", "pass")
    return recorded


def test_strict_mode_rejects_unknown_jump_host_keys(monkeypatch) -> None:
    recorded = _client_for(monkeypatch, strict=True)

    assert isinstance(recorded.policy, paramiko.client.RejectPolicy)
    assert recorded.loaded_system_keys


def test_default_mode_warns_but_accepts(monkeypatch) -> None:
    recorded = _client_for(monkeypatch, strict=False)

    assert isinstance(recorded.policy, paramiko.client.WarningPolicy)


def test_strict_host_keys_defaults_to_false_and_reads_config(tmp_path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text("network:\n  ssh_port: 22\n", encoding="utf-8")
    assert Config(str(config_file)).STRICT_HOST_KEYS is False

    config_file.write_text(
        "network:\n  strict_host_keys: true\n", encoding="utf-8"
    )
    assert Config(str(config_file)).STRICT_HOST_KEYS is True


@pytest.mark.parametrize(
    "value,expected",
    [("1", True), ("true", True), ("YES", True), ("0", False), ("off", False)],
)
def test_env_var_overrides_strict_host_keys(
    tmp_path, monkeypatch, value: str, expected: bool
) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "network:\n  strict_host_keys: false\n", encoding="utf-8"
    )
    monkeypatch.setenv("CDP_STRICT_HOST_KEYS", value)

    assert Config(str(config_file)).STRICT_HOST_KEYS is expected
