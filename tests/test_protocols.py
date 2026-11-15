from __future__ import annotations

from pathlib import Path

import pytest

from cdp_audit.config_loader import Config
from cdp_audit.protocols import (
    DiscoveryMode,
    NeighborProtocol,
    NeighborRecord,
    merge_neighbor_records,
    normalize_hostname,
    normalize_interface,
)


def test_discovery_mode_parses_supported_values() -> None:
    assert DiscoveryMode.parse("CDP") is DiscoveryMode.CDP
    assert DiscoveryMode.parse(" lldp ") is DiscoveryMode.LLDP
    assert DiscoveryMode.parse("both") is DiscoveryMode.BOTH
    assert DiscoveryMode.parse(DiscoveryMode.CDP) is DiscoveryMode.CDP


def test_discovery_mode_rejects_invalid_value() -> None:
    with pytest.raises(ValueError, match="expected one of: cdp, lldp, both"):
        DiscoveryMode.parse("auto")


def test_config_defaults_to_cdp_and_selects_only_required_templates(
    tmp_path: Path,
) -> None:
    for filename in ("version.textfsm", "cdp.textfsm", "report.xlsx"):
        (tmp_path / filename).touch()
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "\n".join(
            (
                "file_paths:",
                '  base_dir: "."',
                '  cdp_template: "cdp.textfsm"',
                '  lldp_template: "missing-lldp.textfsm"',
                '  ver_template: "version.textfsm"',
                '  excel_template: "report.xlsx"',
            )
        ),
        encoding="utf-8",
    )

    loaded = Config(str(config_path))

    assert loaded.DISCOVERY_MODE is DiscoveryMode.CDP
    assert loaded.LLDP_TEMPLATE not in loaded.REQUIRED_SUPPORT_FILES
    assert all(path.exists() for path in loaded.REQUIRED_SUPPORT_FILES)


def test_config_rejects_invalid_protocol(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text("discovery:\n  protocol: auto\n", encoding="utf-8")

    with pytest.raises(ValueError, match="discovery.protocol"):
        Config(str(config_path)).DISCOVERY_MODE


def test_merge_combines_matching_cdp_and_lldp_records() -> None:
    cdp = NeighborRecord(
        local_port="GigabitEthernet1/0/1",
        remote_name="edge-sw-02.example.test",
        remote_port="Gi1/0/48",
        management_ip="192.0.2.20",
        platform="cisco C9300-48P",
        software_version="Cisco IOS XE 17.9.4a",
        capabilities="Router Switch IGMP",
        protocols={NeighborProtocol.CDP},
    )
    lldp = NeighborRecord(
        local_port="Gi1/0/1",
        remote_name="EDGE-SW-02",
        remote_port="GigabitEthernet1/0/48",
        management_ip="192.0.2.20",
        chassis_id="aaaa.bbbb.cccc",
        software_version="Cisco IOS XE Software",
        capabilities="B,R",
        protocols={NeighborProtocol.LLDP},
    )

    merged = merge_neighbor_records([lldp, cdp])

    assert len(merged) == 1
    assert merged[0].protocol_label == "CDP+LLDP"
    assert merged[0].platform == "cisco C9300-48P"
    assert merged[0].software_version == "Cisco IOS XE 17.9.4a"
    assert merged[0].chassis_id == "aaaa.bbbb.cccc"


def test_merge_preserves_ambiguous_remote_ports() -> None:
    left = NeighborRecord(
        local_port="Gi1/0/1",
        remote_name="edge-sw-02",
        remote_port="Gi1/0/47",
        management_ip="192.0.2.20",
        protocols={NeighborProtocol.CDP},
    )
    right = NeighborRecord(
        local_port="GigabitEthernet1/0/1",
        remote_name="edge-sw-02.example.test",
        remote_port="Gi1/0/48",
        management_ip="192.0.2.20",
        protocols={NeighborProtocol.LLDP},
    )

    assert len(merge_neighbor_records([left, right])) == 2


def test_normalization_handles_common_cisco_identifiers() -> None:
    assert normalize_interface(" Gi1/0/1 ") == "gigabitethernet1/0/1"
    assert normalize_interface("GigabitEthernet1/0/1") == "gigabitethernet1/0/1"
    assert normalize_interface("Te1/1/1") == "tengigabitethernet1/1/1"
    assert normalize_hostname("EDGE-SW-02.example.test") == "edge-sw-02"


def test_crawl_policy_is_conservative_for_lldp_peers() -> None:
    cisco = NeighborRecord(
        software_version="Cisco IOS XE Software, Version 17.9.4",
        protocols={NeighborProtocol.LLDP},
    )
    non_cisco = NeighborRecord(
        software_version="ExampleOS 4.2",
        protocols={NeighborProtocol.LLDP},
    )

    assert cisco.is_supported_cisco_infrastructure()
    assert not non_cisco.is_supported_cisco_infrastructure()


def test_chassis_ids_are_preserved_and_never_collide() -> None:
    first = NeighborRecord(
        local_port="Gi1/0/1",
        remote_name="aaaa.bbbb.cccc",
        remote_port="eth0",
        chassis_id="aaaa.bbbb.cccc",
        protocols={NeighborProtocol.LLDP},
    )
    second = NeighborRecord(
        local_port="Gi1/0/1",
        remote_name="aaaa.dddd.eeee",
        remote_port="eth0",
        chassis_id="aaaa.dddd.eeee",
        protocols={NeighborProtocol.LLDP},
    )

    assert first.to_audit_row("core", "192.0.2.1")["DESTINATION_HOST"] == (
        "AAAA.BBBB.CCCC"
    )
    assert len(merge_neighbor_records([first, second])) == 2
