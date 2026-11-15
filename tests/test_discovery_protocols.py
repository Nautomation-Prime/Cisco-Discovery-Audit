from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from cdp_audit.discovery import NetworkDiscoverer
from cdp_audit.protocols import (
    CollectionStatus,
    DeviceCommandResult,
    DiscoveryMode,
    NeighborProtocol,
    NeighborRecord,
    ProtocolCollectionResult,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"
CDP_TEMPLATE = ROOT / "assets/textfsm/cisco_ios_show_cdp_neighbors_detail.textfsm"
LLDP_TEMPLATE = ROOT / "assets/textfsm/cisco_ios_show_lldp_neighbors_detail.textfsm"
VERSION_TEMPLATE = ROOT / "assets/textfsm/cisco_ios_show_version.textfsm"


def make_discoverer(mode: DiscoveryMode = DiscoveryMode.CDP) -> NetworkDiscoverer:
    return NetworkDiscoverer(
        timeout=5,
        limit=1,
        cdp_template=CDP_TEMPLATE,
        lldp_template=LLDP_TEMPLATE,
        ver_template=VERSION_TEMPLATE,
        discovery_mode=mode,
    )


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_ios_xe_lldp_output_is_normalized() -> None:
    discoverer = make_discoverer(DiscoveryMode.LLDP)

    result = discoverer._protocol_result_from_output(
        NeighborProtocol.LLDP,
        fixture_text("cisco_ios_lldp_neighbors_detail.txt"),
    )

    assert result.status is CollectionStatus.OK
    assert len(result.neighbors) == 1
    neighbor = result.neighbors[0]
    assert neighbor.local_port == "Gi1/0/1"
    assert neighbor.remote_name == "edge-sw-02.example.test"
    assert neighbor.remote_port == "GigabitEthernet1/0/48"
    assert neighbor.management_ip == "192.0.2.20"
    assert "Cisco IOS XE Software" in neighbor.system_description


def test_legacy_ios_lldp_output_is_normalized_and_crawlable() -> None:
    discoverer = make_discoverer(DiscoveryMode.LLDP)

    result = discoverer._protocol_result_from_output(
        NeighborProtocol.LLDP,
        fixture_text("cisco_ios_lldp_neighbors_detail_legacy.txt"),
    )

    assert result.status is CollectionStatus.OK
    assert len(result.neighbors) == 1
    neighbor = result.neighbors[0]
    assert neighbor.remote_name == "access-sw-03.example.test"
    assert neighbor.management_ip == "192.0.2.30"
    assert "Cisco IOS Software" in neighbor.system_description
    assert neighbor.is_supported_cisco_infrastructure()


def test_existing_cdp_output_remains_supported() -> None:
    discoverer = make_discoverer(DiscoveryMode.CDP)

    result = discoverer._protocol_result_from_output(
        NeighborProtocol.CDP,
        fixture_text("cisco_ios_cdp_neighbors_detail.txt"),
    )

    assert result.status is CollectionStatus.OK
    assert len(result.neighbors) == 1
    assert result.neighbors[0].management_ip == "192.0.2.20"
    assert result.neighbors[0].protocols == {NeighborProtocol.CDP}


@pytest.mark.parametrize(
    ("protocol", "output", "expected"),
    (
        (
            NeighborProtocol.LLDP,
            "% LLDP is not enabled",
            CollectionStatus.DISABLED,
        ),
        (
            NeighborProtocol.LLDP,
            "% Invalid input detected at '^' marker.",
            CollectionStatus.UNSUPPORTED,
        ),
        (
            NeighborProtocol.LLDP,
            "Total entries displayed: 0",
            CollectionStatus.EMPTY,
        ),
        (
            NeighborProtocol.LLDP,
            "Local Intf: Gi1/0/1\nmalformed neighbor output",
            CollectionStatus.PARSE_FAILED,
        ),
    ),
)
def test_lldp_collection_statuses(
    protocol: NeighborProtocol,
    output: str,
    expected: CollectionStatus,
) -> None:
    result = make_discoverer(DiscoveryMode.LLDP)._protocol_result_from_output(
        protocol, output
    )
    assert result.status is expected


@pytest.mark.parametrize(
    ("protocol", "output"),
    (
        (NeighborProtocol.CDP, "Device ID: edge-sw"),
        (NeighborProtocol.LLDP, "Local Intf: Gi1/0/1"),
        (NeighborProtocol.CDP, "% Authorization failed."),
        (NeighborProtocol.LLDP, "unexpected command response"),
    ),
)
def test_incomplete_or_failed_output_is_never_reported_as_empty_or_ok(
    protocol: NeighborProtocol,
    output: str,
) -> None:
    mode = (
        DiscoveryMode.CDP
        if protocol is NeighborProtocol.CDP
        else DiscoveryMode.LLDP
    )
    result = make_discoverer(mode)._protocol_result_from_output(protocol, output)
    assert result.status is CollectionStatus.PARSE_FAILED


def test_lldp_med_revision_retains_description_for_cisco_detection() -> None:
    rows = [
        {
            "LOCAL_INTERFACE": "Gi1/0/1",
            "NEIGHBOR_NAME": "edge-sw-02",
            "NEIGHBOR_INTERFACE": "Gi1/0/48",
            "MGMT_ADDRESS": "192.0.2.20",
            "SW_REVISION": "17.9.4",
            "NEIGHBOR_DESCRIPTION": "Cisco IOS XE Software, Version 17.9.4",
        }
    ]

    neighbor = make_discoverer(DiscoveryMode.LLDP)._normalize_lldp_rows(rows)[0]

    assert neighbor.software_version == "17.9.4"
    assert "Cisco IOS XE" in neighbor.system_description
    assert neighbor.is_supported_cisco_infrastructure()


def test_both_mode_merges_rows_and_queues_supported_cisco_peer() -> None:
    discoverer = make_discoverer(DiscoveryMode.BOTH)
    cdp = NeighborRecord(
        local_port="GigabitEthernet1/0/1",
        remote_name="edge-sw-02.example.test",
        remote_port="Gi1/0/48",
        management_ip="192.0.2.20",
        platform="cisco C9300-48P",
        capabilities="Router Switch",
        protocols={NeighborProtocol.CDP},
    )
    lldp = NeighborRecord(
        local_port="Gi1/0/1",
        remote_name="edge-sw-02",
        remote_port="GigabitEthernet1/0/48",
        management_ip="192.0.2.20",
        chassis_id="aaaa.bbbb.cccc",
        protocols={NeighborProtocol.LLDP},
    )
    result = DeviceCommandResult(
        version_output=fixture_text("cisco_ios_show_version.txt"),
        protocols={
            NeighborProtocol.CDP: ProtocolCollectionResult(
                NeighborProtocol.CDP, CollectionStatus.OK, [cdp]
            ),
            NeighborProtocol.LLDP: ProtocolCollectionResult(
                NeighborProtocol.LLDP, CollectionStatus.OK, [lldp]
            ),
        },
    )

    discoverer.parse_outputs_and_enqueue_neighbors("192.0.2.10", result)

    assert len(discoverer.neighbour_details) == 1
    assert discoverer.neighbour_details[0]["PROTOCOLS"] == "CDP+LLDP"
    assert discoverer.host_queue.get_nowait() == "192.0.2.20"
    assert (
        discoverer.device_inventory["192.0.2.10"]["PROTOCOL_STATUS"]
        == "CDP: ok (1); LLDP: ok (1)"
    )


def test_non_cisco_lldp_peer_is_reported_but_not_queued() -> None:
    discoverer = make_discoverer(DiscoveryMode.LLDP)
    peer = NeighborRecord(
        local_port="Gi1/0/9",
        remote_name="third-party-ap",
        remote_port="eth0",
        management_ip="192.0.2.90",
        software_version="Example Wireless OS 4.2",
        capabilities="W",
        protocols={NeighborProtocol.LLDP},
    )
    result = DeviceCommandResult(
        version_output=fixture_text("cisco_ios_show_version.txt"),
        protocols={
            NeighborProtocol.LLDP: ProtocolCollectionResult(
                NeighborProtocol.LLDP, CollectionStatus.OK, [peer]
            )
        },
    )

    discoverer.parse_outputs_and_enqueue_neighbors("192.0.2.10", result)

    assert len(discoverer.neighbour_details) == 1
    assert discoverer.host_queue.empty()


def _cdp_switch(local_port: str, management_ip: str) -> NeighborRecord:
    return NeighborRecord(
        local_port=local_port,
        remote_name=f"sw-{local_port}",
        remote_port="Gi1/0/48",
        management_ip=management_ip,
        capabilities="Router Switch",
        protocols={NeighborProtocol.CDP},
    )


@pytest.mark.parametrize("address", ["0.0.0.0", "127.0.0.1", "fe80::1", "169.254.1.1"])
def test_unusable_management_ip_is_reported_but_not_queued(address: str) -> None:
    discoverer = make_discoverer(DiscoveryMode.CDP)
    result = DeviceCommandResult(
        version_output=fixture_text("cisco_ios_show_version.txt"),
        protocols={
            NeighborProtocol.CDP: ProtocolCollectionResult(
                NeighborProtocol.CDP,
                CollectionStatus.OK,
                [_cdp_switch("Gi1/0/1", address)],
            )
        },
    )

    discoverer.parse_outputs_and_enqueue_neighbors("192.0.2.10", result)

    assert discoverer.neighbour_details[0]["MANAGEMENT_IP"] == address
    assert discoverer.host_queue.empty()


def test_ipv6_spellings_of_one_address_are_queued_once() -> None:
    discoverer = make_discoverer(DiscoveryMode.CDP)
    result = DeviceCommandResult(
        version_output=fixture_text("cisco_ios_show_version.txt"),
        protocols={
            NeighborProtocol.CDP: ProtocolCollectionResult(
                NeighborProtocol.CDP,
                CollectionStatus.OK,
                [
                    _cdp_switch("Gi1/0/1", "2001:DB8::20"),
                    _cdp_switch("Gi1/0/2", "2001:db8:0:0::20"),
                ],
            )
        },
    )

    discoverer.parse_outputs_and_enqueue_neighbors("192.0.2.10", result)

    assert discoverer.host_queue.get_nowait() == "2001:db8::20"
    assert discoverer.host_queue.empty()


class FakeConnection:
    def __init__(self) -> None:
        self.commands: list[str] = []
        self.global_cmd_verify = True

    def enable(self) -> None:
        return None

    def clear_buffer(self) -> None:
        return None

    def read_channel(self) -> str:
        return ""

    def disconnect(self) -> None:
        return None

    def send_command(self, command: str, **_: object) -> str:
        self.commands.append(command)
        if command == "show version":
            return fixture_text("cisco_ios_show_version.txt")
        if command == "show cdp neighbors":
            return (
                "Device ID Local Intrfce Holdtme Capability Platform Port ID\n"
                "edge-sw-02 Gi1/0/1 120 S C9300 Gi1/0/48"
            )
        return ""

    def send_command_timing(self, command: str, **_: object) -> str:
        self.commands.append(command)
        if command == "show cdp neighbors detail":
            return fixture_text("cisco_ios_cdp_neighbors_detail.txt") + (" " * 1200)
        if command == "show lldp neighbors detail":
            return fixture_text("cisco_ios_lldp_neighbors_detail.txt")
        raise AssertionError(f"Unexpected command: {command}")


@pytest.mark.parametrize(
    ("mode", "expected_protocol_commands"),
    (
        (DiscoveryMode.CDP, {"show cdp neighbors detail"}),
        (DiscoveryMode.LLDP, {"show lldp neighbors detail"}),
        (
            DiscoveryMode.BOTH,
            {"show cdp neighbors detail", "show lldp neighbors detail"},
        ),
    ),
)
def test_selected_protocols_share_one_session_and_one_version_command(
    monkeypatch: pytest.MonkeyPatch,
    mode: DiscoveryMode,
    expected_protocol_commands: set[str],
) -> None:
    discoverer = make_discoverer(mode)
    connection = FakeConnection()
    monkeypatch.setattr(
        discoverer,
        "_netmiko_via_jump",
        lambda **_: connection,
    )
    monkeypatch.setattr("cdp_audit.discovery.time.sleep", lambda _: None)

    result = discoverer.run_device_commands(
        "",
        "192.0.2.10",
        "operator",
        "secret",
        None,
        None,
    )

    assert connection.commands.count("show version") == 1
    assert expected_protocol_commands.issubset(set(connection.commands))
    assert set(result.protocols) == set(mode.protocols)


class EmptyDetailFallbackConnection(FakeConnection):
    def send_command_timing(self, command: str, **_: object) -> str:
        self.commands.append(command)
        if command == "show cdp neighbors detail":
            return ""
        raise AssertionError(f"Unexpected command: {command}")

    def send_command(self, command: str, **_: object) -> str:
        self.commands.append(command)
        if command == "show cdp neighbors":
            return "Device ID Local Intrfce Holdtme Capability Platform Port ID"
        if command == "show cdp entry * protocol":
            return (
                "Device ID: edge-sw-02\n"
                "IP address: 192.0.2.20\n"
                "Interface: GigabitEthernet1/0/1,  "
                "Port ID (outgoing port): GigabitEthernet1/0/48\n"
            )
        if command == "show cdp entry * version":
            return (
                "Device ID: edge-sw-02\n"
                "Platform: cisco C9300-48P, Capabilities: Router Switch\n"
                "Version :\n"
                "Cisco IOS XE Software, Version 17.09.04a\n"
            )
        return super().send_command(command)


def test_empty_cdp_detail_uses_entry_star_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    discoverer = make_discoverer(DiscoveryMode.CDP)
    connection = EmptyDetailFallbackConnection()
    monkeypatch.setattr("cdp_audit.discovery.time.sleep", lambda _: None)

    result = discoverer._collect_cdp(connection, "192.0.2.10")

    assert result.status is CollectionStatus.OK
    assert result.neighbors[0].management_ip == "192.0.2.20"
    assert "show cdp entry * protocol" in connection.commands
    assert "show cdp entry * version" in connection.commands


def test_entry_star_fallback_keeps_dual_homed_neighbor_as_two_rows() -> None:
    """A neighbor connected on two local interfaces reports the same Device
    ID twice in "show cdp entry *" output; both adjacencies must survive the
    fallback parse instead of collapsing into a single, undercounted row."""
    discoverer = make_discoverer(DiscoveryMode.CDP)
    protocol_text = (
        "Device ID: edge-sw-02\n"
        "IP address: 192.0.2.20\n"
        "Interface: GigabitEthernet1/0/1,  "
        "Port ID (outgoing port): GigabitEthernet1/0/48\n"
        "-------------------------\n"
        "Device ID: edge-sw-02\n"
        "IP address: 192.0.2.20\n"
        "Interface: GigabitEthernet1/0/2,  "
        "Port ID (outgoing port): GigabitEthernet1/0/49\n"
    )
    version_text = (
        "Device ID: edge-sw-02\n"
        "Platform: cisco C9300-48P, Capabilities: Router Switch\n"
        "Version :\n"
        "Cisco IOS XE Software, Version 17.09.04a\n"
        "-------------------------\n"
        "Device ID: edge-sw-02\n"
        "Platform: cisco C9300-48P, Capabilities: Router Switch\n"
        "Version :\n"
        "Cisco IOS XE Software, Version 17.09.04a\n"
    )

    rows = discoverer._parse_cdp_entry_star_blocks(protocol_text, version_text)

    assert len(rows) == 2
    assert {row["LOCAL_PORT"] for row in rows} == {
        "GigabitEthernet1/0/1",
        "GigabitEthernet1/0/2",
    }
    assert all(row["DESTINATION_HOST"] == "edge-sw-02" for row in rows)


def test_workers_atomically_claim_duplicate_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    discoverer = make_discoverer(DiscoveryMode.CDP)
    target = "192.0.2.30"
    started = threading.Event()
    release = threading.Event()
    call_count = 0
    call_lock = threading.Lock()

    def collect_once(*_args, **_kwargs) -> DeviceCommandResult:
        nonlocal call_count
        with call_lock:
            call_count += 1
        started.set()
        assert release.wait(timeout=5)
        return DeviceCommandResult(
            "",
            {
                NeighborProtocol.CDP: ProtocolCollectionResult(
                    NeighborProtocol.CDP,
                    CollectionStatus.EMPTY,
                )
            },
        )

    monkeypatch.setattr(discoverer, "run_device_commands", collect_once)
    monkeypatch.setattr("cdp_audit.discovery.time.sleep", lambda _: None)
    discoverer.enqueued.add(target)
    discoverer.host_queue.put(target)
    discoverer.host_queue.put(target)
    discoverer.host_queue.put(None)
    discoverer.host_queue.put(None)

    workers = [
        threading.Thread(
            target=discoverer.discover_worker,
            args=("", "operator", "secret", None, None),
        )
        for _ in range(2)
    ]
    for worker in workers:
        worker.start()
    assert started.wait(timeout=5)
    deadline = time.monotonic() + 5
    while discoverer.host_queue.qsize() > 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    release.set()
    for worker in workers:
        worker.join(timeout=5)

    assert not any(worker.is_alive() for worker in workers)
    assert call_count == 1
