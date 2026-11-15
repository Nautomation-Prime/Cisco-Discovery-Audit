from __future__ import annotations

import pytest

from cdp_audit.net_types import parse_device_ip


@pytest.mark.parametrize(
    "value,expected",
    [
        ("192.0.2.20", "192.0.2.20"),
        (" 10.1.1.1 ", "10.1.1.1"),
        ("2001:DB8:0:0::1", "2001:db8::1"),
    ],
)
def test_usable_addresses_are_canonicalised(value: str, expected: str) -> None:
    assert parse_device_ip(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "0.0.0.0",
        "127.0.0.1",
        "169.254.10.1",
        "fe80::1",
        "224.0.0.5",
        "255.255.255.255",
        "::",
        "core-sw01",
        "10.0.0.256",
        None,
    ],
)
def test_unusable_addresses_are_rejected(value: object) -> None:
    assert parse_device_ip(value) is None
