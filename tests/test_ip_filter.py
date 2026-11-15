from __future__ import annotations

import time

import pytest

from cdp_audit.discovery import IPFilter, _parse_ip_filter


def test_wide_prefix_parses_without_expanding_the_address_space() -> None:
    """A /8 used to materialise ~16.7M strings and freeze the UI thread."""
    started = time.perf_counter()
    ip_filter = _parse_ip_filter("10.0.0.0/8")
    elapsed = time.perf_counter() - started

    assert elapsed < 0.5
    assert "10.5.5.5" in ip_filter
    assert "11.0.0.1" not in ip_filter


def test_comma_separated_terms_are_unioned() -> None:
    ip_filter = _parse_ip_filter(
        "10.1.0.0/16, 192.168.1.5-192.168.1.9, 172.16.0.1"
    )

    assert "10.1.2.3" in ip_filter
    assert "192.168.1.7" in ip_filter
    assert "172.16.0.1" in ip_filter

    assert "10.2.2.3" not in ip_filter
    assert "192.168.1.10" not in ip_filter
    assert "172.16.0.2" not in ip_filter


def test_range_bounds_are_inclusive() -> None:
    ip_filter = _parse_ip_filter("10.0.0.5-10.0.0.7")

    assert "10.0.0.5" in ip_filter
    assert "10.0.0.7" in ip_filter
    assert "10.0.0.4" not in ip_filter
    assert "10.0.0.8" not in ip_filter


def test_empty_filter_is_falsy_so_discovery_is_unrestricted() -> None:
    assert not IPFilter()
    assert not IPFilter("   ")
    assert not _parse_ip_filter("")
    assert _parse_ip_filter("10.0.0.1")


def test_non_address_membership_tests_are_false_not_errors() -> None:
    ip_filter = _parse_ip_filter("10.0.0.0/24")

    assert "core-switch-01" not in ip_filter
    assert "" not in ip_filter
    assert None not in ip_filter


def test_ipv4_and_ipv6_terms_do_not_match_each_other() -> None:
    v6_filter = _parse_ip_filter("2001:db8::/32")

    assert "2001:db8::1" in v6_filter
    assert "10.0.0.1" not in v6_filter


@pytest.mark.parametrize(
    "spec",
    [
        "10.0.0.999",
        "10.0.0.5-10.0.0.1",
        "::1-10.0.0.1",
        "garbage",
        "10.0.0.0/33",
        "10.0.0.1, nonsense",
    ],
)
def test_malformed_filters_raise_value_error(spec: str) -> None:
    with pytest.raises(ValueError):
        _parse_ip_filter(spec)
