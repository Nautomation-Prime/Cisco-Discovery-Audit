"""Validated network address types shared by config, form input and discovery.

These are the trust boundaries of the tool: values typed by an operator into
config.yaml or the setup screen, and management addresses that devices
advertise over CDP/LLDP. Everything here is a leaf module so that the config
loader can use it without import cycles.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Annotated, Optional, Union

from pydantic import AfterValidator, BeforeValidator, IPvAnyAddress, TypeAdapter

_IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# RFC 1123 labels, plus underscore: Windows estates routinely resolve names
# like "core_sw01" through WINS/AD DNS, and rejecting them would be a
# regression for no safety gain.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)"
    r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
    r"(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*\.?$"
)


def _unusable_reason(address: _IPAddress) -> Optional[str]:
    """Why an address cannot be an SSH target, or None if it can be."""
    if address.is_unspecified:
        return "is the unspecified address"
    if address.is_loopback:
        return "is a loopback address"
    if address.is_multicast:
        return "is a multicast address"
    if address.is_link_local:
        # IPv6 link-local needs a zone index that is meaningless on the far
        # side of a jump host; IPv4 169.254/16 is APIPA, i.e. a device that
        # failed to get an address.
        return "is a link-local address"
    if address.is_reserved:
        return "is in reserved address space"
    return None


def _require_usable(address: _IPAddress) -> _IPAddress:
    reason = _unusable_reason(address)
    if reason:
        raise ValueError(f"{address} {reason} and cannot be used as a device address")
    return address


def _strip(value: object) -> object:
    return value.strip() if isinstance(value, str) else value


# An IPv4/IPv6 address that can actually be SSHed to.
DeviceIP = Annotated[IPvAnyAddress, BeforeValidator(_strip), AfterValidator(_require_usable)]

_DEVICE_IP: TypeAdapter[_IPAddress] = TypeAdapter(DeviceIP)


def parse_device_ip(value: object) -> Optional[str]:
    """Return the canonical text form of a usable device IP, else None.

    Canonical form matters for de-duplication: CDP and LLDP may report the
    same IPv6 address as "2001:DB8::1" and "2001:db8:0:0::1", which must not
    become two crawl targets.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return str(_DEVICE_IP.validate_python(value))
    except ValueError:
        return None


def _validate_host(value: object) -> str:
    """Accept a usable IP (returned canonical) or a syntactically valid hostname."""
    if not isinstance(value, str):
        raise ValueError("must be an IP address or hostname")
    text = value.strip()
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        return str(_require_usable(address))
    if "@" in text:
        raise ValueError(f"{text!r} looks like user@host; enter the host only")
    if text.count(":") == 1:
        raise ValueError(
            f"{text!r} looks like host:port; enter the host only "
            "(the SSH port is network.ssh_port in config.yaml)"
        )
    if not _HOSTNAME_RE.match(text):
        raise ValueError(f"{text!r} is not a valid IP address or hostname")
    return text


# An IP address or hostname, kept as text because hostnames resolve later.
HostOrIP = Annotated[str, BeforeValidator(_validate_host)]


def _validate_optional_host(value: object) -> str:
    if value is None or (isinstance(value, str) and not value.strip()):
        return ""
    return _validate_host(value)


# As HostOrIP, but blank/None means "not set" and becomes "".
OptionalHostOrIP = Annotated[str, BeforeValidator(_validate_optional_host)]
