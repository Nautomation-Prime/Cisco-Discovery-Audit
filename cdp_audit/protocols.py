"""Protocol-neutral discovery records and merge helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Mapping, Set, Tuple


class DiscoveryMode(str, Enum):
    """Protocols selected for a discovery run."""

    CDP = "cdp"
    LLDP = "lldp"
    BOTH = "both"

    @classmethod
    def parse(cls, value: object) -> "DiscoveryMode":
        if isinstance(value, cls):
            return value
        normalized = str(value or "").strip().lower()
        try:
            return cls(normalized)
        except ValueError as exc:
            allowed = ", ".join(mode.value for mode in cls)
            raise ValueError(
                f"Invalid discovery.protocol {value!r}; expected one of: {allowed}"
            ) from exc

    @property
    def protocols(self) -> Tuple["NeighborProtocol", ...]:
        if self is DiscoveryMode.CDP:
            return (NeighborProtocol.CDP,)
        if self is DiscoveryMode.LLDP:
            return (NeighborProtocol.LLDP,)
        return (NeighborProtocol.CDP, NeighborProtocol.LLDP)

    @property
    def display_name(self) -> str:
        return self.value.upper()


class NeighborProtocol(str, Enum):
    """Protocol that reported an adjacency."""

    CDP = "CDP"
    LLDP = "LLDP"


class CollectionStatus(str, Enum):
    """Outcome of collecting one protocol from one device."""

    OK = "ok"
    EMPTY = "empty"
    DISABLED = "disabled"
    UNSUPPORTED = "unsupported"
    PARSE_FAILED = "parse failed"


@dataclass
class NeighborRecord:
    """Normalized directional neighbor observation."""

    local_port: str = ""
    remote_name: str = ""
    remote_port: str = ""
    management_ip: str = ""
    platform: str = ""
    software_version: str = ""
    system_description: str = ""
    capabilities: str = ""
    chassis_id: str = ""
    protocols: Set[NeighborProtocol] = field(default_factory=set)

    @property
    def protocol_label(self) -> str:
        ordered = [
            protocol.value
            for protocol in (NeighborProtocol.CDP, NeighborProtocol.LLDP)
            if protocol in self.protocols
        ]
        return "+".join(ordered)

    def to_audit_row(self, local_host: str, local_ip: str) -> Dict[str, str]:
        """Convert the normalized record to the report schema."""
        return {
            "LOCAL_HOST": local_host,
            "LOCAL_IP": local_ip,
            "LOCAL_PORT": self.local_port,
            "DESTINATION_HOST": _display_remote_name(
                self.remote_name, self.chassis_id
            ),
            "REMOTE_PORT": self.remote_port,
            "MANAGEMENT_IP": self.management_ip,
            "PLATFORM": self.platform,
            "SOFTWARE_VERSION": self.software_version or self.system_description,
            "CAPABILITIES": self.capabilities,
            "PROTOCOLS": self.protocol_label,
        }

    def is_supported_cisco_infrastructure(self) -> bool:
        """Return whether this peer is safe to enqueue with the Cisco driver."""
        capabilities = self.capabilities.lower()
        if NeighborProtocol.CDP in self.protocols:
            return "switch" in capabilities and "host" not in capabilities

        identity = " ".join(
            (
                self.platform,
                self.software_version,
                self.system_description,
                self.remote_name,
            )
        ).lower()
        is_supported_os = (
            "cisco ios software" in identity
            or "cisco ios xe" in identity
            or "cisco ios-xe" in identity
        )
        endpoint_markers = ("phone", "wireless", "access point", "camera")
        return is_supported_os and not any(marker in identity for marker in endpoint_markers)


@dataclass
class ProtocolCollectionResult:
    """Parsed records and status for one protocol command."""

    protocol: NeighborProtocol
    status: CollectionStatus
    neighbors: List[NeighborRecord] = field(default_factory=list)
    diagnostic: str = ""

    @property
    def status_label(self) -> str:
        count = f" ({len(self.neighbors)})" if self.status is CollectionStatus.OK else ""
        return f"{self.protocol.value}: {self.status.value}{count}"


@dataclass
class DeviceCommandResult:
    """All command output collected during one device session."""

    version_output: str
    protocols: Dict[NeighborProtocol, ProtocolCollectionResult]


def format_protocol_status(
    mode: DiscoveryMode,
    results: Mapping[NeighborProtocol, ProtocolCollectionResult],
) -> str:
    """Create the Inventory status string in configured protocol order."""
    labels = []
    for protocol in mode.protocols:
        result = results.get(protocol)
        labels.append(
            result.status_label
            if result is not None
            else f"{protocol.value}: not collected"
        )
    return "; ".join(labels)


def normalize_interface(value: str) -> str:
    """Normalize common Cisco interface abbreviations for comparisons."""
    compact = re.sub(r"\s+", "", value or "").lower()
    aliases = (
        ("hundredgige", "hundredgigabitethernet"),
        ("hu", "hundredgigabitethernet"),
        ("twentyfivegige", "twentyfivegigabitethernet"),
        ("twe", "twentyfivegigabitethernet"),
        ("tengigabitethernet", "tengigabitethernet"),
        ("tengige", "tengigabitethernet"),
        ("te", "tengigabitethernet"),
        ("gigabitethernet", "gigabitethernet"),
        ("gig", "gigabitethernet"),
        ("gi", "gigabitethernet"),
        ("fastethernet", "fastethernet"),
        ("fa", "fastethernet"),
        ("ethernet", "ethernet"),
        ("eth", "ethernet"),
        ("port-channel", "port-channel"),
        ("po", "port-channel"),
    )
    for abbreviation, expanded in aliases:
        if re.match(rf"^{re.escape(abbreviation)}(?=[0-9/.-])", compact):
            return expanded + compact[len(abbreviation) :]
    return compact


def normalize_hostname(value: str) -> str:
    """Return a case-insensitive short hostname for comparisons."""
    return (value or "").strip().rstrip(".").split(".", 1)[0].lower()


def merge_neighbor_records(records: Iterable[NeighborRecord]) -> List[NeighborRecord]:
    """Merge high-confidence CDP/LLDP observations of the same adjacency."""
    merged: List[NeighborRecord] = []
    for record in records:
        match = next(
            (existing for existing in merged if _same_adjacency(existing, record)),
            None,
        )
        if match is None:
            merged.append(record)
            continue
        _merge_into(match, record)
    return merged


def _same_adjacency(left: NeighborRecord, right: NeighborRecord) -> bool:
    left_local = normalize_interface(left.local_port)
    right_local = normalize_interface(right.local_port)
    if not left_local or left_local != right_local:
        return False

    left_remote = normalize_interface(left.remote_port)
    right_remote = normalize_interface(right.remote_port)
    if left_remote and right_remote and left_remote != right_remote:
        return False

    left_ip = left.management_ip.strip().lower()
    right_ip = right.management_ip.strip().lower()
    if left_ip and right_ip and left_ip != right_ip:
        return False

    left_chassis = _normalize_chassis(left.chassis_id)
    right_chassis = _normalize_chassis(right.chassis_id)
    if left_chassis and right_chassis and left_chassis != right_chassis:
        return False

    shared_identity = bool(left_ip and right_ip and left_ip == right_ip)
    left_name = _hostname_identity(left.remote_name, left.chassis_id)
    right_name = _hostname_identity(right.remote_name, right.chassis_id)
    shared_identity = shared_identity or bool(
        left_name and right_name and left_name == right_name
    )

    shared_identity = shared_identity or bool(
        left_chassis and right_chassis and left_chassis == right_chassis
    )
    return shared_identity


def _merge_into(target: NeighborRecord, incoming: NeighborRecord) -> None:
    target_has_cdp = NeighborProtocol.CDP in target.protocols
    incoming_has_cdp = NeighborProtocol.CDP in incoming.protocols

    if incoming_has_cdp and not target_has_cdp:
        preferred, fallback = incoming, target
    else:
        preferred, fallback = target, incoming

    for field_name in (
        "local_port",
        "remote_name",
        "remote_port",
        "management_ip",
        "platform",
        "software_version",
        "system_description",
        "capabilities",
        "chassis_id",
    ):
        setattr(
            target,
            field_name,
            getattr(preferred, field_name) or getattr(fallback, field_name),
        )
    target.protocols.update(incoming.protocols)


def _display_remote_name(value: str, chassis_id: str) -> str:
    if not value:
        return ""
    if _is_chassis_identity(value, chassis_id):
        return value.strip().upper()
    return normalize_hostname(value).upper()


def _hostname_identity(value: str, chassis_id: str) -> str:
    if _is_chassis_identity(value, chassis_id):
        return ""
    return normalize_hostname(value)


def _is_chassis_identity(value: str, chassis_id: str) -> bool:
    normalized_value = _normalize_chassis(value)
    normalized_chassis = _normalize_chassis(chassis_id)
    if normalized_value and normalized_chassis and normalized_value == normalized_chassis:
        return True
    return bool(
        re.fullmatch(
            r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|"
            r"(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}",
            (value or "").strip().lower(),
        )
    )


def _normalize_chassis(value: str) -> str:
    return re.sub(r"[^0-9a-z]", "", (value or "").lower())
