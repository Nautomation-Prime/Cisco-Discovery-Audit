"""Cisco CDP and LLDP network discovery logic."""

from __future__ import annotations

import ipaddress
import logging
import os
import queue
import re
import socket
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple, Union

import paramiko
import textfsm
from netmiko import ConnectHandler

try:
    from netmiko.exceptions import (
        NetmikoAuthenticationException,
        NetmikoTimeoutException,
    )
except ImportError:
    from netmiko.ssh_exception import (  # type: ignore
        NetmikoAuthenticationException,
        NetmikoTimeoutException,
    )

from paramiko.ssh_exception import SSHException

from .app_config import config
from .net_types import parse_device_ip
from .protocols import (
    CollectionStatus,
    DeviceCommandResult,
    DiscoveryMode,
    NeighborProtocol,
    NeighborRecord,
    ProtocolCollectionResult,
    format_protocol_status,
    merge_neighbor_records,
)

logger = logging.getLogger(__name__)


def _raw_output_logging_enabled() -> bool:
    """Whether raw device output may be written to the log file.

    Raw CDP/LLDP detail is a full topology dump — neighbour names, management
    IPs, platforms and software versions — so it is kept out of logs/debug.log
    unless an operator opts in with CDP_DEBUG_RAW.
    """
    return os.getenv("CDP_DEBUG_RAW", "").strip().lower() in ("1", "true", "yes", "on")


def _log_raw_output(protocol: NeighborProtocol, host: str, output: str) -> None:
    """Log raw neighbour-command output, or just its size when opted out."""
    name = protocol.name
    if _raw_output_logging_enabled():
        logger.debug(
            "=== RAW %s OUTPUT FROM %s ===\n%s\n=== END RAW %s ===",
            name,
            host,
            output,
            name,
        )
    else:
        logger.debug(
            "[%s] %s output received: %d characters "
            "(set CDP_DEBUG_RAW=1 to log the full text)",
            host,
            name,
            len(output),
        )


_IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
_IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class IPFilter:
    """Discovery scope restriction, held as parsed networks and ranges.

    Membership is tested against the parsed specification rather than an
    expanded set of addresses, so a wide prefix such as 10.0.0.0/8 costs
    nothing to build or to query.

    Accepts a comma-separated list whose terms may each be a CIDR prefix
    ("10.1.0.0/16"), an inclusive range ("10.1.0.1-10.1.0.50"), or a single
    address ("10.1.0.1").
    """

    def __init__(self, spec: str = "") -> None:
        self.spec = spec.strip()
        self._networks: List[_IPNetwork] = []
        # Ranges are held as (ip version, start, end) with the bounds as plain
        # integers, so comparisons stay within one address family.
        self._ranges: List[Tuple[int, int, int]] = []
        for term in (part.strip() for part in self.spec.split(",")):
            if term:
                self._add_term(term)

    def _add_term(self, term: str) -> None:
        """Parse one filter term, raising ValueError if it is malformed."""
        if "/" in term:
            self._networks.append(ipaddress.ip_network(term, strict=False))
            return
        if "-" in term:
            start_text, end_text = term.split("-", 1)
            start = ipaddress.ip_address(start_text.strip())
            end = ipaddress.ip_address(end_text.strip())
            if start.version != end.version:
                raise ValueError(f"IP range '{term}' mixes IPv4 and IPv6 addresses")
            if int(start) > int(end):
                raise ValueError(f"IP range start {start} is greater than end {end}")
            self._ranges.append((start.version, int(start), int(end)))
            return
        address = ipaddress.ip_address(term)
        self._ranges.append((address.version, int(address), int(address)))

    def __bool__(self) -> bool:
        return bool(self._networks or self._ranges)

    def __contains__(self, candidate: object) -> bool:
        if not isinstance(candidate, str):
            return False
        try:
            address = ipaddress.ip_address(candidate.strip())
        except ValueError:
            return False
        if any(address in network for network in self._networks):
            return True
        value = int(address)
        return any(
            version == address.version and start <= value <= end
            for version, start, end in self._ranges
        )

    def __repr__(self) -> str:
        return f"IPFilter({self.spec!r})"


def _parse_ip_filter(ip_filter: str) -> IPFilter:
    """Parse a comma-separated CIDR/range/address filter into an IPFilter.

    Raises:
        ValueError: If any term in the specification is malformed.
    """
    return IPFilter(ip_filter)


class NetworkDiscoverer:
    """Coordinate threaded Cisco discovery and accumulate report data."""

    def __init__(
        self,
        timeout: int,
        limit: int,
        cdp_template: Path,
        ver_template: Path,
        ip_filter: Optional[Union[IPFilter, Set[str]]] = None,
        *,
        discovery_mode: DiscoveryMode = DiscoveryMode.CDP,
        lldp_template: Optional[Path] = None,
    ) -> None:
        self.timeout = timeout
        self.limit = limit
        self.discovery_mode = discovery_mode
        self.cdp_template = cdp_template
        self.lldp_template = lldp_template
        self.ver_template = ver_template
        # A plain set of address strings is still accepted for compatibility;
        # both it and IPFilter support the `in` and truthiness tests used below.
        self.ip_filter: Union[IPFilter, Set[str]] = (
            ip_filter if ip_filter is not None else IPFilter()
        )

        if (
            discovery_mode in (DiscoveryMode.LLDP, DiscoveryMode.BOTH)
            and lldp_template is None
        ):
            raise ValueError("An LLDP TextFSM template is required for this mode")

        self.neighbour_details: List[Dict[str, str]] = []
        # Compatibility alias for integrations that used the pre-1.0 attribute.
        self.cdp_neighbour_details = self.neighbour_details
        self.device_inventory: Dict[str, Dict[str, str]] = {}
        self.hostnames: Set[str] = set()
        self.visited: Set[str] = set()
        self.enqueued: Set[str] = set()
        self.in_progress: Set[str] = set()
        self.authentication_errors: Set[str] = set()
        self.connection_errors: Dict[str, str] = {}
        self.dns_ip: Dict[str, str] = {}

        self.visited_lock = threading.Lock()
        self.data_lock = threading.Lock()
        self.host_queue: "queue.Queue[Optional[str]]" = queue.Queue()

        # One SSH session to the jump host is shared by every worker; each
        # device gets its own direct-tcpip channel over it.
        self._jump_lock = threading.Lock()
        self._jump_client: Optional[paramiko.SSHClient] = None

        # Set to ask workers to stop early; see request_stop().
        self.stop_event = threading.Event()

    def _parse_textfsm(self, template_path: Path, text: str) -> List[Dict[str, str]]:
        # The templates we ship are ASCII; utf-8 reads them identically to the
        # cp1252 this used to assume, without depending on a Windows codepage.
        with open(template_path, encoding="utf-8") as template_file:
            table = textfsm.TextFSM(template_file)
            rows = table.ParseText(text or "")
            return [dict(zip(table.header, row, strict=False)) for row in rows]

    def _safe_parse_textfsm(
        self, template_path: Path, text: str
    ) -> List[Dict[str, str]]:
        """Parse TextFSM data for non-protocol inventory commands."""
        try:
            return self._parse_textfsm(template_path, text)
        except (OSError, textfsm.TextFSMError) as exc:
            logger.warning("TextFSM parse failed for %s: %s", template_path, exc)
        except Exception:
            logger.exception("Unexpected error while parsing template %s", template_path)
        return []

    def _protocol_result_from_output(
        self,
        protocol: NeighborProtocol,
        output: str,
        preparsed_rows: Optional[List[Dict[str, str]]] = None,
    ) -> ProtocolCollectionResult:
        classified = self._classify_protocol_output(protocol, output)
        if classified is not None and not (
            preparsed_rows is not None
            and classified.status is CollectionStatus.PARSE_FAILED
        ):
            return classified

        template_path = (
            self.cdp_template
            if protocol is NeighborProtocol.CDP
            else self.lldp_template
        )
        if template_path is None:
            return ProtocolCollectionResult(
                protocol,
                CollectionStatus.PARSE_FAILED,
                diagnostic="TextFSM template is not configured",
            )

        try:
            rows = (
                preparsed_rows
                if preparsed_rows is not None
                else self._parse_textfsm(template_path, output)
            )
        except (OSError, textfsm.TextFSMError) as exc:
            return ProtocolCollectionResult(
                protocol,
                CollectionStatus.PARSE_FAILED,
                diagnostic=f"TextFSM parse failed: {exc}",
            )
        except Exception as exc:
            logger.exception("Unexpected %s parser failure", protocol.value)
            return ProtocolCollectionResult(
                protocol,
                CollectionStatus.PARSE_FAILED,
                diagnostic=f"Unexpected parser failure: {type(exc).__name__}",
            )

        if protocol is NeighborProtocol.CDP:
            neighbors = self._normalize_cdp_rows(rows)
        else:
            neighbors = self._normalize_lldp_rows(rows)

        if neighbors:
            return ProtocolCollectionResult(
                protocol,
                CollectionStatus.OK,
                neighbors=neighbors,
            )

        marker = "Device ID:" if protocol is NeighborProtocol.CDP else "Local Intf:"
        if marker.lower() in (output or "").lower():
            return ProtocolCollectionResult(
                protocol,
                CollectionStatus.PARSE_FAILED,
                diagnostic="Neighbor records were present but none could be parsed",
            )
        return ProtocolCollectionResult(
            protocol,
            CollectionStatus.PARSE_FAILED,
            diagnostic="Command output was not a recognized zero-neighbor response",
        )

    @staticmethod
    def _classify_protocol_output(
        protocol: NeighborProtocol, output: str
    ) -> Optional[ProtocolCollectionResult]:
        normalized = (output or "").lower()
        invalid_markers = (
            "% invalid input",
            "invalid input detected",
            "unknown command",
            "unrecognized command",
        )
        if any(marker in normalized for marker in invalid_markers):
            return ProtocolCollectionResult(
                protocol,
                CollectionStatus.UNSUPPORTED,
                diagnostic="Device rejected the command",
            )

        authorization_markers = (
            "% authorization failed",
            "command authorization failed",
            "% permission denied",
            "% access denied",
        )
        if any(marker in normalized for marker in authorization_markers):
            return ProtocolCollectionResult(
                protocol,
                CollectionStatus.PARSE_FAILED,
                diagnostic="Device denied command authorization",
            )

        disabled_markers = {
            NeighborProtocol.CDP: (
                "cdp is not enabled",
                "cdp is disabled",
            ),
            NeighborProtocol.LLDP: (
                "lldp is not enabled",
                "lldp is disabled",
            ),
        }
        if any(marker in normalized for marker in disabled_markers[protocol]):
            return ProtocolCollectionResult(
                protocol,
                CollectionStatus.DISABLED,
                diagnostic=f"{protocol.value} is disabled on the device",
            )

        empty_markers = {
            NeighborProtocol.CDP: (
                "total cdp entries displayed : 0",
                "total cdp entries displayed: 0",
                "no cdp entries",
            ),
            NeighborProtocol.LLDP: (
                "total entries displayed: 0",
                "total entries displayed : 0",
                "no lldp neighbors",
            ),
        }
        if any(marker in normalized for marker in empty_markers[protocol]):
            return ProtocolCollectionResult(protocol, CollectionStatus.EMPTY)

        if not normalized.strip():
            return ProtocolCollectionResult(
                protocol,
                CollectionStatus.PARSE_FAILED,
                diagnostic="Command returned no output",
            )
        return None

    @staticmethod
    def _normalize_cdp_rows(rows: List[Dict[str, str]]) -> List[NeighborRecord]:
        neighbors: List[NeighborRecord] = []
        for row in rows:
            remote_name = (
                row.get("DESTINATION_HOST")
                or row.get("NEIGHBOR_NAME")
                or row.get("DEVICE_ID")
                or ""
            ).strip()
            local_port = (
                row.get("LOCAL_PORT") or row.get("LOCAL_INTERFACE") or ""
            ).strip()
            management_ip = (
                row.get("MANAGEMENT_IP")
                or row.get("MGMT_ADDRESS")
                or ""
            ).strip()
            remote_port = (
                row.get("REMOTE_PORT")
                or row.get("NEIGHBOR_INTERFACE")
                or ""
            ).strip()
            if not remote_name or not (local_port or remote_port or management_ip):
                continue
            neighbors.append(
                NeighborRecord(
                    local_port=local_port,
                    remote_name=remote_name,
                    remote_port=remote_port,
                    management_ip=management_ip,
                    platform=(row.get("PLATFORM") or "").strip(),
                    software_version=(
                        row.get("SOFTWARE_VERSION")
                        or row.get("NEIGHBOR_DESCRIPTION")
                        or ""
                    ).strip(),
                    capabilities=(row.get("CAPABILITIES") or "").strip(),
                    protocols={NeighborProtocol.CDP},
                )
            )
        return neighbors

    @staticmethod
    def _normalize_lldp_rows(rows: List[Dict[str, str]]) -> List[NeighborRecord]:
        neighbors: List[NeighborRecord] = []
        for row in rows:
            chassis_id = (row.get("CHASSIS_ID") or "").strip()
            remote_name = (
                row.get("NEIGHBOR_NAME")
                or row.get("SYSTEM_NAME")
                or chassis_id
            ).strip()
            local_port = (
                row.get("LOCAL_INTERFACE") or row.get("LOCAL_PORT") or ""
            ).strip()
            management_ip = (
                row.get("MGMT_ADDRESS")
                or row.get("MANAGEMENT_IP")
                or ""
            ).strip()
            remote_port = (
                row.get("NEIGHBOR_INTERFACE")
                or row.get("NEIGHBOR_PORT_ID")
                or row.get("REMOTE_PORT")
                or ""
            ).strip()
            if not remote_name or not (local_port or remote_port or management_ip):
                continue

            platform_parts = [
                (row.get("MANUFACTURER") or "").strip(),
                (row.get("PLATFORM") or "").strip(),
            ]
            platform = " ".join(
                part
                for index, part in enumerate(platform_parts)
                if part and part not in platform_parts[:index]
            )
            software = (row.get("SW_REVISION") or "").strip()
            system_description = (
                row.get("NEIGHBOR_DESCRIPTION")
                or row.get("SYSTEM_DESCRIPTION")
                or ""
            ).strip()
            neighbors.append(
                NeighborRecord(
                    local_port=local_port,
                    remote_name=remote_name,
                    remote_port=remote_port,
                    management_ip=management_ip,
                    platform=platform,
                    software_version=software,
                    system_description=system_description,
                    capabilities=(row.get("CAPABILITIES") or "").strip(),
                    chassis_id=chassis_id,
                    protocols={NeighborProtocol.LLDP},
                )
            )
        return neighbors

    def parse_outputs_and_enqueue_neighbors(
        self,
        host: str,
        command_result: Union[DeviceCommandResult, str, List[Dict[str, str]]],
        version_output: Optional[str] = None,
    ) -> None:
        """Add inventory and normalized neighbors, then enqueue eligible peers."""
        if not isinstance(command_result, DeviceCommandResult):
            legacy_output = command_result
            protocol_result = self._protocol_result_from_output(
                NeighborProtocol.CDP,
                legacy_output if isinstance(legacy_output, str) else "",
                legacy_output if isinstance(legacy_output, list) else None,
            )
            command_result = DeviceCommandResult(
                version_output=version_output or "",
                protocols={NeighborProtocol.CDP: protocol_result},
            )

        ver_list = self._safe_parse_textfsm(
            self.ver_template, command_result.version_output
        )
        if ver_list:
            version_row = ver_list[0]
            hostname = version_row.get("HOSTNAME", host)
            # TextFSM List-valued fields come back as lists, scalars as strings.
            serials: object = version_row.get("SERIAL", [])
            serial = (
                ", ".join(serials)
                if isinstance(serials, list)
                else str(serials or "")
            )
            ios_version = str(version_row.get("VERSION", "") or "")
            hardware: object = version_row.get("HARDWARE", [])
            platform = (
                hardware[0]
                if isinstance(hardware, list) and hardware
                else str(hardware or "")
            )
            uptime = str(version_row.get("UPTIME", "") or "")
        else:
            hostname, serial, ios_version, platform, uptime = (
                host,
                "",
                "",
                "",
                "",
            )

        protocol_status = format_protocol_status(
            self.discovery_mode, command_result.protocols
        )
        with self.data_lock:
            if hostname:
                self.hostnames.add(hostname)
            self.device_inventory[host] = {
                "HOSTNAME": hostname,
                "IP": host,
                "SERIAL": serial,
                "PLATFORM": platform,
                "IOS_VERSION": ios_version,
                "UPTIME": uptime,
                "PROTOCOL_STATUS": protocol_status,
            }
        with self.visited_lock:
            self.visited.add(host)

        observations: List[NeighborRecord] = []
        for protocol in self.discovery_mode.protocols:
            result = command_result.protocols.get(protocol)
            if result is None:
                logger.warning("[%s] %s was not collected", host, protocol.value)
                continue
            observations.extend(result.neighbors)
            if result.status in (
                CollectionStatus.DISABLED,
                CollectionStatus.UNSUPPORTED,
                CollectionStatus.PARSE_FAILED,
            ):
                detail = f": {result.diagnostic}" if result.diagnostic else ""
                logger.warning(
                    "[%s] %s collection %s%s",
                    host,
                    protocol.value,
                    result.status.value,
                    detail,
                )
            else:
                logger.info(
                    "[%s] %s collection %s (%d neighbor%s)",
                    host,
                    protocol.value,
                    result.status.value,
                    len(result.neighbors),
                    "" if len(result.neighbors) == 1 else "s",
                )

        for neighbor in merge_neighbor_records(observations):
            with self.data_lock:
                self.neighbour_details.append(
                    neighbor.to_audit_row(str(hostname), host)
                )
                if neighbor.remote_name:
                    self.hostnames.add(neighbor.remote_name)
            self._enqueue_neighbor(host, neighbor)

    def _enqueue_neighbor(self, source_host: str, neighbor: NeighborRecord) -> None:
        raw_ip = neighbor.management_ip.strip()
        if not raw_ip:
            return
        # Devices advertise whatever is configured, including 0.0.0.0,
        # loopbacks and IPv6 link-local. Those are still reported but never
        # crawled, and valid addresses are canonicalised so one device is
        # not queued twice under two spellings.
        management_ip = parse_device_ip(raw_ip)
        if management_ip is None:
            logger.debug(
                "Reporting but not crawling neighbor %s: management address "
                "%r is not a usable SSH target",
                neighbor.remote_name,
                raw_ip,
            )
            return
        if self.ip_filter and management_ip not in self.ip_filter:
            logger.debug(
                "Skipping neighbor %s (%s) - not in IP filter",
                neighbor.remote_name,
                management_ip,
            )
            return
        if not neighbor.is_supported_cisco_infrastructure():
            logger.debug(
                "Reporting but not crawling neighbor %s (%s): not positively "
                "identified as supported Cisco IOS/IOS-XE infrastructure",
                neighbor.remote_name,
                management_ip,
            )
            return

        with self.visited_lock:
            if management_ip in self.visited or management_ip in self.enqueued:
                return
            if management_ip in self.in_progress:
                return
            self.enqueued.add(management_ip)
        logger.debug(
            "Enqueuing neighbor %s (%s) discovered from %s",
            neighbor.remote_name,
            management_ip,
            source_host,
        )
        self.host_queue.put(management_ip)

    def _paramiko_jump_client(
        self, jump_host: str, username: str, password: str
    ) -> paramiko.SSHClient:
        """Establish an SSH client to the jump host using password auth."""
        client = paramiko.SSHClient()
        if config.STRICT_HOST_KEYS:
            # The jump host is the hop that usually crosses a trust boundary,
            # so an unrecognised key here is refused rather than warned about.
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.client.RejectPolicy())
        else:
            # noqa justified: this branch is the documented opt-out. Strict
            # verification is available via network.strict_host_keys above.
            client.set_missing_host_key_policy(
                paramiko.client.WarningPolicy()  # noqa: S507
            )
        client.connect(
            hostname=jump_host,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            banner_timeout=self.timeout,
            auth_timeout=self.timeout,
            timeout=self.timeout,
            channel_timeout=self.timeout,
        )
        try:
            transport = client.get_transport()
            if transport and transport.sock:
                transport.sock.settimeout(self.timeout)
                logger.debug(
                    "Set socket timeout to %d seconds for jump host %s",
                    self.timeout,
                    jump_host,
                )
        except Exception as exc:
            logger.debug("Could not set socket timeout on jump client: %s", exc)
        return client

    def _get_jump_transport(
        self, jump_host: str, username: str, password: str
    ) -> paramiko.Transport:
        """Return a live shared transport to the jump host, connecting if needed.

        All workers multiplex direct-tcpip channels over one transport. Opening
        a separate SSH session per device (and per retry) instead would mean
        hundreds of logins against the bastion, which its authentication rate
        limits and MaxStartups setting typically reject. The lock also collapses
        a simultaneous reconnect by several workers into a single login.
        """
        with self._jump_lock:
            client = self._jump_client
            transport = client.get_transport() if client is not None else None
            if transport is not None and transport.is_active():
                return transport

            if client is not None:
                logger.info("Jump host session to %s dropped; reconnecting", jump_host)
                self._close_jump_client_locked()

            client = self._paramiko_jump_client(jump_host, username, password)
            transport = client.get_transport()
            if transport is None:
                try:
                    client.close()
                except Exception:
                    logger.debug("Failed to close jump client.", exc_info=True)
                raise SSHException("Jump host did not provide an SSH transport")
            self._jump_client = client
            logger.info("Jump host session established to %s", jump_host)
            return transport

    def _close_jump_client_locked(self) -> None:
        """Close the shared jump client. Caller must hold _jump_lock."""
        client = self._jump_client
        self._jump_client = None
        if client is None:
            return
        try:
            client.close()
        except Exception:
            logger.debug("Failed to close jump client.", exc_info=True)

    def close_jump_host(self) -> None:
        """Tear down the shared jump-host session at the end of a run."""
        with self._jump_lock:
            self._close_jump_client_locked()

    def _open_jump_channel(
        self, jump_host: str, target_ip: str, username: str, password: str
    ):
        """Open a direct-tcpip channel to target_ip through the shared transport.

        A transport can go down between the liveness check and open_channel, so
        one reconnect is attempted before giving up.
        """
        destination = (target_ip, config.SSH_PORT)
        source = ("127.0.0.1", 0)
        for attempt in (1, 2):
            transport = self._get_jump_transport(jump_host, username, password)
            try:
                return transport.open_channel(
                    "direct-tcpip",
                    destination,
                    source,
                    timeout=self.timeout,
                )
            except SSHException:
                if attempt == 2 or transport.is_active():
                    # Still active means the far side refused this channel --
                    # the device is unreachable, not the bastion.
                    raise
                logger.debug(
                    "[%s] Jump transport died while opening a channel; retrying",
                    target_ip,
                )
        raise SSHException("Could not open a jump channel")  # pragma: no cover

    def _netmiko_via_jump(
        self,
        jump_host: str,
        target_ip: str,
        primary: bool,
        primary_user: str,
        primary_pass: str,
        answer_user: Optional[str],
        answer_pass: Optional[str],
    ):
        """Create a Netmiko connection, optionally through a jump host."""
        # The jump host always uses the primary credential; only the device
        # credential switches to the fallback pair.
        jump_user, jump_pass = primary_user, primary_pass
        device_user: Optional[str]
        device_pass: Optional[str]
        if primary:
            device_user, device_pass = primary_user, primary_pass
        else:
            device_user, device_pass = answer_user, answer_pass

        if not jump_host:
            return ConnectHandler(
                device_type=config.DEVICE_TYPE,
                host=target_ip,
                username=device_user,
                password=device_pass,
                fast_cli=False,
                timeout=self.timeout,
                conn_timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
            )

        channel = self._open_jump_channel(
            jump_host, target_ip, str(jump_user), str(jump_pass)
        )
        logger.debug("[%s] Jump channel opened via %s", target_ip, jump_host)
        try:
            return ConnectHandler(
                device_type=config.DEVICE_TYPE,
                host=target_ip,
                username=device_user,
                password=device_pass,
                sock=channel,
                fast_cli=False,
                timeout=self.timeout,
                conn_timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
            )
        except Exception:
            # Only this device's channel is discarded; the shared transport
            # stays up for the other workers.
            try:
                channel.close()
            except Exception:
                logger.debug("Failed to close jump channel.", exc_info=True)
            raise

    def _parse_cdp_entry_star_blocks(
        self, protocol_text: str, version_text: str
    ) -> List[Dict[str, str]]:
        """Parse CDP entry-star fallback output into normalized row dictionaries.

        "show cdp entry *" repeats a "Device ID:" block once per adjacency, so
        a neighbor connected on more than one local interface (a dual-homed
        switch, a stack, etc.) appears as several blocks that all share the
        same device ID. Blocks are grouped by device ID and paired positionally
        within each group, rather than keyed by device ID alone, so those
        repeated blocks are kept as separate rows instead of collapsing to one
        (which previously undercounted the neighbor total and dropped rows).
        """

        def split_blocks(raw: str) -> List[Tuple[str, str]]:
            blocks: List[Tuple[str, str]] = []
            parts = re.split(
                r"\n(?=Device ID:\s*)",
                raw or "",
                flags=re.IGNORECASE,
            )
            for part in parts:
                if not part.strip():
                    continue
                match = re.search(r"Device ID:\s*(.+)", part, flags=re.IGNORECASE)
                if match:
                    blocks.append((match.group(1).strip(), part))
            return blocks

        def group_by_id(blocks: List[Tuple[str, str]]) -> Dict[str, List[str]]:
            grouped: Dict[str, List[str]] = {}
            for device_id, block in blocks:
                grouped.setdefault(device_id, []).append(block)
            return grouped

        protocol_blocks = split_blocks(protocol_text)
        version_blocks = split_blocks(version_text)
        protocol_by_id = group_by_id(protocol_blocks)
        version_by_id = group_by_id(version_blocks)

        # Preserve first-seen order across both outputs rather than sorting,
        # so row order still matches the order the device reported entries.
        device_ids: List[str] = []
        for device_id, _ in protocol_blocks + version_blocks:
            if device_id not in device_ids:
                device_ids.append(device_id)

        def grab(pattern: str, text: str) -> str:
            match = re.search(pattern, text or "", flags=re.IGNORECASE | re.DOTALL)
            return match.group(1).strip() if match else ""

        rows: List[Dict[str, str]] = []
        for device_id in device_ids:
            protocol_group = protocol_by_id.get(device_id, [""])
            version_group = version_by_id.get(device_id, [""])
            entry_count = max(len(protocol_group), len(version_group))
            for index in range(entry_count):
                protocol_block = protocol_group[min(index, len(protocol_group) - 1)]
                version_block = version_group[min(index, len(version_group) - 1)]

                management_ip = grab(
                    r"IP address:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)",
                    protocol_block,
                ) or grab(
                    r"IP address:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)",
                    version_block,
                )
                rows.append(
                    {
                        "DESTINATION_HOST": device_id,
                        "MANAGEMENT_IP": management_ip,
                        "PLATFORM": grab(r"Platform:\s*([^,]+)", version_block),
                        "CAPABILITIES": grab(
                            r"Capabilities:\s*([^\n]+)", version_block
                        ),
                        "LOCAL_PORT": grab(
                            r"Interface:\s*([^\s,]+)", protocol_block
                        ),
                        "REMOTE_PORT": grab(
                            r"Port ID\s*\(outgoing port\):\s*([^\s,]+)",
                            protocol_block,
                        ),
                        "SOFTWARE_VERSION": grab(
                            r"Version\s*:\s*\n?([^\n]+)", version_block
                        ),
                    }
                )
        return rows

    def _collect_cdp(self, connection, host: str) -> ProtocolCollectionResult:
        detail = connection.send_command_timing(
            "show cdp neighbors detail",
            delay_factor=4,
            read_timeout=max(self.timeout, 60),
            strip_prompt=False,
            strip_command=False,
        )
        time.sleep(2)
        detail += connection.read_channel()
        _log_raw_output(NeighborProtocol.CDP, host, detail)

        classified = self._classify_protocol_output(NeighborProtocol.CDP, detail)
        if classified is not None and (
            classified.status is not CollectionStatus.PARSE_FAILED
            or detail.strip()
        ):
            return classified

        device_id_count = detail.lower().count("device id:")
        looks_truncated = device_id_count == 0 or len(detail) < 1000
        try:
            summary = connection.send_command(
                "show cdp neighbors",
                expect_string=r"#",
                read_timeout=max(self.timeout, 20),
                delay_factor=2,
                strip_prompt=False,
                strip_command=False,
            )
            summary_count = sum(
                1
                for line in summary.splitlines()
                if line.strip()
                and not line.lstrip().startswith(
                    ("Device ID", "Capability", "Total", "-")
                )
            )
            if 0 < device_id_count < summary_count:
                looks_truncated = True
        except Exception:
            logger.debug("[%s] Could not compare CDP summary output", host)

        if not looks_truncated:
            return self._protocol_result_from_output(NeighborProtocol.CDP, detail)

        logger.debug(
            "[%s] CDP detail may be truncated (%d Device ID records); "
            "trying entry-star fallback",
            host,
            device_id_count,
        )
        try:
            protocol_output = connection.send_command(
                "show cdp entry * protocol",
                expect_string=r"#",
                read_timeout=max(self.timeout, 45),
                delay_factor=4,
                strip_prompt=False,
                strip_command=False,
            )
            version_output = connection.send_command(
                "show cdp entry * version",
                expect_string=r"#",
                read_timeout=max(self.timeout, 45),
                delay_factor=4,
                strip_prompt=False,
                strip_command=False,
            )
            rows = self._parse_cdp_entry_star_blocks(
                protocol_output, version_output
            )
            if rows:
                return self._protocol_result_from_output(
                    NeighborProtocol.CDP,
                    detail,
                    preparsed_rows=rows,
                )
        except Exception:
            logger.debug("[%s] CDP entry-star fallback failed", host, exc_info=True)

        return self._protocol_result_from_output(NeighborProtocol.CDP, detail)

    def _collect_lldp(self, connection, host: str) -> ProtocolCollectionResult:
        detail = connection.send_command_timing(
            "show lldp neighbors detail",
            delay_factor=4,
            read_timeout=max(self.timeout, 60),
            strip_prompt=False,
            strip_command=False,
        )
        time.sleep(1)
        detail += connection.read_channel()
        _log_raw_output(NeighborProtocol.LLDP, host, detail)
        return self._protocol_result_from_output(NeighborProtocol.LLDP, detail)

    def run_device_commands(
        self,
        jump_host: str,
        host: str,
        primary_user: str,
        primary_pass: str,
        answer_user: Optional[str],
        answer_pass: Optional[str],
    ) -> DeviceCommandResult:
        """Collect version and selected protocols over one Netmiko session."""

        def prepare(connection) -> None:
            try:
                connection.enable()
            except Exception as exc:
                # Commands below may return partial output without privileged
                # mode, so make this visible rather than burying it at DEBUG.
                logger.warning(
                    "[%s] Could not enter enable mode (%s); continuing "
                    "unprivileged - neighbour output may be incomplete",
                    host,
                    exc,
                )
            try:
                connection.global_cmd_verify = False
            except Exception:
                logger.debug("[%s] Could not disable command verification", host)
            for command in (
                "terminal length 0",
                "terminal width 512",
                "no logging console",
            ):
                try:
                    connection.send_command(
                        command,
                        expect_string=r"#",
                        read_timeout=self.timeout,
                    )
                except Exception:
                    logger.debug("[%s] Preparation command failed: %s", host, command)
            time.sleep(0.5)

        def connect(primary: bool):
            return self._netmiko_via_jump(
                jump_host=jump_host,
                target_ip=host,
                primary=primary,
                primary_user=primary_user,
                primary_pass=primary_pass,
                answer_user=answer_user,
                answer_pass=answer_pass,
            )

        connection = None
        try:
            try:
                connection = connect(True)
                logger.info(
                    "%s Netmiko connected (primary credentials)%s",
                    host,
                    " via jump" if jump_host else "",
                )
            except NetmikoAuthenticationException:
                if answer_user and answer_pass:
                    connection = connect(False)
                    logger.info(
                        "%s Netmiko connected (fallback credentials)%s",
                        host,
                        " via jump" if jump_host else "",
                    )
                else:
                    raise

            prepare(connection)
            try:
                connection.clear_buffer()
            except Exception:
                logger.debug("[%s] Could not clear the SSH buffer", host)

            version_output = connection.send_command(
                "show version",
                expect_string=r"#",
                read_timeout=max(self.timeout, 20),
            )
            protocol_results: Dict[
                NeighborProtocol, ProtocolCollectionResult
            ] = {}
            for protocol in self.discovery_mode.protocols:
                if protocol is NeighborProtocol.CDP:
                    protocol_results[protocol] = self._collect_cdp(
                        connection, host
                    )
                else:
                    protocol_results[protocol] = self._collect_lldp(
                        connection, host
                    )
            return DeviceCommandResult(version_output, protocol_results)
        finally:
            # Closing the Netmiko connection also closes its jump channel. The
            # shared jump transport stays up for the rest of the run and is
            # torn down by close_jump_host().
            try:
                if connection:
                    connection.disconnect()
            except Exception:
                logger.debug(
                    "Error disconnecting Netmiko connection", exc_info=True
                )

    def request_stop(self) -> None:
        """Ask workers to finish the device in hand and stop taking new ones."""
        if not self.stop_event.is_set():
            logger.info("Stop requested; workers will finish their current device")
        self.stop_event.set()

    def wait_until_idle(self, futures: Iterable["Future"]) -> None:
        """Block until the queue drains, a stop is requested, or workers exit.

        Queue.join() alone would hang forever if a worker ever died without
        calling task_done(), leaving the UI stuck with no way out. Polling the
        outstanding count alongside worker liveness always terminates.
        """
        futures = list(futures)
        while True:
            if self.stop_event.is_set():
                return
            if self.host_queue.unfinished_tasks == 0:
                return
            if futures and all(future.done() for future in futures):
                logger.error(
                    "All discovery workers exited with %d task(s) outstanding",
                    self.host_queue.unfinished_tasks,
                )
                return
            time.sleep(0.25)

    def discover_worker(
        self,
        jump_host: str,
        primary_user: str,
        primary_pass: str,
        answer_user: Optional[str],
        answer_pass: Optional[str],
    ) -> None:
        """Worker thread for parallel device discovery."""
        thread_name = threading.current_thread().name
        logger.info("Worker start: %s", thread_name)
        try:
            while True:
                if self.stop_event.is_set():
                    logger.info("Worker exit (stop requested): %s", thread_name)
                    return
                try:
                    item = self.host_queue.get(timeout=1.0)
                except queue.Empty:
                    continue

                claimed = False
                try:
                    if item is None:
                        logger.info("Worker exit (sentinel): %s", thread_name)
                        return

                    host = item
                    if self.stop_event.is_set():
                        continue

                    with self.visited_lock:
                        self.enqueued.discard(host)
                        if host in self.visited or host in self.in_progress:
                            continue
                        self.in_progress.add(host)
                        claimed = True

                    last_error = None
                    for attempt in range(1, config.MAX_RETRY_ATTEMPTS + 1):
                        if self.stop_event.is_set():
                            break
                        logger.info(
                            "[%s] %s attempt %d: collecting %s + version",
                            host,
                            thread_name,
                            attempt,
                            self.discovery_mode.display_name,
                        )
                        try:
                            result = self.run_device_commands(
                                jump_host,
                                host,
                                primary_user,
                                primary_pass,
                                answer_user,
                                answer_pass,
                            )
                            self.parse_outputs_and_enqueue_neighbors(host, result)
                            logger.info("%s discovery successful", host)
                            last_error = None
                            break
                        except NetmikoAuthenticationException:
                            logger.info("[%s] Authentication failed", host)
                            with self.data_lock:
                                self.authentication_errors.add(host)
                            last_error = None
                            break
                        except (
                            NetmikoTimeoutException,
                            SSHException,
                            socket.timeout,
                        ) as exc:
                            logger.warning(
                                "[%s] Connection issue (attempt %d): %s",
                                host,
                                attempt,
                                exc,
                            )
                            last_error = type(exc).__name__
                        except Exception:
                            logger.exception(
                                "[%s] Unexpected error (attempt %d)",
                                host,
                                attempt,
                            )
                            last_error = "UnexpectedError"

                        # Back off before retrying, so a device that is rate
                        # limiting or still booting gets a moment to recover.
                        # Interruptible so a stop request is not delayed.
                        if attempt < config.MAX_RETRY_ATTEMPTS:
                            self.stop_event.wait(min(2 * attempt, 10))

                    with self.visited_lock:
                        self.visited.add(host)
                    if last_error:
                        with self.data_lock:
                            self.connection_errors.setdefault(host, last_error)
                except Exception:
                    logger.exception("Unexpected error processing item: %s", item)
                finally:
                    if claimed and item is not None:
                        with self.visited_lock:
                            self.in_progress.discard(item)
                    self.host_queue.task_done()
        except Exception:
            logger.exception("Worker thread crashed: %s", thread_name)

    def resolve_dns_for_host(self, hostname: str) -> Tuple[str, str]:
        """Resolve one hostname to IPv4 on a best-effort basis."""
        try:
            logger.debug("[DNS] Resolving %s", hostname)
            ip_address = socket.gethostbyname(hostname)
            logger.debug("[DNS] %s resolved to %s", hostname, ip_address)
            return hostname, ip_address
        except socket.gaierror as exc:
            logger.debug("[DNS] Failed to resolve %s: %s", hostname, exc.strerror)
            return hostname, config.DNS_UNRESOLVED_MARKER
        except Exception:
            logger.exception("[DNS] Unexpected error resolving %s", hostname)
            return hostname, config.DNS_ERROR_MARKER

    def resolve_dns_parallel(self) -> None:
        """Resolve collected hostnames using a bounded thread pool."""
        names = list(self.hostnames)
        if not names:
            return
        results: List[Tuple[str, str]] = []
        with ThreadPoolExecutor(
            max_workers=min(
                config.DNS_MAX_WORKERS,
                max(config.DNS_MIN_WORKERS, self.limit),
            )
        ) as executor:
            futures = [
                executor.submit(self.resolve_dns_for_host, name)
                for name in names
            ]
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception:
                    logger.exception("DNS worker failed while resolving names")
        with self.data_lock:
            for hostname, ip_address in results:
                self.dns_ip[hostname] = ip_address
