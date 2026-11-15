"""Pydantic schema for config.yaml.

config.yaml is edited by hand, so it is validated once, at load time, and
every problem is reported together with its YAML path. Without this, a typo
such as ``default_limit: 0`` or ``device_type: cisco_iso`` only surfaced
mid-run as a crash or as every device failing to connect.
"""

from __future__ import annotations

import difflib
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .net_types import OptionalHostOrIP
from .protocols import DiscoveryMode

# Report keys the code actually produces. A column name outside these sets
# would silently write an empty column, so it is rejected instead.
AUDIT_ROW_KEYS = frozenset(
    (
        "LOCAL_HOST",
        "LOCAL_IP",
        "LOCAL_PORT",
        "DESTINATION_HOST",
        "REMOTE_PORT",
        "MANAGEMENT_IP",
        "PLATFORM",
        "SOFTWARE_VERSION",
        "CAPABILITIES",
        "PROTOCOLS",
    )
)
INVENTORY_ROW_KEYS = frozenset(
    ("HOSTNAME", "IP", "SERIAL", "PLATFORM", "IOS_VERSION", "UPTIME", "PROTOCOL_STATUS")
)

_CELL_RE = re.compile(r"^[A-Z]{1,3}[1-9][0-9]{0,6}$")
_SHEET_FORBIDDEN = re.compile(r"[\[\]:*?/\\]")


class _Section(BaseModel):
    # extra="forbid" turns a misspelt key (e.g. "defualt_timeout") into an
    # error rather than a setting that is silently ignored.
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, frozen=True)

    @model_validator(mode="before")
    @classmethod
    def _empty_section_is_defaults(cls, data: Any) -> Any:
        # A section whose keys are all commented out parses as None.
        return {} if data is None else data


class DiscoverySettings(_Section):
    protocol: DiscoveryMode = DiscoveryMode.CDP

    @field_validator("protocol", mode="before")
    @classmethod
    def _parse_protocol(cls, value: Any) -> DiscoveryMode:
        return DiscoveryMode.parse(value)


class NetworkSettings(_Section):
    jump_host: OptionalHostOrIP = ""
    device_type: str = "cisco_ios"
    ssh_port: int = Field(22, ge=1, le=65535)
    strict_host_keys: bool = False
    default_limit: int = Field(10, ge=1, le=100)
    default_timeout: int = Field(10, ge=1, le=600)
    # Zero would skip every device without recording an error.
    max_retry_attempts: int = Field(3, ge=1, le=10)
    dns_max_workers: int = Field(32, ge=1, le=256)
    dns_min_workers: int = Field(4, ge=1, le=256)

    @field_validator("device_type")
    @classmethod
    def _known_netmiko_platform(cls, value: str) -> str:
        from netmiko.ssh_dispatcher import platforms

        if value not in platforms:
            close = difflib.get_close_matches(value, platforms, n=3)
            hint = f" Did you mean {' or '.join(close)}?" if close else ""
            raise ValueError(f"{value!r} is not a Netmiko device type.{hint}")
        return value

    @model_validator(mode="after")
    def _dns_bounds_ordered(self) -> "NetworkSettings":
        if self.dns_min_workers > self.dns_max_workers:
            raise ValueError(
                f"dns_min_workers ({self.dns_min_workers}) is greater than "
                f"dns_max_workers ({self.dns_max_workers})"
            )
        return self


class CredentialSettings(_Section):
    cred_target: str = Field("CiscoAudit/Primary", min_length=1)
    alt_creds: str = Field("CiscoAudit/Answer", min_length=1)


class FilePathSettings(_Section):
    base_dir: Path = Path(".")
    cdp_template: Path = Path("assets/textfsm/cisco_ios_show_cdp_neighbors_detail.textfsm")
    lldp_template: Path = Path("assets/textfsm/cisco_ios_show_lldp_neighbors_detail.textfsm")
    ver_template: Path = Path("assets/textfsm/cisco_ios_show_version.textfsm")
    excel_template: Path = Path(
        "assets/config_files/Nautomation Prime Cisco Discovery Audit Template.xlsx"
    )
    logging_config_path: Path = Path("assets/config_files/logging.conf")


class SheetNames(_Section):
    audit: str = "Audit"
    inventory: str = "Inventory"
    dns: str = "DNS Resolved"
    auth_errors: str = "Authentication Errors"
    conn_errors: str = "Connection Errors"

    @field_validator("*")
    @classmethod
    def _valid_excel_sheet_name(cls, value: str) -> str:
        if not value or len(value) > 31 or _SHEET_FORBIDDEN.search(value):
            raise ValueError(
                f"{value!r} is not a valid Excel sheet name "
                "(1-31 characters, none of [ ] : * ? / \\)"
            )
        return value


class MetadataCells(_Section):
    site_name: str = "B4"
    date: str = "B5"
    time: str = "B6"
    primary_seed: str = "B7"
    secondary_seed: str = "B8"
    discovery_mode: str = "B9"

    @field_validator("*")
    @classmethod
    def _valid_a1_reference(cls, value: str) -> str:
        normalized = value.upper()
        if not _CELL_RE.match(normalized):
            raise ValueError(f"{value!r} is not an Excel cell reference such as 'B4'")
        return normalized

    @model_validator(mode="after")
    def _cells_distinct(self) -> "MetadataCells":
        cells = list(self.model_dump().values())
        duplicates = sorted({cell for cell in cells if cells.count(cell) > 1})
        if duplicates:
            raise ValueError(f"metadata cells overlap: {', '.join(duplicates)}")
        return self


class DataStartRows(_Section):
    audit: int = Field(11, ge=0, le=1_000_000)
    other: int = Field(4, ge=0, le=1_000_000)


class ExcelDefaults(_Section):
    secondary_seed_default: str = "Secondary Seed device not given"


def _check_columns(value: List[str], allowed: frozenset, label: str) -> List[str]:
    unknown = [column for column in value if column not in allowed]
    if unknown:
        raise ValueError(
            f"unknown {label} column(s) {', '.join(unknown)}; "
            f"valid names are {', '.join(sorted(allowed))}"
        )
    duplicates = sorted({column for column in value if value.count(column) > 1})
    if duplicates:
        raise ValueError(f"duplicate {label} column(s): {', '.join(duplicates)}")
    return value


class ExcelSettings(_Section):
    sheets: SheetNames = Field(default_factory=SheetNames)
    metadata_cells: MetadataCells = Field(default_factory=MetadataCells)
    data_start_rows: DataStartRows = Field(default_factory=DataStartRows)
    defaults: ExcelDefaults = Field(default_factory=ExcelDefaults)
    columns_audit: List[str] = Field(
        default_factory=lambda: [
            "LOCAL_HOST", "LOCAL_IP", "LOCAL_PORT", "DESTINATION_HOST",
            "REMOTE_PORT", "MANAGEMENT_IP", "PLATFORM", "SOFTWARE_VERSION",
            "CAPABILITIES", "PROTOCOLS",
        ],
        min_length=1,
    )
    columns_inventory: List[str] = Field(
        default_factory=lambda: [
            "HOSTNAME", "IP", "SERIAL", "PLATFORM", "IOS_VERSION", "UPTIME",
            "PROTOCOL_STATUS",
        ],
        min_length=1,
    )
    # Header labels only; the writer does not key rows by these names.
    columns_dns: List[str] = Field(default_factory=lambda: ["Hostname", "IP Address"])
    columns_auth_errors: List[str] = Field(
        default_factory=lambda: ["Authentication Errors"]
    )
    columns_conn_errors: List[str] = Field(default_factory=lambda: ["IP Address", "Error"])

    @field_validator("columns_audit")
    @classmethod
    def _known_audit_columns(cls, value: List[str]) -> List[str]:
        return _check_columns(value, AUDIT_ROW_KEYS, "audit")

    @field_validator("columns_inventory")
    @classmethod
    def _known_inventory_columns(cls, value: List[str]) -> List[str]:
        return _check_columns(value, INVENTORY_ROW_KEYS, "inventory")

    @model_validator(mode="after")
    def _sheets_distinct(self) -> "ExcelSettings":
        names = [name.lower() for name in self.sheets.model_dump().values()]
        if len(set(names)) != len(names):
            raise ValueError("sheet names must be distinct (Excel ignores case)")
        return self


class DnsSettings(_Section):
    unresolved_marker: str = "UNRESOLVED"
    error_marker: str = "ERROR"


class AppSettings(_Section):
    discovery: DiscoverySettings = Field(default_factory=DiscoverySettings)
    network: NetworkSettings = Field(default_factory=NetworkSettings)
    credentials: CredentialSettings = Field(default_factory=CredentialSettings)
    file_paths: FilePathSettings = Field(default_factory=FilePathSettings)
    excel: ExcelSettings = Field(default_factory=ExcelSettings)
    dns: DnsSettings = Field(default_factory=DnsSettings)
    # Documentation-only section in the shipped config.yaml.
    advanced: Optional[Dict[str, Any]] = None


# Environment variables that override a config.yaml setting, applied before
# validation so that a bad override is reported like a bad YAML value.
ENV_OVERRIDES: Dict[str, tuple] = {
    "CDP_JUMP_SERVER": ("network", "jump_host"),
    "CDP_STRICT_HOST_KEYS": ("network", "strict_host_keys"),
    "CDP_LIMIT": ("network", "default_limit"),
    "CDP_TIMEOUT": ("network", "default_timeout"),
    "CDP_PRIMARY_CRED_TARGET": ("credentials", "cred_target"),
    "CDP_ANSWER_CRED_TARGET": ("credentials", "alt_creds"),
}
