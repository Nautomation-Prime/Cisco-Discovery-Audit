"""
Nautomation Prime Cisco Discovery Audit Configuration Loader
==============================================================

This module provides the central configuration loader for Cisco Discovery Audit.
It loads structured parameters from a YAML configuration file and allows environment
variables to override specific settings.

The Config class provides a clean API for accessing configuration values throughout
the application, with automatic type conversion and sensible defaults.

Usage Example:
--------------
    from cdp_audit.config_loader import Config

    config = Config()

    # Access configuration values
    jump_host = config.JUMP_HOST
    timeout = config.DEFAULT_TIMEOUT
    templates = config.CDP_TEMPLATE

    print(f"Using jump host: {jump_host}")
    print(f"Timeout: {timeout} seconds")

Design Philosophy:
------------------
- Configuration is loaded from YAML for human readability and ease of editing
- Sensitive values (credentials) can be overridden via environment variables
- The Config class provides a stable API, insulating the application from
  changes to the underlying YAML structure
- All file paths are returned as pathlib.Path objects for cross-platform compatibility
- Default values are provided for all settings to prevent runtime errors

Security Considerations:
------------------------
- Never commit sensitive credentials to the YAML file
- Use environment variables or secure credential stores (Windows Credential Manager)
  for passwords and secrets
- The YAML file should be readable only by authorised users in production

Author: Christopher Davies T/A Nautomation Prime
Email: enquiries@nautomationprime.io

Copyright (c) 2026 Christopher Davies T/A Nautomation Prime
Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
"""

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import ValidationError

from .protocols import DiscoveryMode
from .settings import ENV_OVERRIDES, AppSettings


class ConfigError(ValueError):
    """config.yaml (or an environment override) failed validation."""


class Config:
    """
    Canonical configuration loader for Cisco Discovery Audit.

    - Loads structured parameters from config.yaml
    - Allows environment variable overrides for deployment flexibility
    - Validates everything up front against the AppSettings schema, so a bad
      value stops the tool at start-up with its YAML path rather than
      failing part-way through a discovery run
    - Returns pathlib.Path objects for file paths (cross-platform compatibility)

    Attributes:
        config_file (Path): Path to the YAML configuration file
    """

    def __init__(self, config_file: str = "config.yaml"):
        """
        Initialise the configuration loader.

        Args:
            config_file: Path to the YAML configuration file (relative or absolute).
                        Defaults to "config.yaml" located at the project root.

        Raises:
            FileNotFoundError: If the specified config file doesn't exist.
            yaml.YAMLError: If the YAML file is malformed.
            ConfigError: If any setting fails validation.
        """
        if not Path(config_file).is_absolute():
            module_dir = Path(__file__).resolve().parent
            source_root = module_dir.parent
            runtime_root = (
                Path(sys.executable).resolve().parent
                if getattr(sys, "frozen", False)
                else source_root
            )

            search_paths = [
                runtime_root / config_file,
                Path.cwd() / config_file,
            ]

            # Fall back to the expected location so that, when nothing is
            # found, the error message names a useful path.
            self._config_file: Path = next(
                (path for path in search_paths if path.exists()),
                runtime_root / config_file,
            )
        else:
            self._config_file = Path(config_file)

        # Cache for environment variable lookups (populated on-demand)
        self._env_cache: Dict[str, Optional[str]] = {}

        # Load the YAML configuration, then validate it with env overrides
        self._config = self._load_yaml()
        self._settings = self._validate(self._config)

    def _load_yaml(self) -> dict:
        """
        Load and parse the YAML configuration file.

        Returns:
            Dictionary containing the parsed YAML configuration.

        Raises:
            FileNotFoundError: If the config file doesn't exist.
            yaml.YAMLError: If the YAML file is malformed.
        """
        if not self._config_file.exists():
            raise FileNotFoundError(
                f"Configuration file not found: {self._config_file}\n"
                f"Please ensure config.yaml exists in the project root directory."
            )

        with open(self._config_file, "r", encoding="utf-8") as f:
            try:
                config_data = yaml.safe_load(f)
            except yaml.YAMLError as e:
                raise yaml.YAMLError(
                    f"Error parsing YAML configuration file {self._config_file}: {e}"
                ) from e
        if config_data is None:
            return {}
        if not isinstance(config_data, dict):
            raise ConfigError(
                f"{self._config_file} must contain a mapping of settings, "
                f"not {type(config_data).__name__}"
            )
        return config_data

    def _validate(self, raw: Dict[str, Any]) -> AppSettings:
        """Apply environment overrides and validate against the schema.

        Raises:
            ConfigError: Listing every invalid setting with its YAML path.
        """
        merged: Dict[str, Any] = {
            key: dict(value) if isinstance(value, dict) else value
            for key, value in raw.items()
        }
        env_sources: Dict[tuple, str] = {}
        for var_name, (section, key) in ENV_OVERRIDES.items():
            env_value = self._get_env(var_name)
            if env_value is None:
                continue
            target = merged.get(section)
            if not isinstance(target, dict):
                target = merged[section] = {}
            target[key] = env_value
            env_sources[(section, key)] = var_name

        try:
            return AppSettings.model_validate(merged)
        except ValidationError as exc:
            lines = []
            for error in exc.errors():
                loc = tuple(str(part) for part in error["loc"])
                source = env_sources.get(loc[:2]) if len(loc) >= 2 else None
                where = ".".join(loc) or "(top level)"
                if source:
                    where += f" (from environment variable {source})"
                if error["type"] == "extra_forbidden":
                    message = "unknown setting (check the spelling and indentation)"
                else:
                    message = error["msg"].removeprefix("Value error, ")
                lines.append(f"  - {where}: {message}")
            raise ConfigError(
                f"Invalid configuration in {self._config_file}:\n" + "\n".join(lines)
            ) from None

    def _get_env(self, var_name: str) -> Optional[str]:
        """
        Get an environment variable value with caching.

        Args:
            var_name: Name of the environment variable.

        Returns:
            The environment variable value, or None if not set.
        """
        if var_name not in self._env_cache:
            value = (os.getenv(var_name) or "").strip()
            self._env_cache[var_name] = value or None
        return self._env_cache[var_name]

    @property
    def settings(self) -> AppSettings:
        """The validated settings model."""
        return self._settings

    # =========================================================================
    # DISCOVERY SETTINGS
    # =========================================================================

    @property
    def DISCOVERY_MODE(self) -> DiscoveryMode:
        """Configured neighbor-discovery protocol selection."""
        return self._settings.discovery.protocol

    # =========================================================================
    # NETWORK CONNECTION SETTINGS
    # =========================================================================

    @property
    def JUMP_HOST(self) -> str:
        """
        Jump/bastion server hostname or IP address.
        Can be overridden via CDP_JUMP_SERVER environment variable.

        Returns:
            Jump host address (string), or empty string if not configured.
        """
        return self._settings.network.jump_host

    @property
    def DEVICE_TYPE(self) -> str:
        """
        Netmiko device type for SSH connections.

        Returns:
            Device type string (e.g., "cisco_ios").
        """
        return self._settings.network.device_type

    @property
    def SSH_PORT(self) -> int:
        """
        SSH port for device connections.

        Returns:
            SSH port number (default: 22).
        """
        return self._settings.network.ssh_port

    @property
    def STRICT_HOST_KEYS(self) -> bool:
        """
        Whether unknown jump-host SSH keys are rejected rather than warned about.
        Can be overridden via CDP_STRICT_HOST_KEYS environment variable.

        When true, the jump host must already appear in the user's known_hosts
        file or the connection is refused, which prevents a man-in-the-middle on
        the bastion hop. When false, an unknown key is accepted with a warning.

        Returns:
            True if strict host-key checking is enabled (default: False).
        """
        return self._settings.network.strict_host_keys

    @property
    def DEFAULT_LIMIT(self) -> int:
        """
        Maximum number of concurrent worker threads for device discovery.
        Can be overridden via CDP_LIMIT environment variable.

        Returns:
            Worker limit (default: 10).
        """
        return self._settings.network.default_limit

    @property
    def DEFAULT_TIMEOUT(self) -> int:
        """
        Timeout in seconds for SSH operations.
        Can be overridden via CDP_TIMEOUT environment variable.

        Returns:
            Timeout in seconds (default: 10).
        """
        return self._settings.network.default_timeout

    @property
    def MAX_RETRY_ATTEMPTS(self) -> int:
        """
        Maximum number of connection retry attempts per device.

        Returns:
            Retry count (default: 3).
        """
        return self._settings.network.max_retry_attempts

    @property
    def DNS_MAX_WORKERS(self) -> int:
        """
        Maximum number of DNS resolution worker threads.

        Returns:
            Max DNS workers (default: 32).
        """
        return self._settings.network.dns_max_workers

    @property
    def DNS_MIN_WORKERS(self) -> int:
        """
        Minimum number of DNS resolution worker threads.

        Returns:
            Min DNS workers (default: 4).
        """
        return self._settings.network.dns_min_workers

    # =========================================================================
    # CREDENTIAL SETTINGS
    # =========================================================================

    @property
    def CRED_TARGET(self) -> str:
        """
        Windows Credential Manager target for primary credentials.
        Can be overridden via CDP_PRIMARY_CRED_TARGET environment variable.

        Returns:
            Credential target name (default: "CiscoAudit/Primary").
        """
        return self._settings.credentials.cred_target

    @property
    def ALT_CREDS(self) -> str:
        """
        Windows Credential Manager target for answer/fallback credentials.
        Can be overridden via CDP_ANSWER_CRED_TARGET environment variable.

        Returns:
            Credential target name (default: "CiscoAudit/Answer").
        """
        return self._settings.credentials.alt_creds

    # =========================================================================
    # FILE PATHS
    # =========================================================================

    @property
    def BASE_DIR(self) -> Path:
        """
        Base directory for the application.

        Returns:
            Path object for the base directory (default: current directory).
        """
        base_dir = self._settings.file_paths.base_dir
        if base_dir.is_absolute():
            return base_dir
        return (self._config_file.parent / base_dir).resolve()

    @property
    def CDP_TEMPLATE(self) -> Path:
        """
        Path to the TextFSM template for parsing 'show cdp neighbors detail'.

        Returns:
            Path object for the CDP TextFSM template.
        """
        return self.BASE_DIR / self._settings.file_paths.cdp_template

    @property
    def LLDP_TEMPLATE(self) -> Path:
        """Path to the TextFSM template for Cisco LLDP neighbor details."""
        return self.BASE_DIR / self._settings.file_paths.lldp_template

    @property
    def VER_TEMPLATE(self) -> Path:
        """
        Path to the TextFSM template for parsing 'show version'.

        Returns:
            Path object for the version TextFSM template.
        """
        return self.BASE_DIR / self._settings.file_paths.ver_template

    @property
    def EXCEL_TEMPLATE(self) -> Path:
        """
        Path to the Excel template file for audit reports.

        Returns:
            Path object for the Excel template.
        """
        return self.BASE_DIR / self._settings.file_paths.excel_template

    @property
    def LOGGING_CONFIG_PATH(self) -> Path:
        """
        Path to the logging configuration file.
        Can be overridden via LOGGING_CONFIG environment variable.

        Returns:
            Path object for the logging config file.
        """
        env_value = self._get_env("LOGGING_CONFIG")
        if env_value is not None:
            return Path(env_value)
        return self.BASE_DIR / self._settings.file_paths.logging_config_path

    # =========================================================================
    # EXCEL REPORT SETTINGS
    # =========================================================================

    @property
    def EXCEL_SHEET_AUDIT(self) -> str:
        """Excel sheet name for audit data."""
        return self._settings.excel.sheets.audit

    @property
    def EXCEL_SHEET_DNS(self) -> str:
        """Excel sheet name for DNS resolution data."""
        return self._settings.excel.sheets.dns

    @property
    def EXCEL_SHEET_AUTH_ERRORS(self) -> str:
        """Excel sheet name for authentication errors."""
        return self._settings.excel.sheets.auth_errors

    @property
    def EXCEL_SHEET_CONN_ERRORS(self) -> str:
        """Excel sheet name for connection errors."""
        return self._settings.excel.sheets.conn_errors

    @property
    def EXCEL_SHEET_INVENTORY(self) -> str:
        """Excel sheet name for the deduplicated device inventory."""
        return self._settings.excel.sheets.inventory

    @property
    def EXCEL_CELL_SITE_NAME(self) -> str:
        """Excel cell address for site name metadata."""
        return self._settings.excel.metadata_cells.site_name

    @property
    def EXCEL_CELL_DATE(self) -> str:
        """Excel cell address for date metadata."""
        return self._settings.excel.metadata_cells.date

    @property
    def EXCEL_CELL_TIME(self) -> str:
        """Excel cell address for time metadata."""
        return self._settings.excel.metadata_cells.time

    @property
    def EXCEL_CELL_PRIMARY_SEED(self) -> str:
        """Excel cell address for primary seed device metadata."""
        return self._settings.excel.metadata_cells.primary_seed

    @property
    def EXCEL_CELL_SECONDARY_SEED(self) -> str:
        """Excel cell address for secondary seed device metadata."""
        return self._settings.excel.metadata_cells.secondary_seed

    @property
    def EXCEL_CELL_DISCOVERY_MODE(self) -> str:
        """Excel cell address for the configured discovery mode."""
        return self._settings.excel.metadata_cells.discovery_mode

    @property
    def EXCEL_AUDIT_DATA_START_ROW(self) -> int:
        """Starting row for audit data in Excel (0-indexed)."""
        return self._settings.excel.data_start_rows.audit

    @property
    def EXCEL_OTHER_DATA_START_ROW(self) -> int:
        """Starting row for other data sheets in Excel (0-indexed)."""
        return self._settings.excel.data_start_rows.other

    @property
    def EXCEL_SECONDARY_SEED_DEFAULT(self) -> str:
        """Default text when no secondary seed device is provided."""
        return self._settings.excel.defaults.secondary_seed_default

    @property
    def EXCEL_AUDIT_COLUMNS(self) -> List[str]:
        """Column names for audit data."""
        return list(self._settings.excel.columns_audit)

    @property
    def EXCEL_DNS_COLUMNS(self) -> List[str]:
        """Column names for DNS resolution data."""
        return list(self._settings.excel.columns_dns)

    @property
    def EXCEL_AUTH_ERROR_COLUMNS(self) -> List[str]:
        """Column names for authentication errors."""
        return list(self._settings.excel.columns_auth_errors)

    @property
    def EXCEL_CONN_ERROR_COLUMNS(self) -> List[str]:
        """Column names for connection errors."""
        return list(self._settings.excel.columns_conn_errors)

    @property
    def EXCEL_INVENTORY_COLUMNS(self) -> List[str]:
        """Column names for the device inventory sheet."""
        return list(self._settings.excel.columns_inventory)

    # =========================================================================
    # DNS RESOLUTION SETTINGS
    # =========================================================================

    @property
    def DNS_UNRESOLVED_MARKER(self) -> str:
        """Marker text for unresolved DNS lookups in Excel output."""
        return self._settings.dns.unresolved_marker

    @property
    def DNS_ERROR_MARKER(self) -> str:
        """Marker text for DNS resolution errors in Excel output."""
        return self._settings.dns.error_marker

    # =========================================================================
    # UTILITY METHODS
    # =========================================================================

    def __repr__(self) -> str:
        sections = list(self._config.keys())
        return f"<Config file={self._config_file} sections={sections}>"

    def validate_required_files(self) -> bool:
        """
        Validate that all required files (templates, Excel template) exist.

        Returns:
            True if all required files exist, False otherwise.
        """
        required_files = [
            (path.name, path) for path in self.REQUIRED_SUPPORT_FILES
        ]

        all_exist = True
        for name, path in required_files:
            if not path.exists():
                print(f"ERROR: Required file not found: {name} at {path}")
                all_exist = False

        return all_exist

    @property
    def REQUIRED_SUPPORT_FILES(self) -> List[Path]:
        """Files required by the configured discovery mode."""
        paths = [self.VER_TEMPLATE, self.EXCEL_TEMPLATE]
        if self.DISCOVERY_MODE in (DiscoveryMode.CDP, DiscoveryMode.BOTH):
            paths.append(self.CDP_TEMPLATE)
        if self.DISCOVERY_MODE in (DiscoveryMode.LLDP, DiscoveryMode.BOTH):
            paths.append(self.LLDP_TEMPLATE)
        return paths

    def get_all_settings(self) -> Dict:
        """
        Get a dictionary of all configuration settings (for debugging/logging).

        Returns:
            Dictionary containing all current configuration values.
        """
        return {
            "network": {
                "jump_host":          self.JUMP_HOST,
                "device_type":        self.DEVICE_TYPE,
                "ssh_port":           self.SSH_PORT,
                "default_limit":      self.DEFAULT_LIMIT,
                "default_timeout":    self.DEFAULT_TIMEOUT,
                "max_retry_attempts": self.MAX_RETRY_ATTEMPTS,
                "dns_max_workers":    self.DNS_MAX_WORKERS,
                "dns_min_workers":    self.DNS_MIN_WORKERS,
            },
            "discovery": {
                "protocol": self.DISCOVERY_MODE.value,
            },
            "credentials": {
                "cred_target": self.CRED_TARGET,
                "alt_creds":   self.ALT_CREDS,
            },
            "file_paths": {
                "base_dir":           str(self.BASE_DIR),
                "cdp_template":       str(self.CDP_TEMPLATE),
                "lldp_template":      str(self.LLDP_TEMPLATE),
                "ver_template":       str(self.VER_TEMPLATE),
                "excel_template":     str(self.EXCEL_TEMPLATE),
                "logging_config_path": str(self.LOGGING_CONFIG_PATH),
            },
            "excel": {
                "sheets": {
                    "audit":       self.EXCEL_SHEET_AUDIT,
                    "dns":         self.EXCEL_SHEET_DNS,
                    "auth_errors": self.EXCEL_SHEET_AUTH_ERRORS,
                    "conn_errors": self.EXCEL_SHEET_CONN_ERRORS,
                },
            },
            "dns": {
                "unresolved_marker": self.DNS_UNRESOLVED_MARKER,
                "error_marker":      self.DNS_ERROR_MARKER,
            },
        }
