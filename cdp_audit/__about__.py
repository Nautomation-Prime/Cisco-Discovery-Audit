"""Package metadata for Nautomation Prime Cisco Discovery Audit."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version

from .version import get_version

__title__ = "nautomation-prime-cisco-discovery-audit"
__app_name__ = "Nautomation Prime Cisco Discovery Audit"
__description__ = "Cisco CDP and LLDP discovery audit with Excel reporting"
__license__ = "Apache-2.0"
__author__ = "Christopher Davies"

try:
    __version__ = package_version(__title__)
except PackageNotFoundError:
    __version__ = get_version()
