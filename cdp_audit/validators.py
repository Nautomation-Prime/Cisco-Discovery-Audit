"""Validation helpers."""

import ipaddress
import logging
import socket
from pathlib import Path
from typing import Iterable, List

import openpyxl

from .app_config import config

logger = logging.getLogger(__name__)


def validate_required_files(paths: Iterable[Path]) -> None:
    """Ensure required files exist before execution.

    Raises:
        SystemExit: If any file paths are missing.
    """
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        logger.error("Required files missing: %s", ", ".join(missing))
        raise SystemExit(1)


def validate_excel_template(template_path: Path) -> None:
    """Validate that the Excel template exists and has required sheet structure.

    Raises:
        SystemExit: If the template is missing or invalid.
    """
    if not template_path.exists():
        logger.error("Excel template not found: %s", template_path)
        raise SystemExit(1)

    try:
        wb = openpyxl.load_workbook(template_path, data_only=False)
        required_sheets = [
            config.EXCEL_SHEET_AUDIT,
            config.EXCEL_SHEET_INVENTORY,
            config.EXCEL_SHEET_DNS,
            config.EXCEL_SHEET_AUTH_ERRORS,
            config.EXCEL_SHEET_CONN_ERRORS,
        ]
        missing_sheets = [sheet for sheet in required_sheets if sheet not in wb.sheetnames]

        if missing_sheets:
            logger.error(
                "Excel template is missing required sheets: %s (has: %s)",
                ", ".join(missing_sheets),
                ", ".join(wb.sheetnames),
            )
            wb.close()
            raise SystemExit(1)

        audit_sheet = wb[config.EXCEL_SHEET_AUDIT]
        inventory_sheet = wb[config.EXCEL_SHEET_INVENTORY]
        audit_headers = [
            audit_sheet.cell(
                row=config.EXCEL_AUDIT_DATA_START_ROW,
                column=column,
            ).value
            for column in range(1, len(config.EXCEL_AUDIT_COLUMNS) + 1)
        ]
        inventory_headers = [
            inventory_sheet.cell(
                row=config.EXCEL_OTHER_DATA_START_ROW,
                column=column,
            ).value
            for column in range(1, len(config.EXCEL_INVENTORY_COLUMNS) + 1)
        ]
        if not all(audit_headers) or not all(inventory_headers):
            logger.error("Excel template contains missing Audit or Inventory headers")
            wb.close()
            raise SystemExit(1)

        wb.close()
        logger.debug("Excel template validated successfully: %s", template_path)

    except FileNotFoundError as exc:
        logger.error("Excel template file not readable: %s", template_path)
        raise SystemExit(1) from exc
    except Exception as exc:
        logger.error("Error validating Excel template: %s", exc)
        raise SystemExit(1) from exc


def normalize_seeds(seeds: List[str]) -> List[str]:
    """Validate seed IPs/hostnames and normalize to IP addresses.

    Seeds that cannot be parsed or resolved are logged and skipped, so a single
    typo does not discard an otherwise valid run. Input order is preserved so
    that the first seed remains the one stamped as the primary seed in the
    Excel report.

    Raises:
        SystemExit: If no seed survives validation.
    """
    # dict.fromkeys deduplicates while preserving first-seen order.
    validated: dict = {}
    skipped: List[str] = []
    for seed in seeds:
        try:
            # Canonical text, so "10.0.0.1" and an IPv6 address written two
            # ways each de-duplicate against the addresses CDP/LLDP report.
            validated.setdefault(str(ipaddress.ip_address(seed.strip())), None)
        except ValueError:
            try:
                resolved = socket.gethostbyname(seed)
                validated.setdefault(resolved, None)
                logger.debug("Seed hostname '%s' resolved to %s", seed, resolved)
            except Exception as exc:
                logger.error(
                    "Skipping seed '%s': not a valid IP and could not be resolved: %s",
                    seed,
                    exc,
                )
                skipped.append(seed)

    if not validated:
        logger.error(
            "No usable seed devices: all %d seed(s) were invalid or unresolvable. Aborting.",
            len(seeds),
        )
        raise SystemExit(1)

    duplicates = len(seeds) - len(skipped) - len(validated)
    if duplicates > 0:
        logger.warning(
            "Removed %d duplicate seed(s). Starting with %d unique devices.",
            duplicates,
            len(validated),
        )
    if skipped:
        logger.warning(
            "Continuing without %d unusable seed(s): %s",
            len(skipped),
            ", ".join(skipped),
        )

    return list(validated)
