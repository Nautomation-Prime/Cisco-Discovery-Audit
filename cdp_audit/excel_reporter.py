"""Excel report writer."""

import datetime
import logging
import re
import shutil
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence

import openpyxl
from openpyxl.utils import get_column_letter

from .app_config import config

logger = logging.getLogger(__name__)


class ExcelReporter:
    """Handles writing discovery results to an Excel workbook based on a template."""

    def __init__(self, excel_template: Path) -> None:
        self.excel_template = excel_template

    def save_to_excel(
        self,
        details_list: List[Dict],
        hosts: List[str],
        site_name: str,
        dns_ip: Dict[str, str],
        auth_errors: set,
        conn_errors: Dict[str, str],
        device_inventory: Dict[str, Dict],
        discovery_mode: str = "CDP",
    ) -> str:
        """Persist collected data to an Excel file cloned from the template.

        Args:
            details_list: Parsed CDP neighbour rows to place on the Audit sheet.
            hosts: Seed devices (used to stamp primary/secondary seed cells).
            site_name: Site label used in the output filename and metadata cells.
            dns_ip: Hostname to IP mappings for the DNS sheet.
            auth_errors: IPs that failed authentication (Auth Errors sheet).
            conn_errors: IPs that failed to connect with error labels.
            device_inventory: Per-device inventory records for the Inventory sheet.

        Returns:
            Path to the saved Cisco Discovery Audit workbook.
        """
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)
        safe_site_name = self._safe_filename_component(site_name)
        now = datetime.datetime.now()
        # The timestamp keeps each run's workbook distinct — re-auditing a site
        # must never silently overwrite the previous audit.
        stamp = now.strftime("%Y%m%d_%H%M%S")
        filepath = output_dir / f"{safe_site_name}_Cisco_Discovery_Audit_{stamp}.xlsx"
        shutil.copy2(src=self.excel_template, dst=filepath)

        date_now = now.strftime("%d %B %Y")
        time_now = now.strftime("%H:%M")
        wb = openpyxl.load_workbook(filepath)
        ws1 = wb[config.EXCEL_SHEET_AUDIT]
        ws1[config.EXCEL_CELL_SITE_NAME] = self._excel_literal(site_name)
        ws1[config.EXCEL_CELL_DATE] = date_now
        ws1[config.EXCEL_CELL_TIME] = time_now
        ws1[config.EXCEL_CELL_PRIMARY_SEED] = self._excel_literal(
            hosts[0] if hosts else ""
        )
        ws1[config.EXCEL_CELL_SECONDARY_SEED] = (
            self._excel_literal(hosts[1])
            if len(hosts) > 1
            else config.EXCEL_SECONDARY_SEED_DEFAULT
        )
        ws1[config.EXCEL_CELL_DISCOVERY_MODE] = discovery_mode
        self._write_mapping_rows(
            ws1,
            details_list,
            config.EXCEL_AUDIT_COLUMNS,
            config.EXCEL_AUDIT_DATA_START_ROW + 1,
        )
        self._write_mapping_rows(
            wb[config.EXCEL_SHEET_INVENTORY],
            self._deduplicate_inventory(device_inventory),
            config.EXCEL_INVENTORY_COLUMNS,
            config.EXCEL_OTHER_DATA_START_ROW + 1,
        )
        self._write_sequence_rows(
            wb[config.EXCEL_SHEET_DNS],
            dns_ip.items(),
            config.EXCEL_OTHER_DATA_START_ROW + 1,
        )
        self._write_sequence_rows(
            wb[config.EXCEL_SHEET_AUTH_ERRORS],
            ((address,) for address in sorted(auth_errors)),
            config.EXCEL_OTHER_DATA_START_ROW + 1,
        )
        self._write_sequence_rows(
            wb[config.EXCEL_SHEET_CONN_ERRORS],
            conn_errors.items(),
            config.EXCEL_OTHER_DATA_START_ROW + 1,
        )
        self._post_format_workbook(wb)
        wb.save(filepath)
        wb.close()
        return str(filepath)

    @staticmethod
    def _deduplicate_inventory(
        device_inventory: Mapping[str, Dict],
    ) -> List[Dict]:
        """Collapse inventory rows that share a serial number.

        A switch is keyed in device_inventory by the management IP it was
        discovered at, but the same physical switch can be reachable (and
        so discovered) at more than one IP - a secondary management VLAN, a
        loopback also advertised over CDP/LLDP, and so on. That produced a
        separate Inventory row per IP for what is really one device. The
        serial number is the one identifier that stays constant across those
        IPs, so rows sharing a non-empty serial are merged into a single row
        that lists every IP seen for that device. Rows without a serial
        (version parsing failed, etc.) are kept as-is rather than merged, so
        distinct devices of unknown identity are never collapsed together.
        """
        merged: Dict[str, Dict] = {}
        order: List[str] = []
        for row in device_inventory.values():
            serial = str(row.get("SERIAL") or "").strip()
            key = serial or f"__ip__:{row.get('IP', '')}"
            existing = merged.get(key)
            if existing is None:
                merged[key] = dict(row)
                order.append(key)
                continue
            existing_ips = [
                ip.strip()
                for ip in str(existing.get("IP", "")).split(",")
                if ip.strip()
            ]
            new_ip = str(row.get("IP", "")).strip()
            if new_ip and new_ip not in existing_ips:
                existing_ips.append(new_ip)
                existing["IP"] = ", ".join(existing_ips)
        return [merged[key] for key in order]

    @staticmethod
    def _safe_filename_component(value: str) -> str:
        """Return a Windows-safe filename component without changing metadata."""
        sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", value).strip(" .")
        return sanitized or "Network"

    @staticmethod
    def _excel_literal(value: object) -> object:
        """Prevent untrusted device text from becoming an Excel formula."""
        if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r", "\n")):
            return f"'{value}"
        return value

    @staticmethod
    def _write_mapping_rows(
        worksheet,
        rows: Iterable[Mapping[str, object]],
        columns: Sequence[str],
        start_row: int,
    ) -> None:
        for row_index, row in enumerate(rows, start=start_row):
            for column_index, key in enumerate(columns, start=1):
                worksheet.cell(
                    row=row_index,
                    column=column_index,
                    value=ExcelReporter._excel_literal(row.get(key, "")),
                )

    @staticmethod
    def _write_sequence_rows(
        worksheet,
        rows: Iterable[Sequence[object]],
        start_row: int,
    ) -> None:
        for row_index, row in enumerate(rows, start=start_row):
            for column_index, value in enumerate(row, start=1):
                worksheet.cell(
                    row=row_index,
                    column=column_index,
                    value=ExcelReporter._excel_literal(value),
                )

    # ── Post-write formatting ────────────────────────────────────────────────

    def _post_format_workbook(self, wb) -> None:
        """Apply column autofit and freeze panes to all data sheets."""
        audit_freeze = f"A{config.EXCEL_AUDIT_DATA_START_ROW + 1}"
        other_freeze = f"A{config.EXCEL_OTHER_DATA_START_ROW + 1}"

        ws_audit = wb[config.EXCEL_SHEET_AUDIT]
        ws_audit.freeze_panes = audit_freeze
        self._autofit_columns(ws_audit)

        for sheet_name, freeze in [
            (config.EXCEL_SHEET_INVENTORY,    other_freeze),
            (config.EXCEL_SHEET_DNS,          other_freeze),
            (config.EXCEL_SHEET_AUTH_ERRORS,  other_freeze),
            (config.EXCEL_SHEET_CONN_ERRORS,  other_freeze),
        ]:
            if sheet_name in wb.sheetnames:
                ws = wb[sheet_name]
                ws.freeze_panes = freeze
                self._autofit_columns(ws)

    @staticmethod
    def _autofit_columns(ws) -> None:
        """Set each column's width to fit its widest cell value (capped at 60)."""
        for idx, col in enumerate(ws.columns, start=1):
            max_len = 0
            for cell in col:
                if cell.value is not None:
                    max_len = max(max_len, len(str(cell.value)))
            if max_len > 0:
                ws.column_dimensions[get_column_letter(idx)].width = min(max_len + 2, 60)
