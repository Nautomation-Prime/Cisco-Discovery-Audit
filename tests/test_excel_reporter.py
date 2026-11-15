from __future__ import annotations

import re
import time
from pathlib import Path

import openpyxl

from cdp_audit.app_config import config
from cdp_audit.excel_reporter import ExcelReporter


def test_report_contains_protocol_columns_and_safe_filename(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    reporter = ExcelReporter(config.EXCEL_TEMPLATE)
    details = [
        {
            "LOCAL_HOST": "core-sw-01",
            "LOCAL_IP": "192.0.2.10",
            "LOCAL_PORT": "Gi1/0/1",
            "DESTINATION_HOST": "EDGE-SW-02",
            "REMOTE_PORT": "Gi1/0/48",
            "MANAGEMENT_IP": "192.0.2.20",
            "PLATFORM": "cisco C9300-48P",
            "SOFTWARE_VERSION": "17.9.4a",
            "CAPABILITIES": "Router Switch",
            "PROTOCOLS": "CDP+LLDP",
        }
    ]
    inventory = {
        "192.0.2.10": {
            "HOSTNAME": "core-sw-01",
            "IP": "192.0.2.10",
            "SERIAL": "FCW0000A001",
            "PLATFORM": "C9300-48P",
            "IOS_VERSION": "17.9.4a",
            "UPTIME": "2 years",
            "PROTOCOL_STATUS": "CDP: ok (1); LLDP: ok (1)",
        }
    }

    output = reporter.save_to_excel(
        details,
        ["192.0.2.10"],
        "HQ/West",
        {},
        set(),
        {},
        inventory,
        discovery_mode="BOTH",
    )

    output_path = Path(output)
    assert re.fullmatch(
        r"HQ_West_Cisco_Discovery_Audit_\d{8}_\d{6}\.xlsx", output_path.name
    ), output_path.name
    workbook = openpyxl.load_workbook(output_path, data_only=False)
    try:
        audit = workbook[config.EXCEL_SHEET_AUDIT]
        inventory_sheet = workbook[config.EXCEL_SHEET_INVENTORY]
        assert audit["A1"].value == "Nautomation Prime Cisco Discovery Audit"
        assert audit["B9"].value == "BOTH"
        assert audit["J11"].value == "Protocols"
        assert audit["J12"].value == "CDP+LLDP"
        assert inventory_sheet["G4"].value == "Protocol Status"
        assert inventory_sheet["G5"].value == "CDP: ok (1); LLDP: ok (1)"
    finally:
        workbook.close()


def test_inventory_rows_sharing_a_serial_are_merged_by_ip(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A switch discovered at two management IPs (e.g. a secondary VLAN)
    must appear once in the Inventory sheet, with both IPs listed, instead
    of as two duplicate rows."""
    monkeypatch.chdir(tmp_path)
    reporter = ExcelReporter(config.EXCEL_TEMPLATE)
    inventory = {
        "192.0.2.10": {
            "HOSTNAME": "core-sw-01",
            "IP": "192.0.2.10",
            "SERIAL": "FCW0000A001",
            "PLATFORM": "C9300-48P",
            "IOS_VERSION": "17.9.4a",
            "UPTIME": "2 years",
            "PROTOCOL_STATUS": "CDP: ok (3)",
        },
        "192.0.2.11": {
            "HOSTNAME": "core-sw-01",
            "IP": "192.0.2.11",
            "SERIAL": "FCW0000A001",
            "PLATFORM": "C9300-48P",
            "IOS_VERSION": "17.9.4a",
            "UPTIME": "2 years",
            "PROTOCOL_STATUS": "CDP: ok (2)",
        },
        "192.0.2.20": {
            "HOSTNAME": "edge-sw-02",
            "IP": "192.0.2.20",
            "SERIAL": "FCW0000B002",
            "PLATFORM": "C9300-24P",
            "IOS_VERSION": "17.9.4a",
            "UPTIME": "1 year",
            "PROTOCOL_STATUS": "CDP: ok (1)",
        },
    }

    output = reporter.save_to_excel(
        [], ["192.0.2.10"], "HQ", {}, set(), {}, inventory, discovery_mode="CDP"
    )

    workbook = openpyxl.load_workbook(output, data_only=False)
    try:
        inventory_sheet = workbook[config.EXCEL_SHEET_INVENTORY]
        start_row = config.EXCEL_OTHER_DATA_START_ROW + 1
        rows = [
            [cell.value for cell in row]
            for row in inventory_sheet.iter_rows(
                min_row=start_row, max_row=start_row + 1, max_col=2
            )
        ]
        assert rows[0] == ["core-sw-01", "192.0.2.10, 192.0.2.11"]
        assert rows[1] == ["edge-sw-02", "192.0.2.20"]
    finally:
        workbook.close()


def test_repeat_audits_of_one_site_do_not_overwrite_each_other(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    reporter = ExcelReporter(config.EXCEL_TEMPLATE)

    first = reporter.save_to_excel(
        [], ["192.0.2.10"], "HQ", {}, set(), {}, {}, discovery_mode="CDP"
    )
    # The filename stamp has one-second resolution.
    time.sleep(1.1)
    second = reporter.save_to_excel(
        [], ["192.0.2.10"], "HQ", {}, set(), {}, {}, discovery_mode="CDP"
    )

    assert first != second
    assert Path(first).exists()
    assert Path(second).exists()


def test_report_escapes_device_supplied_excel_formulas(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    reporter = ExcelReporter(config.EXCEL_TEMPLATE)
    details = [
        {
            "LOCAL_HOST": "core-sw-01",
            "DESTINATION_HOST": '=HYPERLINK("https://example.invalid","open")',
            "PROTOCOLS": "LLDP",
        }
    ]

    output = reporter.save_to_excel(
        details,
        ["192.0.2.10"],
        "=1+1",
        {},
        set(),
        {},
        {},
        discovery_mode="LLDP",
    )

    workbook = openpyxl.load_workbook(output, data_only=False)
    try:
        audit = workbook[config.EXCEL_SHEET_AUDIT]
        assert audit["B4"].value == "'=1+1"
        assert audit["D12"].value.startswith("'=HYPERLINK")
        assert audit["D12"].data_type == "s"
    finally:
        workbook.close()
