"""Command line entry point for Nautomation Prime Cisco Discovery Audit."""

import os
import sys

from .app_config import config
from .logging_setup import configure_logging
from .tui import CDPAuditApp
from .validators import validate_excel_template, validate_required_files
from .version import get_version_info


def main() -> None:
    """Program entry point.

    Validates required support files, then launches the full-screen TUI.
    File validation runs before the TUI starts so that any missing-file error
    is reported clearly to the console rather than surfacing mid-session.
    """
    if "--version" in sys.argv[1:]:
        print(get_version_info())
        return

    os.chdir(config.BASE_DIR)
    configure_logging()
    validate_required_files(config.REQUIRED_SUPPORT_FILES)
    validate_excel_template(config.EXCEL_TEMPLATE)
    if "--check-install" in sys.argv[1:]:
        print(
            "Installation check passed "
            f"({config.DISCOVERY_MODE.display_name} mode)."
        )
        return
    CDPAuditApp().run()
