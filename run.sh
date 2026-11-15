#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# Nautomation Prime Cisco Discovery Audit - Developer Launcher (Linux / WSL)
# # Copyright (c) 2026 Christopher Davies
# ------------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/.venv"
PYTHON="$VENV/bin/python"

echo
echo "================================================================================"
echo "            NAUTOMATION PRIME CISCO DISCOVERY AUDIT"
echo "================================================================================"
echo
echo " Starting pre-flight checks..."
echo

# Bootstrap virtual environment on first run
if [ ! -f "$PYTHON" ]; then
    echo " Virtual environment not found - running first-time setup..."
    echo
    bash "$SCRIPT_DIR/setup.sh" || {
        echo
        echo " [FAILED] Setup did not complete. Cannot continue."
        exit 1
    }
    echo
fi

# Check package is present
if [ ! -f "$SCRIPT_DIR/cdp_audit/__init__.py" ]; then
    echo " [ERROR] Package not found at: $SCRIPT_DIR/cdp_audit"
    exit 1
fi

echo " [OK] Pre-flight checks passed"
echo

# Launch the TUI
cd "$SCRIPT_DIR"
"$PYTHON" -m cdp_audit "$@"
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo
    echo " [ERROR] Exited with code $EXIT_CODE. Review logs/debug.log for details."
    echo
fi

exit $EXIT_CODE
