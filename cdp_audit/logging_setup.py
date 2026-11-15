"""Logging bootstrap for Nautomation Prime Cisco Discovery Audit."""

import logging
import logging.config
import logging.handlers
import os
from pathlib import Path

from .app_config import config

# Third-party loggers whose DEBUG output is high volume and, in netmiko's case,
# contains the raw SSH session. Capped regardless of which branch configures
# logging below.
_NOISY_LOGGERS = (
    "paramiko",
    "paramiko.transport",
    "netmiko",
    "netmiko.base_connection",
    "netmiko.transport",
    "netmiko.utilities",
)

_LOG_MAX_BYTES = 5 * 1024 * 1024
_LOG_BACKUP_COUNT = 3


def _quieten_third_party_loggers() -> None:
    """Hold noisy third-party loggers at INFO or above."""
    for name in _NOISY_LOGGERS:
        third_party = logging.getLogger(name)
        if third_party.level in (logging.NOTSET, logging.DEBUG):
            third_party.setLevel(logging.INFO)


def configure_logging() -> None:
    """Configure logging using INI file if available; otherwise fall back
    to a basic file + console setup.

    The LOGGING_CONFIG environment variable can override the default path.
    The logs/ directory is created automatically if it does not yet exist; if
    it cannot be created the run continues with console logging only rather
    than failing at startup.
    """
    cfg_env = os.getenv("LOGGING_CONFIG", "").strip()
    default_cfg = config.LOGGING_CONFIG_PATH
    cfg_path = Path(cfg_env) if cfg_env else default_cfg

    # Ensure logs/ exists before any file handler tries to open the file.
    log_dir = Path("logs")
    try:
        log_dir.mkdir(exist_ok=True)
        file_logging = True
    except OSError as exc:
        file_logging = False
        print(f"Warning: cannot create {log_dir.resolve()} ({exc}); logging to console only.")

    if file_logging and cfg_path.exists():
        try:
            logging.config.fileConfig(str(cfg_path), disable_existing_loggers=False)
            _quieten_third_party_loggers()
            return
        except (OSError, ValueError, KeyError) as exc:
            print(f"Warning: could not apply logging config {cfg_path} ({exc}); using defaults.")

    # Fallback: basic dual-handler setup (console INFO, file DEBUG)
    root = logging.getLogger()
    if root.handlers:
        _quieten_third_party_loggers()
        return  # Already configured — don't add duplicate handlers

    root.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        "%(asctime)s - %(levelname)-8s  %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(fmt)
    root.addHandler(console_handler)

    if file_logging:
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / "debug.log",
            maxBytes=_LOG_MAX_BYTES,
            backupCount=_LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)

    _quieten_third_party_loggers()
