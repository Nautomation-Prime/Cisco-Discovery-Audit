from __future__ import annotations

import logging
import logging.config
import logging.handlers
from pathlib import Path

from cdp_audit import logging_setup
from cdp_audit.app_config import config


def _reset_root_logger() -> None:
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()


def test_shipped_logging_conf_uses_a_capped_rotating_file_handler(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """logs/debug.log holds topology detail; it must not grow without bound."""
    monkeypatch.chdir(tmp_path)
    Path("logs").mkdir()
    _reset_root_logger()
    try:
        logging.config.fileConfig(
            str(config.LOGGING_CONFIG_PATH), disable_existing_loggers=False
        )
        file_handlers = [
            handler
            for handler in logging.getLogger().handlers
            if isinstance(handler, logging.FileHandler)
        ]
        assert file_handlers, "expected a file handler on the root logger"
        for handler in file_handlers:
            assert isinstance(handler, logging.handlers.RotatingFileHandler)
            assert 0 < handler.maxBytes
            assert handler.backupCount > 0
    finally:
        _reset_root_logger()


def test_noisy_third_party_loggers_are_capped_after_configure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """netmiko.base_connection at DEBUG writes the whole SSH session to disk."""
    monkeypatch.chdir(tmp_path)
    _reset_root_logger()
    try:
        logging_setup.configure_logging()
        for name in ("paramiko", "paramiko.transport", "netmiko.base_connection"):
            assert logging.getLogger(name).level >= logging.INFO, name
    finally:
        _reset_root_logger()


def test_configure_logging_survives_an_uncreatable_log_directory(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A read-only install directory must not crash startup with a traceback."""
    monkeypatch.chdir(tmp_path)
    _reset_root_logger()

    real_mkdir = Path.mkdir

    def refuse_logs_dir(self, *args, **kwargs):
        if self.name == "logs":
            raise PermissionError("read-only location")
        return real_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", refuse_logs_dir)
    try:
        logging_setup.configure_logging()  # must not raise
        handlers = logging.getLogger().handlers
        assert handlers, "expected console logging to remain available"
        assert not any(isinstance(h, logging.FileHandler) for h in handlers)
    finally:
        _reset_root_logger()


def test_raw_output_logging_is_opt_in(monkeypatch) -> None:
    from cdp_audit.discovery import _raw_output_logging_enabled

    monkeypatch.delenv("CDP_DEBUG_RAW", raising=False)
    assert _raw_output_logging_enabled() is False

    monkeypatch.setenv("CDP_DEBUG_RAW", "1")
    assert _raw_output_logging_enabled() is True

    monkeypatch.setenv("CDP_DEBUG_RAW", "false")
    assert _raw_output_logging_enabled() is False
