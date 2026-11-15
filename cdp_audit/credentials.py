"""Credential collection and storage helpers."""

import logging
import os
import sys
from typing import Optional, Tuple

from .app_config import config

logger = logging.getLogger(__name__)


class CredentialManager:
    """
    Reads and writes device credentials in the Windows Credential Manager.

    On platforms other than Windows every accessor returns None, and the setup
    screen falls back to prompting. Credentials are never written to disk by
    this application in any other form.
    """

    def __init__(self) -> None:
        self.primary_target = os.getenv("CDP_PRIMARY_CRED_TARGET", config.CRED_TARGET)
        self.answer_target = os.getenv("CDP_ANSWER_CRED_TARGET", config.ALT_CREDS)

    def _read_win_cred(self, target_name: str) -> Tuple[Optional[str], Optional[str]]:
        """Attempt to read a generic credential from Windows Credential Manager."""
        try:
            if not sys.platform.startswith("win"):
                return None, None
            import win32cred  # type: ignore

            cred = win32cred.CredRead(target_name, win32cred.CRED_TYPE_GENERIC)  # type: ignore
            user = cred.get("UserName")
            blob = cred.get("CredentialBlob")
            pwd = blob.decode("utf-16le") if blob else None
            if user and pwd:
                return user, pwd
        except Exception:
            logger.debug(
                "Reading credentials from Windows Credential Manager failed.",
                exc_info=True,
            )
        return None, None

    def _write_win_cred(self, target: str, username: str, password: str, persist: int = 2) -> bool:
        """Write or update a generic credential in Windows Credential Manager."""
        try:
            if not sys.platform.startswith("win"):
                logger.warning(
                    "Not a Windows platform; cannot store credentials in "
                    "Credential Manager."
                )
                return False
            import win32cred  # type: ignore

            blob_bytes = password.encode("utf-16le")
            credential = {
                "Type": win32cred.CRED_TYPE_GENERIC,
                "TargetName": target,
                "UserName": username,
                "CredentialBlob": blob_bytes,
                "Comment": "Created by Nautomation Prime Cisco Discovery Audit",
                "Persist": persist,
            }
            try:
                win32cred.CredWrite(credential, 0)
            except TypeError as exc:
                logger.debug(
                    "CredWrite rejected bytes for CredentialBlob (%s). "
                    "Retrying with unicode string.",
                    exc,
                )
                credential["CredentialBlob"] = password
                win32cred.CredWrite(credential, 0)
            logger.info("Stored/updated credentials in Windows Credential Manager: %s", target)
            return True
        except Exception:
            logger.exception("Failed to write credentials for '%s'", target)
            return False

    # ── TUI helpers ───────────────────────────────────────────────────────────

    def get_stored_primary(self) -> Tuple[Optional[str], Optional[str]]:
        """Return stored primary (username, password) from Credential Manager, or (None, None)."""
        if sys.platform.startswith("win"):
            return self._read_win_cred(self.primary_target)
        return None, None

    def get_stored_answer(self) -> Tuple[Optional[str], Optional[str]]:
        """Return stored fallback (username, password) from Credential Manager, or (None, None)."""
        if sys.platform.startswith("win"):
            return self._read_win_cred(self.answer_target)
        return None, None

    def get_stored_answer_password(self) -> Optional[str]:
        """Return stored answer password from Credential Manager, or None."""
        _, pwd = self.get_stored_answer()
        return pwd

    def save_primary(self, username: str, password: str) -> None:
        """Persist primary credentials to Windows Credential Manager."""
        self._write_win_cred(self.primary_target, username, password)

    def save_answer(self, username: str, password: str) -> None:
        """Persist fallback credentials to Windows Credential Manager."""
        self._write_win_cred(self.answer_target, username, password)
