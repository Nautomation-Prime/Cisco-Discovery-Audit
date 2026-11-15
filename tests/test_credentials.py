"""Cover the Windows Credential Manager paths on every platform.

The real win32cred is Windows-only and CI has historically run on Linux, so
these substitute a fake module and force the platform check. Without this the
credential code ships entirely untested.
"""

from __future__ import annotations

import sys
import types

import pytest

from cdp_audit.credentials import CredentialManager

CRED_TYPE_GENERIC = 1


class FakeWin32Cred(types.ModuleType):
    """Minimal stand-in for pywin32's win32cred module."""

    CRED_TYPE_GENERIC = CRED_TYPE_GENERIC

    def __init__(self) -> None:
        super().__init__("win32cred")
        self.store: dict = {}
        self.reject_bytes_blob = False
        self.write_calls: list = []

    def CredRead(self, target, cred_type):  # noqa: N802 - pywin32 naming
        if target not in self.store:
            raise Exception(f"Element not found: {target}")
        return self.store[target]

    def CredWrite(self, credential, flags):  # noqa: N802 - pywin32 naming
        self.write_calls.append(credential["CredentialBlob"])
        if self.reject_bytes_blob and isinstance(
            credential["CredentialBlob"], bytes
        ):
            raise TypeError("expected a unicode string")
        self.store[credential["TargetName"]] = dict(credential)


@pytest.fixture
def win32cred(monkeypatch):
    fake = FakeWin32Cred()
    monkeypatch.setitem(sys.modules, "win32cred", fake)
    monkeypatch.setattr(sys, "platform", "win32")
    return fake


def test_stored_credentials_round_trip(win32cred) -> None:
    manager = CredentialManager()
    manager.save_primary("netadmin", "p@ss w0rd")

    assert manager.get_stored_primary() == ("netadmin", "p@ss w0rd")


def test_password_is_stored_as_utf_16_le(win32cred) -> None:
    """CredentialBlob is UTF-16LE; a mismatch silently corrupts the password."""
    manager = CredentialManager()
    manager.save_primary("netadmin", "påsswörd")

    blob = win32cred.store[manager.primary_target]["CredentialBlob"]
    assert blob == "påsswörd".encode("utf-16le")
    assert manager.get_stored_primary()[1] == "påsswörd"


def test_write_retries_with_a_unicode_blob_when_bytes_are_rejected(
    win32cred,
) -> None:
    win32cred.reject_bytes_blob = True
    manager = CredentialManager()

    manager.save_primary("netadmin", "secret")

    assert [type(blob) for blob in win32cred.write_calls] == [bytes, str]
    assert win32cred.store[manager.primary_target]["UserName"] == "netadmin"


def test_missing_entry_returns_none_rather_than_raising(win32cred) -> None:
    manager = CredentialManager()

    assert manager.get_stored_primary() == (None, None)
    assert manager.get_stored_answer() == (None, None)
    assert manager.get_stored_answer_password() is None


def test_primary_and_answer_use_separate_targets(win32cred) -> None:
    manager = CredentialManager()
    manager.save_primary("netadmin", "primary-secret")
    manager.save_answer("answer", "answer-secret")

    assert manager.primary_target != manager.answer_target
    assert manager.get_stored_primary() == ("netadmin", "primary-secret")
    assert manager.get_stored_answer() == ("answer", "answer-secret")


def test_targets_can_be_overridden_by_environment(win32cred, monkeypatch) -> None:
    monkeypatch.setenv("CDP_PRIMARY_CRED_TARGET", "MyOrg/Primary")
    monkeypatch.setenv("CDP_ANSWER_CRED_TARGET", "MyOrg/Fallback")

    manager = CredentialManager()

    assert manager.primary_target == "MyOrg/Primary"
    assert manager.answer_target == "MyOrg/Fallback"


def test_non_windows_platforms_never_touch_the_credential_store(
    monkeypatch,
) -> None:
    fake = FakeWin32Cred()
    monkeypatch.setitem(sys.modules, "win32cred", fake)
    monkeypatch.setattr(sys, "platform", "linux")

    manager = CredentialManager()
    manager.save_primary("netadmin", "secret")

    assert fake.store == {}
    assert manager.get_stored_primary() == (None, None)


def test_a_failing_credential_store_does_not_propagate(win32cred) -> None:
    """A broken Credential Manager must fall back to prompting, not crash."""

    def explode(*args, **kwargs):
        raise OSError("credential service unavailable")

    win32cred.CredRead = explode
    win32cred.CredWrite = explode
    manager = CredentialManager()

    assert manager.get_stored_primary() == (None, None)
    manager.save_primary("netadmin", "secret")  # must not raise
