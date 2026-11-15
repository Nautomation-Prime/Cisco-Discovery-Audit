from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from paramiko.ssh_exception import SSHException

from cdp_audit.discovery import NetworkDiscoverer

ROOT = Path(__file__).resolve().parents[1]
CDP_TEMPLATE = ROOT / "assets/textfsm/cisco_ios_show_cdp_neighbors_detail.textfsm"
LLDP_TEMPLATE = ROOT / "assets/textfsm/cisco_ios_show_lldp_neighbors_detail.textfsm"
VERSION_TEMPLATE = ROOT / "assets/textfsm/cisco_ios_show_version.textfsm"


def make_discoverer(limit: int = 4) -> NetworkDiscoverer:
    return NetworkDiscoverer(
        timeout=1,
        limit=limit,
        cdp_template=CDP_TEMPLATE,
        lldp_template=LLDP_TEMPLATE,
        ver_template=VERSION_TEMPLATE,
    )


class FakeTransport:
    def __init__(self) -> None:
        self.active = True
        self.channels = 0

    def is_active(self) -> bool:
        return self.active

    def open_channel(self, kind, dest, source, timeout=None):
        if not self.active:
            raise SSHException("transport is closed")
        self.channels += 1
        return f"channel-{self.channels}"


class FakeJumpClient:
    def __init__(self) -> None:
        self.transport = FakeTransport()
        self.closed = False

    def get_transport(self):
        return self.transport

    def close(self) -> None:
        self.closed = True
        self.transport.active = False


# ── Shared jump transport ────────────────────────────────────────────────────

def test_jump_host_is_logged_into_once_for_many_devices(monkeypatch) -> None:
    """A login per device would trip a bastion's auth rate limits."""
    discoverer = make_discoverer()
    logins = []

    def fake_connect(jump_host, username, password):
        logins.append(jump_host)
        return FakeJumpClient()

    monkeypatch.setattr(discoverer, "_paramiko_jump_client", fake_connect)

    channels = [
        discoverer._open_jump_channel("bastion", f"10.0.0.{n}", "user", "pass")
        for n in range(1, 26)
    ]

    assert len(logins) == 1
    assert len(set(channels)) == 25


def test_concurrent_workers_share_one_jump_login(monkeypatch) -> None:
    discoverer = make_discoverer()
    logins = []
    lock = threading.Lock()

    def fake_connect(jump_host, username, password):
        with lock:
            logins.append(jump_host)
        return FakeJumpClient()

    monkeypatch.setattr(discoverer, "_paramiko_jump_client", fake_connect)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(
                lambda n: discoverer._open_jump_channel(
                    "bastion", f"10.0.0.{n}", "user", "pass"
                ),
                range(1, 33),
            )
        )

    assert len(logins) == 1
    assert len(set(results)) == 32


def test_dropped_jump_session_is_reestablished(monkeypatch) -> None:
    discoverer = make_discoverer()
    clients = []

    def fake_connect(jump_host, username, password):
        client = FakeJumpClient()
        clients.append(client)
        return client

    monkeypatch.setattr(discoverer, "_paramiko_jump_client", fake_connect)

    discoverer._open_jump_channel("bastion", "10.0.0.1", "user", "pass")
    clients[0].transport.active = False  # bastion dropped the session
    discoverer._open_jump_channel("bastion", "10.0.0.2", "user", "pass")

    assert len(clients) == 2


def test_unreachable_device_does_not_tear_down_the_shared_transport(
    monkeypatch,
) -> None:
    """A refused channel means that device is down, not that the bastion is."""
    discoverer = make_discoverer()
    clients = []

    def fake_connect(jump_host, username, password):
        client = FakeJumpClient()
        clients.append(client)
        return client

    monkeypatch.setattr(discoverer, "_paramiko_jump_client", fake_connect)
    discoverer._open_jump_channel("bastion", "10.0.0.1", "user", "pass")

    def refuse(kind, dest, source, timeout=None):
        raise SSHException("connect failed")

    monkeypatch.setattr(clients[0].transport, "open_channel", refuse)

    with pytest.raises(SSHException):
        discoverer._open_jump_channel("bastion", "10.0.0.2", "user", "pass")

    assert len(clients) == 1
    assert not clients[0].closed


def test_close_jump_host_releases_the_session(monkeypatch) -> None:
    discoverer = make_discoverer()
    clients = []

    def fake_connect(jump_host, username, password):
        client = FakeJumpClient()
        clients.append(client)
        return client

    monkeypatch.setattr(discoverer, "_paramiko_jump_client", fake_connect)
    discoverer._open_jump_channel("bastion", "10.0.0.1", "user", "pass")

    discoverer.close_jump_host()

    assert clients[0].closed
    discoverer.close_jump_host()  # idempotent


# ── Stop handling ────────────────────────────────────────────────────────────

def test_stop_request_drains_workers_without_contacting_devices() -> None:
    discoverer = make_discoverer(limit=2)
    contacted = []

    def record(*args, **kwargs):
        contacted.append(args[1])
        raise AssertionError("should not be reached after a stop")

    discoverer.run_device_commands = record  # type: ignore[assignment]

    for n in range(1, 11):
        discoverer.host_queue.put(f"10.0.0.{n}")
    discoverer.request_stop()

    worker = threading.Thread(
        target=discoverer.discover_worker,
        args=("", "user", "pass", None, None),
        daemon=True,
    )
    worker.start()
    worker.join(timeout=5)

    assert not worker.is_alive()
    assert contacted == []


def test_wait_until_idle_returns_when_a_stop_is_requested() -> None:
    discoverer = make_discoverer()
    discoverer.host_queue.put("10.0.0.1")  # never marked done

    stopper = threading.Timer(0.3, discoverer.request_stop)
    stopper.start()
    try:
        discoverer.wait_until_idle([])  # must not hang
    finally:
        stopper.cancel()

    assert discoverer.stop_event.is_set()


def test_wait_until_idle_returns_when_every_worker_has_exited() -> None:
    """Previously a dead worker left Queue.join() blocked forever."""
    discoverer = make_discoverer()
    discoverer.host_queue.put("10.0.0.1")  # never marked done

    with ThreadPoolExecutor(max_workers=1) as pool:
        futures = [pool.submit(lambda: None)]

    discoverer.wait_until_idle(futures)  # must not hang

    assert not discoverer.stop_event.is_set()


def test_wait_until_idle_returns_once_the_queue_drains() -> None:
    discoverer = make_discoverer()
    discoverer.host_queue.put("10.0.0.1")

    def finish() -> None:
        discoverer.host_queue.get()
        discoverer.host_queue.task_done()

    worker = threading.Timer(0.2, finish)
    worker.start()
    try:
        discoverer.wait_until_idle([])
    finally:
        worker.join(timeout=5)

    assert discoverer.host_queue.unfinished_tasks == 0
