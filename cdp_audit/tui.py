"""Full-screen TUI for Nautomation Prime Cisco Discovery Audit."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, wait
from typing import Optional

from pydantic import ValidationError
from rich.markup import escape as markup_escape
from rich.table import Table
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.message import Message
from textual.screen import Screen
from textual.widgets import (
    Button,
    Checkbox,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Static,
)

from .app_config import config
from .audit_request import AuditRequest, describe_validation_error
from .credentials import CredentialManager
from .discovery import NetworkDiscoverer
from .excel_reporter import ExcelReporter
from .validators import normalize_seeds, validate_excel_template, validate_required_files
from .version import get_version_info

logger = logging.getLogger(__name__)

# Loggers that produce very high-volume DEBUG output — suppress to WARNING in the TUI
_NOISY_LOGGERS = (
    "paramiko",
    "paramiko.transport",
    "netmiko.base_connection",
    "netmiko.utilities",
)

_SPINNER_FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")


# ---------------------------------------------------------------------------
# Log message (used to route log records to the RichLog widget via the
# Textual message bus, which is thread-safe and non-blocking).
# ---------------------------------------------------------------------------

class AppendLog(Message):
    """Internal message that carries a single formatted log line."""

    def __init__(self, markup: str) -> None:
        super().__init__()
        self.markup = markup


# ---------------------------------------------------------------------------
# Log handler
# ---------------------------------------------------------------------------

class TUILogHandler(logging.Handler):
    """Pipes log records into the RichLog widget on the discovery screen.

    Uses Textual's thread-safe ``post_message`` so that log records emitted
    from background worker threads are delivered to the UI without blocking
    the caller and without going through ``App.call_from_thread``.
    """

    _LEVEL_MARKUP = {
        logging.DEBUG:    "dim",
        logging.WARNING:  "bold yellow",
        logging.ERROR:    "bold red",
        logging.CRITICAL: "bold white on red",
    }

    def __init__(self, screen: "DiscoveryScreen") -> None:
        super().__init__()
        self._screen = screen
        self.setFormatter(
            logging.Formatter(
                "%(asctime)s  %(levelname)-8s  %(message)s",
                datefmt="%H:%M:%S",
            )
        )

    def emit(self, record: logging.LogRecord) -> None:
        try:
            text = self.format(record)
            style = self._LEVEL_MARKUP.get(record.levelno, "")
            # Escape any Rich markup characters in the log message itself so that
            # patterns like "[hostname]" are rendered literally rather than being
            # interpreted as markup tags (which would cause silent write failures).
            escaped = markup_escape(text)
            markup = f"[{style}]{escaped}[/]" if style else escaped
            self._screen.post_message(AppendLog(markup))
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Setup screen
# ---------------------------------------------------------------------------

class SetupScreen(Screen):
    """Form for entering site details, seed devices, and credentials."""

    BINDINGS = [Binding("ctrl+q", "app.quit", "Quit")]

    def __init__(self) -> None:
        super().__init__()
        self._creds = CredentialManager()
        self._primary_user, self._primary_pass = self._creds.get_stored_primary()
        self._answer_user, self._answer_pass = self._creds.get_stored_answer()

    def compose(self) -> ComposeResult:
        primary_ok = bool(self._primary_user and self._primary_pass)
        answer_ok = bool(self._answer_user and self._answer_pass)
        jump_default = (config.JUMP_HOST or "").strip()

        yield Header(show_clock=True)
        with ScrollableContainer(id="setup-outer"):
            with Container(id="setup-inner"):
                yield Static(
                    "Nautomation Prime Cisco Discovery Audit",
                    id="app-title",
                )
                yield Label(
                    f"Discovery mode: {config.DISCOVERY_MODE.display_name}",
                    classes="field-label",
                )

                # ── Site ─────────────────────────────────────────────────
                yield Label("Site Name", classes="field-label")
                yield Input(
                    placeholder="e.g. London-HQ  (max 50 chars)",
                    id="site-name",
                )

                # ── Seeds ─────────────────────────────────────────────────
                yield Label("Seed Devices", classes="field-label")
                yield Input(
                    placeholder="Comma-separated IPs or hostnames  e.g. 10.0.0.1, 10.0.0.2",
                    id="seeds",
                )

                # ── Primary credentials ───────────────────────────────────
                yield Label("─── Primary Credentials", classes="section-label")
                yield Label("Username", classes="field-label")
                yield Input(
                    value=self._primary_user or "",
                    placeholder="Primary username",
                    id="primary-user",
                )
                yield Label("Password", classes="field-label")
                yield Input(
                    value=self._primary_pass or "",
                    placeholder="Primary password",
                    password=True,
                    id="primary-pass",
                )
                if primary_ok:
                    yield Label(
                        "✓  Loaded from Windows Credential Manager",
                        classes="cred-ok",
                    )
                else:
                    yield Label(
                        "⚠  Not found in Credential Manager — enter manually",
                        classes="cred-missing",
                    )

                # ── Answer credentials ────────────────────────────────────
                yield Label("─── Fallback Credentials  (optional)", classes="section-label")
                yield Label("Username", classes="field-label")
                yield Input(
                    value=self._answer_user or "",
                    placeholder="Fallback username  e.g. answer",
                    id="answer-user",
                )
                yield Label("Password", classes="field-label")
                yield Input(
                    value=self._answer_pass or "",
                    placeholder="Fallback password  (leave both blank to skip)",
                    password=True,
                    id="answer-pass",
                )
                if answer_ok:
                    yield Label(
                        "✓  Loaded from Windows Credential Manager",
                        classes="cred-ok",
                    )
                else:
                    yield Label(
                        "ℹ  Leave blank to disable credential fallback",
                        classes="cred-missing",
                    )

                # ── Jump host ─────────────────────────────────────────────
                yield Label("─── Jump / Bastion Host", classes="section-label")
                yield Label(
                    "Leave blank to connect directly to devices",
                    classes="field-label",
                )
                yield Input(
                    value=jump_default,
                    placeholder="e.g. 10.0.0.254  or  bastion.company.com",
                    id="jump-host",
                )

                # ── IP Filter ────────────────────────────────────────────
                yield Label("─── IP Filter  (optional)", classes="section-label")
                yield Label(
                    "Restrict crawling to these CIDRs / ranges / addresses (comma-separated) "
                    "— leave blank to discover all. Seed devices are always contacted.",
                    classes="field-label",
                )
                yield Input(
                    placeholder="e.g. 192.168.0.0/24, 10.0.0.1-10.0.0.100, 10.1.2.3",
                    id="ip-filter",
                )

                # ── Options ───────────────────────────────────────────────
                yield Checkbox(
                    "Save / update credentials in Windows Credential Manager after starting",
                    id="save-creds",
                    value=False,
                )

                # ── Buttons ───────────────────────────────────────────────
                with Horizontal(id="btn-row"):
                    yield Button("Start Audit", variant="primary", id="btn-start")
                    yield Button("Quit", variant="error", id="btn-quit")

        yield Footer()

    @on(Button.Pressed, "#btn-start")
    def _on_start(self) -> None:
        """Validate form inputs and transition to the discovery screen."""
        try:
            request = AuditRequest.model_validate(
                {
                    "site_name": self.query_one("#site-name", Input).value,
                    "seeds": self.query_one("#seeds", Input).value,
                    "primary_user": self.query_one("#primary-user", Input).value,
                    "primary_pass": self.query_one("#primary-pass", Input).value,
                    "answer_user": self.query_one("#answer-user", Input).value,
                    "answer_pass": self.query_one("#answer-pass", Input).value,
                    "jump_host": self.query_one("#jump-host", Input).value,
                    "ip_filter": self.query_one("#ip-filter", Input).value,
                }
            )
        except ValidationError as exc:
            self.notify(describe_validation_error(exc), severity="error")
            return

        if self.query_one("#save-creds", Checkbox).value:
            self._creds.save_primary(
                request.primary_user, request.primary_pass.get_secret_value()
            )
            if request.answer_user and request.answer_pass:
                self._creds.save_answer(
                    request.answer_user, request.answer_pass.get_secret_value()
                )

        self.app.push_screen(DiscoveryScreen(request))

    @on(Button.Pressed, "#btn-quit")
    def _on_quit(self) -> None:
        self.app.exit()


# ---------------------------------------------------------------------------
# Discovery screen
# ---------------------------------------------------------------------------

class DiscoveryScreen(Screen):
    """Live discovery dashboard with statistics panel and scrollable log."""

    BINDINGS = [
        Binding("ctrl+s", "stop_discovery", "Stop"),
        Binding("ctrl+q", "app.quit", "Quit"),
    ]

    def __init__(self, request: AuditRequest) -> None:
        super().__init__()
        self._request = request
        self._discoverer: Optional[NetworkDiscoverer] = None
        self._spinner_idx: int = 0
        self._status_msg: str = "Initialising…"
        self._status_state: str = "running"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="discovery-body"):
            with Vertical(id="stats-pane"):
                yield Static("STATISTICS", id="stats-heading")
                yield Static(f"Site:  {self._request.site_name}", classes="stat-item")
                yield Static(f"Seeds: {len(self._request.seeds)}", classes="stat-item")
                yield Static(
                    f"Mode:  {config.DISCOVERY_MODE.display_name}",
                    classes="stat-item",
                )
                yield Static("", id="stats-table")
            with Vertical(id="log-pane"):
                yield Static("LIVE LOG", id="log-heading")
                yield RichLog(id="audit-log", highlight=True, markup=True, wrap=True)
        with Horizontal(id="status-bar"):
            yield Static(
                f"[green]{_SPINNER_FRAMES[0]}[/]  Initialising…", id="status-text"
            )
        yield Footer()

    def on_mount(self) -> None:
        self._attach_tui_handler()
        self.set_interval(0.5, self._refresh_stats)
        self._run_discovery()

    def action_stop_discovery(self) -> None:
        """Stop crawling and write a report from what has been collected."""
        discoverer = self._discoverer
        if discoverer is None:
            self.notify("Discovery has not started yet.", severity="warning")
            return
        if discoverer.stop_event.is_set():
            self.notify("Already stopping — waiting for in-flight devices.")
            return
        discoverer.request_stop()
        self._set_status(
            "Stopping — finishing devices in flight…", state="running"
        )
        self.notify(
            "Stopping after the devices currently being queried. "
            "A report will still be written."
        )

    # ── Internals ────────────────────────────────────────────────────────────

    def _attach_tui_handler(self) -> None:
        """Replace console (stream) handlers with the TUI log handler."""
        root = logging.getLogger()
        # Keep file handlers; remove plain stream handlers so Textual's terminal
        # is not polluted with raw log output.
        root.handlers = [
            h for h in root.handlers
            if isinstance(h, logging.FileHandler)
            or not isinstance(h, logging.StreamHandler)
        ]
        tui_handler = TUILogHandler(self)  # pass the screen, not the app
        tui_handler.setLevel(logging.DEBUG)
        root.addHandler(tui_handler)
        for name in _NOISY_LOGGERS:
            logging.getLogger(name).setLevel(logging.WARNING)

    def on_append_log(self, event: AppendLog) -> None:
        """Receive a log line from the TUILogHandler and write it to the RichLog widget."""
        try:
            self.query_one("#audit-log", RichLog).write(event.markup)
        except Exception:
            pass

    def _refresh_stats(self) -> None:
        """Polling callback — refreshes statistics panel and spinner every 0.5 s."""
        if self._status_state == "running":
            self._spinner_idx = (self._spinner_idx + 1) % len(_SPINNER_FRAMES)
            frame = _SPINNER_FRAMES[self._spinner_idx]
            try:
                self.query_one("#status-text", Static).update(
                    f"[green]{frame}[/]  {markup_escape(self._status_msg)}"
                )
            except Exception:
                pass

        if self._discoverer is None:
            return
        d = self._discoverer
        try:
            self.query_one("#stats-table", Static).update(self._make_stats_table(d))
        except Exception:
            pass

    def _set_status(self, msg: str, state: str = "running") -> None:
        """Status bar update, safe from the UI thread or a worker thread.

        state: 'running' | 'ok' | 'error'.
        """
        def _update() -> None:
            try:
                self._status_msg = msg
                self._status_state = state
                widget = self.query_one("#status-text", Static)
                if state == "ok":
                    widget.update(f"[bold green]✓[/]  {markup_escape(msg)}")
                elif state == "error":
                    widget.update(f"[bold red]✗[/]  {markup_escape(msg)}")
                else:
                    frame = _SPINNER_FRAMES[self._spinner_idx]
                    widget.update(f"[green]{frame}[/]  {markup_escape(msg)}")
            except Exception:
                pass

        try:
            self.app.call_from_thread(_update)
        except RuntimeError:
            # call_from_thread refuses to run on the app's own thread, which is
            # where key bindings such as the Stop action are dispatched.
            _update()

    def _make_stats_table(self, d: "NetworkDiscoverer") -> Table:
        """Build a Rich Table for the live statistics pane."""
        table = Table(box=None, padding=(0, 0), show_header=False, expand=True)
        table.add_column("label", no_wrap=True)
        table.add_column("value", justify="right", no_wrap=True)
        table.add_row("Discovered", str(len(d.visited)))
        table.add_row("Queued", str(d.host_queue.qsize()))
        table.add_row("Neighbor entries", str(len(d.neighbour_details)))
        table.add_row("", "")  # visual separator
        auth_count = len(d.authentication_errors)
        conn_count = len(d.connection_errors)
        table.add_row(
            "Auth errors",
            Text(str(auth_count), style="bold yellow" if auth_count else ""),
        )
        table.add_row(
            "Conn errors",
            Text(str(conn_count), style="bold yellow" if conn_count else ""),
        )
        return table

    # ── Discovery worker ──────────────────────────────────────────────────────

    @work(thread=True)
    def _run_discovery(self) -> None:
        """Full discovery pipeline — runs in a background thread."""
        try:
            self._set_status("Validating support files…")
            cdp_tmpl = config.CDP_TEMPLATE
            lldp_tmpl = config.LLDP_TEMPLATE
            ver_tmpl = config.VER_TEMPLATE
            xl_tmpl = config.EXCEL_TEMPLATE
            validate_required_files(config.REQUIRED_SUPPORT_FILES)
            validate_excel_template(xl_tmpl)

            self._set_status("Resolving seed devices…")
            validated_seeds = normalize_seeds(list(self._request.seeds))

            discoverer = NetworkDiscoverer(
                timeout=config.DEFAULT_TIMEOUT,
                limit=config.DEFAULT_LIMIT,
                cdp_template=cdp_tmpl,
                ver_template=ver_tmpl,
                ip_filter=self._request.ip_filter or None,
                discovery_mode=config.DISCOVERY_MODE,
                lldp_template=lldp_tmpl,
            )
            self._discoverer = discoverer

            for seed in validated_seeds:
                with discoverer.visited_lock:
                    if seed not in discoverer.visited and seed not in discoverer.enqueued:
                        discoverer.enqueued.add(seed)
                        discoverer.host_queue.put(seed)

            self._set_status("Discovering network…")
            # Shutdown is driven explicitly rather than by a `with` block: the
            # implicit shutdown(wait=True) would block indefinitely on a wedged
            # worker, which is what made a stuck crawl unrecoverable before.
            request = self._request
            pool = ThreadPoolExecutor(max_workers=config.DEFAULT_LIMIT)
            try:
                futures = [
                    pool.submit(
                        discoverer.discover_worker,
                        request.jump_host,
                        request.primary_user,
                        request.primary_pass.get_secret_value(),
                        request.answer_user,
                        (
                            request.answer_pass.get_secret_value()
                            if request.answer_pass is not None
                            else None
                        ),
                    )
                    for _ in range(config.DEFAULT_LIMIT)
                ]
                discoverer.wait_until_idle(futures)
            finally:
                # A sentinel per worker retires the pool. Workers that already
                # exited leave theirs in the queue, which is harmless because
                # nothing waits on the queue draining any more.
                for _ in range(config.DEFAULT_LIMIT):
                    discoverer.host_queue.put(None)
                _, still_running = wait(futures, timeout=config.DEFAULT_TIMEOUT * 3)
                if still_running:
                    logger.warning(
                        "%d worker(s) still finishing; continuing with the "
                        "results collected so far",
                        len(still_running),
                    )
                discoverer.close_jump_host()
                pool.shutdown(wait=False)

            if discoverer.stop_event.is_set():
                self._set_status("Stopped — writing partial report…")

            self._set_status("Resolving DNS…")
            discoverer.resolve_dns_parallel()

            self._set_status("Writing Excel report…")
            reporter = ExcelReporter(xl_tmpl)
            output_file = reporter.save_to_excel(
                discoverer.neighbour_details,
                validated_seeds,
                request.site_name,
                discoverer.dns_ip,
                discoverer.authentication_errors,
                discoverer.connection_errors,
                discoverer.device_inventory,
                discovery_mode=config.DISCOVERY_MODE.display_name,
            )

            self._set_status(f"Complete — {output_file}", state="ok")
            self.app.call_from_thread(self._refresh_stats)

            # Push the summary screen from the event loop
            def _show_complete() -> None:
                self.app.push_screen(
                    CompleteScreen(
                        discovered=len(discoverer.visited),
                        neighbor_entries=len(discoverer.neighbour_details),
                        discovery_mode=config.DISCOVERY_MODE.display_name,
                        auth_errors=len(discoverer.authentication_errors),
                        conn_errors=len(discoverer.connection_errors),
                        output_file=output_file,
                    )
                )

            self.app.call_from_thread(_show_complete)

        except SystemExit:
            self._set_status("Fatal error — check the log above for details", state="error")
        except Exception as exc:
            logger.exception("Discovery pipeline failed unexpectedly")
            self._set_status(f"Error: {exc}", state="error")


# ---------------------------------------------------------------------------
# Complete screen
# ---------------------------------------------------------------------------

class CompleteScreen(Screen):
    """Summary screen shown after a successful audit run."""

    BINDINGS = [
        Binding("escape", "back_to_log", "Back to Log"),
        Binding("ctrl+q", "app.quit", "Quit"),
    ]

    def __init__(
        self,
        *,
        discovered: int,
        neighbor_entries: int,
        discovery_mode: str,
        auth_errors: int,
        conn_errors: int,
        output_file: str,
    ) -> None:
        super().__init__()
        self._discovered  = discovered
        self._neighbor_entries = neighbor_entries
        self._discovery_mode = discovery_mode
        self._auth_errors = auth_errors
        self._conn_errors = conn_errors
        self._output_file = output_file

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="complete-container"):
            yield Static("AUDIT COMPLETE", id="complete-title")
            yield Static(self._make_complete_table(), id="complete-table")
            yield Static(f"Output → {self._output_file}", id="output-path")
            with Horizontal(id="complete-btn-row"):
                yield Button("Back to Log", variant="default", id="btn-back")
                yield Button("Quit", variant="primary", id="btn-quit-final")
        yield Footer()

    def _make_complete_table(self) -> Table:
        """Build a Rich Table for the audit summary screen."""
        table = Table(box=None, padding=(0, 1), show_header=False, expand=True)
        table.add_column("label", style="dim", no_wrap=True)
        table.add_column("value", justify="right", no_wrap=True)
        table.add_row("Discovered devices", str(self._discovered))
        table.add_row("Discovery mode", self._discovery_mode)
        table.add_row("Neighbor entries", str(self._neighbor_entries))
        table.add_row("", "")  # visual separator
        auth_style = "bold yellow" if self._auth_errors else "green"
        conn_style = "bold yellow" if self._conn_errors else "green"
        table.add_row(
            "Auth errors",
            Text(str(self._auth_errors), style=auth_style),
        )
        table.add_row(
            "Connection errors",
            Text(str(self._conn_errors), style=conn_style),
        )
        if self._auth_errors or self._conn_errors:
            total_errors = self._auth_errors + self._conn_errors
            pct = 100 * total_errors / self._discovered if self._discovered else 0.0
            table.add_row(
                "Error rate",
                Text(f"{pct:.1f}%", style="bold yellow"),
            )
        return table

    @on(Button.Pressed, "#btn-back")
    def _back(self) -> None:
        self.app.pop_screen()

    @on(Button.Pressed, "#btn-quit-final")
    def _quit(self) -> None:
        self.app.exit()

    def action_back_to_log(self) -> None:
        self.app.pop_screen()


# ---------------------------------------------------------------------------
# Application shell
# ---------------------------------------------------------------------------

class CDPAuditApp(App):
    """Textual application shell for Cisco Discovery Audit."""

    TITLE = "Nautomation Prime Cisco Discovery Audit"
    BINDINGS = [Binding("ctrl+q", "quit", "Quit")]

    CSS = """
    /* ─── Global ──────────────────────────────────────────────────────────── */

    Screen {
        background: $background;
    }

    /* ─── Setup screen ─────────────────────────────────────────────────────── */

    SetupScreen {}

    #setup-outer {
        width: 100%;
        height: 1fr;
        align: center top;
    }

    #setup-inner {
        width: 84;
        height: auto;
        border: round $primary;
        padding: 1 3;
        background: $surface;
    }

    #app-title {
        text-align: center;
        text-style: bold;
        color: $primary;
        margin-bottom: 1;
        padding-bottom: 1;
        border-bottom: solid $primary;
    }

    .section-label {
        text-style: bold;
        color: $accent;
        margin-top: 1;
        margin-bottom: 0;
    }

    .field-label {
        color: $text-muted;
        margin-bottom: 0;
    }

    .cred-ok {
        color: $success;
    }

    .cred-missing {
        color: $warning;
    }

    #btn-row {
        align: center middle;
        height: 3;
        margin-top: 1;
    }

    #btn-start {
        margin-right: 2;
    }

    /* ─── Discovery screen ─────────────────────────────────────────────────── */

    #discovery-body {
        height: 1fr;
    }

    #stats-pane {
        width: 26;
        min-width: 22;
        border-right: solid $primary;
        padding: 1 2;
        background: $surface;
    }

    #stats-heading {
        text-align: center;
        text-style: bold;
        color: $primary;
        margin-bottom: 1;
    }

    .stat-item {
        height: 1;
    }

    #log-pane {
        width: 1fr;
        padding: 0 1;
    }

    #log-heading {
        text-style: bold;
        color: $primary;
    }

    #status-bar {
        height: 3;
        border-top: solid $primary;
        background: $surface;
        padding: 0 2;
        align: left middle;
    }

    /* ─── Complete screen ──────────────────────────────────────────────────── */

    CompleteScreen {
        align: center middle;
    }

    #complete-container {
        width: 66;
        border: round $success;
        padding: 2 4;
        background: $surface;
    }

    #complete-title {
        text-align: center;
        text-style: bold;
        color: $success;
        margin-bottom: 1;
        padding-bottom: 1;
        border-bottom: solid $success;
    }

    #complete-table {
        margin-bottom: 1;
    }

    #output-path {
        color: $text;
        text-style: italic;
        margin-bottom: 1;
    }

    #complete-btn-row {
        align: center middle;
        height: 3;
        margin-top: 1;
    }

    #btn-back {
        margin-right: 2;
    }
    """

    def on_mount(self) -> None:
        version = "unknown"
        for line in get_version_info().splitlines():
            if line.lower().startswith("version:"):
                version = line.split(":", 1)[1].strip()
                break
        self.sub_title = (
            f"v{version}  ·  {config.DISCOVERY_MODE.display_name} discovery"
        )
        self.push_screen(SetupScreen())
