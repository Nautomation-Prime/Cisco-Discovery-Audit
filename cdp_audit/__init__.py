"""Nautomation Prime Cisco Discovery Audit package.

Expose a minimal public surface so the package can be imported cleanly while
keeping side effects (like logging setup) behind the CLI entry point.
"""

from __future__ import annotations

from .version import get_version


def main() -> None:
    """Run the CLI entry point when invoked programmatically."""
    from .__main__ import main as _main

    _main()


__version__ = get_version()

__all__ = ["__version__", "main"]
