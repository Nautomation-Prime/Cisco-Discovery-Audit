"""Module entry point."""

import sys

import yaml

from .config_loader import ConfigError


def main() -> None:
    """Run the CLI, reporting configuration problems without a traceback.

    The YAML config is loaded and validated when the CLI module is imported,
    so the import itself is what can fail on a bad config.yaml.
    """
    try:
        from .cli import main as cli_main
    except (ConfigError, FileNotFoundError, yaml.YAMLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    cli_main()


if __name__ == "__main__":
    main()
