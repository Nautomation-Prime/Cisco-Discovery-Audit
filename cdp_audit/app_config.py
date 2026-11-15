"""Application configuration access.

Imports the YAML-backed Config object for app-wide settings.
"""

from .config_loader import Config

config = Config()
