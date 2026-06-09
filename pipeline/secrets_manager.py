"""
Credential resolution with layered fallback.

Resolution order: explicit arg -> .env file -> environment variable -> interactive prompt.

Layer 2 — imports from Layer 0 (constants, helpers).
"""

import getpass
import logging
import os
from pathlib import Path

from pipeline.constants import HAS_DOTENV
from pipeline.helpers import interactive_prompt

logger = logging.getLogger(__name__)


class SecretsManager:
    """
    Resolves credentials from multiple sources with secure fallback.

    Quick-start
    -----------
        from pipeline.secrets_manager import SecretsManager
        sm = SecretsManager()
        password = sm.get_password("DB_PASSWORD")
    """

    def __init__(self, env_file: str = ".env") -> None:
        self._env: dict = {}
        if HAS_DOTENV and Path(env_file).exists():
            from dotenv import dotenv_values
            self._env = {k: v for k, v in dotenv_values(env_file).items() if v}

    def get(self, key: str, prompt_msg: str = "", default: str = "",
            explicit: str | None = None) -> str:
        if explicit is not None:
            return explicit
        if key in self._env:
            return self._env[key]  # type: ignore[no-any-return]
        if key in os.environ:
            return os.environ[key]
        return interactive_prompt(prompt_msg or key, default)

    def get_password(self, key: str, prompt_msg: str = "Password",
                     explicit: str | None = None) -> str:
        if explicit is not None:
            return explicit
        if key in self._env:
            return self._env[key]  # type: ignore[no-any-return]
        if key in os.environ:
            return os.environ[key]
        return getpass.getpass(f"{prompt_msg}: ")
