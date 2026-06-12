"""
Interactive terminal prompts — the only module that reads stdin.

Extracted from helpers.py so the shared-utility module stays pure
(no I/O with the user) and prompting is discoverable by name.

Layer 0 — no internal package imports.

Revision history
────────────────
1.0   2026-06-12   Extracted from helpers.py (interactive_prompt,
                   confirm_yes_no).
"""


def interactive_prompt(message: str, default: str = "") -> str:
    """Interactive prompt with optional default shown in brackets."""
    display = f"{message} [{default}]: " if default else f"{message}: "
    response = input(display).strip()
    return response if response else default


def confirm_yes_no(message: str, default: bool = True) -> bool:
    """Yes/No prompt. Returns bool; accepts default on empty input."""
    suffix = "[Y/n]" if default else "[y/N]"
    response = input(f"{message} {suffix}: ").strip().lower()
    return default if not response else response in ("y", "yes")
