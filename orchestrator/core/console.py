"""
orchestrator/core/console.py

Tiny centralized helpers for status lines. Thin wrapper over `logging` so
DEBUG behavior, log levels, and per-module loggers are untouched.

Convention
----------
  [*]  step in progress       console.step(msg)
  [+]  success / done         console.ok(msg)
  [i]  info / state           console.info(msg)
  [!]  warning                console.warn(msg)
  [-]  error                  console.err(msg)
  === title ===  section      console.section(title)

The PrefixColorFormatter below also colors any pre-existing
`_log.info("[X] ...")` call elsewhere in the project, so callers that still
emit through their own module logger get consistent color for free.

Color is enabled only when stdout is a TTY, NO_COLOR is unset, and
TERM != "dumb". Plain text is the fallback. Script-friendly output is
preserved in pipes and CI logs.

Wording conventions for new code
--------------------------------
- [*] uses present-continuous verbs and ends with "..." ("Waiting for SSH...").
- [+] uses past tense or a noun result and has no trailing punctuation
  ("VM 'X' created"; "Memory dump done (18.3s): path").
- [i] is declarative and has no trailing punctuation.
- Identifiers go in single quotes ('lab-ubuntu-22.04'); paths are bare.
- Time durations are written "(N.Ns)" in parentheses before any colon.
"""

from __future__ import annotations

import logging
import os
import sys

_log = logging.getLogger("console")

_RESET = "\033[0m"
_COLORS = {
    "[*]": "\033[34m",  # blue:   running
    "[+]": "\033[32m",  # green:  success
    "[i]": "\033[36m",  # cyan:   info
    "[!]": "\033[33m",  # yellow: warning
    "[-]": "\033[31m",  # red:    error
}


def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return sys.stdout.isatty()


class PrefixColorFormatter(logging.Formatter):
    """Color the leading [X] token of a record; pass everything else through."""

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        if not _color_enabled():
            return msg
        # Preserve leading newlines used for visual breathing room.
        stripped = msg.lstrip("\n")
        leading = msg[: len(msg) - len(stripped)]
        for token, color in _COLORS.items():
            if stripped.startswith(token):
                return f"{leading}{color}{token}{_RESET}{stripped[len(token):]}"
        return msg


def step(msg: str) -> None:
    """[*] in-progress action. Caller usually ends `msg` with '...'."""
    _log.info("[*] %s", msg)


def ok(msg: str) -> None:
    """[+] success / done. No trailing punctuation by convention."""
    _log.info("[+] %s", msg)


def info(msg: str) -> None:
    """[i] state / informational note."""
    _log.info("[i] %s", msg)


def warn(msg: str) -> None:
    """[!] warning."""
    _log.warning("[!] %s", msg)


def err(msg: str) -> None:
    """[-] error."""
    _log.error("[-] %s", msg)


def section(title: str) -> None:
    """Blank line + `=== title ===` header."""
    _log.info("\n=== %s ===", title)
