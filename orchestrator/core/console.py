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
  --- label  ---  step header console.step_header(label)

Indentation
-----------
Depth is implicit. `section()` and `section_end()` reset depth to 0;
`step_header()` prints its header at depth 0 then opens depth 1, so every
subsequent emit inside the step is auto-indented. Callers do not pass
`indent=True` -- a `with console.indented():` block is the explicit escape
hatch for anything that needs to nest deeper than the structural defaults.

State is held in a ContextVar so concurrent contexts (threads, asyncio
tasks) cannot trample each other's depth.

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
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator

_log = logging.getLogger("console")

_RESET = "\033[0m"
_COLORS = {
    "[*]": "\033[34m",  # blue:   running
    "[+]": "\033[32m",  # green:  success
    "[i]": "\033[36m",  # cyan:   info
    "[!]": "\033[33m",  # yellow: warning
    "[-]": "\033[31m",  # red:    error
}

_INDENT_UNIT = "    "

# Current indent depth. Mutated only by section/step_header/section_end and
# by the indented() context manager. ContextVar (not a plain int) so a
# future async or threaded caller can't corrupt the depth seen by another.
_indent_level: ContextVar[int] = ContextVar("console_indent_level", default=0)


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
        # Preserve leading newlines and indentation; locate the prefix after them.
        stripped = msg.lstrip("\n").lstrip(" ")
        leading = msg[: len(msg) - len(stripped)]
        for token, color in _COLORS.items():
            if stripped.startswith(token):
                return f"{leading}{color}{token}{_RESET}{stripped[len(token):]}"
        return msg


def _prefix() -> str:
    return _INDENT_UNIT * _indent_level.get()


# --- emitters --------------------------------------------------------------


def step(msg: str) -> None:
    """[*] in-progress action. Caller usually ends `msg` with '...'."""
    _log.info("%s[*] %s", _prefix(), msg)


def ok(msg: str) -> None:
    """[+] success / done. No trailing punctuation by convention."""
    _log.info("%s[+] %s", _prefix(), msg)


def info(msg: str) -> None:
    """[i] state / informational note."""
    _log.info("%s[i] %s", _prefix(), msg)


def warn(msg: str) -> None:
    """[!] warning."""
    _log.warning("%s[!] %s", _prefix(), msg)


def err(msg: str) -> None:
    """[-] error."""
    _log.error("%s[-] %s", _prefix(), msg)


# --- structural transitions ------------------------------------------------


def section(title: str) -> None:
    """`=== title ===` top-level section. Resets indent to 0."""
    _indent_level.set(0)
    _log.info("\n=== %s ===", title)


def step_header(label: str) -> None:
    """
    `--- label ---` sub-header at depth 0; subsequent emits indent one level.
    Pairs with section_end() to close.
    """
    _indent_level.set(0)
    _log.info("\n--- %s ---", label)
    _indent_level.set(1)


def section_end() -> None:
    """Blank line + reset depth to 0. Closes a step_header block."""
    _indent_level.set(0)
    _log.info("")


# --- explicit nesting ------------------------------------------------------


@contextmanager
def indented() -> Iterator[None]:
    """
    Push one extra indent level for the block. Escape hatch for callers that
    need to nest deeper than the structural defaults; the context manager
    pattern guarantees the level is restored even on exceptions.
    """
    token = _indent_level.set(_indent_level.get() + 1)
    try:
        yield
    finally:
        _indent_level.reset(token)
