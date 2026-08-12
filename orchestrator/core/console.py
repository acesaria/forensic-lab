"""
orchestrator/core/console.py

Tiny centralized helpers for status lines. Thin wrapper over `logging` so
formatting, log levels, and per-module loggers stay centralized.

Convention
----------
  [*]  step in progress       console.step(msg)
  [+]  success / done         console.ok(msg)
  [i]  info / state           console.info(msg)
  [!]  warning                console.warn(msg)
  [-]  error                  console.err(msg)
  [d]  debug record           PrefixColorFormatter
  [HOST] / [GUEST] phase      console.scope(kind, label)
  === title ===  section      console.section(title)
  --- label  ---  step header console.step_header(label)

Indentation
-----------
Depth is implicit. `section()` and `section_end()` reset depth to 0;
`step_header()` prints its header at depth 0 then opens depth 1, so every
subsequent emit inside the step is auto-indented. `scope()` does the same for
HOST/GUEST phases. Callers never pass an indent argument.

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
from contextvars import ContextVar

_log = logging.getLogger("console")

_RESET = "\033[0m"
_COLORS = {
    "[*]": "\033[34m",  # blue:   running
    "[+]": "\033[32m",  # green:  success
    "[i]": "\033[36m",  # cyan:   info
    "[!]": "\033[33m",  # yellow: warning
    "[-]": "\033[31m",  # red:    error
    "[d]": "\033[2m",   # dim:    debug
    "[HOST]": "\033[35m",
    "[GUEST]": "\033[36m",
}
_PROMPT_COLOR = "\033[32m"

_INDENT_UNIT = "    "

# Current indent depth. Mutated only by the structural helpers below.
# ContextVar (not a plain int) so a future async or threaded caller can't
# corrupt the depth seen by another.
_indent_level: ContextVar[int] = ContextVar("console_indent_level", default=0)


def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return sys.stdout.isatty()


class PrefixColorFormatter(logging.Formatter):
    """Prefix DEBUG records and color recognized leading status tokens."""

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        # Preserve leading newlines and indentation; locate the prefix after them.
        stripped = msg.lstrip("\n").lstrip(" ")
        leading = msg[: len(msg) - len(stripped)]
        if record.levelno == logging.DEBUG and not stripped.startswith("[d]"):
            stripped = f"[d] {stripped}"
            msg = f"{leading}{stripped}"
        if not _color_enabled():
            return msg
        for token, color in _COLORS.items():
            if stripped.startswith(token):
                return f"{leading}{color}{token}{_RESET}{stripped[len(token):]}"
        return msg


def _prefix() -> str:
    return _INDENT_UNIT * _indent_level.get()


def format_terminal(text: str, *, prompt: bool = False) -> str:
    """Indent terminal display text, coloring only a leading shell prompt."""
    if prompt and _color_enabled():
        text = f"{_PROMPT_COLOR}${_RESET}{text[1:]}"
    prefix = _prefix()
    return "".join(prefix + line for line in text.splitlines(keepends=True))


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


def scope(kind: str, label: str) -> None:
    """Print a HOST/GUEST phase at depth 0 and indent its contents."""
    _indent_level.set(0)
    _log.info("\n[%s] %s", kind, label)
    _indent_level.set(1)


def section_end() -> None:
    """Reset depth to 0. Closes a step_header block."""
    _indent_level.set(0)
