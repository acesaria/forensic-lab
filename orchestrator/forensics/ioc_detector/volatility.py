# orchestrator/forensics/ioc_detector/volatility.py
#
# Memory detection (Volatility 3). An artifact_category resolves to an ordered
# list of vol3 plugins; the detector walks them in priority order and stops at
# the first that yields a match, recording the winning plugin as evidence.method.
# vol3 column spellings drift between builds, so matching scans candidate keys
# (and, as a fallback, every string value) rather than hard-coding one schema.

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from orchestrator.forensics.ioc_detector.status import (
    DISK_STATUS_PRESENT,
    empty_detection,
)
from orchestrator.forensics.vol_runner import first_present

if TYPE_CHECKING:
    from orchestrator.forensics.ioc_detector.context import DetectorContext

_ADDR_RE = re.compile(r"[\d.:a-f]+:\d+$", re.IGNORECASE)


# An artifact_category resolves to an ordered list of vol3 plugins. A spec says
# "shared_library" instead of pinning a plugin name that drifts between releases.
# Scenario 02 categories are listed now so adding a spec stays data-only.
MEMORY_CATEGORY_PLUGINS: dict[str, tuple[str, ...]] = {
    "shared_library": ("linux.proc.Maps",),
    # sockstat walks live process fd tables; sockscan pool-scans for socket
    # structs and so recovers a connection whose owning process has already
    # exited (e.g. a reverse shell left in CLOSE state). Try the richer sockstat
    # first, fall back to sockscan for the orphaned case.
    "network_socket": ("linux.sockstat", "linux.sockscan"),
    "process": ("linux.pslist", "linux.psscan"),
    "kernel_module": ("linux.lsmod", "linux.hidden_modules", "linux.check_modules"),
    "syscall_hook": ("linux.check_syscall",),
    "credential_artifact": ("linux.bash", "linux.envars"),
    "ebpf_program": ("linux.bpf", "linux.ebpf"),
}


def _resolve_memory_plugins(spec: dict[str, Any]) -> tuple[str, ...]:
    # Explicit query["plugin"] wins for backward compatibility; otherwise the
    # candidate list comes from artifact_category.
    explicit = spec.get("query", {}).get("plugin")
    if explicit:
        return (explicit,)
    return MEMORY_CATEGORY_PLUGINS.get(spec.get("artifact_category", ""), ())


def _row_string_values(row: dict[str, Any]) -> list[str]:
    return [v for v in row.values() if isinstance(v, str)]


def _row_contains(row: dict[str, Any], needle: str) -> bool:
    # Prefer a path/name-like column, fall back to every string value: vol3
    # column names drift, so scanning all strings keeps substring matching robust.
    mapped = first_present(row, "File Path", "Path", "FilePath", "File", "Name", "Module")
    haystacks = [mapped] if isinstance(mapped, str) else _row_string_values(row)
    return any(needle in h for h in haystacks)


def _summarize_row(row: dict[str, Any]) -> dict[str, Any]:
    # Tolerant projection of the columns a reviewer cares about; absent ones are
    # dropped so the match record stays readable across different plugins.
    fields = {
        "pid": first_present(row, "PID", "Pid", "pid"),
        "process": first_present(row, "Process Name", "Comm", "Process", "Name"),
        "path": first_present(row, "File Path", "Path", "FilePath", "File"),
        "local_port": first_present(row, "LocalPort", "Local Port", "Source Port"),
        "foreign_port": first_present(row, "ForeignPort", "Foreign Port", "Destination Port"),
        "state": first_present(row, "State"),
    }
    return {k: v for k, v in fields.items() if v is not None}


def _socket_port_match(row: dict[str, Any], port: int) -> bool:
    # Column names drift between vol3 builds: sockstat/sockscan on recent builds
    # emit "Source Port"/"Destination Port" rather than Local/Foreign.
    local = first_present(row, "LocalPort", "Local Port", "LocalAddr Port", "Source Port")
    foreign = first_present(row, "ForeignPort", "Foreign Port", "Destination Port")

    for value in (local, foreign):
        if isinstance(value, (int, str)):
            try:
                if int(value) == port:
                    return True
            except ValueError:
                continue

    # Some vol3 builds fold the port into an address string ("0.0.0.0:4444").
    for text in _row_string_values(row):
        if _ADDR_RE.match(text) and f":{port}" in text:
            return True

    return False


def _socket_name_ok(
    row: dict[str, Any], names: list[str], has_other_criteria: bool
) -> bool:
    # A present process name must match. But sockscan recovers orphaned socket
    # structs whose owning process has exited: those carry no process name, and
    # rejecting them would discard exactly the post-mortem evidence we want.
    # Accept a nameless row only when some other positive criterion (port/path)
    # already qualified it, so a names-only query stays strict.
    proc = first_present(row, "Process Name", "Comm", "Process")
    if isinstance(proc, str) and proc:
        return any(n in proc for n in names)
    return has_other_criteria


def _match_memory_rows(
    rows: list[dict[str, Any]], query: dict[str, Any]
) -> list[dict[str, Any]]:
    # Match strategy is inferred from which query keys are present, so one matcher
    # serves every category: a path/name substring and/or a socket port with
    # optional process names. Every present criterion must hold.
    path_needle = query.get("path_substring")
    name_needle = query.get("name_substring")
    port = query.get("port")
    names = query.get("process_names")
    if path_needle is None and name_needle is None and port is None and names is None:
        return []

    has_other_criteria = (
        path_needle is not None or name_needle is not None or port is not None
    )

    matches: list[dict[str, Any]] = []
    for row in rows:
        if path_needle is not None and not _row_contains(row, path_needle):
            continue
        if name_needle is not None and not _row_contains(row, name_needle):
            continue
        if port is not None and not _socket_port_match(row, port):
            continue
        if names is not None and not _socket_name_ok(row, names, has_other_criteria):
            continue
        matches.append(_summarize_row(row))
    return matches


def _memory_locator(match: dict[str, Any]) -> str:
    # A human pointer to the matched row: prefer the mapped path, else the owning
    # process, else the local port, so the report names something concrete.
    if match.get("path"):
        return str(match["path"])
    pid = match.get("pid")
    proc = match.get("process")
    if proc or pid is not None:
        return f"pid {pid} {proc}".strip()
    if match.get("local_port") is not None:
        return f"port {match['local_port']}"
    return "-"


def _memory_match_str(query: dict[str, Any]) -> str:
    # Restate the query criteria that had to hold, in the order the matcher checks.
    parts: list[str] = []
    if query.get("port") is not None:
        parts.append(f"port {query['port']}")
    if query.get("process_names"):
        parts.append("proc " + "/".join(query["process_names"]))
    if query.get("path_substring"):
        parts.append(f"path~{query['path_substring']}")
    if query.get("name_substring"):
        parts.append(f"name~{query['name_substring']}")
    return " ".join(parts) or "match"


def detect_memory(spec: dict[str, Any], ctx: "DetectorContext") -> dict[str, Any]:
    query = spec["query"]
    # Walk candidate plugins in priority order; the first non-empty match wins and
    # the winning plugin is recorded as evidence.method.
    for plugin in _resolve_memory_plugins(spec):
        rows = ctx.plugin_rows(plugin)
        matches = _match_memory_rows(rows, query)
        if matches:
            return {
                "found": True,
                "status": DISK_STATUS_PRESENT,
                "evidence": {
                    "tool": "vol3",
                    "method": plugin,
                    "locator": _memory_locator(matches[0]),
                    "match": _memory_match_str(query),
                },
                "timestamp": None,  # a memory snapshot carries no per-artifact time
                "matches": matches,
            }
    return empty_detection()
