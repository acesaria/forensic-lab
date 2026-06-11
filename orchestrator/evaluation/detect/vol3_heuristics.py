# orchestrator/evaluation/detect/vol3_heuristics.py
#
# Volatility 3 memory heuristics (Phase 3.2). Each heuristic is scenario-agnostic
# and GT-blind: it flags structural anomalies (hidden process, deleted backing
# binary, exec from a world-writable temp dir, external socket, malfind hit,
# recovered bash history) without ever knowing a planted value. Memory findings
# carry no reliable wall-clock time -> ts_quality "none".
#
# Operates on already-extracted plugin JSON (raw_outputs["vol3"][plugin] -> rows)
# so it is unit-testable without a live image.

from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable

from orchestrator.evaluation.detect.base import make_finding
from orchestrator.evaluation.contracts.models import Finding

_TOOL = "vol3"
_TEMP_EXEC_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
_ADDR_RE = re.compile(r"(?P<ip>[0-9a-fA-F:.]+):(?P<port>\d+)$")


def _first(row: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return row[k]
    return None


def _rows(raw: dict[str, Any], plugin: str) -> list[dict[str, Any]]:
    vol = raw.get("vol3", {})
    rows = vol.get(plugin)
    return rows if isinstance(rows, list) else []


def _pid(row: dict[str, Any]) -> Any:
    return _first(row, "PID", "Pid", "pid")


def _comm(row: dict[str, Any]) -> str:
    v = _first(row, "Process Name", "Comm", "Process", "Name")
    return str(v) if v is not None else ""


def detect_hidden_process(raw: dict[str, Any], cfg: dict[str, Any]) -> Iterable[Finding]:
    # T1014: present in psscan (pool scan) but absent from pslist (active list).
    # A rootkit-hidden task keeps a valid command name; psscan-only rows with an
    # empty name are smeared/terminated pool structures, not hidden processes, so
    # requiring a non-empty comm drops that noise without losing a real hide.
    pslist_pids = {_pid(r) for r in _rows(raw, "linux.pslist")}
    for r in _rows(raw, "linux.psscan"):
        pid = _pid(r)
        if pid is None or pid in pslist_pids:
            continue
        comm = _comm(r).strip()
        if not comm:
            continue
        yield make_finding(
            source_tool=_TOOL,
            detector="vol3:hidden_process",
            event_class="process_exec",
            entity_type="process",
            entity_value=comm,
            ts_quality="none",
            technique="T1014",
            raw_ref=f"vol3:linux.psscan:pid={pid}",
            confidence="high",
        )


def detect_deleted_binary(raw: dict[str, Any], cfg: dict[str, Any]) -> Iterable[Finding]:
    # T1036/T1070: a running process whose backing executable is gone from disk.
    for plugin in ("linux.pslist", "linux.elfs", "linux.psscan"):
        for r in _rows(raw, plugin):
            path = _first(r, "File Path", "Path", "FilePath", "File")
            if isinstance(path, str) and "(deleted)" in path:
                yield make_finding(
                    source_tool=_TOOL,
                    detector="vol3:deleted_backing_binary",
                    event_class="process_exec",
                    entity_type="process",
                    entity_value=path.replace(" (deleted)", "").strip(),
                    ts_quality="none",
                    technique="T1070.004",
                    raw_ref=f"vol3:{plugin}:pid={_pid(r)}",
                    confidence="medium",
                )


def detect_temp_exec_mapping(raw: dict[str, Any], cfg: dict[str, Any]) -> Iterable[Finding]:
    # T1059: executable region mapped from a world-writable temp directory.
    for plugin in ("linux.proc.Maps", "linux.malfind"):
        for r in _rows(raw, plugin):
            path = _first(r, "File Path", "Path", "FilePath", "File", "Mapping")
            if not isinstance(path, str):
                continue
            if any(path.startswith(d) or d in path for d in _TEMP_EXEC_DIRS):
                yield make_finding(
                    source_tool=_TOOL,
                    detector="vol3:temp_exec_mapping",
                    event_class="process_exec",
                    entity_type="path",
                    entity_value=path.strip(),
                    ts_quality="none",
                    technique="T1059.004",
                    raw_ref=f"vol3:{plugin}:pid={_pid(r)}",
                    confidence="medium",
                )


def detect_malfind(raw: dict[str, Any], cfg: dict[str, Any]) -> Iterable[Finding]:
    # T1055: anomalous executable memory region (injected code).
    for r in _rows(raw, "linux.malfind"):
        pid = _pid(r)
        start = _first(r, "Start", "Start VPN", "Address")
        yield make_finding(
            source_tool=_TOOL,
            detector="vol3:malfind",
            event_class="process_exec",
            entity_type="process",
            entity_value=f"{_comm(r)}".strip() or str(pid),
            ts_quality="none",
            technique="T1055",
            raw_ref=f"vol3:linux.malfind:pid={pid}:start={start}",
            confidence="medium",
        )


def _is_external(ip: str, cfg: dict[str, Any]) -> bool:
    # External = not loopback and not RFC1918 (configurable allowlist of private
    # ranges). A non-parseable address is treated as not-external (skip).
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_unspecified:
        return False
    extra = cfg.get("vol3", {}).get("private_ranges", []) if cfg else []
    for cidr in extra:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return False
        except ValueError:
            continue
    return True


def _port_int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _no_peer(ip: str | None) -> bool:
    # Listening sockets carry an unspecified remote endpoint, not a real peer.
    return ip is None or str(ip).strip() in ("", "0.0.0.0", "::", "*")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def detect_suspicious_socket(raw: dict[str, Any], cfg: dict[str, Any]) -> Iterable[Finding]:
    # A connection is suspicious when it reaches an external (non-RFC1918)
    # address, OR when it is an outbound connection (ephemeral local port) to a
    # remote port that is not a well-known service: the reverse-shell pattern.
    # The second arm catches C2 on the lab's own private network, which the
    # external-only test would miss. No instance port/address is hardcoded; the
    # service-port allowlist and ephemeral floor are behavioral classes.
    vol_cfg = (cfg.get("vol3", {}) if cfg else {}) or {}
    service_ports = {
        _port_int(p) for p in vol_cfg.get("service_ports", [22, 53, 80, 123, 443])
    }
    ephemeral_min = int(vol_cfg.get("ephemeral_min_port", 32768))

    for plugin in ("linux.sockstat", "linux.netstat", "linux.sockscan"):
        for r in _rows(raw, plugin):
            proto = str(_first(r, "Proto", "Protocol") or "")
            if proto and "TCP" not in proto.upper():
                # UNIX/NETLINK/UDP rows are not a network connection of interest.
                continue
            dst_ip = _first(r, "Destination Addr", "ForeignAddr", "Foreign Address", "Dest IP", "DestinationAddr")
            dst_port = _first(r, "Destination Port", "ForeignPort", "Foreign Port", "DestinationPort")
            src_port = _first(r, "Source Port", "LocalPort", "Local Port", "SourcePort")
            if dst_ip is None:
                # Some builds fold "ip:port" into one string column.
                for v in r.values():
                    if isinstance(v, str):
                        m = _ADDR_RE.search(v)
                        if m:
                            dst_ip, dst_port = m.group("ip"), m.group("port")
                            break
            if not isinstance(dst_ip, str) or _no_peer(dst_ip):
                continue
            dport = _port_int(dst_port)
            sport = _port_int(src_port)
            if dport is None or dport <= 0 or not _is_ip(dst_ip):
                # A real connection has a parseable peer IP and non-zero port.
                continue
            external = _is_external(dst_ip, cfg)
            outbound_unusual = (
                dport is not None
                and dport not in service_ports
                and sport is not None
                and sport >= ephemeral_min
            )
            if not (external or outbound_unusual):
                continue
            value = f"{dst_ip}:{dport}" if dport is not None else dst_ip
            yield make_finding(
                source_tool=_TOOL,
                detector="vol3:suspicious_socket",
                event_class="network_connection",
                entity_type="socket",
                entity_value=value,
                ts_quality="none",
                technique="T1071",
                raw_ref=f"vol3:{plugin}:pid={_pid(r)}",
                confidence="medium",
            )


def detect_bash_history(raw: dict[str, Any], cfg: dict[str, Any]) -> Iterable[Finding]:
    # Recovered bash history is emitted as-is; the matcher decides relevance.
    for r in _rows(raw, "linux.bash"):
        cmd = _first(r, "Command", "command", "CommandLine")
        if not isinstance(cmd, str) or not cmd.strip():
            continue
        yield make_finding(
            source_tool=_TOOL,
            detector="vol3:bash_history",
            event_class="process_exec",
            entity_type="process",
            entity_value=cmd.strip(),
            ts_quality="none",
            technique="T1059.004",
            raw_ref=f"vol3:linux.bash:pid={_pid(r)}",
            confidence="low",
        )


_DETECTORS = (
    detect_hidden_process,
    detect_deleted_binary,
    detect_temp_exec_mapping,
    detect_malfind,
    detect_suspicious_socket,
    detect_bash_history,
)


def detect(raw_outputs: dict[str, Any], rules_config: dict[str, Any]) -> Iterable[Finding]:
    for fn in _DETECTORS:
        yield from fn(raw_outputs, rules_config)
