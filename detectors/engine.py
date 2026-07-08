"""GT-blind detector engine over ToolFinding records.

Inputs are canonical ToolFinding rows only. This module does not load ground
truth manifests, scenario modules, step names, expected observables, or target
hash/path values.
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

import yaml

from orchestrator.canonical import DetectionClaim, ToolFinding, load_jsonl, write_jsonl

_RULES_DIR = Path(__file__).resolve().parent / "rules"


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    description: str
    source_types: tuple[str, ...]
    artifact_classes: tuple[str, ...]
    attck: tuple[str, ...]
    parameters: dict[str, Any]
    path: Path


DetectorFn = Callable[[Rule, list[ToolFinding]], Iterable[DetectionClaim]]


def run_detectors(
    findings: Iterable[ToolFinding],
    rules_dir: str | Path | None = None,
) -> list[DetectionClaim]:
    items = list(findings)
    claims: list[DetectionClaim] = []
    for rule in load_rules(rules_dir):
        detector = _DETECTORS.get(rule.id)
        if detector is None:
            continue
        claims.extend(detector(rule, items))
    return assign_claim_ids(claims)


def run_detectors_file(
    findings_path: str | Path,
    *,
    rules_dir: str | Path | None = None,
) -> list[DetectionClaim]:
    return run_detectors(load_jsonl(findings_path, ToolFinding), rules_dir=rules_dir)


def write_detection_claims(path: str | Path, claims: Iterable[DetectionClaim]) -> Path:
    return write_jsonl(path, assign_claim_ids(claims))


def load_rules(rules_dir: str | Path | None = None) -> list[Rule]:
    base = Path(rules_dir) if rules_dir is not None else _RULES_DIR
    rules: list[Rule] = []
    for path in sorted(base.rglob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        rules.append(
            Rule(
                id=str(data["id"]),
                name=str(data["name"]),
                description=str(data["description"]),
                source_types=tuple(str(x) for x in data.get("source_types") or []),
                artifact_classes=tuple(str(x) for x in data.get("artifact_classes") or []),
                attck=tuple(str(x) for x in data.get("attck") or []),
                parameters=dict(data.get("parameters") or {}),
                path=path,
            )
        )
    return rules


def assign_claim_ids(claims: Iterable[DetectionClaim]) -> list[DetectionClaim]:
    items = list(claims)
    items.sort(key=_claim_sort_key)
    for idx, claim in enumerate(items):
        digest = hashlib.sha1(
            "|".join(str(x) for x in _claim_sort_key(claim)).encode("utf-8")
        ).hexdigest()[:10]
        claim.claim_id = f"dc-{idx:06d}-{digest}"
    return items


def _claim(
    rule: Rule,
    finding: ToolFinding,
    *,
    artifact_class: str | None = None,
    entity: dict[str, Any] | None = None,
    source_findings: list[str] | None = None,
    notes: str = "",
) -> DetectionClaim:
    return DetectionClaim(
        claim_id="dc-pending",  # assign_claim_ids gives the real deterministic id
        run_id=finding.run_id,
        rule_id=rule.id,
        artifact_class=artifact_class or finding.artifact_class,
        entity=entity or dict(finding.entity),
        source_findings=source_findings or [finding.finding_id],
        attck=list(rule.attck),
        notes=_notes(rule, notes),
    )


def _notes(rule: Rule, extra: str) -> str:
    base = f"{rule.name}: {rule.description}"
    return f"{base} {extra}".strip()


def _claim_sort_key(claim: DetectionClaim) -> tuple[Any, ...]:
    return (
        claim.run_id,
        claim.rule_id,
        claim.artifact_class,
        str(claim.entity.get("type")),
        str(claim.entity.get("value")),
        ",".join(claim.source_findings),
    )


def _source_allowed(rule: Rule, finding: ToolFinding) -> bool:
    return str(finding.source_type.value) in rule.source_types


def _class_allowed(rule: Rule, finding: ToolFinding) -> bool:
    return finding.artifact_class in rule.artifact_classes


def _entity_value(finding: ToolFinding) -> str:
    return str(finding.entity.get("value") or "")


def _entity_path(finding: ToolFinding) -> str:
    value = _entity_value(finding)
    path = finding.entity.get("path")
    if isinstance(path, str) and path:
        return path
    return value


def _pid(finding: ToolFinding) -> Any:
    return finding.entity.get("pid")


def _suspicious_temp_path(rule: Rule, findings: list[ToolFinding]) -> Iterable[DetectionClaim]:
    prefixes = tuple(rule.parameters.get("prefixes") or [])
    for finding in findings:
        if not (_source_allowed(rule, finding) and _class_allowed(rule, finding)):
            continue
        if _entity_path(finding).startswith(prefixes):
            yield _claim(rule, finding)


def _userland_persistence(rule: Rule, findings: list[ToolFinding]) -> Iterable[DetectionClaim]:
    prefixes = tuple(rule.parameters.get("prefixes") or [])
    suffixes = tuple(rule.parameters.get("suffixes") or [])
    for finding in findings:
        if not (_source_allowed(rule, finding) and _class_allowed(rule, finding)):
            continue
        path = _entity_path(finding)
        home_user_service = "/.config/systemd/user/" in path and path.endswith(suffixes)
        systemd_unit = path.startswith(prefixes) and (path.endswith(suffixes) or "/cron" in path)
        if home_user_service or systemd_unit:
            yield _claim(rule, finding)


def _ebpf_object(rule: Rule, findings: list[ToolFinding]) -> Iterable[DetectionClaim]:
    tokens = tuple(str(x).lower() for x in rule.parameters.get("path_tokens") or [])
    for finding in findings:
        if not (_source_allowed(rule, finding) and _class_allowed(rule, finding)):
            continue
        path = _entity_path(finding).lower()
        if any(token in path for token in tokens):
            yield _claim(rule, finding, notes="benign/kernel-like scope")


def _ld_preload_configuration(rule: Rule, findings: list[ToolFinding]) -> Iterable[DetectionClaim]:
    tokens = tuple(str(x).lower() for x in rule.parameters.get("tokens") or [])
    for finding in findings:
        if not (_source_allowed(rule, finding) and _class_allowed(rule, finding)):
            continue
        value = (_entity_value(finding) + " " + str(finding.entity.get("path") or "")).lower()
        if finding.artifact_class == "preload_configuration" or any(token.lower() in value for token in tokens):
            yield _claim(rule, finding, artifact_class="preload_configuration")


def _suspicious_shared_object(rule: Rule, findings: list[ToolFinding]) -> Iterable[DetectionClaim]:
    suffixes = tuple(rule.parameters.get("suffixes") or [])
    prefixes = tuple(rule.parameters.get("suspicious_prefixes") or [])
    tokens = tuple(str(x).lower() for x in rule.parameters.get("suspicious_tokens") or [])
    for finding in findings:
        if not (_source_allowed(rule, finding) and _class_allowed(rule, finding)):
            continue
        path = _entity_path(finding)
        lower = path.lower()
        is_so = path.endswith(suffixes) or ".so." in path
        suspicious = path.startswith(prefixes) or any(token in lower for token in tokens)
        if is_so and suspicious:
            yield _claim(rule, finding, artifact_class="shared_object")


def _deleted_artifact_cleanup(rule: Rule, findings: list[ToolFinding]) -> Iterable[DetectionClaim]:
    for finding in findings:
        if not (_source_allowed(rule, finding) and _class_allowed(rule, finding)):
            continue
        if finding.entity.get("deleted") is False:
            continue
        yield _claim(rule, finding)


def _process_from_unusual_path(rule: Rule, findings: list[ToolFinding]) -> Iterable[DetectionClaim]:
    prefixes = tuple(rule.parameters.get("path_prefixes") or [])
    marker = str(rule.parameters.get("deleted_marker") or "(deleted)")
    for finding in findings:
        if not (_source_allowed(rule, finding) and _class_allowed(rule, finding)):
            continue
        path = _entity_path(finding)
        if path.startswith(prefixes) or marker in path:
            yield _claim(rule, finding)


def _pid_buckets(
    rule: Rule,
    findings: list[ToolFinding],
    other_classes: tuple[str, ...],
) -> Iterable[tuple[str, list[ToolFinding], list[ToolFinding]]]:
    """Group rule-eligible findings by (run_id, pid) into process vs other rows."""
    by_run_pid: dict[tuple[str, str], tuple[list[ToolFinding], list[ToolFinding]]] = {}
    for finding in findings:
        if not (_source_allowed(rule, finding) and _class_allowed(rule, finding)):
            continue
        pid = _pid(finding)
        if pid in (None, ""):
            continue
        procs, others = by_run_pid.setdefault((finding.run_id, str(pid)), ([], []))
        if finding.artifact_class == "process":
            procs.append(finding)
        elif finding.artifact_class in other_classes:
            others.append(finding)
    for (_run_id, pid), (procs, others) in by_run_pid.items():
        yield pid, procs, others


def _process_name(proc: ToolFinding) -> str:
    e = proc.entity
    return str(e.get("name") or e.get("comm") or e.get("value") or e.get("path") or "").lower()


def _process_library_correlation(rule: Rule, findings: list[ToolFinding]) -> Iterable[DetectionClaim]:
    prefixes = tuple(rule.parameters.get("path_prefixes") or [])
    tokens = tuple(str(x).lower() for x in rule.parameters.get("path_tokens") or [])
    for pid, procs, libs in _pid_buckets(rule, findings, ("library_mapping", "shared_object")):
        # One claim per (process name, library path): pslist/psscan duplicates
        # of the same logical process->library link merge into one candidate.
        groups: dict[tuple[str, str], list[tuple[ToolFinding, ToolFinding]]] = {}
        for proc in procs:
            for lib in libs:
                path = _entity_path(lib)
                lower = path.lower()
                if path.startswith(prefixes) or any(token in lower for token in tokens):
                    groups.setdefault((_process_name(proc), lower), []).append((proc, lib))
        for pairs in groups.values():
            proc, lib = pairs[0]
            entity = {
                "type": "process_library",
                "value": f"{proc.entity.get('value')} -> {_entity_path(lib)}",
                "pid": pid,
                "process": dict(proc.entity),
                "library": dict(lib.entity),
            }
            yield _claim(
                rule,
                lib,
                artifact_class="library_mapping",
                entity=entity,
                source_findings=sorted({f.finding_id for pair in pairs for f in pair}),
            )


def _is_remote_connection(finding: ToolFinding) -> bool:
    # A process holding a socket is only suspicious when the socket is an active
    # remote network connection: a real peer IP (not loopback/unspecified) and a
    # non-zero port. Every daemon owns unix, netlink and listening sockets, and
    # the upstream adapter records their paths in the address field, so correlating
    # on any socket would flag the whole system. Requiring a parseable, routable IP
    # rejects all of those.
    remote = finding.entity.get("remote")
    addr = port = ""
    if isinstance(remote, dict):
        addr = str(remote.get("address") or "").strip()
        port = str(remote.get("port") or "").strip()
    if not addr:
        value = str(finding.entity.get("value") or "")
        if ":" in value:
            addr, _, port = value.rpartition(":")
            addr, port = addr.strip(), port.strip()
    addr = addr.strip("[]")
    if not port or port == "0":
        return False
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast)


def _process_socket_correlation(rule: Rule, findings: list[ToolFinding]) -> Iterable[DetectionClaim]:
    for pid, procs, socks in _pid_buckets(rule, findings, ("socket",)):
        # One claim per (process name, endpoint): duplicate scans of the same
        # logical process->connection link merge into one candidate.
        groups: dict[tuple[str, str], list[tuple[ToolFinding, ToolFinding]]] = {}
        for proc in procs:
            for sock in socks:
                if not _is_remote_connection(sock):
                    continue
                key = (_process_name(proc), _entity_value(sock).lower())
                groups.setdefault(key, []).append((proc, sock))
        for pairs in groups.values():
            proc, sock = pairs[0]
            entity = {
                "type": "process_socket",
                "value": f"{proc.entity.get('value')} -> {sock.entity.get('value')}",
                "pid": pid,
                "process": dict(proc.entity),
                "socket": dict(sock.entity),
            }
            yield _claim(
                rule,
                sock,
                artifact_class="process_socket_correlation",
                entity=entity,
                source_findings=sorted({f.finding_id for pair in pairs for f in pair}),
            )


def _suspicious_shell_history(rule: Rule, findings: list[ToolFinding]) -> Iterable[DetectionClaim]:
    tokens = tuple(str(x).lower() for x in rule.parameters.get("tokens") or [])
    for finding in findings:
        if not (_source_allowed(rule, finding) and _class_allowed(rule, finding)):
            continue
        value = _entity_value(finding).lower()
        if any(token in value for token in tokens):
            yield _claim(rule, finding)


_DETECTORS: dict[str, DetectorFn] = {
    "flab.filesystem.suspicious_temp_path": _suspicious_temp_path,
    "flab.filesystem.userland_persistence": _userland_persistence,
    "flab.filesystem.ebpf_kernel_like_object": _ebpf_object,
    "flab.filesystem.ld_preload_configuration": _ld_preload_configuration,
    "flab.filesystem.suspicious_shared_object": _suspicious_shared_object,
    "flab.filesystem.deleted_artifact_cleanup": _deleted_artifact_cleanup,
    "flab.memory.process_from_unusual_path": _process_from_unusual_path,
    "flab.memory.process_library_correlation": _process_library_correlation,
    "flab.memory.process_socket_correlation": _process_socket_correlation,
    "flab.timeline.suspicious_shell_history": _suspicious_shell_history,
}
