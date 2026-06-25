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
    confidence_default: float
    parameters: dict[str, Any]
    path: Path


DetectorFn = Callable[[Rule, list[ToolFinding]], Iterable[DetectionClaim]]


def run_detectors(findings: Iterable[ToolFinding], rules_dir: str | Path | None = None) -> list[DetectionClaim]:
    items = list(findings)
    claims: list[DetectionClaim] = []
    for rule in load_rules(rules_dir):
        detector = _DETECTORS.get(rule.id)
        if detector is None:
            continue
        claims.extend(detector(rule, items))
    return prepare_detection_claims(claims)


def run_detectors_file(
    findings_path: str | Path,
    *,
    rules_dir: str | Path | None = None,
) -> list[DetectionClaim]:
    return run_detectors(load_jsonl(findings_path, ToolFinding), rules_dir=rules_dir)


def write_detection_claims(path: str | Path, claims: Iterable[DetectionClaim]) -> Path:
    return write_jsonl(path, prepare_detection_claims(claims))


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
                confidence_default=float(data.get("confidence_default", 0.5)),
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


def prepare_detection_claims(claims: Iterable[DetectionClaim]) -> list[DetectionClaim]:
    return assign_claim_ids(_dedupe_memory_correlation_claims(claims))


def _dedupe_memory_correlation_claims(claims: Iterable[DetectionClaim]) -> list[DetectionClaim]:
    passthrough: list[DetectionClaim] = []
    groups: dict[tuple[Any, ...], list[DetectionClaim]] = {}
    for claim in claims:
        key = _memory_correlation_key(claim)
        if key is None:
            passthrough.append(claim)
        else:
            groups.setdefault(key, []).append(claim)
    return [*passthrough, *(_collapse_memory_group(group) for group in groups.values())]


def _memory_correlation_key(claim: DetectionClaim) -> tuple[Any, ...] | None:
    entity = claim.entity
    if claim.rule_id == "flab.memory.process_library_correlation":
        process = _entity_dict(entity, "process")
        library = _entity_dict(entity, "library")
        return (
            claim.run_id,
            claim.rule_id,
            claim.artifact_class,
            entity.get("type"),
            _normalized_scalar(entity.get("pid")),
            _process_identity(process),
            _path_identity(library),
            _normalized_scalar(entity.get("expectation_class") or entity.get("artifact_class")),
        )
    if claim.rule_id == "flab.memory.process_socket_correlation":
        process = _entity_dict(entity, "process")
        socket = _entity_dict(entity, "socket")
        return (
            claim.run_id,
            claim.rule_id,
            claim.artifact_class,
            entity.get("type"),
            _normalized_scalar(entity.get("pid")),
            _process_identity(process),
            _endpoint_identity(_entity_dict(socket, "local")),
            _endpoint_identity(_entity_dict(socket, "remote")),
            _normalized_scalar(socket.get("value")),
            _normalized_scalar(socket.get("protocol") or entity.get("protocol")),
            _normalized_scalar(entity.get("expectation_class") or entity.get("artifact_class")),
        )
    return None


def _collapse_memory_group(group: list[DetectionClaim]) -> DetectionClaim:
    representative = min(group, key=_claim_sort_key)
    if len(group) == 1:
        return representative

    source_findings = sorted({fid for claim in group for fid in claim.source_findings})
    entity = dict(representative.entity)
    entity["collapsed_candidate_count"] = len(group)
    entity["source_finding_count"] = len(source_findings)
    entity["representative_source_findings"] = source_findings[:8]
    notes = representative.notes
    marker = f"collapsed_from={len(group)} memory-correlation candidates"
    if marker not in notes:
        notes = f"{notes}; {marker}" if notes else marker
    return DetectionClaim(
        claim_id=representative.claim_id,
        run_id=representative.run_id,
        rule_id=representative.rule_id,
        artifact_class=representative.artifact_class,
        entity=entity,
        confidence=max(float(claim.confidence) for claim in group),
        source_findings=source_findings,
        attck=list(representative.attck),
        notes=notes,
    )


def _entity_dict(entity: dict[str, Any], key: str) -> dict[str, Any]:
    value = entity.get(key)
    return dict(value) if isinstance(value, dict) else {}


def _normalized_scalar(value: Any) -> str:
    return str(value or "").strip().lower()


def _process_identity(process: dict[str, Any]) -> str:
    return _normalized_scalar(
        process.get("name")
        or process.get("comm")
        or process.get("value")
        or process.get("path")
        or process.get("argv")
    )


def _path_identity(entity: dict[str, Any]) -> str:
    return _normalized_scalar(entity.get("path") or entity.get("value"))


def _endpoint_identity(endpoint: dict[str, Any]) -> tuple[str, str]:
    return (
        _normalized_scalar(endpoint.get("address") or endpoint.get("ip")),
        _normalized_scalar(endpoint.get("port")),
    )


def _claim(
    rule: Rule,
    finding: ToolFinding,
    *,
    artifact_class: str | None = None,
    entity: dict[str, Any] | None = None,
    confidence: float | None = None,
    source_findings: list[str] | None = None,
    notes: str = "",
) -> DetectionClaim:
    return DetectionClaim(
        claim_id=_initial_claim_id(rule, finding),
        run_id=finding.run_id,
        rule_id=rule.id,
        artifact_class=artifact_class or finding.artifact_class,
        entity=entity or dict(finding.entity),
        confidence=confidence if confidence is not None else rule.confidence_default,
        source_findings=source_findings or [finding.finding_id],
        attck=list(rule.attck),
        notes=_notes(rule, notes),
    )


def _initial_claim_id(rule: Rule, finding: ToolFinding) -> str:
    digest = hashlib.sha1(
        f"{finding.run_id}|{rule.id}|{finding.finding_id}|{finding.raw_ref}".encode("utf-8")
    ).hexdigest()[:12]
    return f"dc-{digest}"


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
        path = _entity_path(finding)
        if not path.startswith(prefixes):
            continue
        confidence = rule.confidence_default
        mode = str(finding.entity.get("mode") or "")
        if "x" in mode:
            confidence = min(0.95, confidence + 0.12)
        if finding.artifact_class == "deleted_file_candidate" or finding.entity.get("deleted"):
            confidence = min(0.95, confidence + 0.08)
        yield _claim(rule, finding, confidence=confidence)


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
            yield _claim(rule, finding, notes="low-confidence benign/kernel-like scope")


def _ld_preload_configuration(rule: Rule, findings: list[ToolFinding]) -> Iterable[DetectionClaim]:
    tokens = tuple(str(x).lower() for x in rule.parameters.get("tokens") or [])
    for finding in findings:
        if not (_source_allowed(rule, finding) and _class_allowed(rule, finding)):
            continue
        value = (_entity_value(finding) + " " + str(finding.entity.get("path") or "")).lower()
        if finding.artifact_class == "preload_configuration" or any(token.lower() in value for token in tokens):
            yield _claim(
                rule,
                finding,
                artifact_class="preload_configuration",
                entity=dict(finding.entity),
            )


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
            yield _claim(
                rule,
                finding,
                artifact_class="shared_object",
                entity=dict(finding.entity),
            )


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


def _process_library_correlation(rule: Rule, findings: list[ToolFinding]) -> Iterable[DetectionClaim]:
    prefixes = tuple(rule.parameters.get("path_prefixes") or [])
    tokens = tuple(str(x).lower() for x in rule.parameters.get("path_tokens") or [])
    by_run_pid: dict[tuple[str, str], dict[str, list[ToolFinding]]] = {}
    for finding in findings:
        if not (_source_allowed(rule, finding) and _class_allowed(rule, finding)):
            continue
        pid = _pid(finding)
        if pid in (None, ""):
            continue
        bucket = by_run_pid.setdefault((finding.run_id, str(pid)), {"process": [], "library": []})
        if finding.artifact_class == "process":
            bucket["process"].append(finding)
        elif finding.artifact_class in ("library_mapping", "shared_object"):
            bucket["library"].append(finding)
    for (_run_id, pid), bucket in by_run_pid.items():
        for proc in bucket["process"]:
            for lib in bucket["library"]:
                path = _entity_path(lib)
                lower = path.lower()
                if not (path.startswith(prefixes) or any(token in lower for token in tokens)):
                    continue
                entity = {
                    "type": "process_library",
                    "value": f"{proc.entity.get('value')} -> {path}",
                    "pid": pid,
                    "process": dict(proc.entity),
                    "library": dict(lib.entity),
                }
                yield _claim(
                    rule,
                    lib,
                    artifact_class="library_mapping",
                    entity=entity,
                    source_findings=[proc.finding_id, lib.finding_id],
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
    by_run_pid: dict[tuple[str, Any], dict[str, list[ToolFinding]]] = {}
    for finding in findings:
        if not (_source_allowed(rule, finding) and _class_allowed(rule, finding)):
            continue
        pid = _pid(finding)
        if pid in (None, ""):
            continue
        if finding.artifact_class == "socket" and not _is_remote_connection(finding):
            continue
        bucket = by_run_pid.setdefault((finding.run_id, str(pid)), {"process": [], "socket": []})
        if finding.artifact_class in bucket:
            bucket[finding.artifact_class].append(finding)
    for (_run_id, pid), bucket in by_run_pid.items():
        for proc in bucket["process"]:
            for sock in bucket["socket"]:
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
                    source_findings=[proc.finding_id, sock.finding_id],
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
