# orchestrator/evaluation/match/matcher.py
#
# GT-aware matching (Phase 4). Consumes GT-blind findings.jsonl plus the
# gt_manifest and produces matches.json (TP/FP/FN + background_noise). This is
# the ONLY layer besides metrics that reads ground truth.
#
# Algorithm (Phase 4.1):
#   1. dedup findings into per-(family,class,entity,bucket) clusters = one claim
#   2. candidate pairs cluster x GT by class equivalence + entity match + |dt|
#   3. greedy 1:1 assignment by smallest |dt| (timeless candidates last)
#   4. corroborating clusters attach to a matched GT (multi-tool TP), the rest
#      inside the scope window are FP, outside are background_noise.

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from orchestrator.evaluation.contracts.models import Entity, Finding, GtManifest, Matches
from orchestrator.evaluation.match.entity import entities_match, entity_key
from orchestrator.forensics.timeutil import parse_iso_utc

_CONFIG_DEFAULT = Path(__file__).resolve().parent.parent / "config" / "matching.yaml"


def _finding_epoch(f: Finding) -> float | None:
    # Only wallclock-quality findings carry a usable time; relative/none are
    # treated as timeless for matching (entity + class only).
    if f.ts_quality != "wallclock" or not f.ts_utc:
        return None
    try:
        return parse_iso_utc(f.ts_utc)
    except ValueError:
        return None


@dataclass
class _Cluster:
    cluster_id: str
    family: str
    event_class: str
    entity: Entity
    findings: list[Finding] = field(default_factory=list)

    @property
    def epoch(self) -> float | None:
        times = [t for t in (_finding_epoch(f) for f in self.findings) if t is not None]
        return min(times) if times else None

    @property
    def representative(self) -> Finding:
        # Deterministic: earliest time-bearing finding, else smallest finding_id.
        timed = [(t, f) for f in self.findings if (t := _finding_epoch(f)) is not None]
        if timed:
            return min(timed, key=lambda tf: (tf[0], tf[1].finding_id))[1]
        return min(self.findings, key=lambda f: f.finding_id)

    @property
    def tools(self) -> list[str]:
        return sorted({f.source_tool for f in self.findings})

    @property
    def technique(self) -> str | None:
        return self.representative.technique

    @property
    def finding_ids(self) -> list[str]:
        return sorted(f.finding_id for f in self.findings)


def _corroborates(cluster: _Cluster, ev, gt_epoch: float, window: float) -> bool:
    # Cross-channel corroboration: a leftover cluster observes the SAME action as
    # a matched GT -- same technique, within the window -- through a DIFFERENT
    # entity channel (type) than the GT entity. Anchored on technique, not on
    # entity identity, so a log/process observation of a disk write folds into it.
    # Same entity type with a different value is a distinct instance (e.g. another
    # socket), not corroboration, so it is excluded.
    if cluster.technique is None or cluster.technique != ev.technique:
        return False
    if cluster.entity.type == ev.entity.type:
        return False
    ce = cluster.epoch
    if ce is None:
        return True  # timeless (memory) corroborator: technique + channel only
    return abs(ce - gt_epoch) <= window


def _is_known_good(cluster: _Cluster, known_good: list[dict[str, Any]]) -> bool:
    # A documented benign baseline that trips a GT-blind detector. Matched on
    # detector id and/or an entity substring; not a planted instance value.
    for rule in known_good:
        det = rule.get("detector")
        contains = rule.get("entity_contains")
        if not (det or contains):
            continue
        for f in cluster.findings:
            if det and f.detector != det:
                continue
            if contains and contains not in str(f.entity.value):
                continue
            return True
    return False


def load_matching_config(path: str | Path | None = None) -> dict[str, Any]:
    cfg_path = Path(path) if path else _CONFIG_DEFAULT
    return yaml.safe_load(cfg_path.read_text(encoding="utf-8"))


def hash_matching_config(path: str | Path | None = None) -> str:
    cfg_path = Path(path) if path else _CONFIG_DEFAULT
    digest = hashlib.sha256(cfg_path.read_bytes()).hexdigest()
    return "sha256:" + digest


def _family(f: Finding) -> str:
    # Detector family groups near-duplicate findings for dedup. A finding's
    # source tool is its family; two detectors of the same tool reporting the
    # same entity/class/bucket are one claim.
    return f.source_tool


def _dedup(findings: list[Finding], bucket_s: int) -> list[_Cluster]:
    groups: dict[tuple[str, str, str, Any], _Cluster] = {}
    # Stable order so cluster ids are deterministic regardless of input order.
    for f in sorted(findings, key=lambda x: x.finding_id):
        ekey = entity_key(f.entity)
        epoch = _finding_epoch(f)
        bucket = int(epoch // bucket_s) if epoch is not None else None
        key = (_family(f), f.event_class, ekey, bucket)
        cluster = groups.get(key)
        if cluster is None:
            cluster = _Cluster(
                cluster_id="",  # assigned after sorting below
                family=_family(f),
                event_class=f.event_class,
                entity=f.entity,
            )
            groups[key] = cluster
        cluster.findings.append(f)
    # Deterministic cluster ids by (earliest epoch or +inf, representative id).
    ordered = sorted(
        groups.values(),
        key=lambda c: (
            c.epoch if c.epoch is not None else float("inf"),
            c.representative.finding_id,
        ),
    )
    for i, c in enumerate(ordered):
        c.cluster_id = f"c-{i:03d}"
    return ordered


def _class_compatible(gt_class: str, finding_class: str, equivalence: dict) -> bool:
    allowed = equivalence.get(gt_class, [gt_class])
    return finding_class in allowed


def match(
    manifest: GtManifest,
    findings: list[Finding],
    config: dict[str, Any] | None = None,
    config_path: str | Path | None = None,
    ruleset_hash: str = "sha256:0",
) -> Matches:
    cfg = config if config is not None else load_matching_config(config_path)
    tol = float(cfg["tolerance_s"])
    bucket_s = int(cfg["dedup_bucket_s"])
    margin = float(cfg["scope_margin_s"])
    corr_window = float(cfg.get("corroboration_window_s", tol))
    known_good = cfg.get("known_good", []) or []
    equivalence = cfg.get("equivalence", {})

    clusters = _dedup(findings, bucket_s)

    gt_epochs = {e.gt_id: parse_iso_utc(e.ts_utc) for e in manifest.events}
    events_by_id = {e.gt_id: e for e in manifest.events}

    # Candidate pairs: (|dt| or +inf, timeless_flag, gt_id, cluster_id).
    candidates: list[tuple[float, int, str, str]] = []
    compat: dict[tuple[str, str], bool] = {}
    for c in clusters:
        c_epoch = c.epoch
        for ev in manifest.events:
            if not _class_compatible(ev.event_class, c.event_class, equivalence):
                continue
            if not entities_match(ev.entity, c.entity, cfg):
                continue
            compat[(ev.gt_id, c.cluster_id)] = True
            if c_epoch is None:
                candidates.append((float("inf"), 1, ev.gt_id, c.cluster_id))
            else:
                dt = abs(c_epoch - gt_epochs[ev.gt_id])
                if dt <= tol:
                    candidates.append((dt, 0, ev.gt_id, c.cluster_id))

    # Greedy 1:1 by smallest |dt|; timeless candidates (flag=1) assigned last.
    candidates.sort(key=lambda t: (t[1], t[0], t[2], t[3]))
    gt_to_cluster: dict[str, str] = {}
    cluster_to_gt: dict[str, str] = {}
    for _, _, gt_id, cluster_id in candidates:
        if gt_id in gt_to_cluster or cluster_id in cluster_to_gt:
            continue
        gt_to_cluster[gt_id] = cluster_id
        cluster_to_gt[cluster_id] = gt_id

    clusters_by_id = {c.cluster_id: c for c in clusters}

    # Build TP rows; attach corroborating clusters (compatible, still free).
    tp: list[dict[str, Any]] = []
    consumed: set[str] = set(cluster_to_gt.keys())
    for ev in manifest.events:
        primary_cid = gt_to_cluster.get(ev.gt_id)
        if primary_cid is None:
            continue
        primary = clusters_by_id[primary_cid]
        attached = [primary]
        for c in clusters:
            if c.cluster_id in consumed:
                continue
            # compat = same entity observed by another tool; _corroborates = the
            # same action seen through a different channel (technique-anchored).
            if compat.get((ev.gt_id, c.cluster_id)) or _corroborates(
                c, ev, gt_epochs[ev.gt_id], corr_window
            ):
                attached.append(c)
                consumed.add(c.cluster_id)
        rep = primary.representative
        rep_epoch = _finding_epoch(rep)
        delta = (
            round(abs(rep_epoch - gt_epochs[ev.gt_id]), 6)
            if rep_epoch is not None
            else None
        )
        finding_ids = sorted(
            fid for c in attached for fid in c.finding_ids
        )
        tools = sorted({t for c in attached for t in c.tools})
        tp.append(
            {
                "gt_id": ev.gt_id,
                "finding_ids": finding_ids,
                "primary_finding": rep.finding_id,
                "delta_t_s": delta,
                "tools": tools,
                # Count of claim-clusters folded into this TP (primary +
                # corroborators). Precision is counted in these claim units.
                "n_clusters": len(attached),
                # Carried so metrics computes order/time over the TP subset
                # without re-matching: GT time + the primary finding's time and
                # quality (memory findings -> "none", excluded from ordering).
                "gt_ts_utc": ev.ts_utc,
                "primary_ts_utc": rep.ts_utc,
                "primary_ts_quality": rep.ts_quality,
            }
        )

    # FN: GT events with no assigned cluster.
    fn = sorted(ev.gt_id for ev in manifest.events if ev.gt_id not in gt_to_cluster)

    # Scope window for FP eligibility.
    if gt_epochs:
        lo = min(gt_epochs.values()) - margin
        hi = max(gt_epochs.values()) + margin
    else:
        lo, hi = float("-inf"), float("inf")

    fp: list[dict[str, Any]] = []
    background: list[dict[str, Any]] = []
    for c in clusters:
        if c.cluster_id in consumed:
            continue
        epoch = c.epoch
        in_window = epoch is None or (lo <= epoch <= hi)
        row = {
            "cluster_id": c.cluster_id,
            "finding_ids": c.finding_ids,
            "representative": c.representative.finding_id,
        }
        # A documented benign baseline is not a false claim: score it as
        # background noise (excluded from precision), like an out-of-scope hit.
        if _is_known_good(c, known_good):
            background.append(row)
        else:
            (fp if in_window else background).append(row)

    tp.sort(key=lambda r: r["gt_id"])
    fp.sort(key=lambda r: r["cluster_id"])
    background.sort(key=lambda r: r["cluster_id"])

    return Matches(
        matching_config_hash=hash_matching_config(config_path),
        ruleset_hash=ruleset_hash,
        tp=tp,
        fp=fp,
        fn=fn,
        background_noise=background,
    )


def write_matches(matches: Matches, out_path: str | Path) -> Path:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(matches.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return p
