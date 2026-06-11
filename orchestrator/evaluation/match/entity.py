# orchestrator/evaluation/match/entity.py
#
# Entity normalization + equality. This is the repurposed core of the old
# ioc_detector path/port/name comparison (sleuthkit.detect_disk path_equals,
# volatility._socket_port_match, plaso substring matching) -- moved AFTER a
# GT-blind detection pass so it compares a finding's entity against a GT entity
# rather than searching tool output for a planted value.

from __future__ import annotations

import posixpath
from typing import Any

from orchestrator.evaluation.contracts.models import Entity


def normalize_path(value: Any) -> str:
    s = str(value).strip()
    if not s:
        return ""
    # fls and plaso spell volume-relative paths without a leading slash; make
    # every path absolute-looking, collapse . / .. / //, drop trailing slash.
    if not s.startswith("/"):
        s = "/" + s
    s = posixpath.normpath(s)
    return s


def normalize_socket(value: Any) -> str:
    # "host:port" -> "host:port" with surrounding whitespace stripped. Bracketed
    # IPv6 forms are left intact; comparison is on the canonical string.
    return str(value).strip()


def _split_process(value: Any) -> tuple[str, str]:
    # "name arg1 arg2" -> (name, "arg1 arg2"). Name only -> (name, "").
    s = str(value).strip()
    if not s:
        return "", ""
    parts = s.split(None, 1)
    name = posixpath.basename(parts[0]) if parts[0].startswith("/") else parts[0]
    args = parts[1] if len(parts) > 1 else ""
    return name, args


def entity_key(entity: Entity) -> str:
    # A canonical, hashable string per entity, used as the dedup cluster key.
    if entity.type == "path":
        return "path::" + normalize_path(entity.value)
    if entity.type == "socket":
        return "socket::" + normalize_socket(entity.value)
    if entity.type == "process":
        name, args = _split_process(entity.value)
        return f"process::{name}::{args}"
    return f"{entity.type}::{str(entity.value).strip()}"


def entities_match(gt: Entity, found: Entity, cfg: dict[str, Any]) -> bool:
    if gt.type != found.type:
        return False
    ecfg = cfg.get("entity", {}) if cfg else {}
    if gt.type == "path":
        g, f = normalize_path(gt.value), normalize_path(found.value)
        if g == f:
            return True
        if ecfg.get("path_basename_fallback"):
            return posixpath.basename(g) == posixpath.basename(f) and bool(g)
        return False
    if gt.type == "socket":
        return normalize_socket(gt.value) == normalize_socket(found.value)
    if gt.type == "process":
        g_name, g_args = _split_process(gt.value)
        f_name, f_args = _split_process(found.value)
        if g_name != f_name:
            return False
        if ecfg.get("process_arg_prefix", True):
            return f_args.startswith(g_args)
        return g_args == f_args
    return str(gt.value).strip() == str(found.value).strip()
