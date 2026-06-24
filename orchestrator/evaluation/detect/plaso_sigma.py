# orchestrator/evaluation/detect/plaso_sigma.py
#
# Sigma detector over the Plaso timeline, evaluated with SQLite. No hand-written
# rule engine: pySigma parses each vendored SigmaHQ Linux rule and compiles it,
# then stdlib sqlite3 runs the result against an in-memory table built from the
# Plaso event stream. GT-blind: rules express behavioral patterns only and never
# see the manifest.
#
# Two evaluation paths, both standard SQLite:
#   1. field-bound rules (Image, CommandLine, TargetFilename, ...) -> pySigma's
#      sqlite backend compiles them to a SQL WHERE clause over a columnar table.
#   2. pure full-text "keyword" rules (no field; e.g. the ld.so.preload rule),
#      which the sqlite backend cannot express -> evaluated with SQLite FTS5
#      MATCH over a full-text column holding each event's text. Only rules whose
#      whole detection is a single value-only selection take this path; rules
#      mixing keywords with field selections or and/not logic are skipped (no
#      condition engine here, by design).
#
# Rules whose fields Plaso does not emit (auditd: name/type/a*/exe/...) reference
# a missing column and are skipped; an auditd parser would let them fire (future
# work). FTS5 phrase matching tokenizes on punctuation, so a keyword like
# "/etc/ld.so.preload" matches the same tokens in an event's text.

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule

from orchestrator.evaluation.contracts.models import Finding
from orchestrator.evaluation.detect.base import make_finding
from orchestrator.forensics.sigma_runner import load_rules
from orchestrator.forensics.timeutil import epoch_us_to_iso_ms

_TOOL = "plaso_sigma"

# Sigma field -> ordered Plaso attributes to fill it from. These columns are the
# table schema; a rule referencing a field NOT here hits a missing column and is
# skipped (the auditd case above).
_COLUMNS: dict[str, tuple[str, ...]] = {
    "Image": ("executable", "Image", "filename", "display_name"),
    "CommandLine": ("command", "CommandLine", "body", "message"),
    "ParentImage": ("parent_executable", "ParentImage"),
    "ParentCommandLine": ("parent_command", "ParentCommandLine"),
    "TargetFilename": ("filename", "TargetFilename", "display_name"),
    "CurrentDirectory": ("cwd", "CurrentDirectory"),
    "DestinationIp": ("dest_ip", "DestinationIp"),
    "DestinationPort": ("dest_port", "DestinationPort"),
    "DestinationHostname": ("hostname", "DestinationHostname"),
    "User": ("username", "user", "User"),
    "message": ("message", "body"),
}

_CATEGORY_TO_CLASS = {
    "process_creation": "process_exec",
    "file_event": "file_created",
    "file_change": "file_modified",
    "file_delete": "file_deleted",
    "network_connection": "network_connection",
}

# Event classes that may legitimately derive from a filesystem-metadata (fs:stat)
# row. A process/network rule must not fire on a bare file-existence row (a file
# under /tmp is not proof it executed), so those classes gate filestat out.
_FILE_EVENT_CLASSES = frozenset(
    {
        "file_created",
        "file_modified",
        "file_deleted",
        "persistence_installed",
        "log_tampering",
        "history_cleared",
    }
)


def _value(event: dict[str, Any], attrs: tuple[str, ...]) -> str | None:
    for a in attrs:
        v = event.get(a)
        if isinstance(v, (str, int)) and str(v) != "":
            return str(v)
    return None


def _is_filestat(event: dict[str, Any]) -> bool:
    return event.get("data_type") == "fs:stat" or event.get("parser") == "filestat"


def _ts(event: dict[str, Any]) -> str | None:
    ts = event.get("timestamp")
    if isinstance(ts, int) and ts > 0:
        return epoch_us_to_iso_ms(ts)
    return None


def _rule_event_class(rule: dict[str, Any]) -> str:
    ls = rule.get("logsource", {}) or {}
    cat = ls.get("category")
    if cat in _CATEGORY_TO_CLASS:
        return _CATEGORY_TO_CLASS[cat]
    if ls.get("service") == "cron":
        return "persistence_installed"
    # No category (keyword/IOC or generic linux rule): treat the hit as "artifact
    # present on disk". file_created is bridged to persistence/file_modified by the
    # matcher's equivalence table, and it is allowed on filestat rows.
    return "file_created"


def _rule_technique(rule: dict[str, Any]) -> str | None:
    for tag in rule.get("tags", []) or []:
        m = re.match(r"attack\.(t\d{4}(?:\.\d{3})?)", str(tag), re.IGNORECASE)
        if m:
            return m.group(1).upper()
    return None


def _entity_for(event_class: str, event: dict[str, Any]) -> tuple[str, str]:
    if event_class in _FILE_EVENT_CLASSES:
        v = _value(event, _COLUMNS["TargetFilename"]) or _value(event, _COLUMNS["Image"])
        return "path", (v or "-")
    if event_class == "network_connection":
        ip = _value(event, _COLUMNS["DestinationIp"]) or "-"
        port = _value(event, _COLUMNS["DestinationPort"])
        return "socket", (f"{ip}:{port}" if port else ip)
    v = _value(event, _COLUMNS["CommandLine"]) or _value(event, _COLUMNS["Image"])
    return "process", (v or "-")


def _regexp(pattern: str, value: Any) -> bool:
    # SQLite REGEXP hook: "<col> REGEXP <pat>" calls regexp(pat, col).
    if value is None:
        return False
    try:
        return re.search(pattern, str(value)) is not None
    except re.error:
        return False


def _event_fulltext(event: dict[str, Any]) -> str:
    # Everything searchable in one string, so a keyword can match a value in any
    # field (path, message, command, ...), like a full-text search over the event.
    return " ".join(str(v) for v in event.values() if isinstance(v, (str, int)))


def _keyword_selection(rule: dict[str, Any]) -> list[str] | None:
    # A "pure keyword" rule: the condition is a single selection name and that
    # selection is a plain list/string of values (no field, no and/or/not). Those
    # values are OR-ed full-text terms. Anything more complex returns None and is
    # left to the field-bound path (or skipped).
    det = rule.get("detection", {}) or {}
    cond = str(det.get("condition", "")).strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", cond):
        return None
    sel = det.get(cond)
    if isinstance(sel, str):
        return [sel]
    if isinstance(sel, list) and all(isinstance(x, (str, int)) for x in sel):
        return [str(x) for x in sel]
    return None


def _fts_match_query(keywords: list[str]) -> str | None:
    # Build an FTS5 MATCH expression: each keyword becomes AND-ed phrases (one per
    # "*"-separated chunk, approximating Sigma's wildcard "contains"), OR-ed across
    # keywords. Pure-punctuation chunks are dropped (FTS5 has no token for them).
    terms: list[str] = []
    for kw in keywords:
        chunks = [c.strip() for c in str(kw).split("*")]
        phrases = ['"' + c.replace('"', '""') + '"' for c in chunks if any(ch.isalnum() for ch in c)]
        if not phrases:
            continue
        terms.append("(" + " AND ".join(phrases) + ")" if len(phrases) > 1 else phrases[0])
    return " OR ".join(terms) if terms else None


def _build_db(events: list[dict[str, Any]]) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.create_function("regexp", 2, _regexp, deterministic=True)
    cols = ", ".join(f'"{c}" TEXT' for c in _COLUMNS)
    conn.execute(f"CREATE TABLE events (event_index INTEGER, {cols})")
    conn.execute("CREATE VIRTUAL TABLE events_fts USING fts5(content)")
    names = list(_COLUMNS)
    placeholders = ",".join(["?"] * (len(names) + 1))
    field_rows = []
    fts_rows = []
    for i, ev in enumerate(events):
        if not isinstance(ev, dict):
            continue
        field_rows.append((i, *[_value(ev, _COLUMNS[c]) for c in names]))
        fts_rows.append((i, _event_fulltext(ev)))
    conn.executemany(f"INSERT INTO events VALUES ({placeholders})", field_rows)
    conn.executemany("INSERT INTO events_fts(rowid, content) VALUES (?, ?)", fts_rows)
    return conn


def _rule_to_sql(rule: dict[str, Any]) -> list[str]:
    clean = {k: v for k, v in rule.items() if k not in ("_path", "event_class")}
    return sqliteBackend().convert(SigmaCollection([SigmaRule.from_dict(clean)]))


def _field_match(conn: sqlite3.Connection, rule: dict[str, Any]) -> set[int] | None:
    # Field-bound path. Returns matched event indices, or None when the backend
    # cannot express the rule (full-text keyword rule) so the caller tries FTS5.
    try:
        sqls = _rule_to_sql(rule)
    except SigmaError:
        return None
    indices: set[int] = set()
    for sql in sqls:
        if "WHERE" not in sql:
            continue
        where = sql.split("WHERE", 1)[1]
        try:
            rows = conn.execute(f"SELECT event_index FROM events WHERE{where}").fetchall()
        except sqlite3.OperationalError:
            return set()  # references a column Plaso does not emit -> skip rule
        indices.update(i for (i,) in rows)
    return indices


def _keyword_hits(
    conn: sqlite3.Connection, events: list[dict[str, Any]], rule: dict[str, Any]
) -> list[tuple[int, str, str]]:
    # FTS5 path for pure keyword rules. Returns (event_index, "path", ioc) tuples.
    # The entity is the path-like keyword IOC the event text contains, NOT the
    # event's own fields: a log line mentioning /etc/ld.so.preload must map to that
    # IOC, not to the log file it appears in. Non-path keywords (commands, generic
    # strings) carry no entity that GT matching can use, so they are dropped.
    keywords = _keyword_selection(rule)
    if not keywords:
        return []
    query = _fts_match_query(keywords)
    if not query:
        return []
    try:
        rows = conn.execute(
            "SELECT rowid FROM events_fts WHERE events_fts MATCH ?", (query,)
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    paths = [k for k in keywords if k.startswith("/") and "*" not in k]
    hits: list[tuple[int, str, str]] = []
    for idx in sorted(i for (i,) in rows):
        text = _event_fulltext(events[idx])
        for p in paths:
            if p in text:
                hits.append((idx, "path", p))
    return hits


def _load_rules(rules_config: dict[str, Any]) -> list[dict[str, Any]]:
    dirs = rules_config.get("sigma_vendored_dirs")
    if not dirs:
        return load_rules()  # default vendor/sigma/rules/linux
    rules: list[dict[str, Any]] = []
    for d in dirs:
        rules.extend(load_rules(Path(d)))
    return rules


def detect(raw_outputs: dict[str, Any], rules_config: dict[str, Any]) -> Iterable[Finding]:
    events = raw_outputs.get("plaso", [])
    if not isinstance(events, list) or not events:
        return
    rules = _load_rules(rules_config)
    if not rules:
        return

    conn = _build_db(events)
    try:
        for rule in rules:
            event_class = _rule_event_class(rule)
            technique = _rule_technique(rule)
            gate_filestat = event_class not in _FILE_EVENT_CLASSES
            rule_id = rule.get("id") or rule.get("title") or Path(rule.get("_path", "rule")).stem

            indices = _field_match(conn, rule)
            if indices is None:  # keyword rule: FTS5 full-text path, entity = IOC
                hits = _keyword_hits(conn, events, rule)
            else:
                hits = [
                    (idx, *_entity_for(event_class, events[idx]))
                    for idx in sorted(indices)
                    if not (gate_filestat and _is_filestat(events[idx]))
                ]

            seen: set[tuple[str, str]] = set()
            for idx, etype, evalue in hits:
                if evalue == "-" or (etype, evalue) in seen:
                    continue
                seen.add((etype, evalue))
                ts = _ts(events[idx])
                yield make_finding(
                    source_tool=_TOOL,
                    detector=f"sigma:{rule_id}",
                    rule_layer="community",
                    event_class=event_class,
                    entity_type=etype,
                    entity_value=evalue,
                    ts_quality="wallclock" if ts else "none",
                    forensic_operation="timeline",
                    technique=technique,
                    ts_utc=ts,
                    raw_ref=f"plaso_sigma:event:{idx}",
                    confidence="medium",
                )
    finally:
        conn.close()
