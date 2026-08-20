#!/usr/bin/env python3
"""Father memory-phase metrics.

Consumes the raw Volatility 3 JSON output already written by
runme_memory.sh under derived/memory/raw/. Never invokes vol3 itself.

Two modes, both operating on the same DERIVED directory:

    memory_metrics.py --write-findings RUN_ID DERIVED_DIR ISF_PATH \
        proc_maps_status pslist_status pstree_status psaux_status \
        sockstat_status bash_status
        Parse derived/memory/raw/* into derived/memory/findings.json.

    memory_metrics.py RUN_ID DERIVED_DIR MANIFEST_PATH
        Read derived/memory/findings.json and write derived/memory/metrics.json.
"""
import json
import sys
from pathlib import Path

PLUGIN_FILES = {
    "linux.proc.Maps": "proc-maps.json",
    "linux.pslist": "pslist.json",
    "linux.pstree": "pstree.json",
    "linux.psaux": "psaux.json",
    "linux.sockstat": "sockstat.json",
    "linux.bash": "bash.json",
}


def _load_rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict) and isinstance(data.get("rows"), list):
        return [r for r in data["rows"] if isinstance(r, dict)]
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    return []


def write_findings(run_id: str, derived: Path, isf_path: str, statuses: list[str]) -> None:
    raw = derived / "raw"
    plugins = {}
    for (plugin, filename), status in zip(PLUGIN_FILES.items(), statuses):
        rows = _load_rows(raw / filename)
        plugins[plugin] = {"status": status, "row_count": len(rows)}

    maps_rows = _load_rows(raw / PLUGIN_FILES["linux.proc.Maps"])
    lib_mappings = [
        r for r in maps_rows
        if "selinux.so.3" in str(r.get("File Path") or r.get("Path") or r.get("file_path") or "")
    ]

    bash_rows = _load_rows(raw / PLUGIN_FILES["linux.bash"])
    sockstat_rows = _load_rows(raw / PLUGIN_FILES["linux.sockstat"])

    observations = []
    if lib_mappings:
        observations.append(
            f"linux.proc.Maps: {len(lib_mappings)} mapping row(s) reference "
            "selinux.so.3 — candidate evidence the library was loaded into a "
            "process's address space; confirm the owning process/PID by hand."
        )
    elif plugins["linux.proc.Maps"]["status"] == "ok":
        observations.append(
            "linux.proc.Maps: ran but no row referenced selinux.so.3 by that "
            "exact path string — check the raw file manually before treating "
            "this as a true negative (path formatting varies by vol3 version)."
        )
    if bash_rows:
        observations.append(
            f"linux.bash: {len(bash_rows)} row(s) recovered from process bash "
            "history buffers — content requires human review."
        )
    if sockstat_rows:
        observations.append(
            f"linux.sockstat: {len(sockstat_rows)} socket row(s) present — "
            "cross-reference manually against the manifest's "
            "scenario_facts.backdoor_connection port."
        )

    findings = {
        "run_id": run_id,
        "isf_path": isf_path,
        "plugins": plugins,
        "observations": observations,
    }
    out = derived / "findings.json"
    out.write_text(json.dumps(findings, indent=2) + "\n")
    print(f"wrote {out}")


def write_metrics(run_id: str, derived: Path, manifest_path: Path) -> None:
    findings_path = derived / "findings.json"
    if not findings_path.exists():
        raise SystemExit(f"missing {findings_path}; run with --write-findings first")
    f = json.loads(findings_path.read_text())

    backdoor_port = None
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text())
            backdoor_port = (
                manifest.get("scenario_facts", {})
                .get("backdoor_connection", {})
                .get("server_port")
            )
        except json.JSONDecodeError:
            pass

    def status_of(plugin: str) -> str:
        return f["plugins"].get(plugin, {}).get("status", "unknown")

    def rows_of(plugin: str) -> int:
        return f["plugins"].get(plugin, {}).get("row_count", 0)

    def unknown_if_failed(plugin: str, value):
        return value if status_of(plugin) == "ok" else "unknown (plugin did not run)"

    metrics = {
        "run_id": run_id,
        "process_visibility": unknown_if_failed("linux.pslist", rows_of("linux.pslist")),
        "process_tree_available": unknown_if_failed(
            "linux.pstree", status_of("linux.pstree") == "ok" and rows_of("linux.pstree") > 0
        ),
        "library_mapping": {
            "plugin_status": status_of("linux.proc.Maps"),
            "note": "presence of a selinux.so.3 mapping row is recorded in "
            "findings.json.observations; requires human confirmation of the "
            "owning PID, not asserted numerically here",
        },
        "socket_backdoor_observation": {
            "plugin_status": status_of("linux.sockstat"),
            "sockstat_row_count": unknown_if_failed("linux.sockstat", rows_of("linux.sockstat")),
            "manifest_backdoor_port": backdoor_port if backdoor_port is not None else "unknown",
            "note": "row count does not by itself prove the backdoor socket; "
            "cross-reference the manifest port manually against raw/sockstat.json",
        },
        "bash_evidence": {
            "plugin_status": status_of("linux.bash"),
            "row_count": unknown_if_failed("linux.bash", rows_of("linux.bash")),
        },
        "negative_or_unknown": [
            plugin for plugin, info in f["plugins"].items() if info["status"] != "ok"
        ],
    }

    out = derived / "metrics.json"
    out.write_text(json.dumps(metrics, indent=2) + "\n")
    print(f"wrote {out}")


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--write-findings":
        run_id, derived, isf_path = argv[1], Path(argv[2]), argv[3]
        statuses = argv[4:]
        write_findings(run_id, derived, isf_path, statuses)
        return 0
    run_id, derived, manifest_path = argv[0], Path(argv[1]), Path(argv[2])
    write_metrics(run_id, derived, manifest_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
