# orchestrator/evaluation/scenario/scenario_01.py
#
# Calibration ground truth for scenario_01 (LD_PRELOAD persistence + reverse
# shell), expressed with observables. One logical attack, two scenario IDs:
#
#   scenario_01_ldpreload          no cleanup: every artifact left on disk.
#   scenario_01_ldpreload_cleanup  the attacker reverts/deletes some artifacts.
#
# An event is the unit of ground truth; each event lists the acceptable
# evidentiary loci (observables) where it may legitimately be recovered. The
# cleanup variant keeps the SAME events but prunes the observables that the
# cleanup destroys, so its expectation -- and therefore its achievable metric
# profile -- is strictly harder than the no-cleanup variant.
#
# These per-event observable builders are the single source of truth for the
# observable shapes: the live attack module (orchestrator/attacks/
# scenario_01_ldpreload.py) calls them while recording wall-clock events, and the
# calibration fixtures are generated from build_calibration_manifest() below.

from __future__ import annotations

from typing import Any

from orchestrator.evaluation.contracts.models import GtManifest, Observable
from orchestrator.evaluation.scenario.manifest import GtManifestBuilder
from orchestrator.forensics.timeutil import epoch_us_to_iso_ms, parse_iso_utc

SCENARIO_NOCLEANUP = "scenario_01_ldpreload"
SCENARIO_CLEANUP = "scenario_01_ldpreload_cleanup"

# Planted artifact locators (defaults; the live run may randomize fifo/port).
SO_PATH = "/tmp/T1574006.so"
# The ART T1574.006 test drops the payload source under PathToAtomicsFolder
# (fixed at /tmp/atomics) and compiles it to SO_PATH. The source persists the
# sed-unhook cleanup, so tsk flags it as a temp file; it is a real attack
# artifact and belongs in ground truth (otherwise it scores as a false positive).
SRC_PATH = "/tmp/atomics/T1574.006/src/Linux/T1574.006.c"
PRELOAD_PATH = "/etc/ld.so.preload"
DISCOVERY_OUTPUT = "/tmp/T1082.txt"
RS_FIFO = "/tmp/.rs_fifo"
RS_PORT = 4444


def _obs(operation: str, source_tool: str, entity_type: str, entity_value: str) -> Observable:
    return Observable(
        operation=operation,
        source_tool=source_tool,
        entity_type=entity_type,
        entity_value=entity_value,
    )


# --- per-event observable builders (cleanup-aware) ----------------------------
# Each returns the observables for one event. The cleanup flag prunes loci the
# attacker's cleanup removes; memory mappings, logs, and the (emptied) preload
# config persist because memory is acquired before cleanup runs.


def discovery_observables(output_path: str = DISCOVERY_OUTPUT, *, cleanup: bool) -> list[Observable]:
    # E1_discovery_os_info (T1082). The file is on disk and recoverable on the
    # timeline (tsk) in both variants; cleanup deletes it so recovery typically
    # fails, but the timeline locus is the modeled expectation either way.
    return [_obs("timeline", "tsk", "path", output_path)]


def ldpreload_persistence_observables(
    preload_path: str = PRELOAD_PATH, so_path: str = SO_PATH, *, cleanup: bool
) -> list[Observable]:
    # E2_ldpreload_persistence (T1574.006). The preload config and the log entry of
    # the write survive cleanup (cleanup only empties the file via sed), so the
    # persistence stays observable on disk (tsk), in the logs (plaso), and via a
    # Sigma rule over those logs (plaso_sigma) in both variants.
    return [
        _obs("timeline", "tsk", "path", preload_path),
        _obs("timeline", "plaso", "process", f"sudo sh -c 'echo {so_path} > {preload_path}'"),
        _obs("timeline", "plaso_sigma", "path", preload_path),
    ]


def ldpreload_so_observables(
    so_path: str = SO_PATH, src_path: str = SRC_PATH, *, cleanup: bool
) -> list[Observable]:
    # E2 disk artifacts of the compiled payload: the .so output (so_path is a GT
    # entity here AND in E3, so a detection of it is always a TP, never an FP) and
    # the .c source the ART test drops under /tmp/atomics. Both are recoverable on
    # the timeline (tsk) and persist the sed-unhook cleanup; the yara signature
    # locus needs the .so on disk, so it is no-cleanup only. The in-memory mapping
    # is a SEPARATE event (E3).
    obs = [
        _obs("timeline", "tsk", "path", so_path),
        _obs("timeline", "tsk", "path", src_path),
    ]
    if not cleanup:
        obs.append(_obs("content_scan", "yara", "path", so_path))
    return obs


def ldpreload_triggered_observables(so_path: str = SO_PATH, *, cleanup: bool) -> list[Observable]:
    # E3_ldpreload_triggered (T1574.006): the .so mapped into the triggered PID.
    # Memory mappings outlive disk cleanup, so this is identical in both variants.
    return [_obs("memory_analysis", "vol3", "path", so_path)]


def reverse_shell_socket_observables(socket_value: str, *, cleanup: bool) -> list[Observable]:
    # E4_reverse_shell (T1059.004): the established C2 socket. Lives only in memory
    # (acquired before cleanup), so it survives in both variants.
    return [_obs("memory_analysis", "vol3", "socket", socket_value)]


def reverse_shell_fifo_observables(fifo_path: str = RS_FIFO, *, cleanup: bool) -> list[Observable]:
    # E4 disk artifact: the reverse-shell FIFO, recoverable on the timeline (tsk).
    # The custom steps have no ART cleanup, so the FIFO persists on disk in both
    # variants.
    return [_obs("timeline", "tsk", "path", fifo_path)]


def _ts(base_epoch: float, offset_s: float) -> str:
    return epoch_us_to_iso_ms(int((base_epoch + offset_s) * 1_000_000))


def build_calibration_manifest(
    *,
    cleanup: bool,
    distro: str = "ubuntu-22.04",
    run_id: str | None = None,
    seed: int = 1337,
    host_ip: str = "192.168.100.1",
    port: int = RS_PORT,
    fifo: str = RS_FIFO,
    base_ts: str = "2026-06-13T12:00:00.000Z",
) -> GtManifest:
    # Deterministic GT for the two calibration variants, used to generate the
    # fixtures and to document the expected ground truth. The six events realize
    # the four logical steps (E2 and E4 each split a disk + a memory/log locus).
    scenario_id = SCENARIO_CLEANUP if cleanup else SCENARIO_NOCLEANUP
    run_id = run_id or f"{distro}_{scenario_id}_calibration"
    socket_value = f"{host_ip}:{port}"
    base = parse_iso_utc(base_ts)
    b = GtManifestBuilder(scenario_id, run_id, distro, seed=seed, cleanup=cleanup)

    b.record(
        technique="T1082",
        event_class="file_created",
        entity_type="path",
        entity_value=DISCOVERY_OUTPUT,
        ts_utc=_ts(base, 0),
        details={"step": "E1_discovery_os_info"},
        expected_sources=["disk_fs"],
        observables=discovery_observables(cleanup=cleanup),
    )
    b.record(
        technique="T1574.006",
        event_class="persistence_installed",
        entity_type="path",
        entity_value=PRELOAD_PATH,
        ts_utc=_ts(base, 5),
        details={"step": "E2_ldpreload_persistence"},
        expected_sources=["disk_fs", "disk_logs"],
        observables=ldpreload_persistence_observables(cleanup=cleanup),
    )
    b.record(
        technique="T1574.006",
        event_class="file_created",
        entity_type="path",
        entity_value=SO_PATH,
        ts_utc=_ts(base, 6),
        details={"step": "E2_ldpreload_payload"},
        expected_sources=["disk_fs", "memory"],
        observables=ldpreload_so_observables(cleanup=cleanup),
    )
    b.record(
        technique="T1574.006",
        event_class="process_exec",
        entity_type="path",
        entity_value=SO_PATH,
        ts_utc=_ts(base, 8),
        details={"step": "E3_ldpreload_triggered"},
        expected_sources=["memory"],
        observables=ldpreload_triggered_observables(cleanup=cleanup),
    )
    b.record(
        technique="T1059.004",
        event_class="network_connection",
        entity_type="socket",
        entity_value=socket_value,
        ts_utc=_ts(base, 10),
        details={"step": "E4_reverse_shell"},
        expected_sources=["memory"],
        observables=reverse_shell_socket_observables(socket_value, cleanup=cleanup),
    )
    b.record(
        technique="T1059.004",
        event_class="file_created",
        entity_type="path",
        entity_value=fifo,
        ts_utc=_ts(base, 12),
        details={"step": "E4_reverse_shell_fifo"},
        expected_sources=["disk_fs"],
        observables=reverse_shell_fifo_observables(fifo, cleanup=cleanup),
    )
    return b.to_manifest()
