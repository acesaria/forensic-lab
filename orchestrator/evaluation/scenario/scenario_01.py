# orchestrator/evaluation/scenario/scenario_01.py
#
# Ground truth for scenario_01 (LD_PRELOAD persistence + reverse
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
# EVENTS below is the single source of truth for the scenario's event skeleton:
# the live attack module (orchestrator/attacks/scenario_01_ldpreload.py) and the
# calibration manifest both iterate it via record_event(), each supplying only
# its layer-specific values (live wall-clock + resolved paths vs deterministic
# timestamps + default locators). The calibration fixtures are generated from
# build_calibration_manifest() below.

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from orchestrator.evaluation.contracts.models import GtManifest, Observable
from orchestrator.evaluation.scenario.manifest import GtManifestBuilder
from orchestrator.forensics.timeutil import epoch_us_to_iso_ms, parse_iso_utc

SCENARIO_NOCLEANUP = "scenario_01_ldpreload"
SCENARIO_CLEANUP = "scenario_01_ldpreload_cleanup"

# Planted artifact locators (defaults; the live run may randomize fifo/port).
SO_PATH = "/tmp/T1574006.so"
# The scenario writes the payload source under its own /tmp workspace and
# compiles it to SO_PATH. The source persists the sed-unhook cleanup, so tsk
# flags it as a temp file; it is a real attack artifact and belongs in ground
# truth (otherwise it scores as a false positive).
SRC_PATH = "/tmp/scenario_01_ldpreload/T1574.006.c"
PRELOAD_PATH = "/etc/ld.so.preload"
DISCOVERY_OUTPUT = "/tmp/T1082.txt"
RS_FIFO = "/tmp/.rs_fifo"
RS_PORT = 4444
DEFAULT_HOST_IP = "192.168.100.1"


def _obs(
    operation: str, source_tool: str, entity_type: str, entity_value: str
) -> Observable:
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


def discovery_observables(
    output_path: str = DISCOVERY_OUTPUT, *, cleanup: bool
) -> list[Observable]:
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
        _obs(
            "timeline",
            "plaso",
            "process",
            f"sudo sh -c 'echo {so_path} > {preload_path}'",
        ),
        _obs("timeline", "plaso_sigma", "path", preload_path),
    ]


def ldpreload_so_observables(
    so_path: str = SO_PATH, src_path: str = SRC_PATH, *, cleanup: bool
) -> list[Observable]:
    # E2 disk artifacts of the compiled payload: the .so output (so_path is a GT
    # entity here AND in E3, so a detection of it is always a TP, never an FP) and
    # the .c source written by the scenario. Both are recoverable on the timeline
    # (tsk) and persist the sed-unhook cleanup; the yara signature locus needs the
    # .so on disk, so it is no-cleanup only. The in-memory mapping is a SEPARATE
    # event (E3).
    obs = [
        _obs("timeline", "tsk", "path", so_path),
        _obs("timeline", "tsk", "path", src_path),
    ]
    if not cleanup:
        obs.append(_obs("content_scan", "yara", "path", so_path))
    return obs


def ldpreload_triggered_observables(
    so_path: str = SO_PATH, *, cleanup: bool
) -> list[Observable]:
    # E3_ldpreload_triggered (T1574.006): the .so mapped into the triggered PID.
    # Memory mappings outlive disk cleanup, so this is identical in both variants.
    return [_obs("memory_analysis", "vol3", "path", so_path)]


def reverse_shell_socket_observables(
    socket_value: str, *, cleanup: bool
) -> list[Observable]:
    # E4_reverse_shell (T1059.004): the established C2 socket. Lives only in memory
    # (acquired before cleanup), so it survives in both variants.
    return [_obs("memory_analysis", "vol3", "socket", socket_value)]


def reverse_shell_fifo_observables(
    fifo_path: str = RS_FIFO, *, cleanup: bool
) -> list[Observable]:
    # E4 disk artifact: the reverse-shell FIFO, recoverable on the timeline (tsk).
    # The reverse-shell step has no cleanup, so the FIFO persists on disk in both
    # variants.
    return [_obs("timeline", "tsk", "path", fifo_path)]


def discovery_deleted_observables(
    output_path: str = DISCOVERY_OUTPUT, *, cleanup: bool
) -> list[Observable]:
    # E5_discovery_deleted (T1070.004): cleanup-only. The deletion of the discovery
    # file is itself observable as a recoverable tombstone (deleted-inode recovery
    # via tsk), a different locus than the live file. Only the cleanup variant
    # deletes it, so this event is marked cleanup_only in EVENTS.
    return [_obs("deleted_file", "tsk", "path", output_path)]


def _ts(base_epoch: float, offset_s: float) -> str:
    return epoch_us_to_iso_ms(int((base_epoch + offset_s) * 1_000_000))


# --- event skeleton (single source of truth) ----------------------------------
# EventCtx carries the per-run locator values; the live attack fills it with
# resolved/randomized paths, calibration leaves the defaults. Each EventSpec maps
# that context to the event's primary entity and its observables, so the static
# shape (technique, class, entity_type, expected_sources, builder) lives once.


@dataclass(frozen=True)
class EventCtx:
    cleanup: bool
    discovery_output: str = DISCOVERY_OUTPUT
    preload_path: str = PRELOAD_PATH
    so_path: str = SO_PATH
    src_path: str = SRC_PATH
    socket_value: str = f"{DEFAULT_HOST_IP}:{RS_PORT}"
    fifo: str = RS_FIFO


@dataclass(frozen=True)
class EventSpec:
    step: str
    technique: str
    event_class: str
    entity_type: str
    expected_sources: tuple[str, ...]
    offset_s: float  # deterministic calibration timing only; live uses wall-clock
    cleanup_only: bool
    entity: Callable[[EventCtx], str]
    observables: Callable[[EventCtx], list[Observable]]


EVENTS: tuple[EventSpec, ...] = (
    EventSpec(
        "E1_discovery_os_info", "T1082", "file_created", "path", ("disk_fs",), 0,
        False,
        entity=lambda c: c.discovery_output,
        observables=lambda c: discovery_observables(c.discovery_output, cleanup=c.cleanup),
    ),
    EventSpec(
        "E2_ldpreload_persistence", "T1574.006", "persistence_installed", "path",
        ("disk_fs", "disk_logs"), 5, False,
        entity=lambda c: c.preload_path,
        observables=lambda c: ldpreload_persistence_observables(
            c.preload_path, c.so_path, cleanup=c.cleanup
        ),
    ),
    EventSpec(
        "E2_ldpreload_payload", "T1574.006", "file_created", "path",
        ("disk_fs", "memory"), 6, False,
        entity=lambda c: c.so_path,
        observables=lambda c: ldpreload_so_observables(
            c.so_path, c.src_path, cleanup=c.cleanup
        ),
    ),
    EventSpec(
        "E3_ldpreload_triggered", "T1574.006", "process_exec", "path", ("memory",),
        8, False,
        entity=lambda c: c.so_path,
        observables=lambda c: ldpreload_triggered_observables(c.so_path, cleanup=c.cleanup),
    ),
    EventSpec(
        "E4_reverse_shell", "T1059.004", "network_connection", "socket", ("memory",),
        10, False,
        entity=lambda c: c.socket_value,
        observables=lambda c: reverse_shell_socket_observables(
            c.socket_value, cleanup=c.cleanup
        ),
    ),
    EventSpec(
        "E4_reverse_shell_fifo", "T1059.004", "file_created", "path", ("disk_fs",),
        12, False,
        entity=lambda c: c.fifo,
        observables=lambda c: reverse_shell_fifo_observables(c.fifo, cleanup=c.cleanup),
    ),
    EventSpec(
        "E5_discovery_deleted", "T1070.004", "file_deleted", "path", ("disk_fs",),
        14, True,
        entity=lambda c: c.discovery_output,
        observables=lambda c: discovery_deleted_observables(
            c.discovery_output, cleanup=c.cleanup
        ),
    ),
)

EVENTS_BY_STEP: dict[str, EventSpec] = {e.step: e for e in EVENTS}


def record_event(
    builder: GtManifestBuilder,
    spec: EventSpec,
    ctx: EventCtx,
    *,
    ts_utc: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    # The shared record path. ts_utc=None lets the builder stamp wall-clock time
    # (the live attack); calibration passes a deterministic ts_utc. details is
    # optional metadata (calibration tags the step name; the live attack omits it).
    builder.record(
        technique=spec.technique,
        event_class=spec.event_class,
        entity_type=spec.entity_type,
        entity_value=spec.entity(ctx),
        ts_utc=ts_utc,
        details=details,
        expected_sources=list(spec.expected_sources),
        observables=spec.observables(ctx),
    )


def build_calibration_manifest(
    *,
    cleanup: bool,
    distro: str = "ubuntu-22.04",
    run_id: str | None = None,
    seed: int = 1337,
    host_ip: str = DEFAULT_HOST_IP,
    port: int = RS_PORT,
    fifo: str = RS_FIFO,
    base_ts: str = "2026-06-13T12:00:00.000Z",
) -> GtManifest:
    # Deterministic GT for the two calibration variants, used to generate the
    # fixtures and to document the expected ground truth. The six core events
    # realize the four logical steps (E2 and E4 each split a disk + a memory/log
    # locus). cleanup_only events (the T1070.004 deletion tombstone) are NOT
    # materialized here: calibration keeps the event set equal across variants so
    # the two are directly comparable (cleanup prunes observables, not events).
    # The deletion is a live-execution artifact only.
    scenario_id = SCENARIO_CLEANUP if cleanup else SCENARIO_NOCLEANUP
    run_id = run_id or f"{distro}_{scenario_id}_calibration"
    base = parse_iso_utc(base_ts)
    b = GtManifestBuilder(scenario_id, run_id, distro, seed=seed, cleanup=cleanup)
    ctx = EventCtx(cleanup=cleanup, socket_value=f"{host_ip}:{port}", fifo=fifo)
    for spec in EVENTS:
        if spec.cleanup_only:
            continue
        record_event(b, spec, ctx, ts_utc=_ts(base, spec.offset_s), details={"step": spec.step})
    return b.to_manifest()
