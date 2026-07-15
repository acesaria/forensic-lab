"""
orchestrator/core/orchestrator.py

Coordinates the full experiment lifecycle. Sits above vm_manager and
below attack modules -- it knows the sequence, not the details.

Public API
----------
setup_infra()              one-time: libvirt network + pool
prepare_lab(distro_id)     one-time: image + VM + baseline snapshot + pipeline verify
build_isf(distro_id)       one-time: Volatility symbol file
run_declarative_experiment(...)  experiment loop
destroy_lab(distro_id)     teardown
lab_exists(distro_id)      predicate
verify_pipeline(distro_id) acquire a baseline image and probe Volatility/SleuthKit/Plaso

Naming contract
---------------
distro_id    short config key  e.g. "ubuntu-22.04"
vm_name      libvirt domain    e.g. "lab-ubuntu-22.04"
Public methods accept distro_id. Private helpers use vm_name after resolution.

VM power-state contract
-----------------------
prepare_lab        ends OFF (snapshot taken, pipeline probe done)
build_isf          ends OFF (lab parked, build VM destroyed)
_reset_lab         ends ON + SSH ready
_run_acquisition   ends OFF (guest powered down for host-side disk acquisition)
run_declarative_experiment  ends OFF when acquire=True; ends ON when acquire=False
"""

from datetime import datetime
import functools
import json
import os
from pathlib import Path
from typing import Any

from orchestrator.core.config import (
    BASELINE_SNAPSHOT,
    MEMORY_DUMP_FILENAME,
    BUILD_VM_PREFIX,
    EVIDENCE_DISK_FILENAME,
    ISF_BUILD_PLAYBOOK,
    LAB_VM_PREFIX,
    VERIFY_SCENARIO,
    load_profile,
)
from orchestrator.core import console
from orchestrator.core.paths import ProjectPaths
from orchestrator.core.provenance import file_sha256
from orchestrator.core.ssh_client import SSHClient
from orchestrator.core.vm_manager import VMManager
from orchestrator.forensics import Dumper
from orchestrator.forensics import SleuthKitRunner, VolatilityRunner
from orchestrator.forensics.plaso_runner import (
    default_linux_filter,
    run_timeline,
)
from orchestrator.forensics.extract import extract_bodyfile, extract_plugins
from orchestrator.forensics.pipeline_config import reported_version
from orchestrator.scenarios import run_scenario
from orchestrator.scenarios.executors import SSHClientExecutor


class ForensicOrchestrator:
    def __init__(
        self,
        vm_manager: VMManager,
        dumper: Dumper,
        vol_runner: VolatilityRunner,
        sleuth_runner: SleuthKitRunner,
        paths: ProjectPaths,
        role_defaults: dict[str, Any],
        raw_tools: dict[str, str],
    ) -> None:
        self.vm_manager = vm_manager
        self.dumper = dumper
        self._vol_runner = vol_runner
        self._sleuth_runner = sleuth_runner
        self._paths = paths
        self._role_defaults = role_defaults
        self._raw_tools = raw_tools

    # Convenience accessor keeps the call sites readable.
    @property
    def repo_root(self) -> Path:
        return self._paths.repo_root

    # --- one-time setup --------------------------------------------------

    def setup_infra(self) -> None:
        """Create libvirt network and storage pool. Run once on a new machine."""
        self.vm_manager.ensure_isolated_network()
        self.vm_manager.ensure_storage_pool()

    def prepare_lab(self, distro_id: str) -> None:
        """
        Download image, create lab VM, provision, take baseline snapshot.
        Safe to run multiple times -- skips steps already done.
        VM ends OFF.
        """
        profile = load_profile(self.repo_root, distro_id)
        role_cfg = self._role_defaults.get("lab")
        if not isinstance(role_cfg, dict):
            raise RuntimeError("Missing 'role_defaults.lab' in config")

        vm_name = f"{LAB_VM_PREFIX}-{distro_id}"
        if not self.vm_manager.vm_exists(vm_name):
            self.vm_manager.prepare_lab(distro_id, profile, role_cfg)
            console.ok(f"'{distro_id}' ready for experiments")
        else:
            console.info(f"'{distro_id}' already present; skipping")

    def build_isf(self, distro_id: str) -> Path:
        """
        Ensure a Volatility ISF symbol file exists for the lab VM's kernel.
        Starts the lab VM briefly to detect the kernel, then shuts it down.
        Creates an ephemeral build VM if the ISF is not cached.
        VM ends OFF. Returns the ISF path.
        """
        profile = load_profile(self.repo_root, distro_id)
        lab_vm_name = f"{LAB_VM_PREFIX}-{distro_id}"

        kernel_release = self._detect_kernel_release(lab_vm_name)

        isf_name = _isf_filename(distro_id, kernel_release)
        self._paths.isf_dir.mkdir(parents=True, exist_ok=True)
        isf_path = self._paths.isf_dir / isf_name

        if isf_path.exists():
            console.info(f"symbol file already present: {isf_path.absolute()}")
            return isf_path

        role_cfg = self._role_defaults.get("build-isf")
        if not isinstance(role_cfg, dict):
            raise RuntimeError("Missing 'role_defaults.build-isf' in config")

        self._build_isf_with_ephemeral_vm(
            distro_id=distro_id,
            profile=profile,
            role_cfg=role_cfg,
            kernel_release=kernel_release,
            isf_name=isf_name,
        )

        if not isf_path.exists():
            raise RuntimeError(f"ISF build completed but output not found: {isf_path}")

        console.ok(f"ISF exported: {isf_path}")
        return isf_path

    def lab_exists(self, distro_id: str) -> bool:
        return self.vm_manager.vm_exists(f"{LAB_VM_PREFIX}-{distro_id}")

    # --- declarative experiment loop -------------------------------------

    def run_declarative_experiment(
        self,
        distro_id: str,
        scenario_id: str,
        scenario_cfg: dict[str, Any],
        acquire: bool = True,
    ) -> str | None:
        """
        VM-backed run of a declarative scenario.yml.

        Reverts to baseline, runs the scenario's steps inside the guest over SSH
        (writing manifest.json and command_log.jsonl at the run root), then --
        unless acquire is False -- acquires RAM+disk and writes raw forensic
        exports under analysis/. The VM ends OFF when acquire is True, ON
        otherwise.

        Declarative scenarios always run their full step list; the scenario.yml
        owns its own step sequence.
        """
        scenario_yml = self.repo_root / str(scenario_cfg["scenario_yml"])
        if not scenario_yml.is_file():
            raise RuntimeError(
                f"scenario '{scenario_id}': scenario.yml not found: {scenario_yml}"
            )

        profile = "vanilla"
        console.section(
            f"experiment: {scenario_id} | distro: {distro_id} | profile: {profile}"
        )
        console.step_header("baseline restoration and readiness")
        try:
            vm_name = self._reset_lab(distro_id)
        finally:
            console.section_end()
        run_id = _make_run_id(distro_id, scenario_id)
        run_root = self._paths.experiments_dir / run_id
        run_display = Path(os.path.relpath(run_root, self.repo_root))

        ctx = None
        guest: dict[str, Any] | None = None

        console.step_header("scenario execution")
        try:
            with self.vm_manager.open_ssh(vm_name) as ssh:
                ctx = run_scenario(
                    scenario_yml,
                    executor=SSHClientExecutor(ssh),
                    out_dir=run_root,
                    run_id=run_id,
                    repo_root=self.repo_root,
                    distro=distro_id,
                    profile=profile,
                    internet_on=functools.partial(self.vm_manager.internet_on, vm_name),
                    internet_off=functools.partial(self.vm_manager.internet_off, vm_name),
                )
                if guest is None:
                    guest = self._guest_facts(ssh)
                ctx.update_environment(
                    guest=guest,
                    distro=distro_id,
                )
        finally:
            self.vm_manager.internet_off(vm_name, quiet=True)
            console.section_end()

        if not acquire:
            console.step_header("summary")
            console.ok(f"scenario status: {ctx.final_status}")
            console.info(f"distro/profile: {distro_id} / {profile}")
            console.info("acquisition: intentionally skipped (--no-acquire)")
            console.info("raw extraction: intentionally skipped (--no-acquire)")
            console.info("final VM state: running")
            console.info(f"run directory: {run_display}")
            console.info(f"root manifest: {run_display / ctx.manifest_path.name}")
            console.section_end()
            return None

        manifest_path = self._run_acquisition(vm_name, run_id, scenario_id)
        if ctx is not None:
            ctx.record_acquisition_output(manifest_path)
        raw_status, raw_status_path = self._extract_raw_outputs(
            run_id,
            distro_id,
            manifest_path,
            ctx=ctx,
            kernel_release=(guest or {}).get("kernel"),
        )
        console.step_header("summary")
        console.ok(f"scenario status: {ctx.final_status}")
        console.info(f"distro/profile: {distro_id} / {profile}")
        console.ok("acquisition status: completed")
        for label, key in (
            ("Volatility", "volatility"),
            ("TSK", "tsk"),
            ("Plaso", "plaso"),
        ):
            state = raw_status.get(key, {}).get("status", "unknown")
            emit = console.ok if state == "completed" else console.warn
            emit(f"{label}: {state}")
        console.info("final VM state: off")
        console.info(f"run directory: {run_display}")
        console.info(f"root manifest: {run_display / ctx.manifest_path.name}")
        console.info(
            "raw extraction status: "
            f"{run_display / raw_status_path.relative_to(run_root)}"
        )
        console.section_end()
        return manifest_path

    @staticmethod
    def _guest_facts(ssh: SSHClient) -> dict[str, Any]:
        cmd = (
            ". /etc/os-release 2>/dev/null; "
            'printf "distro=%s\\n" "${PRETTY_NAME:-unknown}"; '
            'printf "kernel=%s\\n" "$(uname -r)"; '
            'printf "timezone=%s\\n" '
            '"$(cat /etc/timezone 2>/dev/null || '
            'timedatectl show -p Timezone --value 2>/dev/null || echo UTC)"'
        )
        facts: dict[str, Any] = {
            "distro": None,
            "kernel": None,
            "timezone": "UTC",
        }
        try:
            code, out, _ = ssh.run(cmd, timeout=30)
        except Exception:
            return facts
        if code != 0:
            return facts
        for line in out.splitlines():
            key, sep, value = line.partition("=")
            if sep and key.strip() in facts and value.strip():
                facts[key.strip()] = value.strip()
        return facts

    def _extract_raw_outputs(
        self,
        run_id: str,
        distro_id: str,
        manifest_path: str,
        *,
        ctx=None,
        kernel_release: str | None = None,
    ) -> tuple[dict[str, Any], Path]:
        """Produce raw TSK, Plaso, and Volatility exports after acquisition."""
        analysis_dir = self._paths.run_analysis_dir(run_id)
        analysis_dir.mkdir(parents=True, exist_ok=True)

        console.step_header("raw extraction")
        try:
            status = self._produce_raw_outputs(
                run_id,
                distro_id,
                manifest_path,
                analysis_dir,
                kernel_release=kernel_release,
            )
            status_path = analysis_dir / "raw_extraction_status.json"
            status_path.write_text(
                json.dumps(status, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            if ctx is not None:
                ctx.record_raw_analysis_output(status_path)
            return status, status_path
        finally:
            console.section_end()

    def _produce_raw_outputs(
        self,
        run_id: str,
        distro_id: str,
        manifest_path: str,
        analysis_dir: Path,
        *,
        kernel_release: str | None = None,
    ) -> dict[str, Any]:
        """Run each raw extractor best-effort and return manifest-ready status."""
        manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        memory_path = Path(manifest["memory_image"]["path"])
        disk_path = Path(manifest["disk_image"]["path"])
        status: dict[str, Any] = {}

        vol_errors: dict[str, str] = {}
        vol_invocations: dict[str, dict[str, Any]] = {}
        try:
            vol_rows = extract_plugins(
                self._vol_runner,
                memory_path,
                distro_id,
                kernel_release=kernel_release,
                errors=vol_errors,
                invocations=vol_invocations,
            )
            vol_path = analysis_dir / "vol3.json"
            vol_path.write_text(
                json.dumps(vol_rows, indent=2, default=str), encoding="utf-8"
            )
            plugin_counts = {
                plugin: len(rows) if rows is not None else None
                for plugin, rows in sorted(vol_rows.items())
            }
            for invocation in vol_invocations.values():
                invocation["output_path"] = str(vol_path)
            state = "completed"
            if vol_errors:
                state = "failed" if len(vol_errors) == len(vol_rows) else "degraded"
                result_state = (
                    "no_successful_results"
                    if len(vol_errors) == len(vol_rows)
                    else "partial_results"
                )
                console.warn(
                    f"vol3 extraction {state}: "
                    + "; ".join(f"{name}: {err}" for name, err in vol_errors.items())
                )
            else:
                result_state = (
                    "results" if any(plugin_counts.values()) else "zero_results"
                )
                console.ok(f"vol3 output written: {vol_path}")
            status["volatility"] = {
                "status": state,
                "path": str(vol_path),
                "tool": "volatility3",
                "version": reported_version("volatility3", self._raw_tools),
                "plugin_rows": plugin_counts,
                "result": result_state,
                "invocations": vol_invocations,
                "output": _output_metadata(vol_path),
            }
            if vol_errors:
                status["volatility"]["errors"] = vol_errors
        except Exception as exc:
            console.warn(f"vol3 extraction failed: {exc}")
            status["volatility"] = _failed_status(
                "volatility3",
                reported_version("volatility3", self._raw_tools),
                exc,
                paths={"path": str(analysis_dir / "vol3.json")},
                invocations=vol_invocations,
            )

        tsk_invocations: list[dict[str, Any]] = []
        try:
            tsk = extract_bodyfile(
                self._sleuth_runner,
                disk_path,
                invocations=tsk_invocations,
            )
            bodyfile = tsk.get("bodyfile") or ""
            bodyfile_path = analysis_dir / "bodyfile"
            bodyfile_path.write_text(
                bodyfile + ("\n" if bodyfile else ""), encoding="utf-8"
            )
            for invocation in tsk_invocations:
                if Path(invocation["command"][0]).name == "fls":
                    invocation["stdout_path"] = str(bodyfile_path)
            console.ok(f"tsk bodyfile written: {bodyfile_path}")
            status["tsk"] = {
                "status": "completed",
                "path": str(bodyfile_path),
                "tool": "sleuthkit",
                "version": reported_version("sleuthkit", self._raw_tools),
                "row_count": len(bodyfile.splitlines()),
                "result": "zero_results" if not bodyfile else "results",
                "invocations": tsk_invocations,
                "output": _output_metadata(bodyfile_path),
            }
        except Exception as exc:
            console.warn(f"tsk extraction failed: {exc}")
            status["tsk"] = _failed_status(
                "sleuthkit",
                reported_version("sleuthkit", self._raw_tools),
                exc,
                paths={"path": str(analysis_dir / "bodyfile")},
                invocations=tsk_invocations,
            )

        try:
            timeline = self._build_timeline(disk_path, analysis_dir)
            events = timeline["events"]
            storage_path = analysis_dir / "timeline.plaso"
            timeline_path = analysis_dir / "timeline.jsonl"
            status["plaso"] = {
                "status": "completed",
                "storage_path": str(storage_path),
                "path": str(timeline_path),
                "tool": "plaso",
                "version": reported_version("plaso", self._raw_tools),
                "event_count": len(events),
                "result": "zero_results" if not events else "results",
                "invocations": {
                    "log2timeline": timeline["log2timeline"],
                    "psort": timeline["psort"],
                },
                "outputs": {
                    "storage": _output_metadata(storage_path),
                    "timeline": _output_metadata(timeline_path),
                },
            }
        except Exception as exc:
            console.warn(f"plaso timeline failed: {exc}")
            status["plaso"] = _failed_status(
                "plaso",
                reported_version("plaso", self._raw_tools),
                exc,
                paths={
                    "storage_path": str(analysis_dir / "timeline.plaso"),
                    "path": str(analysis_dir / "timeline.jsonl"),
                },
                invocations=getattr(exc, "invocations", None),
            )

        status["run_id"] = run_id
        status["acquisition_manifest"] = str(manifest_path)
        return status

    def _build_timeline(self, disk_path: Path, analysis_dir: Path) -> dict:
        """
        Run the Plaso pipeline over the acquired disk and return the events.
        Keep timeline.plaso/timeline.jsonl in the caller's analysis directory
        and return invocation provenance with the events.
        """

        storage_path = analysis_dir / "timeline.plaso"
        timeline_path = analysis_dir / "timeline.jsonl"

        file_filter = default_linux_filter()
        result = run_timeline(
            disk_path=disk_path,
            storage_path=storage_path,
            output_path=timeline_path,
            log2timeline_bin=self._raw_tools["log2timeline"],
            psort_bin=self._raw_tools["psort"],
            file_filter=file_filter,
        )
        events = result["events"]
        console.ok(f"timeline built: {len(events)} event(s) ({timeline_path})")
        return result

    # --- teardown --------------------------------------------------------

    def destroy_lab(self, distro_id: str) -> None:
        """Remove the lab VM and all its associated storage."""
        self.vm_manager.destroy_lab(distro_id)

    def close(self) -> None:
        self.vm_manager.close()

    def __enter__(self) -> "ForensicOrchestrator":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # --- private: setup helpers ------------------------------------------

    def _detect_kernel_release(self, lab_vm_name: str) -> str:
        console.step(f"detecting kernel on {lab_vm_name}...")
        self.vm_manager.start_vm(lab_vm_name)
        self.vm_manager.wait_ssh_ready(lab_vm_name, reason="kernel detection")
        with self.vm_manager.open_ssh(lab_vm_name) as ssh:
            kernel_release = ssh.run_checked("uname -r")
        console.ok(f"kernel: {kernel_release}")
        self.vm_manager.shutdown_vm(lab_vm_name)
        return kernel_release

    def _build_isf_with_ephemeral_vm(
        self,
        distro_id: str,
        profile: dict[str, Any],
        role_cfg: dict[str, Any],
        kernel_release: str,
        isf_name: str,
    ) -> None:
        """
        Create a temporary build VM, run the ISF build playbook, destroy it.
        Lab VM is not touched here.
        """
        build_vm_name = f"{BUILD_VM_PREFIX}-{distro_id}"
        base_image = self.vm_manager.ensure_base_image(profile)
        self.vm_manager.create_vm(
            role="build-isf",
            distro_id=distro_id,
            profile=profile,
            role_cfg=role_cfg,
            base_image=base_image,
        )
        try:
            self.vm_manager.start_vm(build_vm_name)
            console.step(
                f"provisioning {distro_id} (kernel {kernel_release}) "
                "(may take up to 20 minutes)..."
            )
            try:
                self.vm_manager.run_playbook_on_vm(
                    build_vm_name,
                    self.repo_root / ISF_BUILD_PLAYBOOK,
                    extra_vars={
                        "kernel_version": kernel_release,
                        "isf_filename": isf_name,
                        "shared_isf_dir": str(self._paths.isf_dir),
                    },
                    reason="isf build",
                )
            except RuntimeError as exc:
                raise RuntimeError(
                    f"ISF build: Ansible playbook failed for '{distro_id}'.\n"
                    "Common causes: no internet on build VM, kernel debuginfo "
                    f"package not available for kernel '{kernel_release}'.\n"
                    "Run with --debug to see full Ansible output.\n"
                    f"Original error: {exc}"
                ) from exc
        finally:
            self.vm_manager.destroy_vm(build_vm_name)

    def verify_pipeline(self, distro_id: str) -> None:
        """
        Acquire a baseline image and probe with Volatility + SleuthKit + Plaso.
        Called automatically at the end of the CLI 'setup' sequence.
        Requires the ISF to already exist (call after build_isf).
        VM ends OFF.
        """
        vm_name = self._reset_lab(distro_id)
        # Compute run_id ONCE so dumps/ and analysis/ share the same timestamp.
        run_id = _make_run_id(distro_id, VERIFY_SCENARIO)

        manifest_path = self._run_acquisition(vm_name, run_id, VERIFY_SCENARIO)

        manifest = json.loads(Path(manifest_path).read_text())
        memory_path = Path(manifest["memory_image"]["path"])
        disk_path = Path(manifest["disk_image"]["path"])

        console.step(f"probing acquired images for {distro_id}...")
        self._vol_runner.probe(memory_path, distro_id)
        self._sleuth_runner.probe(disk_path)
        # Plaso probe: confirm the toolchain can ingest the disk and emit events.
        self._build_timeline(disk_path, self._paths.run_analysis_dir(run_id))
        console.ok(f"pipeline verified for '{distro_id}'")

    # --- private: experiment helpers -------------------------------------

    def _reset_lab(self, distro_id: str) -> str:
        """
        Revert to baseline snapshot, start VM, wait for SSH.
        VM ends ON + SSH ready. Returns vm_name.
        """
        vm_name = f"{LAB_VM_PREFIX}-{distro_id}"
        console.step(f"reverting '{vm_name}' to baseline snapshot...")
        self.vm_manager.revert_to_baseline(distro_id)
        self.vm_manager.start_vm(vm_name)
        self.vm_manager.wait_ssh_ready(vm_name, reason="after snapshot revert")
        return vm_name

    def _run_acquisition(
        self,
        vm_name: str,
        run_id: str,
        scenario_id: str,
    ) -> str:
        """
        Acquire memory (VM ON), then shut the guest down and acquire its disk
        host-side from the released qcow2. Returns the manifest path.
        """
        vm_disk_path = self.vm_manager.get_disk_path(vm_name)

        run_dir = self.dumper.run_dir(run_id)
        memory_dump_path = run_dir / "memory" / MEMORY_DUMP_FILENAME
        disk_dump_path = run_dir / "disk" / EVIDENCE_DISK_FILENAME

        console.step_header("acquisition")
        try:
            memory_meta = self.dumper.acquire_memory(vm_name, memory_dump_path)
            # qemu-img convert needs the qcow2 not held by QEMU; a clean guest
            # shutdown is the simplest way to release the lock.
            console.step(
                f"shutting down '{vm_name}' for offline disk acquisition..."
            )
            self.vm_manager.shutdown_vm(vm_name)
            disk_meta = self.dumper.acquire_disk(vm_disk_path, disk_dump_path)
            return self.dumper.write_manifest(
                run_id, scenario_id, memory_meta, disk_meta
            )
        finally:
            console.section_end()


# --- module helpers ------------------------------------------------------


def _failed_status(
    tool: str,
    version: str | None,
    exc: Exception,
    *,
    paths: dict[str, str] | None = None,
    invocations: Any = None,
) -> dict[str, Any]:
    status = {
        "status": "failed",
        "tool": tool,
        "version": version,
        "error": str(exc),
    }
    if paths:
        status.update(paths)
    if invocations:
        status["invocations"] = invocations
    return status


def _output_metadata(path: Path) -> dict[str, Any]:
    return {
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "sha256": file_sha256(path),
    }


def _isf_filename(distro_id: str, kernel_release: str) -> str:
    family = distro_id.split("-", 1)[0]
    safe_kernel = kernel_release.replace("/", "_")
    return f"{family}_{safe_kernel}.json"


def _make_run_id(distro_id: str, scenario_id: str) -> str:
    """
    Build the stable per-run identifier:
        "{distro_id}_{scenario_id}_{YYYYMMDD-HHMMSS}"
    Used as the experiment directory name under experiments_dir; its dumps/
    and analysis/ subtrees stay in lockstep for a given run.
    """
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{distro_id}_{scenario_id}_{ts}"
