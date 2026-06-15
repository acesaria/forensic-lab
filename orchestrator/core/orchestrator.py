"""
orchestrator/core/orchestrator.py

Coordinates the full experiment lifecycle. Sits above vm_manager and
below attack modules -- it knows the sequence, not the details.

Public API
----------
setup_infra()              one-time: libvirt network + pool
prepare_lab(distro_id)     one-time: image + VM + baseline snapshot + pipeline verify
build_isf(distro_id)       one-time: Volatility symbol file
run_experiment(...)        experiment loop
destroy_lab(distro_id)     teardown
lab_exists(distro_id)      predicate
def verify_pipeline(distro_id: str): Acquire a baseline image and probe with Volatility + SleuthKit.

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
_run_acquisition   end state depends on mode: "offline" -> OFF,
                   "external_snapshot" -> ON (guest never stopped)
run_experiment     mirrors _run_acquisition when acquire=True; ends ON when
                   acquire=False
"""

from datetime import datetime
import functools
import importlib
import json
from pathlib import Path
from typing import Any, Callable

from orchestrator.core.config import (
    BASELINE_DISK_FILENAME,
    MEMORY_DUMP_FILENAME,
    BUILD_VM_PREFIX,
    ISF_BUILD_PLAYBOOK,
    ISOLATED_NETWORK_GATEWAY,
    LAB_VM_PREFIX,
    VERIFY_SCENARIO,
    load_profile,
)
from orchestrator.core import console
from orchestrator.core.paths import ProjectPaths
from orchestrator.core.ssh_client import SSHClient
from orchestrator.core.vm_manager import VMManager
from orchestrator.attacks import ArtRunner
from orchestrator.forensics import Dumper
from orchestrator.forensics import SleuthKitRunner, VolatilityRunner
from orchestrator.forensics.dumper import (
    ImageMetadata,
    normalize_disk_acquisition_mode,
)
from orchestrator.forensics.plaso_runner import (
    default_linux_filter,
    read_timeline,
    run_log2timeline,
    run_psort,
    verify_plaso_inputs,
)
# Evaluation goes through the GT-blind framework pipeline (detect -> match ->
# metrics). The old direct-GT-lookup path (artifact_specs.resolve_specs +
# ioc_detector + evaluator) is no longer executed here; GT is read only inside
# orchestrator.evaluation.match.
from orchestrator.evaluation.scenario.manifest import GtManifestBuilder
from orchestrator.evaluation.contracts.models import GtManifest
from orchestrator.evaluation.contracts.validate import load_gt_manifest
from orchestrator.evaluation.extract.vol3 import extract_plugins
from orchestrator.evaluation.extract.tsk import extract_bodyfile
from orchestrator.evaluation.provenance import build_provenance, write_provenance
from orchestrator.forensics import deleted_file_runner, yara_runner
from orchestrator.evaluation.pipeline import run_from_raw


class ForensicOrchestrator:
    def __init__(
        self,
        vm_manager: VMManager,
        dumper: Dumper,
        vol_runner: VolatilityRunner,
        sleuth_runner: SleuthKitRunner,
        paths: ProjectPaths,
        role_defaults: dict[str, Any],
    ) -> None:
        self.vm_manager = vm_manager
        self.dumper = dumper
        self._vol_runner = vol_runner
        self._sleuth_runner = sleuth_runner
        self._paths = paths
        self._role_defaults = role_defaults

    # Convenience accessors keep the call sites readable.
    @property
    def repo_root(self) -> Path:
        return self._paths.repo_root

    @property
    def atomics_path(self) -> Path:
        return self._paths.atomics_dir

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

        vm_name = "lab-" + distro_id
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

    # --- experiment loop -------------------------------------------------

    def run_experiment(
        self,
        distro_id: str,
        scenario_id: str,
        scenario_cfg: dict[str, Any],
        acquire: bool = True,
        evaluate: bool = True,
        run_cleanup: bool = True,
        seed: int = 0,
    ) -> str | None:
        """
        Full experiment cycle:
        1. Revert VM to baseline and start it
        2. Dispatch the scenario module, persist ground truth
        3. Acquire RAM + disk (unless acquire=False)
        4. Detect IOCs + score per-step metrics (unless evaluate=False)

        End VM state mirrors the acquisition mode: "offline" leaves the
        VM OFF, "external_snapshot" leaves it ON. When acquire=False the
        VM is left ON. Evaluation needs the acquired images, so it only
        runs when acquire is True.
        Returns manifest path if acquired, else None.
        """
        console.section(f"experiment: {scenario_id} on {distro_id}")
        vm_name = self._reset_lab(distro_id)
        run_id = _make_run_id(distro_id, scenario_id)
        # ground_truth is owned here and mutated in place by the scenario so
        # whatever steps ran before an exception are still on disk afterwards.
        ground_truth: dict[str, Any] = {"scenario_id": scenario_id, "steps": []}
        # The GT-blind pipeline's ground-truth manifest, emitted at execution time
        # by the scenario (additive to ground_truth). Persisted in the finally so a
        # partial run still yields a manifest of whatever actions completed.
        gt_builder = GtManifestBuilder(
            scenario_id, run_id, distro_id, seed=seed, cleanup=run_cleanup
        )

        try:
            with self.vm_manager.open_ssh(vm_name) as ssh:
                self._dispatch_scenario(
                    vm_name,
                    ssh,
                    scenario_id,
                    scenario_cfg,
                    ground_truth,
                    run_cleanup=run_cleanup,
                    gt_builder=gt_builder,
                )
        finally:
            console.section_end()
            self._persist_ground_truth(run_id, ground_truth)
            gt_manifest_path = self._persist_gt_manifest(run_id, gt_builder)

        if acquire:
            manifest_path = self._run_acquisition(
                vm_name,
                run_id,
                scenario_id,
                disk_acquisition_mode="offline",
            )
            if evaluate:
                self._evaluate_run_framework(
                    run_id, scenario_id, distro_id, gt_manifest_path, manifest_path
                )
            return manifest_path
        return None

    def analyze_run(
        self, distro_id: str, scenario_id: str, run_id: str | None = None
    ) -> Path:
        """
        Re-run IOC detection + scoring on an already-acquired run, reusing its
        dumps and cached timeline (no VM, no Plaso re-run). Rewrites that run's
        forensics_report.json + metrics.csv so specs/filters can be iterated fast.
        """
        if run_id is None:
            run_id = self._latest_run_id(distro_id, scenario_id)
        run_dir = self.dumper.run_dir(run_id)
        gt_manifest_path = run_dir / "gt_manifest.json"
        manifest_path = str(run_dir / "manifest.json")
        console.section(f"re-analyze: {run_id}")
        self._evaluate_run_framework(
            run_id,
            scenario_id,
            distro_id,
            gt_manifest_path,
            manifest_path,
            reuse_cached_timeline=True,
        )
        return self._paths.run_analysis_dir(run_id) / "metrics.csv"

    def _latest_run_id(self, distro_id: str, scenario_id: str) -> str:
        # run_id ends in a timestamp, so lexical sort over the matching run dirs
        # is chronological; the last one is the most recent.
        prefix = f"{distro_id}_{scenario_id}_"
        runs = sorted(
            p.name
            for p in self._paths.experiments_dir.glob(f"{prefix}*")
            if p.is_dir()
        )
        if not runs:
            raise RuntimeError(
                f"no acquired run found for {distro_id} / {scenario_id} "
                f"under {self._paths.experiments_dir}"
            )
        return runs[-1]

    def _dispatch_scenario(
        self,
        vm_name: str,
        ssh: SSHClient,
        scenario_id: str,
        scenario_cfg: dict[str, Any],
        ground_truth: dict[str, Any],
        run_cleanup: bool = True,
        gt_builder=None,
    ) -> None:
        """
        Import the scenario module named in scenario_cfg["module"] and call
        its run() with ssh/runner/host_ip + internet_on/off + ground_truth
        plus any remaining cfg keys as kwargs. The scenario appends to
        ground_truth["steps"] in place; nothing is returned.

        Ensures the NAT NIC link is down before returning so the memory dump
        doesn't capture stray network state.
        """
        module_path = scenario_cfg.get("module")
        if not module_path:
            raise RuntimeError(f"scenario '{scenario_id}' missing 'module' key")
        try:
            module = importlib.import_module(module_path)
        except ImportError as exc:
            raise RuntimeError(
                f"scenario '{scenario_id}': cannot import module '{module_path}': {exc}"
            ) from exc
        run_fn = getattr(module, "run", None)
        if run_fn is None:
            raise RuntimeError(
                f"scenario module '{module_path}' has no top-level run() function"
            )
        extras = {k: v for k, v in scenario_cfg.items() if k != "module"}
        # run_cleanup comes straight from the CLI --cleanup/--no-cleanup flag.
        extras["run_cleanup"] = run_cleanup
        runner = ArtRunner(ssh, self.atomics_path)
        internet_on = functools.partial(self.vm_manager.internet_on, vm_name)
        internet_off = functools.partial(self.vm_manager.internet_off, vm_name)
        try:
            run_fn(
                ssh=ssh,
                runner=runner,
                host_ip=ISOLATED_NETWORK_GATEWAY,
                internet_on=internet_on,
                internet_off=internet_off,
                ground_truth=ground_truth,
                gt_builder=gt_builder,
                **extras,
            )
        finally:
            self.vm_manager.internet_off(vm_name, quiet=True)

    def _persist_ground_truth(
        self,
        run_id: str,
        ground_truth: dict[str, Any],
    ) -> Path:
        """Write ground_truth.json beside the acquisition outputs."""
        run_dir = self.dumper.run_dir(run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        out = run_dir / "ground_truth.json"
        out.write_text(json.dumps(ground_truth, indent=2, default=str))
        console.ok(f"ground truth written: {out}")
        return out

    def _persist_gt_manifest(self, run_id: str, gt_builder) -> Path:
        """Write gt_manifest.json beside the dumps. Best-effort: a manifest write
        failure must not sink the run."""
        run_dir = self.dumper.run_dir(run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        out = run_dir / "gt_manifest.json"
        try:
            gt_builder.write(out)
            console.ok(f"gt manifest written: {out}")
        except Exception as exc:
            console.warn(f"gt manifest not written: {exc}")
        return out

    def _evaluate_run_framework(
        self,
        run_id: str,
        scenario_id: str,
        distro_id: str,
        gt_manifest_path: Path,
        manifest_path: str,
        reuse_cached_timeline: bool = False,
    ) -> None:
        """
        GT-blind detection + GT-aware matching + metrics on the acquired images.

        Best-effort: the acquisition has already succeeded and is on disk, so a
        failure here is logged and swallowed rather than discarding a good run.
        Writes analysis/<run_id>/{findings.jsonl,matches.json,metrics.csv,report.md}.
        """
        if not Path(gt_manifest_path).is_file():
            console.info(
                f"no gt_manifest for '{scenario_id}'; skipping evaluation"
            )
            return

        manifest = json.loads(Path(manifest_path).read_text())
        memory_path = Path(manifest["memory_image"]["path"])
        disk_path = Path(manifest["disk_image"]["path"])

        console.step_header("detect -> match -> metrics")
        try:
            gt = GtManifest.from_dict(load_gt_manifest(gt_manifest_path))
            timeline_events = self._build_timeline(
                run_id, disk_path, reuse_cached=reuse_cached_timeline
            )
            raw_outputs: dict[str, Any] = {"plaso": timeline_events}
            try:
                raw_outputs["vol3"] = extract_plugins(
                    self._vol_runner, memory_path, distro_id
                )
            except Exception as exc:
                console.warn(f"vol3 extraction degraded: {exc}")
            try:
                raw_outputs["tsk"] = extract_bodyfile(self._sleuth_runner, disk_path)
            except Exception as exc:
                console.warn(f"tsk extraction degraded: {exc}")

            # External-tool channels (best-effort, like vol3/tsk). YARA needs a
            # mounted/extracted FS root, provided per-distro by self._fs_scan_root
            # (None -> skipped). The plaso_sigma detector runs automatically over
            # raw_outputs["plaso"].
            scan_root = self._fs_scan_root(distro_id)
            if scan_root is not None:
                try:
                    raw_outputs["yara"] = yara_runner.run(scan_root)
                except Exception as exc:
                    console.warn(f"yara scan degraded: {exc}")

            # Escalating deleted-file recovery. Targets are the GT deleted_file
            # observables, passed as plain dicts so the runner stays GT-blind.
            analysis_dir = self._paths.run_analysis_dir(run_id)
            recovery_versions: dict[str, Any] = {}
            targets = self._deleted_file_targets(gt)
            if targets:
                try:
                    payload = deleted_file_runner.run(
                        disk_path,
                        self._partition_info(distro_id, disk_path),
                        targets,
                        analysis_dir / "deleted_file",
                        run_id,
                    )
                    raw_outputs["deleted_file"] = payload
                    recovery_versions = payload.get("tool_versions", {})
                except Exception as exc:
                    console.warn(f"deleted-file recovery degraded: {exc}")

            case_window = self._case_window(gt)
            row = run_from_raw(
                gt,
                raw_outputs,
                analysis_dir,
                case_window=case_window,
            )
            self._write_recovery_provenance(run_id, analysis_dir, recovery_versions)
        except Exception as exc:
            console.warn(f"evaluation failed (acquisition is intact): {exc}")
            console.section_end()
            return

        v = row.values
        console.ok(
            f"metrics written: recall={v['recall']} precision={v['precision']} "
            f"tp={v['tp']} fp={v['fp']} fn={v['fn']} "
            f"({self._paths.run_analysis_dir(run_id) / 'metrics.csv'})"
        )
        console.section_end()

    @staticmethod
    def _case_window(gt: GtManifest) -> dict[str, str] | None:
        # The case window bounds which on-disk creations the tsk heuristic
        # considers, from the seeded action span padded by a margin. Derived from
        # the manifest's own event times (acquisition metadata), never from a
        # planted entity value.
        from orchestrator.forensics.timeutil import parse_iso_utc, iso_utc_ms
        from datetime import datetime, timezone

        times = [parse_iso_utc(e.ts_utc) for e in gt.events]
        if not times:
            return None
        margin = 1800.0
        lo = datetime.fromtimestamp(min(times) - margin, timezone.utc)
        hi = datetime.fromtimestamp(max(times) + margin, timezone.utc)
        return {"start": iso_utc_ms(lo), "end": iso_utc_ms(hi)}

    def _fs_scan_root(self, distro_id: str) -> Path | None:
        # Root of a mounted/extracted filesystem for YARA to walk (/tmp, /etc
        # under it). The current acquisition flow does not mount the E01, so this
        # is opt-in: set host.fs_scan_root (or role default) to a directory where
        # the image is mounted/extracted, else YARA is skipped.
        # TODO: mount the read-only E01 (ewfmount + loop) here so YARA runs
        # automatically without an externally provided root.
        root = self._role_defaults.get("fs_scan_root")
        if not root:
            return None
        p = Path(root)
        return p if p.is_dir() else None

    @staticmethod
    def _deleted_file_targets(gt: GtManifest) -> list[dict[str, Any]]:
        # Artifacts to attempt recovery for: the GT observables whose operation is
        # deleted_file, deduped by value. Read from GT here (orchestrator is
        # GT-aware) and handed to the runner as plain dicts to keep it blind.
        targets: list[dict[str, Any]] = []
        seen: set[str] = set()
        for ev in gt.events:
            for o in ev.observables:
                if o.operation == "deleted_file" and o.entity_value not in seen:
                    seen.add(o.entity_value)
                    targets.append(
                        {"entity_type": o.entity_type, "entity_value": o.entity_value}
                    )
        return targets

    def _partition_info(self, distro_id: str, disk_path: Path) -> dict[str, Any]:
        # Filesystem context for the recovery runner. fs_type gates ext4magic;
        # tmpfs_mounts mark volatile paths (deletions there are unrecoverable).
        # offset_sectors locates the partition for tsk_recover; best-effort.
        try:
            offset = self._sleuth_runner.partition_offset(disk_path)
        except Exception:
            offset = 0
        return {
            "fs_type": self._role_defaults.get("root_fs_type", "ext4"),
            "offset_sectors": offset,
            "is_tmpfs": False,
            "tmpfs_mounts": self._role_defaults.get(
                "tmpfs_mounts", ["/tmp", "/dev/shm", "/run"]
            ),
        }

    def _write_recovery_provenance(
        self, run_id: str, analysis_dir: Path, tool_versions: dict[str, Any]
    ) -> None:
        # Record the recovery tool versions actually used in provenance.json so the
        # run is reproducible (which of tsk_recover/ext4magic/scalpel/photorec ran).
        if not tool_versions:
            return
        try:
            prov = build_provenance(
                run_id,
                artifacts={"findings": analysis_dir / "findings.jsonl"},
                extra={"recovery_tool_versions": tool_versions},
            )
            write_provenance(prov, analysis_dir / "provenance.json")
        except Exception as exc:
            console.warn(f"provenance write degraded: {exc}")

    def _build_timeline(
        self, run_id: str, disk_path: Path, reuse_cached: bool = False
    ) -> list[dict]:
        """
        Run the Plaso pipeline over the acquired disk and return the events.
        Mirrors _verify_plaso but keeps the timeline as a named run artifact
        (analysis/<run_id>/timeline.jsonl) for the timeline-based IOC specs.

        reuse_cached skips the (expensive) Plaso run and reads the existing
        timeline.jsonl instead -- used by analyze_run to iterate on specs.
        """

        analysis_dir = self._paths.run_analysis_dir(run_id)
        storage_path = analysis_dir / "timeline.plaso"
        timeline_path = analysis_dir / "timeline.jsonl"

        if reuse_cached:
            events = read_timeline(timeline_path)
            console.ok(f"timeline reused: {len(events)} event(s) ({timeline_path})")
            return events

        file_filter = default_linux_filter()
        verify_plaso_inputs(file_filter=file_filter)
        run_log2timeline(
            disk_path=disk_path, storage_path=storage_path, file_filter=file_filter
        )
        run_psort(storage_path=storage_path, output_path=timeline_path)
        events = read_timeline(timeline_path)
        console.ok(f"timeline built: {len(events)} event(s) ({timeline_path})")
        return events

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
        self._verify_plaso(run_id, disk_path)
        console.ok(f"pipeline verified for '{distro_id}'")

    def _verify_plaso(self, run_id: str, disk_path: Path) -> None:
        # Shallow sanity check: confirm the host's Plaso toolchain can ingest
        # the disk and emit at least one JSON event. Artifacts land under the
        # run's analysis/ subtree so they survive for inspection and don't sit
        # inside the dumps/ subtree (acquisition outputs) or the repo root. The
        # default Linux filter keeps this fast and verify_plaso_inputs()
        # catches missing binaries / YAML up front.
        file_filter = default_linux_filter()
        verify_plaso_inputs(file_filter=file_filter)

        verify_dir = self._paths.run_analysis_dir(run_id)
        storage_path = verify_dir / "verify.plaso"
        timeline_path = verify_dir / "verify.jsonl"
        run_log2timeline(
            disk_path=disk_path, storage_path=storage_path, file_filter=file_filter
        )
        run_psort(storage_path=storage_path, output_path=timeline_path)
        events = read_timeline(timeline_path)
        console.ok(
            f"plaso probe passed: {len(events)} event(s) readable "
            f"(artifacts: {verify_dir})"
        )

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
        disk_acquisition_mode: str = "offline",
    ) -> str:
        """
        Acquire memory (VM ON) then disk via the chosen workflow:
          - "offline":           shut down VM, then host-side acquire qcow2.
          - "external_snapshot": take a live external disk snapshot so writes
                                 divert to an overlay, host-side acquire the
                                 quiesced base, then blockcommit + pivot.

        Returns manifest path. The canonical mode label is recorded in the
        manifest under disk_acquisition_mode.
        """
        mode = normalize_disk_acquisition_mode(disk_acquisition_mode)
        vm_disk_path = self.vm_manager.get_disk_path(vm_name)

        run_dir = self.dumper.run_dir(run_id)
        memory_dump_path = run_dir / "memory" / MEMORY_DUMP_FILENAME
        disk_dump_path = run_dir / "disk" / BASELINE_DISK_FILENAME

        console.step_header("acquisition")
        memory_meta = self.dumper.acquire_memory(vm_name, memory_dump_path)
        disk_meta = self._acquire_disk_for_mode(
            vm_name, vm_disk_path, disk_dump_path, mode
        )

        console.section_end()

        return self.dumper.write_manifest(
            run_id,
            scenario_id,
            memory_meta,
            disk_meta,
            disk_acquisition_mode=mode,
        )

    def _acquire_disk_for_mode(
        self,
        vm_name: str,
        vm_disk_path: Path,
        dump_path: Path,
        mode: str,
    ) -> ImageMetadata:
        # Mode dispatch lives here, not in the dumper: VM lifecycle and
        # snapshot prepare/finalize are orchestration concerns, while the
        # dumper is pure host-side I/O.
        console.step(f"acquiring disk from '{vm_name} (mode={mode})'...")

        if mode == "offline":
            # qemu-img convert needs the qcow2 not held by QEMU; a clean
            # guest shutdown is the simplest way to release the lock.
            self.vm_manager.shutdown_vm(vm_name)
            return self.dumper.acquire_disk(vm_disk_path, dump_path)

        if mode == "external_snapshot":
            # Live external disk snapshot diverts guest writes to an overlay,
            # leaving the VM disk stable for host-side acquisition without the
            # shutdown noise that would otherwise alter guest-visible artifacts.
            overlay_path = vm_disk_path.parent / (
                f"{vm_name}-acq-{int(datetime.now().timestamp())}.overlay.qcow2"
            )

            self.vm_manager.prepare_disk_acquisition_external(vm_name, overlay_path)

            acq_exc: BaseException | None = None
            disk_meta: ImageMetadata | None = None

            try:
                disk_meta = self.dumper.acquire_disk(vm_disk_path, dump_path)
            except BaseException as exc:
                acq_exc = exc

            try:
                self.vm_manager.finalize_disk_acquisition_external(
                    vm_name, overlay_path
                )
            except Exception as fin_exc:
                if acq_exc is not None:
                    raise RuntimeError(
                        "disk acquisition failed AND snapshot finalize failed; "
                        "qcow2 chain needs manual cleanup.\n"
                        f"  acquisition: {acq_exc}\n"
                        f"  finalize:    {fin_exc}\n"
                        f"  overlay:     {overlay_path}"
                    ) from acq_exc
                raise RuntimeError(
                    "disk acquisition succeeded but snapshot finalize failed; "
                    "qcow2 chain may need manual cleanup.\n"
                    f"  overlay: {overlay_path}"
                ) from fin_exc

            if acq_exc is not None:
                raise acq_exc

            assert disk_meta is not None
            return disk_meta

        raise ValueError(f"unknown disk acquisition mode: {mode!r}")


# --- module helpers ------------------------------------------------------


def _isf_filename(distro_id: str, kernel_release: str) -> str:
    family = distro_id.split("-", 1)[0]
    safe_kernel = kernel_release.replace("/", "_")
    return f"{family}_{safe_kernel}.json"


def _make_run_id(distro_id: str, scenario_id: str) -> str:
    """
    Build the canonical per-run identifier:
        "{distro_id}_{scenario_id}_{YYYYMMDD-HHMMSS}"
    Used as the experiment directory name under experiments_dir; its dumps/
    and analysis/ subtrees stay in lockstep for a given run.
    """
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{distro_id}_{scenario_id}_{ts}"
