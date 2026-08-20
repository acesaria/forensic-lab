"""
orchestrator/core/orchestrator.py

Coordinates the full experiment lifecycle. Sits above vm_manager and
below the scenario runners -- it knows the sequence, not the details.

Public API
----------
setup_infra()              one-time: libvirt network + pool
prepare_lab(distro_id)     one-time: image + VM + baseline snapshot + pipeline verify
build_isf(distro_id)       one-time: Volatility symbol file
build_father(distro_id)    build + publish Father's rk.so to the host cache
build_badbpf(distro_id)    build + publish Bad-BPF and XCrypto inputs
build_diamorphine(...)     build + publish Diamorphine's exact-kernel module
build_ptrace_fa(distro_id) build + publish ptrace_fa binaries to the host cache
run_experiment(...)        explicit scenario dispatch + experiment loop
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
build_isf          ends OFF (lab parked, build VM retained)
build_father       ends OFF (builder VM retained; lab never started)
_reset_lab         ends ON + SSH ready
_run_acquisition   ends OFF (guest powered down for host-side disk acquisition)
Explicit scenarios end OFF, including when
acquisition is skipped or a step fails
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any, TypeAlias

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
from orchestrator.core.provenance import command_output, file_sha256, utc_now
from orchestrator.core.ssh_client import SSHClient
from orchestrator.core.vm_manager import VMManager
from orchestrator.forensics import Dumper
from orchestrator.forensics import SleuthKitRunner, VolatilityRunner
from orchestrator.forensics.plaso_runner import (
    default_linux_filter,
    run_timeline,
)
from scenarios.interactive_shell.runner import (
    SCENARIO_ID as INTERACTIVE_SHELL_SCENARIO,
    run_interactive_shell,
)
from scenarios.kernel_diamorphine import runner as diamorphine
from scenarios.kernel_ebpf_badbpf import runner as badbpf
from scenarios.ptrace_fa import runner as ptrace
from scenarios.userland_father_ldpreload import runner as father

CleanupCallback: TypeAlias = Callable[[], None]
# (ssh, transcript_path, command_log_path, staged artifacts, build record)
ScenarioExecutor: TypeAlias = Callable[
    [SSHClient, Path, Path, tuple[Path, ...], dict],
    tuple[dict, CleanupCallback],
]


@dataclass(frozen=True)
class PreparedScenario:
    """A scenario that runs from a published build and cleans up before shutdown."""

    artifact_names: tuple[str, ...]
    execute: ScenarioExecutor
    # Raises when the published build no longer matches its recipe.
    check_record: Callable[[dict], None] | None


@dataclass(frozen=True)
class PreparedRun:
    """One scenario's verified prebuilt input, resolved before the VM starts."""

    scenario: PreparedScenario
    artifacts: tuple[Path, ...]
    build_record: dict


def _run_father(
    ssh: SSHClient,
    transcript_path: Path,
    command_log_path: Path,
    artifacts: tuple[Path, ...],
    build_record: dict,
) -> tuple[dict, CleanupCallback]:
    (artifact,) = artifacts
    return father.run_father(
        ssh,
        transcript_path,
        command_log_path=command_log_path,
        artifact_path=artifact,
        build_record=build_record,
    )


def _run_ptrace_fa(
    ssh: SSHClient,
    transcript_path: Path,
    command_log_path: Path,
    artifacts: tuple[Path, ...],
    build_record: dict,
) -> tuple[dict, CleanupCallback]:
    injector, victim = artifacts
    return ptrace.run_ptrace_fa(
        ssh,
        transcript_path,
        command_log_path=command_log_path,
        artifact_paths=(injector, victim),
        build_record=build_record,
    )


def _run_badbpf(
    ssh: SSHClient,
    transcript_path: Path,
    command_log_path: Path,
    artifacts: tuple[Path, ...],
    build_record: dict,
) -> tuple[dict, CleanupCallback]:
    return badbpf.run_badbpf(
        ssh,
        transcript_path,
        command_log_path=command_log_path,
        artifact_paths=artifacts,
        build_record=build_record,
    )


def _run_diamorphine(
    ssh: SSHClient,
    transcript_path: Path,
    command_log_path: Path,
    artifacts: tuple[Path, ...],
    build_record: dict,
) -> tuple[dict, CleanupCallback]:
    (artifact,) = artifacts
    return diamorphine.run_diamorphine(
        ssh,
        transcript_path,
        command_log_path=command_log_path,
        artifact_path=artifact,
        build_record=build_record,
    )


def _require_current_badbpf(build_record: dict) -> None:
    if not badbpf.build_record_is_current(build_record, badbpf.verify_source()):
        raise RuntimeError(
            "published bad-bpf build uses a stale recipe; rerun the build"
        )


def _require_current_diamorphine(build_record: dict) -> None:
    if not diamorphine.build_record_is_current(
        build_record, diamorphine.verify_source()
    ):
        raise RuntimeError(
            "published Diamorphine build uses a stale recipe; rerun the build"
        )


# The one scenario table. interactive_shell is deliberately absent: it needs no
# published build and no cleanup, which is exactly what "not in here" means.
PREPARED_SCENARIOS: dict[str, PreparedScenario] = {
    father.SCENARIO_ID: PreparedScenario(
        artifact_names=(father.ARTIFACT_NAME,),
        execute=_run_father,
        check_record=None,
    ),
    ptrace.SCENARIO_ID: PreparedScenario(
        artifact_names=ptrace.ARTIFACT_NAMES,
        execute=_run_ptrace_fa,
        check_record=None,
    ),
    badbpf.SCENARIO_ID: PreparedScenario(
        artifact_names=badbpf.ARTIFACT_NAMES,
        execute=_run_badbpf,
        check_record=_require_current_badbpf,
    ),
    diamorphine.SCENARIO_ID: PreparedScenario(
        artifact_names=(diamorphine.ARTIFACT_NAME,),
        execute=_run_diamorphine,
        check_record=_require_current_diamorphine,
    ),
}


class ForensicOrchestrator:
    def __init__(
        self,
        vm_manager: VMManager,
        dumper: Dumper,
        vol_runner: VolatilityRunner | None,
        sleuth_runner: SleuthKitRunner | None,
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
        Reuses a stopped build VM if the ISF is not cached.
        VM ends OFF. Returns the ISF path.
        """
        lab_vm_name = f"{LAB_VM_PREFIX}-{distro_id}"

        kernel_release = self._detect_kernel_release(lab_vm_name)

        isf_name = _isf_filename(distro_id, kernel_release)
        self._paths.isf_dir.mkdir(parents=True, exist_ok=True)
        isf_path = self._paths.isf_dir / isf_name

        if isf_path.exists():
            console.info(f"symbol file already present: {self._display(isf_path)}")
            return isf_path

        self._build_isf_on_builder(
            distro_id=distro_id,
            kernel_release=kernel_release,
            isf_name=isf_name,
        )

        if not isf_path.exists():
            raise RuntimeError(f"ISF build completed but output not found: {isf_path}")

        console.ok(f"ISF exported: {self._display(isf_path)}")
        return isf_path

    def build_father(self, distro_id: str) -> Path:
        """
        Build Father's rk.so on the builder VM and publish it with its build
        record under shared/prebuilt/. Never overwrites. Builder ends OFF.
        """
        source = father.verify_source()

        def build_artifacts(
            ssh: SSHClient, staging: Path, vm_name: str
        ) -> tuple[tuple[Path, ...], str]:
            artifact, stdout = father.build(ssh, staging, source)
            return (artifact,), stdout

        return self._publish_scenario_build(
            distro_id,
            father.SCENARIO_ID,
            (father.ARTIFACT_NAME,),
            build=build_artifacts,
            record_source=source,
            recipe=father.build_recipe(),
        )

    def build_ptrace_fa(self, distro_id: str) -> Path:
        """Build and publish the two ptrace_fa binaries. Builder ends OFF."""

        def build_artifacts(
            ssh: SSHClient, staging: Path, vm_name: str
        ) -> tuple[tuple[Path, ...], str]:
            console.step(f"building ptrace_fa on {vm_name}...")
            return ptrace.build(ssh, staging)

        return self._publish_scenario_build(
            distro_id,
            ptrace.SCENARIO_ID,
            ptrace.ARTIFACT_NAMES,
            build=build_artifacts,
            record_source=ptrace.build_source(),
            recipe=ptrace.build_recipe(),
        )

    def build_badbpf(self, distro_id: str) -> Path:
        """Build and publish Bad-BPF and XCrypto. Builder ends OFF."""
        source = badbpf.verify_source()

        def build_artifacts(
            ssh: SSHClient, staging: Path, vm_name: str
        ) -> tuple[tuple[Path, ...], str]:
            return badbpf.build(ssh, staging, source)

        return self._publish_scenario_build(
            distro_id,
            badbpf.SCENARIO_ID,
            badbpf.ARTIFACT_NAMES,
            build=build_artifacts,
            # Bad-BPF's source record names the vendored archive and the
            # lab-owned payload only; the rest of verify_source() is local.
            record_source={
                "repository": source["repository"],
                "commit": source["commit"],
                "archive_sha256": source["archive_sha256"],
                "xcrypto_sha256": source["xcrypto_sha256"],
            },
            recipe=badbpf.build_recipe(),
            is_current=lambda record: badbpf.build_record_is_current(record, source),
            target_facts=badbpf.build_target,
        )

    def build_diamorphine(self, distro_id: str) -> Path:
        """Build and publish Diamorphine for the builder's exact kernel."""
        source = diamorphine.verify_source()

        def build_artifacts(
            ssh: SSHClient, staging: Path, vm_name: str
        ) -> tuple[tuple[Path, ...], str]:
            artifact, stdout = diamorphine.build(ssh, staging, source)
            return (artifact,), stdout

        return self._publish_scenario_build(
            distro_id,
            diamorphine.SCENARIO_ID,
            (diamorphine.ARTIFACT_NAME,),
            build=build_artifacts,
            record_source=source,
            recipe=diamorphine.build_recipe(),
            is_current=lambda record: diamorphine.build_record_is_current(
                record, source
            ),
            target_facts=diamorphine.build_target,
        )

    def _publish_scenario_build(
        self,
        distro_id: str,
        scenario_id: str,
        artifact_names: tuple[str, ...],
        *,
        build: Callable[[SSHClient, Path, str], tuple[tuple[Path, ...], str]],
        record_source: dict,
        recipe: dict,
        is_current: Callable[[dict], bool] | None = None,
        target_facts: Callable[[dict[str, str]], dict[str, str]] | None = None,
    ) -> Path:
        """
        The lifecycle every build_<scenario>() shares: reuse a trusted published
        build, else build once on the builder VM, record it, and publish it
        atomically. Builder ends OFF. Returns the primary artifact path.

        Each keyword marks a real difference between the scenarios: how the
        builder is driven, what source and recipe the record names, whether a
        published build can go stale, and which target facts it must carry.
        """
        published = self._resolve_prebuilt_input(
            distro_id, scenario_id, artifact_names
        )
        if published is not None:
            artifacts, record = published
            if is_current is not None and not is_current(record):
                raise RuntimeError(
                    f"published {scenario_id} build uses a stale recipe; remove "
                    f"{self._display(artifacts[0].parent)} and rerun the build"
                )
            console.info(f"already published: {self._display(artifacts[0])}")
            return artifacts[0]

        vm_name = self._ensure_builder_vm(distro_id)
        with tempfile.TemporaryDirectory() as staging:
            try:
                with self.vm_manager.open_ssh(vm_name) as ssh:
                    artifacts, stdout = build(ssh, Path(staging), vm_name)
            finally:
                self.vm_manager.shutdown_vm(vm_name)

            facts = _builder_facts(stdout)
            record = self._build_record(
                distro_id,
                scenario_id,
                artifacts,
                record_source,
                recipe,
                facts,
                target_facts(facts) if target_facts is not None else {},
            )
            cache_dir = self._publish_build(distro_id, scenario_id, artifacts, record)

        return cache_dir / artifact_names[0]

    def _build_record(
        self,
        distro_id: str,
        scenario_id: str,
        artifacts: tuple[Path, ...],
        source: dict,
        recipe: dict,
        facts: dict[str, str],
        target_facts: dict[str, str],
    ) -> dict[str, Any]:
        profile = load_profile(self.repo_root, distro_id)
        return {
            "schema": "forensic-lab.build_manifest.v1",
            "scenario": scenario_id,
            "built_at": utc_now(),
            "artifacts": [
                {"filename": path.name, "sha256": file_sha256(path)}
                for path in artifacts
            ],
            "target": {
                "distro_id": distro_id,
                "image_checksum": profile["image"]["checksum"],
                "arch": facts["arch"].strip(),
                **target_facts,
            },
            "source": source,
            "recipe": recipe,
            "packages": dict(
                entry.split("=", 1) for entry in facts["packages"].split()
            ),
        }

    def _prebuilt_cache_dir(self, distro_id: str, scenario_id: str) -> Path:
        return self._paths.shared_dir / "prebuilt" / distro_id / scenario_id

    def _publish_build(
        self,
        distro_id: str,
        scenario_id: str,
        artifacts: tuple[Path, ...],
        record: dict,
    ) -> Path:
        """Install artifacts + build.json into the cache under one rename."""
        cache_dir = self._prebuilt_cache_dir(distro_id, scenario_id)
        new_dir = cache_dir.with_name(f".{cache_dir.name}.new")
        shutil.rmtree(new_dir, ignore_errors=True)
        new_dir.mkdir(parents=True)
        for artifact in artifacts:
            shutil.copy2(artifact, new_dir / artifact.name)
        (new_dir / "build.json").write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.rename(new_dir, cache_dir)
        console.ok(f"published: {self._display(cache_dir)}")
        return cache_dir

    def _resolve_prebuilt_input(
        self, distro_id: str, scenario_id: str, filenames: tuple[str, ...]
    ) -> tuple[tuple[Path, ...], dict] | None:
        """
        Return (artifacts, record) when a published build matches this distro's
        pinned image, None when nothing is published, raise when it exists but
        cannot be trusted.
        """
        cache_dir = self._prebuilt_cache_dir(distro_id, scenario_id)
        if not cache_dir.exists():
            return None
        artifacts = tuple(cache_dir / filename for filename in filenames)
        fix = (
            f"remove {self._display(cache_dir)} and rerun: .venv/bin/python "
            f"cli.py build --distro {distro_id} --scenario {scenario_id}"
        )
        try:
            record = json.loads((cache_dir / "build.json").read_text(encoding="utf-8"))
            target = record["target"]
            expected = tuple(
                (item["filename"], item["sha256"])
                for item in record["artifacts"]
            )
        except (OSError, ValueError, LookupError, TypeError) as exc:
            raise RuntimeError(f"unreadable build record ({exc}); {fix}") from exc

        if tuple(name for name, _sha in expected) != filenames or any(
            not artifact.is_file() or file_sha256(artifact) != expected_sha
            for artifact, (_name, expected_sha) in zip(artifacts, expected, strict=True)
        ):
            raise RuntimeError(f"published artifacts missing or altered; {fix}")
        # A missing checksum on either side is a mismatch, never a pass.
        image = load_profile(self.repo_root, distro_id)["image"]
        wanted = (distro_id, image.get("checksum"))
        if None in wanted or wanted != (
            target.get("distro_id"),
            target.get("image_checksum"),
        ):
            raise RuntimeError(f"published build targets another image; {fix}")
        return artifacts, record

    def _display(self, path: Path) -> str:
        return os.path.relpath(path, self.repo_root)

    def lab_exists(self, distro_id: str) -> bool:
        return self.vm_manager.vm_exists(f"{LAB_VM_PREFIX}-{distro_id}")

    def run_experiment(
        self,
        distro_id: str,
        scenario_id: str,
        acquire: bool = True,
    ) -> str | None:
        """Run one explicit scenario through the full experiment lifecycle."""
        scenario = PREPARED_SCENARIOS.get(scenario_id)
        if scenario is None and scenario_id != INTERACTIVE_SHELL_SCENARIO:
            raise RuntimeError(f"Unknown scenario: {scenario_id}")

        # Resolved before anything touches the victim: a missing or stale build
        # must never cost a baseline.
        prepared_run = None
        if scenario is not None:
            resolved = self._resolve_prebuilt_input(
                distro_id, scenario_id, scenario.artifact_names
            )
            if resolved is None:
                raise RuntimeError(
                    f"{scenario_id} build missing; run: .venv/bin/python cli.py build "
                    f"--distro {distro_id} --scenario {scenario_id}"
                )
            artifacts, build_record = resolved
            if scenario.check_record is not None:
                scenario.check_record(build_record)
            prepared_run = PreparedRun(scenario, artifacts, build_record)

        repository = _repository_state(self.repo_root)

        vm_name = f"{LAB_VM_PREFIX}-{distro_id}"
        vm_off = False
        before_shutdown_cleanup: CleanupCallback | None = None

        def run_cleanup() -> None:
            """Run the scenario's before-shutdown cleanup at most once."""
            nonlocal before_shutdown_cleanup
            callback, before_shutdown_cleanup = before_shutdown_cleanup, None
            if callback is not None:
                callback()

        try:
            console.section(
                f"experiment: {scenario_id} | distro: {distro_id} | profile: vanilla"
            )
            console.step_header("baseline restoration and readiness")
            try:
                vm_name = self._reset_lab(distro_id)
                snapshot_created_at = self.vm_manager.snapshot_created_at(
                    vm_name, BASELINE_SNAPSHOT
                )
            finally:
                console.section_end()

            run_id, sequence = _make_run_id(
                self._paths.experiments_dir, distro_id, scenario_id
            )
            run_root = self._paths.experiments_dir / run_id
            # exist_ok=False: an accepted run directory is never written twice.
            run_root.mkdir(parents=True)
            manifest_path = run_root / "manifest.json"
            command_log_path = run_root / "command_log.jsonl"
            transcript_path = run_root / "terminal_transcript.txt"
            command_log_path.touch()

            input_record = None
            staged_artifacts: tuple[Path, ...] = ()
            if prepared_run is not None:
                input_record = self._stage_run_inputs(
                    run_root, scenario_id, prepared_run.artifacts
                )
                staged_artifacts = _verified_staged_artifacts(
                    run_root, input_record, prepared_run.build_record
                )

            manifest = _new_run_manifest(
                run_id=run_id,
                scenario_id=scenario_id,
                distro_id=distro_id,
                sequence=sequence,
                repository=repository,
                command_log_name=command_log_path.name,
                transcript_name=transcript_path.name,
                vm_name=vm_name,
                snapshot_created_at=snapshot_created_at,
                input_record=input_record,
            )
            _write_run_manifest(manifest_path, manifest)

            console.step_header("scenario execution")
            scenario_facts = None
            try:
                with self.vm_manager.open_ssh(vm_name) as ssh:
                    guest = self._guest_facts(ssh)
                    if prepared_run is None:
                        run_interactive_shell(
                            ssh,
                            transcript_path,
                            command_log_path=command_log_path,
                        )
                    else:
                        scenario_facts, before_shutdown_cleanup = (
                            prepared_run.scenario.execute(
                                ssh,
                                transcript_path,
                                command_log_path,
                                staged_artifacts,
                                prepared_run.build_record,
                            )
                        )
            except Exception:
                ended_at = utc_now()
                manifest.update(
                    status="failed", scenario_status="failed", failed_phase="scenario"
                )
                manifest["timestamps"].update(
                    scenario_ended_at=ended_at, run_ended_at=ended_at
                )
                _write_run_manifest(manifest_path, manifest)
                raise
            finally:
                self.vm_manager.internet_off(vm_name, quiet=True)
                console.section_end()

            manifest["platform"].update(
                guest_os=guest.get("distro"),
                kernel=guest.get("kernel"),
                timezone=guest.get("timezone"),
            )
            if prepared_run is not None:
                manifest["scenario_facts"] = scenario_facts
            manifest["scenario_status"] = "completed"
            manifest["timestamps"]["scenario_ended_at"] = utc_now()
            _write_run_manifest(manifest_path, manifest)

            acquisition_path = None
            if acquire:
                try:
                    acquisition_path, _, _ = self._run_acquisition(
                        vm_name,
                        run_id,
                        before_shutdown=(
                            run_cleanup if prepared_run is not None else None
                        ),
                    )
                    vm_off = True
                    manifest["artifacts"]["acquisition_manifest"] = str(
                        Path(acquisition_path).resolve().relative_to(run_root.resolve())
                    )
                    _write_run_manifest(manifest_path, manifest)
                except Exception:
                    manifest.update(status="failed", failed_phase="acquisition")
                    manifest["timestamps"]["run_ended_at"] = utc_now()
                    _write_run_manifest(manifest_path, manifest)
                    raise
            elif prepared_run is not None:
                run_cleanup()
                self.vm_manager.shutdown_vm(vm_name)
                vm_off = True

            manifest["status"] = "completed"
            manifest["timestamps"]["run_ended_at"] = utc_now()
            _write_run_manifest(manifest_path, manifest)

            console.step_header("summary")
            console.ok(f"run: {self._display(run_root)}")
            console.info(
                "acquisition: "
                + ("completed" if acquire else "intentionally skipped (--no-acquire)")
            )
            console.info(f"final VM state: {'off' if vm_off else 'running'}")
            console.section_end()
            return acquisition_path
        finally:
            if prepared_run is not None:
                try:
                    run_cleanup()
                finally:
                    if not vm_off:
                        self.vm_manager.shutdown_vm(vm_name)

    def _stage_run_inputs(
        self, run_root: Path, scenario_id: str, artifacts: tuple[Path, ...]
    ) -> dict[str, Any]:
        scenario_short = _SCENARIO_SHORT[scenario_id]
        inputs_dir = run_root / "inputs" / scenario_short
        inputs_dir.mkdir(parents=True)
        staged_build = inputs_dir / "build.json"
        staged_artifacts = []
        for artifact in artifacts:
            staged_artifact = inputs_dir / artifact.name
            shutil.copy2(artifact, staged_artifact)
            staged_artifacts.append(staged_artifact)
        shutil.copy2(artifacts[0].parent / "build.json", staged_build)
        return {
            "scenario": scenario_short,
            "artifacts": [
                {
                    "path": str(artifact.relative_to(run_root)),
                    "sha256": file_sha256(artifact),
                }
                for artifact in staged_artifacts
            ],
            "build_json": {
                "path": str(staged_build.relative_to(run_root)),
                "sha256": file_sha256(staged_build),
            },
        }

    @staticmethod
    def _guest_facts(ssh: SSHClient) -> dict[str, str | None]:
        cmd = (
            ". /etc/os-release 2>/dev/null; "
            'printf "distro=%s\\n" "${PRETTY_NAME:-unknown}"; '
            'printf "kernel=%s\\n" "$(uname -r)"; '
            'printf "timezone=%s\\n" '
            '"$(cat /etc/timezone 2>/dev/null || '
            'timedatectl show -p Timezone --value 2>/dev/null || echo UTC)"'
        )
        facts: dict[str, str | None] = {
            "distro": None,
            "kernel": None,
            "timezone": "UTC",
        }
        # No swallowing: a manifest recording kernel=null under a completed run
        # is a false evidence record.
        out = ssh.run_checked(cmd, timeout=30)
        for line in out.splitlines():
            key, sep, value = line.partition("=")
            if sep and key.strip() in facts and value.strip():
                facts[key.strip()] = value.strip()
        return facts

    def _build_timeline(self, disk_path: Path, analysis_dir: Path) -> None:
        """
        Run the Plaso pipeline over the acquired disk, leaving
        timeline.plaso/timeline.jsonl in the caller's analysis directory.
        """
        timeline_path = analysis_dir / "timeline.jsonl"
        run_timeline(
            disk_path=disk_path,
            storage_path=analysis_dir / "timeline.plaso",
            output_path=timeline_path,
            log2timeline_bin=self._raw_tools["log2timeline"],
            psort_bin=self._raw_tools["psort"],
            file_filter=default_linux_filter(),
        )
        console.ok(f"timeline built: {self._display(timeline_path)}")

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

    def _ensure_builder_vm(self, distro_id: str) -> str:
        profile = load_profile(self.repo_root, distro_id)
        role_cfg = self._role_defaults.get(BUILD_VM_PREFIX)
        if not isinstance(role_cfg, dict):
            raise RuntimeError(f"Missing 'role_defaults.{BUILD_VM_PREFIX}' in config")
        vm_name = f"{BUILD_VM_PREFIX}-{distro_id}"
        exists = self.vm_manager.vm_exists(vm_name)
        required = 8 * 1024**3 + (0 if exists else int(str(role_cfg["disk_size"]).upper().removesuffix("G")) * 1024**3)
        available = shutil.disk_usage(self._paths.pool_dir).free
        if available < required:
            raise RuntimeError(f"builder host free: {available // 1024**3} GiB; required: {required // 1024**3} GiB")
        if not exists:
            base_image = self.vm_manager.ensure_base_image(profile)
            self.vm_manager.create_vm(
                role=BUILD_VM_PREFIX,
                distro_id=distro_id,
                profile=profile,
                role_cfg=role_cfg,
                base_image=base_image,
            )
        self.vm_manager.start_vm(vm_name)
        try:
            self.vm_manager.wait_ssh_ready(vm_name, reason="builder access")
            with self.vm_manager.open_ssh(vm_name) as ssh:
                available = int(ssh.run_checked("df --output=avail -B1 / | tail -n 1"))
            if available < 8 * 1024**3:
                raise RuntimeError(f"builder guest storage is low: {available // 1024**3} GiB free, 8 GiB required")
        except BaseException:
            self.vm_manager.shutdown_vm(vm_name)
            raise
        return vm_name

    def _detect_kernel_release(self, lab_vm_name: str) -> str:
        console.step(f"detecting kernel on {lab_vm_name}...")
        self.vm_manager.start_vm(lab_vm_name)
        try:
            self.vm_manager.wait_ssh_ready(lab_vm_name, reason="kernel detection")
            with self.vm_manager.open_ssh(lab_vm_name) as ssh:
                kernel_release = ssh.run_checked("uname -r")
            console.ok(f"kernel: {kernel_release}")
        finally:
            self.vm_manager.shutdown_vm(lab_vm_name)
        return kernel_release

    def _build_isf_on_builder(
        self,
        distro_id: str,
        kernel_release: str,
        isf_name: str,
    ) -> None:
        """
        Create or reuse the builder VM, run the ISF build playbook, then stop
        it. The builder is retained. Lab VM is not touched here.
        """
        build_vm_name = self._ensure_builder_vm(distro_id)
        try:
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
            self.vm_manager.shutdown_vm(build_vm_name)

    def verify_pipeline(self, distro_id: str) -> None:
        """
        Acquire a baseline image and probe with Volatility + SleuthKit + Plaso.
        Called automatically at the end of the CLI 'setup' sequence.
        Requires the ISF to already exist (call after build_isf).
        VM ends OFF. This run carries no manifest.json and is not an
        experiment record, only a disposable pipeline self-test: on a
        successful probe its directory is deleted. It is kept on failure so
        the dumps/ and analysis/ output remain available for debugging.
        """
        vol_runner, sleuth_runner = self._vol_runner, self._sleuth_runner
        if vol_runner is None or sleuth_runner is None:
            raise RuntimeError(
                "verify_pipeline needs the Volatility and SleuthKit runners"
            )
        vm_name = self._reset_lab(distro_id)
        # Compute run_id ONCE so dumps/ and analysis/ share the same timestamp.
        run_id, _ = _make_run_id(self._paths.experiments_dir, distro_id, VERIFY_SCENARIO)
        run_dir = self._paths.experiments_dir / run_id

        _, memory_path, disk_path = self._run_acquisition(vm_name, run_id)

        console.step(f"probing acquired images for {distro_id}...")
        vol_runner.probe(memory_path, distro_id)
        sleuth_runner.probe(disk_path)
        # Plaso probe: confirm the toolchain can ingest the disk and emit events.
        self._build_timeline(disk_path, self._paths.run_analysis_dir(run_id))
        shutil.rmtree(run_dir, ignore_errors=True)
        console.ok(f"pipeline verified for '{distro_id}' (verify run cleaned up)")

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
        *,
        before_shutdown: Callable[[], None] | None = None,
    ) -> tuple[str, Path, Path]:
        """
        Acquire memory (VM ON), then shut the guest down and acquire its disk
        host-side from the released qcow2. Run before_shutdown between memory
        capture and shutdown when provided.
        Returns (manifest path, memory image, disk image).
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
            if before_shutdown is not None:
                before_shutdown()
            self.vm_manager.shutdown_vm(vm_name)
            disk_meta = self.dumper.acquire_disk(vm_disk_path, disk_dump_path)
            manifest_path = self.dumper.write_manifest(run_id, memory_meta, disk_meta)
            return manifest_path, memory_dump_path, Path(disk_meta.path)
        finally:
            console.section_end()


# --- module helpers ------------------------------------------------------


def _repository_state(repo_root: Path) -> dict[str, str]:
    """
    The exact commit a run was made from, plus whether the working tree had
    uncommitted changes at run time. A run that cannot record this is not a
    run. Kept as two separate fields rather than a synthetic "<hash>-dirty"
    string: a modified tree is not the commit, and squashing the two loses
    the distinction between "this code" and "this code, plus unknown local
    changes".
    """
    commit = command_output(["git", "-C", str(repo_root), "rev-parse", "HEAD"])
    if commit is None:
        raise RuntimeError(f"cannot record the repository commit of {repo_root}")
    status = command_output(["git", "-C", str(repo_root), "status", "--porcelain"])
    if status is None:
        raise RuntimeError(f"cannot record the working tree state of {repo_root}")
    return {
        "commit": commit.strip(),
        "working_tree": "modified" if status.strip() else "clean",
    }


def _verified_staged_artifacts(
    run_root: Path, input_record: dict[str, Any], build_record: dict
) -> tuple[Path, ...]:
    """Locate the staged copies, refusing any that differ from the build."""
    if [item["sha256"] for item in input_record["artifacts"]] != [
        item["sha256"] for item in build_record["artifacts"]
    ]:
        raise RuntimeError("staged artifacts differ from verified build")
    return tuple(run_root / item["path"] for item in input_record["artifacts"])


def _new_run_manifest(
    *,
    run_id: str,
    scenario_id: str,
    distro_id: str,
    sequence: int,
    repository: dict[str, str],
    command_log_name: str,
    transcript_name: str,
    vm_name: str,
    snapshot_created_at: str,
    input_record: dict[str, Any] | None,
) -> dict[str, Any]:
    """The running manifest, written before the scenario touches the guest."""
    manifest: dict[str, Any] = {
        "run_id": run_id,
        "scenario": _SCENARIO_SHORT[scenario_id],
        "distro_token": _DISTRO_SHORT[distro_id],
        "date": datetime.now().strftime("%Y-%m-%d"),
        "sequence": sequence,
        "platform": {
            "distro_id": distro_id,
            "guest_os": None,
            "kernel": None,
            "timezone": "UTC",
            "profile": "vanilla",
        },
        "repository": repository,
        "timestamps": {
            "scenario_started_at": utc_now(),
        },
        "status": "running",
        "scenario_status": "running",
        "artifacts": {
            "command_log": command_log_name,
            "terminal_transcript": transcript_name,
        },
        # The snapshot this run reverted to before touching the guest --
        # not "baseline" in the abstract, the actual starting point.
        "starting_snapshot": {
            "vm": vm_name,
            "name": BASELINE_SNAPSHOT,
            "created_at": snapshot_created_at,
        },
    }
    if input_record is not None:
        manifest["inputs"] = [input_record]
    return manifest


def _builder_facts(stdout: str) -> dict[str, str]:
    """Parse the build script's `FACT key=value` lines. Fails closed."""
    facts = dict(
        line.removeprefix("FACT ").split("=", 1)
        for line in stdout.splitlines()
        if line.startswith("FACT ") and "=" in line
    )
    missing = [k for k in ("arch", "packages") if not facts.get(k, "").strip()]
    if missing:
        raise RuntimeError(
            f"builder reported no {', '.join(missing)}; build not published"
        )
    return facts


def _write_run_manifest(path: Path, manifest: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _isf_filename(distro_id: str, kernel_release: str) -> str:
    family = distro_id.split("-", 1)[0]
    safe_kernel = kernel_release.replace("/", "_")
    return f"{family}_{safe_kernel}.json"


_SCENARIO_SHORT = {
    "user_ldpreload_father": "father",
    "kernel_ebpf_badbpf": "badbpf",
    "kernel_lkm_diamorphine": "diamorphine",
    "user_procinj_ptracefa": "ptrace",
    "interactive_shell": "shell",
    "verify": "verify",
}
_DISTRO_SHORT = {
    "ubuntu-22.04": "u22",
    "ubuntu-24.04": "u24",
    "debian-13": "deb13",
}


def _make_run_id(
    experiments_dir: Path, distro_id: str, scenario_id: str
) -> tuple[str, int]:
    """
    Build the short per-run identifier:
        "{scenario_short}-{distro_short}-{YYYYMMDD}-{NN}"
    NN is a two-digit, per-day sequence starting at 01: one past the highest
    sequence already present under experiments_dir for the same
    scenario/distro/date prefix. Used as the experiment directory name under
    experiments_dir; its dumps/ and analysis/ subtrees stay in lockstep for a
    given run. Returns (run_id, sequence).
    """
    scenario_short = _SCENARIO_SHORT[scenario_id]
    distro_short = _DISTRO_SHORT[distro_id]
    date_str = datetime.now().strftime("%Y%m%d")
    prefix = f"{scenario_short}-{distro_short}-{date_str}-"
    existing_seqs = [
        int(p.name[len(prefix) :])
        for p in experiments_dir.glob(f"{prefix}[0-9][0-9]")
        if p.is_dir()
    ]
    sequence = max(existing_seqs, default=0) + 1
    if sequence > 99:
        raise RuntimeError(f"run-id sequence exhausted for prefix {prefix!r}")
    return f"{prefix}{sequence:02d}", sequence
