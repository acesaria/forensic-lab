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
Father, ptrace_fa, and Diamorphine experiments end OFF, including when
acquisition is skipped or a step fails
"""

from collections.abc import Callable
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import tempfile
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
from scenarios.ptrace_fa import runner as ptrace
from scenarios.userland_father_ldpreload import runner as father


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
        published = self._resolve_prebuilt_input(
            distro_id, father.SCENARIO_ID, (father.ARTIFACT_NAME,)
        )
        if published is not None:
            artifacts, _record = published
            console.info(f"already published: {self._display(artifacts[0])}")
            return artifacts[0]

        vm_name = self._ensure_builder_vm(distro_id)
        with tempfile.TemporaryDirectory() as staging:
            try:
                with self.vm_manager.open_ssh(vm_name) as ssh:
                    artifact, stdout = father.build(ssh, Path(staging), source)
            finally:
                self.vm_manager.shutdown_vm(vm_name)

            record = self._build_record(
                distro_id,
                father.SCENARIO_ID,
                (artifact,),
                source,
                father.build_recipe(),
                _builder_facts(stdout),
            )
            cache_dir = self._publish_build(
                distro_id, father.SCENARIO_ID, (artifact,), record
            )

        return cache_dir / father.ARTIFACT_NAME

    def build_ptrace_fa(self, distro_id: str) -> Path:
        """Build and publish the two ptrace_fa binaries. Builder ends OFF."""
        published = self._resolve_prebuilt_input(
            distro_id, ptrace.SCENARIO_ID, ptrace.ARTIFACT_NAMES
        )
        if published is not None:
            artifacts, _record = published
            console.info(f"already published: {self._display(artifacts[0])}")
            return artifacts[0]

        vm_name = self._ensure_builder_vm(distro_id)
        with tempfile.TemporaryDirectory() as staging:
            try:
                with self.vm_manager.open_ssh(vm_name) as ssh:
                    console.step(f"building ptrace_fa on {vm_name}...")
                    artifacts, stdout = ptrace.build(ssh, Path(staging))
            finally:
                self.vm_manager.shutdown_vm(vm_name)

            record = self._build_record(
                distro_id,
                ptrace.SCENARIO_ID,
                artifacts,
                ptrace.build_source(),
                ptrace.build_recipe(),
                _builder_facts(stdout),
            )
            cache_dir = self._publish_build(
                distro_id, ptrace.SCENARIO_ID, artifacts, record
            )

        return cache_dir / ptrace.ARTIFACT_NAMES[0]

    def build_diamorphine(self, distro_id: str) -> Path:
        """Build and publish Diamorphine for the builder's exact kernel."""
        source = diamorphine.verify_source()
        published = self._resolve_prebuilt_input(
            distro_id, diamorphine.SCENARIO_ID, (diamorphine.ARTIFACT_NAME,)
        )
        if published is not None:
            artifacts, record = published
            if not diamorphine.build_record_is_current(record, source):
                raise RuntimeError(
                    "published Diamorphine build uses a stale recipe; remove "
                    f"{self._display(artifacts[0].parent)} and rerun the build"
                )
            console.info(f"already published: {self._display(artifacts[0])}")
            return artifacts[0]

        vm_name = self._ensure_builder_vm(distro_id)
        with tempfile.TemporaryDirectory() as staging:
            artifact = Path(staging) / diamorphine.ARTIFACT_NAME
            try:
                with self.vm_manager.open_ssh(vm_name) as ssh:
                    ssh.put(diamorphine.ARCHIVE, diamorphine.UPLOAD_PATH)
                    ssh.put(
                        diamorphine.BUILD_SCRIPT, diamorphine.REMOTE_BUILD_SCRIPT
                    )
                    ssh.put(
                        diamorphine.COMPATIBILITY_PATCH,
                        diamorphine.REMOTE_COMPATIBILITY_PATCH,
                    )
                    console.step(f"building {diamorphine.ARTIFACT_NAME} on {vm_name}...")
                    stdout = ssh.run_checked(
                        f"bash {diamorphine.REMOTE_BUILD_SCRIPT} "
                        f"{diamorphine.UPLOAD_PATH} "
                        f"{diamorphine.REMOTE_COMPATIBILITY_PATCH} "
                        f"{diamorphine.REMOTE_BUILD_ROOT}",
                        timeout=1800,
                    )
                    ssh.get(
                        f"{diamorphine.REMOTE_BUILD_ROOT}/Diamorphine-"
                        f"{source['commit']}/{diamorphine.ARTIFACT_NAME}",
                        artifact,
                    )
            finally:
                self.vm_manager.shutdown_vm(vm_name)

            facts = _builder_facts(stdout)
            missing = [
                key
                for key in ("kernel", "vermagic", "syscall_dispatch")
                if not facts.get(key)
            ]
            if missing:
                raise RuntimeError(
                    f"builder reported no {', '.join(missing)}; build not published"
                )
            record = self._build_record(
                distro_id,
                diamorphine.SCENARIO_ID,
                (artifact,),
                {
                    "repository": source["repository"],
                    "commit": source["commit"],
                    "archive_sha256": source["archive_sha256"],
                    "compatibility_patch_sha256": source[
                        "compatibility_patch_sha256"
                    ],
                },
                {"sha256": file_sha256(diamorphine.BUILD_SCRIPT)},
                facts,
            )
            record["target"].update(
                kernel=facts["kernel"].strip(),
                vermagic=facts["vermagic"].strip(),
                syscall_dispatch=facts["syscall_dispatch"].strip(),
            )
            cache_dir = self._publish_build(
                distro_id, diamorphine.SCENARIO_ID, (artifact,), record
            )

        return cache_dir / diamorphine.ARTIFACT_NAME

    def _build_record(
        self,
        distro_id: str,
        scenario_id: str,
        artifacts: tuple[Path, ...],
        source: dict,
        recipe: dict,
        facts: dict[str, str],
    ) -> dict:
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
        is_father = scenario_id == father.SCENARIO_ID
        is_ptrace_fa = scenario_id == ptrace.SCENARIO_ID
        is_diamorphine = scenario_id == diamorphine.SCENARIO_ID
        # Father and ptrace keep a connection open through memory capture;
        # Diamorphine uses a no-op callback to share their OFF lifecycle.
        has_scenario_cleanup = is_father or is_ptrace_fa or is_diamorphine
        if scenario_id != INTERACTIVE_SHELL_SCENARIO and not has_scenario_cleanup:
            raise RuntimeError(f"Unknown scenario: {scenario_id}")

        if is_father:
            build_scenario = father.SCENARIO_ID
            artifact_names = (father.ARTIFACT_NAME,)
        elif is_ptrace_fa:
            build_scenario = ptrace.SCENARIO_ID
            artifact_names = ptrace.ARTIFACT_NAMES
        elif is_diamorphine:
            build_scenario = diamorphine.SCENARIO_ID
            artifact_names = (diamorphine.ARTIFACT_NAME,)
        else:
            build_scenario = None
            artifact_names = ()
        prepared_input = (
            self._resolve_prebuilt_input(distro_id, build_scenario, artifact_names)
            if build_scenario
            else None
        )
        if build_scenario and prepared_input is None:
            raise RuntimeError(
                f"{build_scenario} build missing; run: .venv/bin/python cli.py build "
                f"--distro {distro_id} --scenario {build_scenario}"
            )
        if is_diamorphine and not diamorphine.build_record_is_current(
            prepared_input[1], diamorphine.verify_source()
        ):
            raise RuntimeError(
                "published Diamorphine build uses a stale recipe; rerun the build"
            )

        # Every run records the revision it ran from; "-dirty" marks a run made
        # from uncommitted code. A run that cannot record this is not a run.
        revision = command_output(
            ["git", "-C", str(self.repo_root),
             "describe", "--always", "--dirty", "--abbrev=40", "--match="]
        )
        if revision is None:
            raise RuntimeError(
                f"cannot record the repository revision of {self.repo_root}"
            )

        vm_name = f"{LAB_VM_PREFIX}-{distro_id}"
        vm_off = False
        backdoor_cleanup: Callable[[], None] | None = None

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

            run_id = _make_run_id(distro_id, scenario_id)
            run_root = self._paths.experiments_dir / run_id
            # exist_ok=False: an accepted run directory is never written twice.
            run_root.mkdir(parents=True)
            manifest_path = run_root / "manifest.json"
            command_log_path = run_root / "command_log.jsonl"
            transcript_path = run_root / "terminal_transcript.txt"
            command_log_path.touch()

            input_record = None
            if prepared_input is not None:
                input_record = self._stage_run_inputs(
                    run_root, scenario_id, prepared_input[0]
                )
                if [item["sha256"] for item in input_record["artifacts"]] != [
                    item["sha256"] for item in prepared_input[1]["artifacts"]
                ]:
                    raise RuntimeError("staged artifacts differ from verified build")

            manifest = {
                "schema": "forensic-lab.run_manifest",
                "version": 3,
                "run_id": run_id,
                "scenario_id": scenario_id,
                "platform": {
                    "distro_id": distro_id,
                    "guest_os": None,
                    "kernel": None,
                    "timezone": "UTC",
                    "profile": "vanilla",
                },
                "repository": {
                    "commit": revision,
                },
                "timestamps": {
                    "scenario_started_at": utc_now(),
                },
                "status": "running",
                "scenario_status": "running",
                "acquisition_requested": acquire,
                "artifacts": {
                    "command_log": command_log_path.name,
                    "terminal_transcript": transcript_path.name,
                },
                "baseline": {
                    "vm_name": vm_name,
                    "snapshot": BASELINE_SNAPSHOT,
                    "snapshot_created_at": snapshot_created_at,
                },
            }
            if input_record is not None:
                manifest["inputs"] = [input_record]
            _write_run_manifest(manifest_path, manifest)

            console.step_header("scenario execution")
            try:
                with self.vm_manager.open_ssh(vm_name) as ssh:
                    guest = self._guest_facts(ssh)
                    if is_father:
                        assert prepared_input is not None and input_record is not None
                        facts, backdoor_cleanup = father.run_father(
                            ssh,
                            transcript_path,
                            command_log_path=command_log_path,
                            artifact_path=(
                                run_root / input_record["artifacts"][0]["path"]
                            ),
                            build_record=prepared_input[1],
                        )
                    elif is_ptrace_fa:
                        assert prepared_input is not None and input_record is not None
                        facts, backdoor_cleanup = ptrace.run_ptrace_fa(
                            ssh,
                            transcript_path,
                            command_log_path=command_log_path,
                            artifact_paths=tuple(
                                run_root / item["path"]
                                for item in input_record["artifacts"]
                            ),
                            build_record=prepared_input[1],
                        )
                    elif is_diamorphine:
                        assert prepared_input is not None and input_record is not None
                        facts, backdoor_cleanup = diamorphine.run_diamorphine(
                            ssh,
                            transcript_path,
                            command_log_path=command_log_path,
                            artifact_path=(
                                run_root / input_record["artifacts"][0]["path"]
                            ),
                            build_record=prepared_input[1],
                        )
                    else:
                        run_interactive_shell(
                            ssh,
                            transcript_path,
                            command_log_path=command_log_path,
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
            if has_scenario_cleanup:
                manifest["scenario_facts"] = facts
            manifest["scenario_status"] = "completed"
            manifest["timestamps"]["scenario_ended_at"] = utc_now()
            _write_run_manifest(manifest_path, manifest)

            acquisition_path = None
            if acquire:
                try:
                    acquisition_path, _, _ = self._run_acquisition(
                        vm_name,
                        run_id,
                        scenario_id,
                        before_shutdown=backdoor_cleanup,
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
            elif has_scenario_cleanup:
                assert backdoor_cleanup is not None
                backdoor_cleanup()
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
            if has_scenario_cleanup:
                try:
                    if backdoor_cleanup is not None:
                        backdoor_cleanup()
                finally:
                    if not vm_off:
                        self.vm_manager.shutdown_vm(vm_name)

    def _stage_run_inputs(
        self, run_root: Path, scenario_id: str, artifacts: tuple[Path, ...]
    ) -> dict[str, Any]:
        inputs_dir = run_root / "inputs" / scenario_id
        inputs_dir.mkdir(parents=True)
        staged_build = inputs_dir / "build.json"
        staged_artifacts = []
        for artifact in artifacts:
            staged_artifact = inputs_dir / artifact.name
            shutil.copy2(artifact, staged_artifact)
            staged_artifacts.append(staged_artifact)
        shutil.copy2(artifacts[0].parent / "build.json", staged_build)
        return {
            "scenario": scenario_id,
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
        self.vm_manager.wait_ssh_ready(lab_vm_name, reason="kernel detection")
        with self.vm_manager.open_ssh(lab_vm_name) as ssh:
            kernel_release = ssh.run_checked("uname -r")
        console.ok(f"kernel: {kernel_release}")
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
        assert self._vol_runner is not None and self._sleuth_runner is not None
        vm_name = self._reset_lab(distro_id)
        # Compute run_id ONCE so dumps/ and analysis/ share the same timestamp.
        run_id = _make_run_id(distro_id, VERIFY_SCENARIO)
        run_dir = self._paths.experiments_dir / run_id

        _, memory_path, disk_path = self._run_acquisition(
            vm_name, run_id, VERIFY_SCENARIO
        )

        console.step(f"probing acquired images for {distro_id}...")
        self._vol_runner.probe(memory_path, distro_id)
        self._sleuth_runner.probe(disk_path)
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
        scenario_id: str,
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
            manifest_path = self.dumper.write_manifest(
                run_id, scenario_id, memory_meta, disk_meta
            )
            return manifest_path, memory_dump_path, Path(disk_meta.path)
        finally:
            console.section_end()


# --- module helpers ------------------------------------------------------


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


def _make_run_id(distro_id: str, scenario_id: str) -> str:
    """
    Build the stable per-run identifier:
        "{distro_id}_{scenario_id}_{YYYYMMDD-HHMMSS}"
    Used as the experiment directory name under experiments_dir; its dumps/
    and analysis/ subtrees stay in lockstep for a given run.
    """
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{distro_id}_{scenario_id}_{ts}"
