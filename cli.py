"""CLI entry point for forensic-lab."""

import argparse
import json
import logging
import shutil
import sys
from pathlib import Path
from typing import Any

from infra.provider import Provider
from orchestrator.core import console
from orchestrator.core.bootstrap import run_init
from orchestrator.core.config import load_config, load_profile, load_scenarios
from orchestrator.core.orchestrator import ForensicOrchestrator
from orchestrator.core.paths import ProjectPaths
from orchestrator.core.vm_manager import VMManager
from orchestrator.forensics import Dumper, SleuthKitRunner, VolatilityRunner


def build_parser(scenario_keys: tuple[str, ...]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forensic-lab",
        description="Reproducible Linux attack reconstruction lab.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Show verbose subprocess output and internal detail",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # init: one-time host setup (sudo required)
    sub.add_parser(
        "init",
        help="One-time host setup: system dirs, sudoers, libvirt network/pool",
    )

    # setup: prepare lab VM + build ISF + verify pipeline (idempotent)
    setup = sub.add_parser(
        "setup",
        help="Create lab VM, provision baseline, build ISF, verify pipeline (idempotent)",
    )
    setup.add_argument("--distro", default="ubuntu-22.04", help="Distro ID")

    # run: execute an experiment
    run = sub.add_parser(
        "run",
        help="Run a full experiment: revert, attack, acquire",
    )
    run.add_argument("--distro", default="ubuntu-22.04", help="Distro ID")
    run.add_argument(
        "--scenario",
        required=True,
        choices=scenario_keys,
        help="Attack scenario to run",
    )
    run.add_argument(
        "--acquire",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Acquire memory + disk after the scenario (default: enabled)",
    )
    run.add_argument(
        "--cleanup",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Run the scenario's cleanup phase after the attack "
        "(--cleanup / --no-cleanup); overrides the scenario's run_cleanup "
        "default. Unset uses the scenario default (--no-cleanup preserves all "
        "artifacts)",
    )
    run.add_argument(
        "--seed",
        type=int,
        default=0,
        help="Seed for the scenario's randomized instance values (default: 0)",
    )

    # analyze: re-run IOC detection + scoring on an already-acquired run,
    # reusing its dumps and cached timeline (no VM, no Plaso re-run)
    analyze = sub.add_parser(
        "analyze",
        help="Re-evaluate an existing run's dumps (no VM): refresh report + metrics",
    )
    analyze.add_argument("--distro", default="ubuntu-22.04", help="Distro ID")
    analyze.add_argument(
        "--scenario",
        required=True,
        choices=scenario_keys,
        help="Scenario whose specs to apply",
    )
    analyze.add_argument(
        "--run-id",
        default=None,
        help="Specific run_id to analyze (default: latest run for distro+scenario)",
    )

    # destroy: remove lab VM and storage
    destroy = sub.add_parser("destroy", help="Destroy lab VM and storage")
    destroy.add_argument("--distro", required=True, help="Distro ID")

    # --- offline evaluation commands (no VM, no lab host) ----------------
    # The detector -> matcher -> metrics pipeline can be re-run over cached
    # artifacts without touching libvirt. These deliberately skip the host
    # prerequisite check and orchestrator construction (see main()).

    score = sub.add_parser(
        "score",
        help="Match + metrics from an existing findings.jsonl + gt_manifest.json",
    )
    score.add_argument("--manifest", required=True)
    score.add_argument("--findings", required=True)
    score.add_argument("--out-dir", required=True)
    score.add_argument("--ruleset-hash", default="sha256:0")

    pipeline = sub.add_parser(
        "pipeline",
        help="Detect from cached raw outputs in a run dir, then match + metrics",
    )
    pipeline.add_argument("--run-dir", required=True)
    pipeline.add_argument("--out-dir", default=None)
    pipeline.add_argument("--case-start", default=None, help="ISO-8601 UTC window start")
    pipeline.add_argument("--case-end", default=None, help="ISO-8601 UTC window end")

    verify = sub.add_parser(
        "verify",
        help="Check pinned tool versions and print the ruleset hash",
    )

    return parser


# --- init helpers --------------------------------------------------------


def _setup_logging(debug: bool) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG if debug else logging.INFO)
    handler.setFormatter(console.PrefixColorFormatter("%(message)s"))

    root = logging.getLogger()
    root.setLevel(logging.DEBUG if debug else logging.INFO)
    root.addHandler(handler)

    for noisy in ("paramiko", "ansible", "libvirt", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def _check_prerequisites() -> None:
    required = {
        "virsh": "libvirt-clients",
        "virt-install": "virtinst",
        "qemu-img": "qemu-utils",
        "cloud-localds": "cloud-image-utils",
        "ansible-playbook": "ansible",
        "ewfacquire": "libewf-dev",
        "vol3": "volatility3 (install manually)",
        "log2timeline": "plaso (pip install plaso)",
        "psort": "plaso (pip install plaso)",
    }
    missing = [
        f"  {cmd}  (apt: {pkg})"
        for cmd, pkg in required.items()
        if shutil.which(cmd) is None
    ]
    if missing:
        raise RuntimeError("prereq: Missing required binaries:\n" + "\n".join(missing))


# --- offline evaluation handlers -----------------------------------------

_OFFLINE_COMMANDS = ("score", "pipeline", "verify")


def _print_metric_row(row) -> None:
    from orchestrator.evaluation.metrics.compute import METRICS_COLS

    v = row.values
    print("metrics row:")
    for col in METRICS_COLS:
        print(f"  {col:16} {v.get(col)}")


def _load_raw_from_dir(run_dir: Path) -> dict[str, Any]:
    # Assemble raw_outputs from whatever extracted artifacts exist in run_dir.
    raw: dict[str, Any] = {}
    timeline = run_dir / "timeline.jsonl"
    if timeline.is_file():
        from orchestrator.forensics.plaso_runner import read_timeline

        raw["plaso"] = read_timeline(timeline)
    vol3 = run_dir / "vol3.json"
    if vol3.is_file():
        raw["vol3"] = json.loads(vol3.read_text(encoding="utf-8"))
    bodyfile = run_dir / "bodyfile"
    if bodyfile.is_file():
        raw["tsk"] = {"bodyfile": bodyfile.read_text(encoding="utf-8")}
    return raw


def _cmd_score(args: argparse.Namespace) -> int:
    from orchestrator.evaluation.pipeline import run_score

    row = run_score(
        args.manifest,
        args.findings,
        args.out_dir,
        ruleset_hash_value=args.ruleset_hash,
    )
    _print_metric_row(row)
    print(f"\nwrote matches.json + metrics.csv + report.md to {args.out_dir}")
    return 0


def _cmd_pipeline(args: argparse.Namespace) -> int:
    from orchestrator.evaluation.contracts.models import GtManifest
    from orchestrator.evaluation.contracts.validate import load_gt_manifest
    from orchestrator.evaluation.pipeline import run_from_raw

    run_dir = Path(args.run_dir)
    manifest_path = run_dir / "gt_manifest.json"
    if not manifest_path.is_file():
        print(f"error: no gt_manifest.json in {run_dir}", file=sys.stderr)
        return 2
    manifest = GtManifest.from_dict(load_gt_manifest(manifest_path))
    raw = _load_raw_from_dir(run_dir)
    if not raw:
        print(
            f"error: no extracted raw outputs in {run_dir} "
            "(expected timeline.jsonl / vol3.json / bodyfile)",
            file=sys.stderr,
        )
        return 2
    case_window = None
    if args.case_start and args.case_end:
        case_window = {"start": args.case_start, "end": args.case_end}
    row = run_from_raw(
        manifest,
        raw,
        args.out_dir or run_dir,
        case_window=case_window,
    )
    _print_metric_row(row)
    print("\nwrote findings.jsonl + matches.json + metrics.csv + report.md")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    from orchestrator.evaluation.pipeline import load_pipeline_config, ruleset_hash
    from orchestrator.evaluation.provenance import verify_versions

    cfg = load_pipeline_config()
    problems = verify_versions(cfg)
    print(f"ruleset_hash: {ruleset_hash(cfg)}")
    if problems:
        print("version problems:")
        for p in problems:
            print(f"  - {p}")
        return 1 if cfg.get("version_policy") == "strict" else 0
    print("all pinned tool versions satisfied")
    return 0


def _run_offline_command(args: argparse.Namespace) -> int:
    handlers = {
        "score": _cmd_score,
        "pipeline": _cmd_pipeline,
        "verify": _cmd_verify,
    }
    return handlers[args.command](args)


# --- main ----------------------------------------------------------------


def main() -> None:
    repo_root = Path(__file__).resolve().parent
    scenarios = load_scenarios(repo_root)
    args = build_parser(tuple(sorted(scenarios.keys()))).parse_args()
    _setup_logging(args.debug)

    # Offline evaluation commands re-score cached artifacts and need neither the
    # lab host nor the acquisition toolchain, so they bypass the prerequisite
    # check and orchestrator construction below.
    if args.command in _OFFLINE_COMMANDS:
        sys.exit(_run_offline_command(args))

    _check_prerequisites()
    if args.debug:
        console.info("debug mode on")

    # All host path fields are absolute Paths after load_config(); ProjectPaths
    # then derives every layout-specific subdirectory once. Downstream code
    # only sees `paths`, never raw host_cfg path entries.
    cfg = load_config(repo_root)
    host_cfg = cfg["host"]
    paths = ProjectPaths.from_config(repo_root, host_cfg)
    role_defaults = cfg.get("role_defaults") or {}
    nat_network = host_cfg.get("nat_network_name", "default")
    if isinstance(role_defaults.get("lab"), dict):
        role_defaults["lab"]["network"] = host_cfg["isolated_network_name"]
        role_defaults["lab"]["nat_network"] = nat_network
    if isinstance(role_defaults.get("build-isf"), dict):
        role_defaults["build-isf"]["network"] = nat_network

    provider = Provider(
        libvirt_uri=host_cfg["libvirt_uri"],
        pool_name=host_cfg["pool_name"],
        pool_path=paths.pool_dir,
        network_name=host_cfg["isolated_network_name"],
    )

    vm_manager = VMManager(provider=provider, paths=paths)

    dumper = Dumper(paths)
    vol_runner = VolatilityRunner.from_config(host_cfg, paths.isf_dir)
    sleuth_runner = SleuthKitRunner.from_config(host_cfg)

    distro_id: str = getattr(args, "distro", "ubuntu-22.04")

    try:
        with ForensicOrchestrator(
            vm_manager=vm_manager,
            dumper=dumper,
            vol_runner=vol_runner,
            sleuth_runner=sleuth_runner,
            paths=paths,
            role_defaults=role_defaults,
        ) as orchestrator:

            if args.command == "init":
                run_init(paths)
                orchestrator.setup_infra()

            elif args.command == "setup":
                try:
                    load_profile(repo_root, args.distro)
                except (KeyError, FileNotFoundError, ValueError) as exc:
                    raise RuntimeError(
                        f"config: distro '{args.distro}' not found: {exc}"
                    ) from exc

                console.section("infrastructure")
                orchestrator.setup_infra()
                console.section("lab VM setup")
                orchestrator.prepare_lab(distro_id)
                console.section("volatility symbols")
                orchestrator.build_isf(distro_id)
                console.section("pipeline verification")
                orchestrator.verify_pipeline(distro_id)
                console.ok(f"setup complete for '{distro_id}'")

            elif args.command == "run":
                try:
                    load_profile(repo_root, args.distro)
                except (KeyError, FileNotFoundError, ValueError) as exc:
                    raise RuntimeError(
                        f"config: distro '{args.distro}' not found: {exc}"
                    ) from exc

                if not orchestrator.lab_exists(distro_id):
                    console.warn(f"lab '{distro_id}' not found; run 'setup' first")
                    raise SystemExit(1)
                scenario_id = args.scenario
                scenario_cfg = scenarios.get(args.scenario)
                if not scenario_cfg:
                    raise RuntimeError(f"Unknown scenario '{args.scenario}'")
                if "module" in scenario_cfg:
                    # The --cleanup/--no-cleanup flag overrides the scenario's
                    # run_cleanup default; unset falls back to the registry value.
                    run_cleanup = (
                        args.cleanup
                        if args.cleanup is not None
                        else bool(scenario_cfg.get("run_cleanup", False))
                    )
                    orchestrator.run_experiment(
                        distro_id,
                        scenario_id,
                        scenario_cfg,
                        acquire=args.acquire,
                        run_cleanup=run_cleanup,
                        seed=args.seed,
                    )
                else:
                    raise RuntimeError(f"Invalid scenario config for '{args.scenario}'")

            elif args.command == "analyze":
                report_path = orchestrator.analyze_run(
                    distro_id, args.scenario, run_id=args.run_id
                )
                console.ok(f"re-analysis complete: {report_path}")

            elif args.command == "destroy":
                orchestrator.destroy_lab(distro_id)

    except KeyboardInterrupt:
        console.err("interrupted")
        sys.exit(1)
    except RuntimeError as exc:
        console.err(str(exc))
        if args.debug:
            raise
        sys.exit(1)
    except Exception as exc:
        console.err(f"unexpected error: {exc}")
        if args.debug:
            raise
        sys.exit(1)


if __name__ == "__main__":
    main()
