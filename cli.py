"""CLI entry point for forensic-lab."""

import argparse
import json
import logging
import shutil
import sys
from pathlib import Path

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
        description=(
            "Linux post-mortem forensic reconstruction lab. Primary thesis path: "
            "declarative Father_LDPRELOAD -> canonical tool findings -> "
            "DetectionClaim candidate evidence -> GT-aware matching/metrics."
        ),
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
        help=(
            "Run a VM experiment. The active thesis registry path is "
            "userland_father_ldpreload."
        ),
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

    # destroy: remove lab VM and storage
    destroy = sub.add_parser("destroy", help="Destroy lab VM and storage")
    destroy.add_argument("--distro", required=True, help="Distro ID")

    # --- offline evaluation commands (no VM, no lab host) ----------------
    # The detector -> matcher -> metrics pipeline can be re-run over cached
    # artifacts without touching libvirt. These deliberately skip the host
    # prerequisite check and orchestrator construction (see main()).

    sub.add_parser(
        "verify",
        help="Check pinned tool versions and print the ruleset hash",
    )

    run_scenario = sub.add_parser(
        "run-scenario",
        help=(
            "Run a declarative scenario.yml and write canonical execution truth "
            "and artifact expectations"
        ),
    )
    run_scenario.add_argument("scenario_yml")
    run_scenario.add_argument("--out-dir", default=None)
    run_scenario.add_argument("--run-id", default=None)

    run_adapters = sub.add_parser(
        "run-adapters",
        help="Adapt cached raw tool outputs to canonical tool_findings.jsonl",
    )
    run_adapters.add_argument("--bodyfile", default=None)
    run_adapters.add_argument("--vol3-json", default=None)
    run_adapters.add_argument("--plaso-jsonl", default=None)
    run_adapters.add_argument("--run-id", required=True)
    run_adapters.add_argument("--out", required=True)
    run_adapters.add_argument("--command-log", default=None)
    run_adapters.add_argument("--margin-s", type=float, default=600.0)

    run_detectors = sub.add_parser(
        "run-detectors",
        help="Run GT-blind detector rule packs over canonical tool_findings.jsonl",
    )
    run_detectors.add_argument("--findings", required=True)
    run_detectors.add_argument("--out", required=True)
    run_detectors.add_argument(
        "--rules-dir",
        default=None,
        help="Optional detector rules directory (default: detectors/rules)",
    )
    run_detectors.add_argument(
        "--baseline-findings",
        default=None,
        help=(
            "Optional clean baseline canonical tool_findings.jsonl. Known-good "
            "findings are filtered out before rules run (writes "
            "tool_findings_filtered.jsonl + baseline_filter.json next to --out); "
            "applied only when --baseline-identity is also supplied."
        ),
    )
    run_detectors.add_argument(
        "--baseline-identity",
        default=None,
        help=(
            "Verified clean baseline identity, using existing VM/snapshot names "
            "such as lab-ubuntu-22.04:baseline."
        ),
    )

    match_canonical = sub.add_parser(
        "match-canonical",
        help=(
            "PRIMARY THESIS: GT-aware claim-level match + metrics over canonical "
            "JSONL artifacts"
        ),
    )
    match_canonical.add_argument("--expectations", required=True)
    match_canonical.add_argument("--tool-findings", required=True)
    match_canonical.add_argument("--detection-claims", required=True)
    match_canonical.add_argument(
        "--execution-truth",
        default=None,
        help="Optional execution_truth.jsonl enabling the temporal block (RQ4)",
    )
    match_canonical.add_argument(
        "--baseline-filter",
        default=None,
        help=(
            "Optional baseline_filter.json (written by run-detectors) embedded "
            "into metrics block C"
        ),
    )
    match_canonical.add_argument("--out-dir", required=True)

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


def _cmd_verify(args: argparse.Namespace) -> int:
    from orchestrator.forensics.pipeline_config import (
        load_pipeline_config,
        ruleset_hash,
        verify_versions,
    )

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


def _cmd_run_scenario(args: argparse.Namespace) -> int:
    from orchestrator.scenarios import run_scenario

    ctx = run_scenario(
        args.scenario_yml,
        out_dir=args.out_dir,
        run_id=args.run_id,
        repo_root=Path(__file__).resolve().parent,
    )
    print(f"scenario run written: {ctx.out_dir}")
    print("  command_log.jsonl")
    print("  execution_truth.jsonl")
    print("  artifact_expectations.jsonl")
    print("  reference_context.json")
    return 0


def _cmd_run_adapters(args: argparse.Namespace) -> int:
    from orchestrator.adapters import (
        case_window_from_command_log,
        filter_findings_to_window,
        write_tool_findings,
    )
    from orchestrator.adapters.plaso import adapt_plaso_jsonl_file
    from orchestrator.adapters.sleuthkit import adapt_bodyfile_file
    from orchestrator.adapters.volatility3 import adapt_volatility_json_file

    if not (args.bodyfile or args.vol3_json or args.plaso_jsonl):
        print("error: at least one raw output path is required", file=sys.stderr)
        return 2
    findings = []
    if args.bodyfile:
        findings += adapt_bodyfile_file(args.bodyfile, run_id=args.run_id)
    if args.vol3_json:
        findings += adapt_volatility_json_file(args.vol3_json, run_id=args.run_id)
    if args.plaso_jsonl:
        findings += adapt_plaso_jsonl_file(args.plaso_jsonl, run_id=args.run_id)
    window = None
    if args.command_log:
        window = case_window_from_command_log(Path(args.command_log), args.margin_s)
        if window:
            findings = filter_findings_to_window(findings, *window)
    write_tool_findings(args.out, findings)
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.tool] = counts.get(finding.tool, 0) + 1
    for tool in sorted(counts):
        print(f"{tool}: {counts[tool]}")
    print(f"total: {len(findings)}")
    print(f"window: {window[0]}..{window[1]}" if window else "window: no window")
    return 0


def _cmd_run_detectors(args: argparse.Namespace) -> int:
    from detectors.engine import run_detectors_file, write_detection_claims

    if bool(args.baseline_findings) != bool(args.baseline_identity):
        print(
            "warning: --baseline-findings and --baseline-identity must be "
            "supplied together; baseline filtering disabled",
            file=sys.stderr,
        )
        return 2
    findings_path = Path(args.findings)
    if args.baseline_findings and args.baseline_identity:
        from detectors.baseline import apply_baseline_filter
        from orchestrator.canonical import ToolFinding, load_jsonl

        findings_path, stats = apply_baseline_filter(
            load_jsonl(findings_path, ToolFinding),
            args.baseline_findings,
            Path(args.out).parent,
            identity=args.baseline_identity,
        )
        for source, counts in stats["per_source"].items():
            print(f"baseline filter {source}: {counts['pre']} -> {counts['post']}")
    claims = run_detectors_file(findings_path, rules_dir=args.rules_dir)
    out = write_detection_claims(args.out, claims)
    print(f"wrote {len(claims)} detection claim(s): {out}")
    return 0


def _cmd_match_canonical(args: argparse.Namespace) -> int:
    from matcher.engine import render_console_summary, run_matcher_files

    baseline_filter = None
    if args.baseline_filter:
        baseline_filter = json.loads(
            Path(args.baseline_filter).read_text(encoding="utf-8")
        )
    else:
        default_filter = Path(args.detection_claims).parent / "baseline_filter.json"
        if default_filter.exists():
            baseline_filter = json.loads(default_filter.read_text(encoding="utf-8"))
    result = run_matcher_files(
        expectations_path=args.expectations,
        tool_findings_path=args.tool_findings,
        detection_claims_path=args.detection_claims,
        execution_truth_path=args.execution_truth,
        out_dir=args.out_dir,
        baseline_filter=baseline_filter,
    )
    for line in render_console_summary(result["metrics"]):
        print(line)
    print(f"wrote outcomes.jsonl + metrics.json + report.md to {args.out_dir}")
    return 0


# Offline evaluation commands re-score cached artifacts and need neither the
# lab host nor the acquisition toolchain, so main() dispatches them before the
# prerequisite check and orchestrator construction.
_OFFLINE_HANDLERS = {
    "verify": _cmd_verify,
    "run-scenario": _cmd_run_scenario,
    "run-adapters": _cmd_run_adapters,
    "run-detectors": _cmd_run_detectors,
    "match-canonical": _cmd_match_canonical,
}


# --- main ----------------------------------------------------------------


def main() -> None:
    repo_root = Path(__file__).resolve().parent
    scenarios = load_scenarios(repo_root)
    args = build_parser(tuple(sorted(scenarios.keys()))).parse_args()
    _setup_logging(args.debug)

    if args.command in _OFFLINE_HANDLERS:
        sys.exit(_OFFLINE_HANDLERS[args.command](args))

    _check_prerequisites()
    if args.debug:
        console.info("debug mode on")

    # The 'setup' and 'run' paths need a valid distro profile; fail fast with a
    # config error before any VM work starts.
    if args.command in ("setup", "run"):
        try:
            load_profile(repo_root, args.distro)
        except (KeyError, FileNotFoundError, ValueError) as exc:
            console.err(f"config: distro '{args.distro}' not found: {exc}")
            sys.exit(1)

    # All host path fields are absolute Paths and role_defaults carry their
    # network names after load_config(); ProjectPaths then derives every
    # layout-specific subdirectory once. Downstream code only sees `paths`,
    # never raw host_cfg path entries.
    cfg = load_config(repo_root)
    host_cfg = cfg["host"]
    paths = ProjectPaths.from_config(repo_root, host_cfg)
    role_defaults = cfg.get("role_defaults") or {}

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
                if not orchestrator.lab_exists(distro_id):
                    console.warn(f"lab '{distro_id}' not found; run 'setup' first")
                    raise SystemExit(1)
                # argparse choices guarantee the key exists in the registry.
                scenario_cfg = scenarios[args.scenario]
                if "scenario_yml" not in scenario_cfg:
                    raise RuntimeError(
                        f"Invalid scenario config for '{args.scenario}': "
                        "missing 'scenario_yml'"
                    )
                orchestrator.run_declarative_experiment(
                    distro_id,
                    args.scenario,
                    scenario_cfg,
                    acquire=args.acquire,
                )

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
