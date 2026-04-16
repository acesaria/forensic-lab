import argparse

from orchestrator.core.orchestrator import ForensicOrchestrator
from orchestrator.forensics.dumper import Dumper


PROFILES = [
    "ubuntu22"
]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Forensic orchestration CLI (single-profile now, multi-profile ready)."
    )
    parser.add_argument(
        "--profile",
        default="ubuntu22",
        choices=sorted(PROFILES),
        help="Execution profile (multi-distro selector).",
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List available profiles and exit.",
    )
    return parser


def _run_bootstrap(profile_name: str) -> None:

    orchestrator = ForensicOrchestrator(
        victim_vm="victim-"+profile_name
    )

    # 1. Build ISF only if missing
    #orchestrator.build_isf_if_missing()

    # 2. Prepare victim with baseline + snapshot
    orchestrator.prepare_victim_baseline()
    orchestrator.create_victim_snapshot(snapshot_name="victim_baseline")

    dumper = Dumper()
    scenario_id = "victim_baseline_"+profile_name
    dumper.acquire_pristine_baseline(
        orchestrator=orchestrator,
        snapshot_name="victim_baseline",
        scenario_id=scenario_id,
    )


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.list_profiles:
        for name in PROFILES:
            print(name)
        return

    _run_bootstrap(profile_name=args.profile)


if __name__ == "__main__":
    main()
