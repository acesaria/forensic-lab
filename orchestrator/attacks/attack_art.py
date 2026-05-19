"""Generic ART-based scenario handler driven by experiment config."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from orchestrator.core.art_runner import ArtRunner
from orchestrator.core.config import ATOMICS_DIR
from orchestrator.core.ssh_client import SSHClient


def run(
    ssh: SSHClient, scenario_id: str, config: dict[str, Any] | None = None
) -> dict[str, Any]:
    """
    Execute an ART scenario based on config.

    The config dict may contain:
    - technique_id: MITRE technique (required, e.g., "T1059.004")
    - test_guids: list of test GUIDs, or None to auto-select from YAML
    - run_cleanup: whether to run cleanup after test (default: False)
    - input_arguments: dict of argument overrides (optional)

    Args:
        ssh: Connected SSH client.
        scenario_id: Scenario execution identifier.
        config: Scenario configuration dict (defaults to empty if None).

    Returns:
        Ground truth dict with scenario metadata and executed tests.
    """
    if config is None:
        config = {}

    repo_root = Path(__file__).resolve().parents[2]
    atomics_path = repo_root / ATOMICS_DIR

    technique_id = config.get("technique_id")
    if not technique_id:
        raise ValueError("config must specify 'technique_id'")

    test_guids = config.get("test_guids")
    if not test_guids:
        test_guids = _resolve_test_guids(atomics_path, technique_id)

    run_cleanup = config.get("run_cleanup", False)
    input_arguments = config.get("input_arguments")
    scenario_metadata = config.get("scenario")

    runner = ArtRunner(
        host=ssh._ip,
        username=ssh._user,
        ssh_key_path=ssh._key_path,
        atomics_path=atomics_path,
    )

    tests_run: list[dict[str, Any]] = []
    for guid in test_guids:
        try:
            result = runner.run_test(
                technique_id,
                guid,
                input_arguments=input_arguments,
            )
            tests_run.append(
                {
                    "guid": result.get("guid", guid),
                    "technique": technique_id,
                    "status": "executed",
                    "result": result,
                }
            )

            if run_cleanup:
                runner.run_cleanup(
                    technique_id,
                    guid,
                    input_arguments=input_arguments,
                )
                tests_run[-1]["cleanup_executed"] = True
        except Exception as exc:
            tests_run.append(
                {
                    "guid": guid,
                    "technique": technique_id,
                    "status": "failed",
                    "error": str(exc),
                }
            )

    ground_truth: dict[str, Any] = {
        "scenario_id": scenario_id,
        "scenario": scenario_metadata or {"id": f"art-{technique_id}"},
        "tests_run": tests_run,
    }

    return ground_truth


def _resolve_test_guids(atomics_path: Path, technique_id: str) -> list[str]:
    """
    Resolve test GUIDs from YAML if not explicitly provided.
    Returns all test GUIDs for the technique.
    """
    yaml_path = atomics_path / technique_id / f"{technique_id}.yaml"
    if not yaml_path.exists():
        raise FileNotFoundError(f"Atomic YAML not found: {yaml_path}")

    data = yaml.safe_load(yaml_path.read_text()) or {}
    tests = data.get("atomic_tests", [])

    guids = []
    for test in tests:
        guid = test.get("auto_generated_guid")
        if guid:
            guids.append(guid)

    return guids
