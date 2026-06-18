"""ART atomic calibration scenario.

This scenario executes a deliberately small Linux subset from
attacks/art/selected_tests.yml. It uses ArtRunner as the execution backend, but
records canonical ground truth through the same gt_manifest path used by custom
framework scenarios.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from orchestrator.attacks.art_runner import ArtRunner
from orchestrator.core import console
from orchestrator.core.ssh_client import SSHClient


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
    selected = _load_selected_tests()
    work_dir = str(selected.get("work_dir") or "/tmp/art_calibration")
    steps = ground_truth["steps"]
    ssh.run_checked(f"mkdir -p {work_dir}", timeout=15)

    for idx, test in enumerate(selected["tests"], start=1):
        step_id = str(test["id"])
        console.step_header(f"[{idx}/{len(selected['tests'])}] ART calibration: {step_id}")
        input_arguments = dict(test.get("input_arguments") or {})
        timeout = int(test.get("timeout") or 60)

        for command in test.get("pre_commands") or []:
            ssh.run_checked(command, timeout=timeout)

        if test.get("run_prerequisites", False):
            runner.run_prerequisites(
                str(test["technique"]),
                str(test["guid"]),
                input_arguments=input_arguments or None,
                timeout=timeout,
            )

        result = runner.run_test(
            str(test["technique"]),
            str(test["guid"]),
            input_arguments=input_arguments or None,
            timeout=timeout,
            raise_on_error=True,
            executor=_cwd_executor(ssh, work_dir),
        )
        row = {
            "step": step_id,
            "technique": test["technique"],
            "guid": test["guid"],
            "name": test.get("name", ""),
            "calibration_goal": test.get("calibration_goal", ""),
            "locators": _locators(test),
            **result,
        }
        steps.append(row)
        _record_truth(gt_builder, step_id, test)

        if run_cleanup and test.get("cleanup", False):
            runner.run_cleanup(
                str(test["technique"]),
                str(test["guid"]),
                input_arguments=input_arguments or None,
                timeout=timeout,
                executor=_cwd_executor(ssh, work_dir),
            )
            steps.append(
                {
                    "step": f"cleanup_{step_id}",
                    "technique": "T1070.004",
                    "run": True,
                }
            )


def _load_selected_tests() -> dict[str, Any]:
    repo_root = Path(__file__).resolve().parents[2]
    path = repo_root / "attacks" / "art" / "selected_tests.yml"
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    tests = data.get("tests") or []
    if not 3 <= len(tests) <= 5:
        raise RuntimeError(f"{path}: expected 3-5 selected ART tests, got {len(tests)}")
    return data


def _cwd_executor(ssh: SSHClient, work_dir: str):
    def execute(command: str, timeout: int) -> tuple[int, str]:
        code, out, err = ssh.run(
            f"mkdir -p {work_dir} && cd {work_dir} && {command}",
            timeout=timeout,
        )
        return code, out + err

    return execute


def _record_truth(gt_builder, step_id: str, test: dict[str, Any]) -> None:
    if gt_builder is None:
        return
    truth = test.get("truth") or {}
    gt_builder.record(
        technique=str(test["technique"]),
        event_class=str(truth["event_class"]),
        entity_type=str(truth["entity_type"]),
        entity_value=str(truth["entity_value"]),
        details={
            "step": step_id,
            "art_guid": str(test["guid"]),
            "art_test_name": str(test.get("name", "")),
            "calibration_goal": str(test.get("calibration_goal", "")),
        },
        expected_sources=[str(x) for x in truth.get("expected_sources", [])],
        observables=[dict(x) for x in truth.get("observables", [])],
    )


def _locators(test: dict[str, Any]) -> dict[str, str]:
    truth = test.get("truth") or {}
    out = {
        "entity_type": str(truth.get("entity_type", "")),
        "entity_value": str(truth.get("entity_value", "")),
    }
    for key, value in (test.get("input_arguments") or {}).items():
        out[str(key)] = str(value)
    return out
