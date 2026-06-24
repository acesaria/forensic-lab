# forensic-lab — Copilot instructions

## Project summary
Reproducible Linux attack-reconstruction lab. Orchestrates QEMU/KVM VMs via
libvirt to acquire RAM (virsh dump) and disk (ewfacquire) images, then probes
them with Volatility 3 and SleuthKit.

## Key entry points
- cli.py              -- argparse CLI; calls orchestrator public API only
- orchestrator/core/orchestrator.py  -- main coordinator (public API documented in module docstring)
- orchestrator/core/vm_manager.py    -- libvirt / SSH abstraction
- orchestrator/forensics/dumper.py   -- memory + disk acquisition (no VM lifecycle)
- orchestrator/forensics/vol_runner.py -- vol3 subprocess wrapper + ISF lookup
- infra/provider.py                  -- libvirt network + pool setup

## Naming conventions
- distro_id   short config key  e.g. "ubuntu-22.04", "debian-12"
- vm_name     libvirt domain    e.g. "lab-ubuntu-22.04"
  Public methods accept distro_id; private helpers resolve vm_name internally.

## VM power-state contract (do not break)
- prepare_lab       ends OFF
- build_isf         ends OFF
- _reset_lab        ends ON + SSH ready
- _run_acquisition  ends ON (VM restarted after disk dump)
- verify_pipeline   ends OFF

## Critical constraints
- virsh dump requires VM ON; ewfacquire requires VM OFF.
  This ordering is enforced in orchestrator._run_acquisition -- never reorder.
- sudo is used only for: virsh, chown on dumps dir, chmod on dumps dir.
  Rules are installed by `forensic-lab init` into /etc/sudoers.d/forensic-lab.
- Do not add sudo calls outside of cli.py::run_init and dumper.py.
- No Ansible; shell scripts for one-time setup; Python for experiment-time logic.

## vol3 JSON output shape
vol3 -r json emits {"columns": [...], "rows": [...]}.
VolatilityRunner._run_vol_subprocess must extract ["rows"], not return the raw dict.

## Code style
- No backticks outside code blocks in comments or docstrings.
- Comments explain why, not what.
- Orchestrator public API: setup_infra, prepare_lab, build_isf, verify_pipeline,
  run_experiment, destroy_lab, lab_exists.
  Do not call private methods (underscore prefix) from cli.py.