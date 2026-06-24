You are auditing the forensic-lab Python project at acesaria/forensic-lab.

## Your task

Perform a two-part review: bug finding and refactoring planning.

## Context

Project layout:
- cli.py               CLI entry point
- orchestrator/core/   config.py, orchestrator.py, vm_manager.py, ssh_client.py, console.py, bootstrap.py
- orchestrator/attacks/ art_runner.py, scenario_01_ldpreload.py (and stubs)
- orchestrator/forensics/ dumper.py, vol_runner.py, sleuth_runner.py, ioc_detector.py
- infra/               provider.py, image_store.py, profiles/
- scenarios.yaml       scenario registry

Coding conventions (non-negotiable):
- No fancy unicode, emojis, decorative symbols, or LLM-style verbose comments
- Comments explain why, not what
- No complex regex without documentation

Known planned refactoring (from TODO.md, do not re-propose these unless you find a concrete bug in them):
- Consolidate constants into config.py
- Merge bootstrap.py into cli.py
- Move build VM lifecycle from Orchestrator into VMManager
- Strip Orchestrator of direct Provider references
- Migrate to libvirt-python API
- Replace ssh_client.py wrapper with direct paramiko

## Part 1: Bug Report

Read all source files. For each bug found, report:
FILE: <path>
FUNCTION: <name>
SEVERITY: critical | warning | minor
DESCRIPTION: one clear sentence describing the bug
FIX: concrete fix (code snippet or specific change)
Focus on:
- Race conditions in VM lifecycle (start/stop/snapshot timing)
- SSH connection handling (unclosed connections, exception paths that skip close)
- Subprocess error handling (missing check=True, ignored returncode, stderr swallowed)
- Incorrect assumptions about VM state (calling SSH on a stopped VM, etc.)
- Resource leaks (temp files in /dev/shm not cleaned on failure, EWF segments left on disk)
- ground_truth.json data loss (exception between scenario run and _persist_ground_truth)
- Argument substitution edge cases in art_runner._build_command

## Part 2: Refactoring Plan

Produce a prioritized list of refactoring tasks NOT already in TODO.md. For each:
PRIORITY: high | medium | low
FILE(S): affected files
TITLE: short name
RATIONALE: why this reduces complexity or fixes a structural problem
EFFORT: small (< 30 lines) | medium (30-100 lines) | large (> 100 lines)

Focus on:
- Dead code (empty stubs, unreachable branches)
- Duplicated logic across files
- Unnecessary abstraction layers
- Functions that do more than one thing
- Places where fewer lines would be clearer

End with a one-paragraph summary of the project's overall health and the single highest-impact change.