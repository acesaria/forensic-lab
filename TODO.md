# Thesis delivery queue

Updated 2026-08-06. This file contains mutable priorities only.

## Immediate sequence

1. After the `ptrace_fa` implementation commit, make a new Ubuntu 22.04 full
   acquired run and use it as the authoritative investigation case. Retain
   `ubuntu-22.04_ptrace_fa_20260806-155755` as successful treatment/evidence
   validation only: its recorded repository revision predates the uncommitted
   integration.
2. Produce one concise `ptrace_fa` investigation, led by memory (`pslist`,
   `psaux`, `sockstat`, and `malfind`) with only the disk/timeline observations
   that materially help.
3. Run `ptrace_fa` without acquisition on Ubuntu 24.04 as a targeted replication
   after the Ubuntu 22.04 implementation is frozen.
4. Resolve the concrete Father Ubuntu 24.04 prerequisite failure with the
   smallest baseline/package fix and validate without acquisition.
5. Integrate and investigate one traditional LKM scenario, while starting the
   kernel-dependent ftrace feasibility check early enough to expose blockers.

## August 10-11 deadline queue

- Finish the authoritative `ptrace_fa` run and concise investigation first.
- Complete one traditional LKM scenario and the focused ftrace scenario with
  concise disk, memory, and timeline investigations only where each source is
  relevant. Keep ftrace as the kernel-dependent risk lane.
- Perform the Ubuntu 24.04 ptrace replication and Father prerequisite fix
  without expanding them into second deep investigations.

Passing Ubuntu 22.04 and Ubuntu 24.04 supports a targeted two-release Ubuntu
replication claim, not a claim of compatibility with arbitrary Linux distros.

Existing draft reports and comparative material are review inputs, not standing
instructions. Use `METHODOLOGY.md` for the current method and cite the exact
immutable run in every evidence-facing task.

## Delivery milestones

- By `2026-08-19`: experimental work substantially complete.
- By `2026-09-21`: final project, LaTeX integration, and slides complete.

## Investigation workflow follow-up

- Re-evaluate whether every acquisition should automatically run the default
  TSK, Plaso, and Volatility extraction. Compare its runtime and provenance
  value with running only the relevant tools, Plaso parsers, and Volatility
  plugins from each scenario's reproducible Runme investigation. Consider
  removing automatic extraction and its unused broad outputs (including
  `vol3.json`) if investigation-time execution preserves enough provenance and
  reproducibility; explicitly identify removable code such as the combined
  `extract.py` workflow. Do not redesign this before the deadline work.
- If automatic raw extraction is retained, generate
  `analysis/raw_extraction_index.json` immediately after
  `analysis/raw_extraction_status.json` as a small, non-authoritative summary
  for Runme notebooks. Keep acquisition/raw exports under `shared/experiments/`
  and do not make acquisition create `shared/investigations/` workspaces.

## Scenario workflow follow-up

- Reconsider installing every scenario prerequisite in the shared offline VM
  baseline. After the deadline work, evaluate a small scenario-owned
  `run_prerequisites` step that installs each runner's explicit packages and
  libraries immediately before scenario execution, then restores the intended
  offline state. Accept the small per-run delay if it keeps unrelated packages
  out of other scenarios; do not design or implement this now.

## After the minimum deliverable

- Integrate accepted Father results into the thesis, figures, limitations, and
  presentation material.
- Perform only targeted Ubuntu 24.04 or Debian 13 replication that strengthens a
  specific thesis claim without threatening the milestones.
- Add another scenario or security-profile comparison only if the minimum
  Ubuntu 22.04 deliverables are already secure.

## Deferred unless explicitly reopened

- automatic detection, matching, scoring, or reconstruction;
- Fedora/SELinux and broad platform expansion;
- Timesketch, Velociraptor, AIDE/NSRL, graph/ontology, or broad Sigma/YARA work;
- a large test rewrite, architecture refactor, new framework, or major
  dependency; and
- optional scenarios that do not directly protect a thesis research question or
  delivery milestone.
