# Thesis Delivery Roadmap

## 1. Current thesis goal

Deliver `forensic-lab` as a Linux post-mortem forensic reconstruction and
evaluation framework for controlled VM scenarios.

The thesis story is:

- run a controlled scenario from a clean VM baseline;
- acquire RAM, disk, and timeline evidence;
- normalize tool output into canonical `ToolFinding` records;
- emit GT-blind candidate evidence as `DetectionClaim` records;
- match candidate evidence against expected artifacts in the GT-aware layer;
- report thesis-defensible reconstruction metrics over matched expected
  artifacts, especially strong instance reconstruction.

Father_LDPRELOAD is the primary scenario. Candidate precision is diagnostic only;
it is not the headline thesis metric. Timesketch remains an optional sidecar,
not the primary evaluation backend.

## 2. Must-have before thesis delivery

1. Clean baseline artifact cache.
   Generate or reuse a clean baseline `tool_findings.jsonl` from the existing
   pristine `lab-<distro>:baseline` snapshot. Store enough manifest/identity
   metadata to prevent stale baseline reuse across incompatible VM images,
   kernels, snapshots, or tool versions. PR #3 added a baseline-aware hook, but
   it did not generate this clean baseline artifact cache yet.

2. Re-run Father_LDPRELOAD with real baseline evidence.
   Use the clean baseline artifact cache as detector input, regenerate Father
   candidate claims and canonical matching output, and explain what changed.
   If candidate counts do not improve, document why.

3. Explain remaining Father false positives.
   Make clear that low candidate precision reflects broad GT-blind candidate
   evidence, not final reconstruction quality. Identify which FPs remain after
   baseline comparison, grouped by rule/source/artifact class.

4. Fix CLI metric labels.
   `cli.py run` must not print candidate precision as if it were final detection
   precision. Console output should distinguish candidate diagnostics,
   reconstruction summary, source coverage, and warnings.

5. Fix acquisition artifact naming.
   Compromised evidence must not be named `baseline_disk.E01`. The baseline
   snapshot can remain named `baseline`, but acquired compromised disk images
   and clean baseline artifact caches must be clearly distinguishable.

6. Save or reproducibly reference ground truth and expected observables.
   Each result directory must contain, or clearly reference, the scenario
   ground truth, artifact expectations, command log, reference context, and
   rules/config versions used for scoring.

7. Add phase timing.
   Record setup/revert, scenario execution, memory acquisition, disk acquisition,
   disk extraction, memory extraction, timeline generation, detector runtime,
   matcher/report runtime, and total runtime. Do not infer thesis runtime from
   file timestamps.

8. Review CLI commands and console output.
   `setup`, `run`, `analyze`, `run-detectors`, and `match-canonical` should be
   clear enough for thesis/demo use. Scenario step progress should be visible
   without flooding the console with low-level libvirt noise.

9. Review acquisition lifecycle.
   Preserve the contract: memory acquisition requires the VM on; disk acquisition
   requires the VM off. External acquisition helpers must not perform unexpected
   shutdowns outside the orchestrator-controlled phase.

10. Scenario review and second-scenario decision.
    Keep Father as primary. Select at most one second scenario, only after
    Father with real baseline evidence is thesis-defensible. Avoid choosing a
    scenario that creates a new framework-sized problem. A weak second scenario
    should be deferred rather than implemented only to claim two scenarios.

## 3. Should-have

1. Plaso/log2timeline/psort verification and timing.
   Confirm the exact command path, filters, cached output behavior, and timing
   fields. Make failures explicit and best-effort, not silent.

2. Tool pluggability check.
   Keep Sleuth Kit, Volatility3, Plaso, and libewf usage isolated behind the
   existing wrappers/adapters. Do not add new tools; just verify that current
   boundaries are clear enough to describe.

3. Ext4 journal preservation for deleted-file reconstruction.
   Add an ext4-only, best-effort review of whether the current EWF/disk workflow
   preserves enough journal metadata for deleted-file reconstruction. Keep this
   scoped; do not build a general filesystem recovery framework.

4. Rule cleanup after baseline.
   After real baseline comparison exists, downgrade broad rules and tighten
   `ld_preload_configuration`. Avoid broad token matching where path class,
   source, baseline status, or memory corroboration is a better discriminator.

5. Cleanup mode design.
   Define `none | normal | high` cleanup modes and expected observability impact,
   but do not implement this before the core Father metrics and baseline story
   are stable.

6. ART and ground-truth review.
   Document Atomic Red Team limitations and keep ART as calibration/reference
   only. Review the ART runner and legacy ground-truth path only enough to avoid
   confusing it with the canonical thesis pipeline.

## 4. Nice-to-have / defer

1. LiME + `dd` acquisition mode.
   Useful comparison point, but not needed for the thesis core unless the
   current `virsh dump` / EWF path blocks delivery.

2. Hardened VM variant.
   auditd/AppArmor/SELinux or kernel-hardening variants are interesting, but
   they expand the experimental matrix. Defer unless one focused hardening
   comparison is explicitly selected.

3. Timestomping scenario.
   Good future test for timeline and metadata reasoning, but not before Father
   baseline reconstruction is complete.

4. Realistic Linux worm.
   High scope and safety risk. Only consider a tightly constrained, non-network
   lab-safe simulation after the thesis core is complete.

5. Broad YARA/Sigma/Timesketch integration.
   Timesketch can remain a sidecar. YARA/Sigma should not become the main metric
   path or a substitute for baseline comparison.

6. ART runner dependency.
   Keep ART optional/calibration-only. Do not make thesis delivery depend on ART
   coverage.

7. CLI cosmetic polish.
   Improve clarity where it affects thesis/demo usability; defer cosmetic
   renaming, command reshuffling, and broad UX polish.

## 5. Explicitly deferred / out of scope

- Full evasion framework.
- Real worm behavior or uncontrolled propagation.
- General kernel rootkit/eBPF/LKM scenario suite.
- Package ownership DB, reputation checks, HashR, THOR, Loki, Velociraptor,
  OpenRelik, Dissect, or similar external platforms.
- libewf-python exploration unless the existing libewf command-line path blocks
  a required result.
- Broad VM lifecycle refactors that do not directly improve thesis metrics or
  reproducibility.
- Replacing the current orchestrator with Timesketch, Sigma, YARA, or a SIEM-like
  backend.

Evasion, kernel-rootkit, and worm work are dangerous scope expansion unless they
are reduced to one tightly bounded scenario with clear expected artifacts.

## 6. Immediate next PR sequence

1. PR 4: CLI/report label cleanup.
   Fix `cli.py run` console summaries so candidate precision is visibly
   diagnostic. Surface reconstruction summary, baseline availability, and
   methodology warnings.

2. PR 5: clean baseline artifact cache.
   Reuse the existing `lab-<distro>:baseline` snapshot. Generate a clean
   `tool_findings.jsonl` plus manifest/identity metadata. Do not add new tools or
   a second baseline naming scheme.

3. PR 6: Father rerun with baseline evidence.
   Regenerate Father detector and matcher output using the real clean baseline
   artifact set. Update docs with candidate diagnostics, strong reconstruction,
   source coverage, corroboration, noise reduction, and remaining FPs.

4. PR 7: acquisition/result reproducibility cleanup.
   Rename compromised acquisition artifacts, verify ground truth / expectations
   are saved or reproducibly referenced, and add phase timing.

5. PR 8: Father rule cleanup after baseline.
   Tighten broad filesystem/timeline rules based on real baseline behavior.
   Avoid rule tuning before baseline evidence exists.

6. PR 9: second-scenario decision.
   Choose one second scenario or explicitly defer it. The selection criteria are:
   fast to run, safe, clear expected artifacts, and useful contrast with Father.

## 7. Current thesis risks

- No clean baseline `tool_findings.jsonl` cache exists yet. PR #3 added the hook,
  but current Father metrics remain unchanged unless a real clean baseline
  artifact set is supplied.
- Candidate precision is low and easy to misread. The thesis must present it as
  a detector/candidate-stream diagnostic, not a final reconstruction score.
- Broad filesystem and timeline rules still create many candidate FPs. Baseline
  comparison is the next real feature, not more detectors.
- CLI output can still blur candidate diagnostics and final reconstruction.
- Disk acquisition naming can confuse baseline snapshot state with compromised
  run artifacts.
- Runtime claims are weak until phase timing is explicitly measured.
- Adding evasion, hardening, worm, Timesketch, Sigma, or YARA work before Father
  is stable would likely dilute the thesis deliverable.


P.S Keep ART only if justified.. example we have a dedicated pipeline that "can test which artifacts are created when a specific technique is run"