# METHODOLOGY.md

Normative methodology for forensic-lab. The current thesis is a reproducible
manual multi-source Linux post-mortem investigation study. Behavioral rules for
contributors stay in `AGENTS.md`; repo facts stay in `PROJECT_CONTEXT.md`.

## 1. Thesis contribution

The project contribution is not an automatic detector or scoring system. The
current contribution is to:

- reproducibly execute controlled Linux compromise scenarios;
- acquire disk and memory evidence safely;
- automatically produce raw TSK, Plaso, and Volatility exports;
- manually investigate and correlate filesystem, timeline, and memory evidence;
- compare vanilla and hardened Linux profiles;
- document tool limitations, including negative findings;
- preserve provenance and reproducibility without automatic scoring.

The previous automatic reconstruction/evaluation pipeline is preserved by the
immutable tag `automatic-reconstruction-v3-final`. It may be discussed as
previous work or future work, but it is not the current thesis deliverable.

## 2. Research questions

- **RQ1 - Reproducibility and acquisition.** Can controlled Linux compromise
  scenarios be executed repeatedly while preserving enough command, manifest,
  hash, and tool provenance to support later forensic review?
- **RQ2 - Multi-source investigation.** What does manual correlation across
  filesystem state, timeline events, and memory state reveal for each scenario?
- **RQ3 - Profile comparison.** How do vanilla and hardened Linux profiles
  change scenario execution, residual evidence, denial traces, and analyst
  interpretation?
- **RQ4 - Tool limitations.** Where do TSK, Plaso, Volatility, and the lab
  workflow produce incomplete, ambiguous, empty, failed, or negative evidence?

No RQ is answered by precision, recall, F1, canonical matching, ruleset hashes,
or automatic reconstruction metrics.

## 3. Experimental matrix

One run is `(scenario, distro, profile)`.

- **Deep-analysis platform:** Ubuntu 22.04.
- **Targeted replication platforms:** Ubuntu 24.04 and Fedora.
- **Vanilla profile:** distro defaults.
- **Hardened profile:** one fixed, documented native-control bundle.
- **Ubuntu native control:** AppArmor.
- **Fedora native control:** SELinux.
- **hardened+telemetry:** the hardened bundle plus `auditd`; used only for the
  Father cleanup comparison.

Hardened profile runs do not need to let the scenario complete. If a native
control blocks the scenario, the run is recorded as **prevented**. Remaining
evidence, command output, policy denials, audit traces where enabled, memory
state when available, disk state, and raw tool outputs are still acquired and
analysed.

Passwordless sudo is a laboratory precondition for deploying techniques that
require root inside controlled scenarios. It is not an emulation of initial
compromise and must not be interpreted as an attack finding.

## 4. Workflow

The target workflow is:

`scenario execution -> manifest/command log -> acquisition -> raw extraction -> manual investigation -> profile comparison -> thesis reporting`

Required phases:

1. Execute a deterministic controlled scenario.
2. Write a minimal run manifest and append-only command log.
3. Acquire memory while the VM is ON.
4. Acquire disk while the VM is OFF.
5. Hash acquired evidence and retain provenance.
6. Produce raw TSK, Plaso, and Volatility exports automatically.
7. Manually inspect and correlate raw filesystem, timeline, and memory evidence.
8. Record positive findings, negative findings, tool failures, and limitations.
9. Compare vanilla and hardened profiles without pooling them into a single
   automatic score.

Automatic acquisition and raw extraction are in scope. Manual investigation is
the analysis method. Automatic detection, canonical matching, and scoring are
out of scope for the current deliverable.

## 5. Evidence and provenance contract

Every thesis run must retain:

- run identifier, scenario identifier, distro, profile, and timestamp;
- scenario source revision or equivalent source provenance;
- minimal run manifest;
- append-only command log;
- memory image path, disk image path, and cryptographic hashes;
- raw TSK, Plaso, and Volatility export paths;
- tool names, versions where available, command lines, exit statuses, and error
  output;
- analyst notes that cite raw evidence locations rather than undocumented
  conclusions.

The run-root manifest is a small index. It points to the append-only command
log and, when acquisition is requested, `dumps/acquisition.json` and
`analysis/raw_extraction_status.json`; it does not embed scenario parameters,
per-step records, expected observables, evidence hashes, or full tool records.
Its root status covers the requested workflow. A completed `--no-acquire` run
is explicitly scenario-only and is not an accepted forensic experiment. The
Father calibration includes one concise `scenario_facts` block for deployment,
activation, PIDs, privilege, and execution validation.

Memory provenance includes the full-image SHA-256, byte size, acquisition
timestamp and duration, exact `virsh dump --memory-only` command, and reported
virsh version. Disk provenance includes the logical media size and the SHA-256
calculated by `ewfverify -d sha256`, plus the path, byte size, and SHA-256 of
every EWF segment. The verification command, output, exit status, calculated
digest, and pass/fail state are retained; failed verification or a missing
calculated SHA-256 fails acquisition.

Raw extraction retains separate TSK, Plaso, and Volatility outputs plus an
adjacent status record containing their versions, invocations, exit status,
output paths and hashes. A successful invocation with zero rows or events is
recorded as `zero_results`; it is not interchangeable with a failed tool or
plugin. Tool failures recorded in this sidecar do not change scenario status or
prevent workflow completion once the status record is written.

Raw evidence is immutable. If a tool is rerun, the new output is a separate
derived artifact with its own provenance; the acquired disk and memory evidence
are not modified.

Tool failures are first-class results. A failed plugin, empty output file,
unsupported kernel profile, parser limitation, missing timestamp, or absent
artifact must be recorded explicitly instead of hidden behind a summary.

## 6. Source-family analysis

Filesystem, timeline, and memory evidence are separate source families.

- **TSK/filesystem:** file and directory state, inode metadata, deletion flags,
  allocation state, mode, size, and filesystem timestamps.
- **Plaso/timeline:** event ordering and timestamped activity reconstructed from
  disk evidence.
- **Volatility/memory:** point-in-time process, module, mapping, socket, and
  kernel state from RAM.

Manual correlation may compare these families, but the methodology does not
flatten them into a universal automatic finding stream. A filesystem object, a
timeline event, and a memory observation may support the same interpretation
while retaining different provenance and failure modes.

Negative findings are meaningful only with source-family context. For example,
"not visible in Volatility process output" is a memory-tool observation, not
proof that no process ever existed.

## 7. Manual investigation record

Investigation remains manual. Notes should be written so another analyst can
reproduce the reasoning from raw exports and command logs.

Each scenario/profile report should include:

- case setup and profile description;
- acquisition summary and hashes;
- raw extraction summary for TSK, Plaso, and Volatility;
- tool failures and negative findings;
- filesystem observations;
- timeline observations;
- memory observations;
- cross-source correlations;
- vanilla vs hardened comparison where applicable;
- limitations and unresolved ambiguities.

The report may describe whether a scenario was completed, partially completed,
or prevented. It must not convert those descriptions into automatic precision,
recall, F1, or reconstruction scores.

## 8. Explicitly non-normative legacy concepts

The following are no longer normative requirements for the thesis:

- `ToolFinding`;
- `DetectionClaim`;
- canonical matching;
- automatic expectation matching;
- precision, recall, F1, or automatic evaluation metrics;
- automatic reconstruction as a current deliverable;
- ruleset hashes as an experimental result.

Historical documentation and generated artifacts may still contain these terms.
Treat them as legacy automatic-pipeline residue. Do not reintroduce them into
runtime source, do not add tests for them, and do not use them to define
current thesis claims.

Ruleset hashes are not a result. Tool versions, command lines, source revisions,
raw evidence hashes, and profile definitions are provenance.

## 9. Standards alignment

- **NIST SP 800-86:** collection maps to acquisition; examination maps to raw
  extraction; analysis maps to manual source-family investigation; reporting
  maps to analyst-written findings, limitations, and profile comparisons.
- **ISO/IEC 27037-style handling:** acquired evidence is preserved immutably,
  hashes are retained, and later analysis is performed on acquired images or
  derived exports.
- **Linux security controls:** Ubuntu hardening is AppArmor-based; Fedora
  hardening is SELinux-based. `auditd` is an added telemetry condition only for
  the Father cleanup comparison.
- **DFIR reproducibility:** command logs, manifests, hashes, tool command
  lines, tool failures, and negative findings are part of the evidence record.

## 10. Migration guardrails

This repository is between architectures. Documentation now describes the
target manual-investigation method, and current runtime source no longer
contains the old automatic detector/matcher pipeline.

During the remaining cleanup:

- do not modify Python, YAML scenarios, tests, or dependencies to revive legacy
  automatic evaluation;
- do not present legacy detector or matcher output as a current thesis result;
- do not add new detector rules, matcher aliases, evaluation schemas, or metric
  fields;
- keep VM power-state and acquisition-safety contracts unchanged;
- keep changes small and tests minimal;
- prefer deletion of remaining historical residue over extension when a later
  cleanup task explicitly reopens it.
