# General Context — Linux Multi-Source DFIR Lab

## Project identity

This project supports a Master’s thesis in Computer Engineering/Cybersecurity on Linux post-mortem digital forensics.

Project name: **Linux Multi-Source DFIR Lab**  
Repository: https://github.com/acesaria/forensic-lab

The repository provides reproducible infrastructure for executing controlled Linux compromise scenarios in isolated virtual machines, acquiring disk and memory evidence, producing raw forensic-tool outputs, and conducting a manual multi-source investigation.

Use this document for stable scope and methodological decisions. Inspect the repository, its normative documentation, Git history, and `TODO.md` for the current implementation state. If the repository conflicts with this scope, identify the conflict rather than silently restoring an older design.

## Thesis objective

The thesis studies what can be reconstructed after controlled Linux compromises by combining:

- disk and filesystem evidence;
- memory evidence;
- Plaso-generated temporal evidence;
- evidence from security controls when a scenario is prevented.

The central contribution is the reproducible experimental infrastructure and the comparative, manually documented investigation. The analysis should show what each source reveals independently, what becomes visible only through correlation, and where existing forensic tools have limitations.

The project is **not** currently attempting to build an automatic detection, event-matching, scoring, or reconstruction engine.

## Committed workflow

1. Restore the correct powered-off baseline snapshot.
2. Fresh-boot the experimental guest and wait for deterministic readiness conditions.
3. Execute the selected controlled scenario.
4. Record execution provenance in a minimal run manifest and append-only command log.
5. Acquire disk and memory evidence while preserving hashes, tool output, status, and provenance.
6. Automatically generate raw TSK, Plaso, and Volatility exports.
7. Investigate the case manually with low-level and higher-level tools.
8. Complete an evidence matrix and describe cross-source correlation, contradictions, negative observations, prevention, and tool limitations.

Scenario execution validation establishes whether the experimental treatment occurred. It must not be presented as forensic detection or as the analyst’s conclusion.

## Evidence sources and tools

Core low-level tools:

- Sleuth Kit for disk/filesystem examination;
- Plaso for timeline generation;
- Volatility 3 for memory analysis.

Higher-level tools:

- Autopsy for disk-oriented investigation;
- Timesketch for the selected timeline/telemetry comparison;
- BPFVol3 for the eBPF case, compared with standard Volatility;
- Velociraptor only if it contributes clearly without expanding the core scope.

Acquisition and raw export execution may be automated. Interpretation and correlation remain manual.

## Experimental platforms

Target distributions:

- Ubuntu 22.04: primary platform for deep analysis;
- Ubuntu 24.04: targeted replication;
- Debian13: targeted replication.

Profiles:

- **Vanilla:** distribution defaults plus documented laboratory prerequisites.
- **Hardened:** one fixed, documented hardening bundle. Ubuntu uses AppArmor and Fedora uses SELinux, together with the bundle’s applicable technique-specific controls.
- **Hardened+telemetry:** the hardened profile plus auditd, used only for the representative Father/Timesketch comparison.

If hardening prevents a scenario, record the case as `prevented`, acquire the remaining evidence when safe, and analyse the denial traces. Prevention is an experimental result, not a failed cell.

## Baseline and boot protocol

Each profile has a separate baseline created after provisioning is complete:

1. finish cloud-init/provisioning and verify prerequisites;
2. cleanly shut down the guest;
3. create the baseline snapshot while the VM is powered off;
4. before each run, restore the snapshot while powered off;
5. fresh-boot the guest, synchronize/measure its clock, check readiness, and use a documented stabilization interval.

Experiments start from equivalent persistent state, not bit-identical runtime state. PIDs, ASLR addresses, boot identifiers, timestamps, leases, and service scheduling are controlled nuisance variables. Record relevant boot and timing provenance and interpret temporal evidence relative to the scenario start marker as well as by wall-clock time.

A clean RAM reference, if needed, is acquired in a separate fresh-boot control run; it is not supplied by a saved-memory snapshot.

## Scenario scope

Core scenarios:

1. **Father / system-wide LD_PRELOAD calibration:** use real `/etc/ld.so.preload`; validate file hiding and the native backdoor, persist then delete the uploaded staging library and shell history, and retain the installed persistence artefacts and selected affected processes through acquisition.
2. **ptrace injection:** integrate the existing functional proof of concept as a controlled process-injection case.
3. **Meterpreter case:** execute one common Linux x64 Meterpreter payload, remove its filesystem launcher, retain the live session for acquisition, and analyse it as a controlled real-world-framework example.
4. **LKM case:** primary traditional kernel-rootkit experiment.
5. **eBPF case:** one minimal published proof of concept demonstrating a clear capability; compare standard Volatility with BPFVol3.

Appendices:

- the existing ftrace proof of concept beside the main LKM case;
- CopyFail as a recent low-level privilege-escalation case, asking what traditional post-mortem DFIR can observe.

Use a selective matrix: investigate scenarios deeply on Ubuntu 22.04 and replicate only targeted questions on Ubuntu 24.04 and Fedora. Do not expand every scenario across every profile by default.

## Privilege and safety model

The experiments run only in isolated, disposable, authorized laboratory VMs.

Passwordless sudo is available as a laboratory mechanism for deploying techniques that require root. It is a documented experimental precondition, not an emulation of the attacker’s initial compromise. Record the execution user and required privilege. Privilege-escalation scenarios such as CopyFail must retain their own appropriate initial privilege model.

Preserve host/guest separation, failure recovery, snapshot restoration, and evidence-acquisition safety. Do not execute scenario artefacts on the development host.

## Required case records

Keep the runtime record small and factual:

- run and scenario identifiers;
- distribution and profile;
- baseline/snapshot identity;
- repository revision;
- timestamps and clock information;
- execution user and required privilege;
- scenario parameters and status;
- command log;
- acquisition hashes and verification status;
- raw tool versions, commands, output paths, and statuses.

Manual evidence status vocabulary:

- `observed`;
- `partially observed`;
- `not observed`;
- `prevented`;
- `tool failed`;
- `not applicable`.

Cross-source contribution vocabulary:

- `unique`;
- `corroborated`;
- `contradictory`;
- `specialized`.

`Not observed` must not be equated automatically with absence of evidence. A tool failure must remain distinct from a valid negative result.

## Explicit non-goals

Do not reintroduce as current deliverables:

- `ToolFinding`, `DetectionClaim`, canonical matching, or expectation scoring;
- precision, recall, F1, or arbitrary evidence scores;
- automatic detection or automatic event reconstruction;
- a production SIEM, EDR, or generic malware detector;
- broad live-telemetry infrastructure;
- a large adapter, plugin, schema, or ruleset architecture.

Auditd/Timesketch is a single bounded comparison, not a new default telemetry pipeline. The removed automatic-reconstruction implementation is preserved only as previous work and possible future work under the immutable tag `automatic-reconstruction-v3-final`.

## Engineering principles

- Prefer the smallest defensible implementation.
- Preserve working VM lifecycle, acquisition, and raw-export code unless a concrete defect requires change.
- Avoid new abstractions, schemas, dependencies, documentation, and tests unless they protect thesis-relevant behaviour.
- Use focused commits and keep unrelated changes untouched.
- Distinguish acquisition integrity failures, tool failures, scenario failures, and genuine negative observations.
- Do not improve apparent results by hard-coding scenario-specific forensic conclusions.
- Treat unexpected or difficult-to-detect evidence as a potentially valuable finding, not something that must be engineered away.
- Complete and validate the consolidated Father calibration before expanding the remaining scenario set.
