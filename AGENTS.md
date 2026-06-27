# AGENTS.md

Universal coding-agent entrypoint for forensic-lab.

Read `PROJECT_CONTEXT.md` first. Then inspect the exact code and config files
needed for the task before changing anything.

Work in small, isolated tasks. Avoid broad refactors unless explicitly
requested. When the task is instruction-layer-only, do not touch forensic
pipeline code, scenario code, matcher code, detector code, or README unless an
instruction reference would become invalid.

Preserve the VM power-state contract: memory acquisition requires the VM ON;
disk acquisition requires the VM OFF. Preserve GT-blindness: detectors and YAML
rules must not read ground truth or artifact expectations.

Treat YAML rules and `DetectionClaim` records as candidate evidence, not final
verdicts. Reports should distinguish raw findings, candidate evidence, matched
reconstruction, and metric results.

## Scope Guards

forensic-lab owns RAM, disk, baseline comparison, ground truth, matching, and
metrics. Keep it post-mortem, simple, and thesis-deliverable.

- Timesketch is an optional timeline sidecar only. It is not the active core and
  must not become the primary metric backend.
- Do not add Timesketch, Sigma, YARA, baseline tooling, or any other external
  tool unless a task explicitly asks for it.
- Do not create a persisted `FinalClaim` model (or a large final-claim
  architecture) unless a task explicitly requests it. `DetectionClaim` stays
  candidate/supporting evidence.
- Headline metrics must not silently score raw findings or all candidate claims
  as final reconstruction. Reconstruction is derived from matched expected
  artifacts / strong instance matches.

For audits, produce a structured report with:

- inspected files
- findings
- proposed minimal changes
- intentionally unchanged areas

For implementation tasks, make the smallest patch that satisfies the request
and list what was intentionally left alone.
