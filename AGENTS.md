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

For audits, produce a structured report with:

- inspected files
- findings
- proposed minimal changes
- intentionally unchanged areas

For implementation tasks, make the smallest patch that satisfies the request
and list what was intentionally left alone.
