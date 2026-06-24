---
description: "Path-scoped guidance for detectors, matcher, canonical records, and evaluation code."
applyTo: ["detectors/**/*.py", "detectors/rules/**/*.yml", "matcher/**/*.py", "orchestrator/canonical/**/*.py", "orchestrator/evaluation/**/*.py"]
---
# Forensic Evaluation

- Read `PROJECT_CONTEXT.md` before editing these paths.
- Preserve GT-blindness: detectors, adapters, YAML rules, and candidate-evidence generation must not read ground truth or artifact expectations.
- Treat YAML rules as candidate/supporting evidence rules, not final detections.
- Treat `DetectionClaim` as candidate evidence, not a final verdict.
- Keep GT-aware logic in matching, metrics, reporting, or explicit scenario truth generation.
- Reports and schemas should distinguish raw findings, candidate evidence, matched reconstruction, and metric results.
- Prefer small wording and boundary fixes over pipeline rewrites.
