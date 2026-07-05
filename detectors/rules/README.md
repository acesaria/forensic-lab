# Detector Rule Packs

These rules are GT-blind. They run only over canonical `ToolFinding` records and
do not receive scenario ground truth, target paths, hashes, step names, or
expected observables.

Each rule is Sigma-lite YAML:

- `id`: stable rule identifier;
- `name`: human-readable rule name;
- `description`: thesis-citable intent;
- `source_types`: canonical evidence sources accepted by the rule;
- `artifact_classes`: canonical artifact classes accepted by the rule;
- `attck`: ATT&CK tags attached to resulting `DetectionClaim` rows;
- `parameters`: rule-specific, non-scenario target predicates.

The engine in `detectors/engine.py` loads these YAML files and emits
`detection_claims.jsonl`.
