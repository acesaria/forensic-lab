# Legacy Detector Rule Packs

Status: legacy automatic-evaluation surface retained during migration. These
rules are not part of the current manual-investigation thesis method and should
not be extended. They remain only until the old automatic pipeline is removed or
quarantined in a later cleanup.

Historically, these rules were GT-blind. They ran only over canonical
`ToolFinding` records and did not receive scenario ground truth, target paths,
hashes, step names, or expected observables.

Historical rule format:

- `id`: stable rule identifier;
- `name`: human-readable rule name;
- `description`: thesis-citable intent;
- `source_types`: canonical evidence sources accepted by the rule;
- `artifact_classes`: canonical artifact classes accepted by the rule;
- `attck`: ATT&CK tags attached to resulting `DetectionClaim` rows;
- `parameters`: rule-specific, non-scenario target predicates.

The legacy engine in `detectors/engine.py` loads these YAML files and emits
`detection_claims.jsonl`. Current thesis work should use raw TSK, Plaso, and
Volatility exports plus manual investigation notes instead.
