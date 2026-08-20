# Thesis review checklist

Portable stage-05 contract for a supervisor-style audit, bounded refactor, or
final thesis gate. Load it only when the task asks for one of those activities;
ordinary fragment drafting does not require it.

## Authority and scope

1. Follow the exact task, file allowlist, and stop gate.
2. Use current repository behavior and accepted evidence for project facts.
3. Use the active stage-03 results-table methodology for result wording.
4. Use current official rules or literature only for claims they govern.
5. Do not load historical plans, archived methodology, unrelated stages, or
   comparison theses unless the task names them.

## Scientific gate

Check only the links material to the scope:

```text
RQ -> method -> evidence -> result -> conclusion
claim -> citation, repository fact, or accepted evidence locator
limitation -> affected claim and residual validity
```

For forensic results, keep these separate:

- scenario execution or ground-truth validation;
- observation from a named disk, memory, or timeline method;
- analyst interpretation, including alternatives or uncertainty;
- conclusion limited to the observed scenario/distribution/run.

Treat bounded negative results, recovery failures, unavailable sources, and
rejected candidates as reportable outcomes. Do not convert them into universal
absence claims. Do not add precision, recall, F1, false-positive rates, or
automatic scoring unless the active prospective method defines them.

For a material methodology/results/conclusion audit, use a small claim ledger:

```text
Claim | Type | Support/locator | Scope or uncertainty | Status
```

Never invent a citation, metric, command output, evidence locator, or novelty
claim. Narrow or remove unsupported prose.

## Edit and validation gate

- Preserve citations, labels, commands, paths, identifiers, encoding, and the
  meaning of accepted evidence.
- Prefer precise, established English Linux/DFIR terms over forced Italian
  translations; remove filler and inflated certainty.
- Do not change scenarios, notebooks, evidence, metrics, or reporting contracts
  merely to simplify thesis prose.
- For a bounded LaTeX edit, inspect the diff, references, labels, placeholders,
  encoding, and affected build when available.
- For a final gate, inspect the complete build log and rendered PDF and trace
  every visible result to accepted evidence.

## Handoff

For an audit or final gate, lead with `PASS`, `REVISE`, or `BLOCKED`. For a
refactor, lead with the outcome. Then give only scoped findings or changes,
validation, residual risks or supervisor decisions, and the exact next bounded
action. Do not emit empty sections.
