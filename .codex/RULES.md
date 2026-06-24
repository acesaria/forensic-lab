# RULES.md - Charter for Core Correctness & Simplification Audit (forensic-lab)

> **CRITICAL CONTEXT:** Read this file alongside `CONTEXT.md`. This document establishes non-negotiable architectural boundaries, defines anti-patterns for over-engineering, and dictates the evaluation bar for all findings.
> **RULE #1:** The output of this audit MUST be a structured plan, NOT an immediate code rewrite. Apply changes ONLY when explicitly requested.

---

## 🎯 Goal
For one specific domain at a time (*infra, attacks, core, forensics, or evaluation/metrics*):
1. **Review** logical correctness.
2. **Identify** over-engineered modules (unnecessary layers, single-user abstractions, hand-rolled code replacing stdlib/deps).
3. **Plan** a simplification to drastically reduce line count and maximize readability **WITHOUT** altering observed behavior or touching invariants.

---

## ⛔ HARD INVARIANTS (NEVER BREAK)
*If a proposed simplification risks touching or altering any of these points, **STOP IMMEDIATELY and flag it as a hard constraint violation** instead of processing.*

- **Vanilla Lab VMs:** The only mechanism to modify a lab VM is via Ansible playbooks invoked by the orchestrator inside an experiment transaction. *Manual SSH modification is strictly forbidden.*
- **Single Snapshot Rule:** Exactly one snapshot per lab VM exists, named `baseline`. The orchestrator reverts to it before every run; it is never automatically re-created.
- **Power-State Contract:** Owned strictly by the orchestrator. `acquire_memory` requires the VM **ON**. `acquire_disk` requires the VM **OFF**. The Dumper tool must never mutate power states itself.
- **Error Handing Strategy:** On run error, leave the target VM destroyed. No half-modified or zombie VMs must survive.
- **Ephemeral Build VM:** The `build-isf` VM is ephemeral and is the *only* VM with internet access. It must be created, utilized, and destroyed strictly within a single `build_isf` call.
- **Isolated Network:** Lab VMs must remain strictly on the host-only isolated network (No NAT, no internet access).
- **Strict Dependency Tree:** One-way direction only: `core` ➔ `evaluation` ➔ `forensics`. `infra` and `orchestrator` must cross paths ONLY through the `Provider` via `VMManager`.
- **GT-Blindness Split:** The Detect layer is strictly Ground-Truth-blind. Detectors and rules **MUST NOT** read ground truth. Guarded natively by `tests/test_detect_blindness.py` and `test_rule_leakage.py`.
- **Schema Validation:** Stage boundaries are strictly schema-validated (`contracts/`). Keep this validation fully intact. A detector/matcher that stops emitting schema-valid output is fundamentally broken.

---

## 🔍 WHAT "OVER-ENGINEERED" MEANS HERE
Flag these issues in order of priority:

1. **Single-Use Boilerplate:** Any class, dataclass, factory, or registry with exactly one implementation or one caller, where a raw function or a literal is sufficient.
2. **Hand-Rolled Duplication:** Custom logic written for parsing, hashing, CSV, datetime, or path manipulation that is already covered by the Python standard library (`json`, `csv`, `hashlib`, `datetime`, `pathlib`) or pre-installed dependencies (`pyyaml`, `paramiko`, `jsonschema`, `pysigma`).
3. **Static Configuration:** Flags or config parameters exposed for values that never actually vary in practice.
4. **Redundant Indirection:** Code with no second user (e.g., forwarding wrappers, adapters-on-adapters, helpers called exactly once).
5. **Speculative Generality:** Dead extension points, hooks, or "future-proofing" scaffolding unused by current code.
6. **Code Duplication:** Shared logic that should be centralized into a single function (*Note: distinct from deliberate architectural boundaries*).

⚠️ **DO NOT FLAG AS OVER-ENGINEERING:** Schema validation at stage boundaries, infra/orchestrator separation, GT-blindness isolation, and power-state contracts. These are intentional, high-value structural boundaries, not bloat.

---

## 🧪 HOW TO JUDGE CORRECTNESS
Evaluate every reviewed module against these technical baselines:
- **Data-Flow Alignment:** Trace inputs/outputs using `CONTEXT.md`. Does the code produce the exact documented artifact shape?
- **Trust Boundary Edge Cases:** Explicitly check for empty findings, missing cached files, zero Ground Truth events (confirm metrics division-by-zero handling), and VM operations that hang or fail mid-run.
- **Error Swallowing:** Confirm **zero** bare `except:` blocks. No errors that could mask data loss or state corruption should be swallowed.
- **Math Verification:** For metrics, mathematically verify recall, precision, and F1 calculations against the exact formulas in `compute.py` comments. Ensure legacy columns line up properly.

---

## 📈 SIMPLIFICATION BAR (THE GATEKEEPER)
A proposed optimization is approved for shipping **ONLY** if all the following conditions are met:
- [ ] **Efficiency:** Net fewer lines of code, or drastically higher readability for the same line count.
- [ ] **Live-Path Identity:** Behavior is identical on the live path. Validate VM-facing changes using `cli.py run` (do not rely on mocked unit tests).
- [ ] **Invariants Untouched:** Zero impact on the hard invariants list.
- [ ] **Testability:** Non-trivial logic retains at least one runnable check (an assert-based self-check or a small `test_*.py`). Trivial one-liners require none.

---

## ✍️ CONVENTIONS TO PRESERVE
- **ASCII Only:** Absolutely no backticks, emojis, decorative bullets, or fancy unicode (arrows, em-dashes) in code or comments.
- **Noisy Comments:** Comments must explain **WHY**, not *what*. Eliminate verbose, LLM-style conversational comments or heavy section dividers.
- **Python Standard:** Strict type hints on public functions, no bare `except:`, enforce `pathlib.Path` over `os.path`.
- **Shell Standard:** Every script must use `set -euo pipefail`. Absolutely no bashisms.
- **Path Handling:** Normalize configured paths to absolute `Path` objects exactly once at load time. Path layout lives strictly inside `ProjectPaths`, never in individual callers.
- **Philosophy:** Explicit is always better than clever.

---

## 🛠️ PROCESS & OUT OF SCOPE
### The Process
- Inspect only the precise files needed, not entire folders. Locate the single owner of a behavior before drafting a change.
- Deliver minimal, targeted patches. Never submit wide refactors crossing the infra/orchestrator boundary or power-state contracts.
- Isolate tasks: Run, debug, and analysis must remain fully separate. A run mutates VMs and creates a new `run_id` dir; analysis only reads existing ones.
- Treat `shared/` outputs as disposable artifacts, not source files.

### Strictly Out of Scope
- `vendor/atomic-red-team` (squashed subtree; do not edit).
- Gitignored WIP scripts: `attack_0{1,5,6}_*.py`, `config.yaml`, `manifest.json`, `ground_truth.json`, VM IPs, SSH key paths.
- Automatically generated artifacts within `shared/`.
- Adding new external dependencies or frameworks. "Lazy coding" means shrinking lines using what is already installed.
