# Prompt for Claude — ICM Cleanup & Review (Phase 1)

**Context:** We are working on a cybersecurity/DFIR thesis project. The ICM (Inter-Contextual Memory) structure organizes documentation, experiments, investigations, and thesis work. The structure has grown organically and now contains obsolete files, duplicates, and unverified assertions. We need to clean it up before proceeding with metrics definition.

**Your role:** You are a technical reviewer and archivist. Your task is to read, map, and clean the ICM structure to make it coherent, minimal, and "agent-friendly".

---

## Task 1 — Structure Mapping

1. **Read all configuration files:**
   - `ai/_config/conventions.md`
   - `ai/_config/scope.md`
   - `ai/_config/done.md`
   - `ai/ROUTING.md`
   - `ai/IDENTITY.md`
   - `ai/DECISIONS.md`
   - `ai/phase-a-inspect.md`
   - `ai/phase-b-implement.md`
   - `ai/father-refactor-plan.md`

2. **Read all CONTEXT.md files:**
   - `ai/01_refactor/CONTEXT.md`
   - `ai/02_experiments/CONTEXT.md`
   - `ai/03_investigation/CONTEXT.md`
   - `ai/04_docs/CONTEXT.md`
   - `ai/05_thesis/CONTEXT.md`

3. **For each directory (01_–05_), list:**
   - Declared purpose (from CONTEXT.md)
   - Files in `output/` (what are they? drafts, finals, generated?)
   - Files in `references/` (are they stable or drafts?)
   - Any inconsistencies (e.g., files mentioned but missing, wrong paths)

4. **Produce a summary map** (`ai/STRUCTURE_MAP.md`) with:
   - Description of each directory (1-2 sentences)
   - List of "source of truth" files (to keep)
   - List of "generated output" files (to archive or delete if obsolete)
   - Notes on inconsistencies or problems found

---

## Task 2 — Cleanup and Simplification

1. **Identify obsolete or duplicate files:**
   - Look for files with similar names (e.g., `disk-notebook-refactor.md` vs `notebook-implementation.md`)
   - Look for files that seem like superseded drafts (e.g., old versions of plans)
   - Flag files with unverified assertions or untested hypotheses

2. **Simplify CONTEXT.md files:**
   - Each CONTEXT.md should be ≤ 1 page
   - Structure: Problem → Current state → Next steps (3-5 bullets)
   - Remove operational details (move them to `output/` or `references/`)
   - Remove repetitions of concepts already in `_config/`

3. **Verify reference consistency:**
   - Each `references/` should contain only stable documents
   - Move drafts to `output/` or a new `work/` folder
   - Fix any broken internal links

4. **Propose an archival plan:**
   - Create `ai/archive/` for obsolete but potentially useful files
   - List which files to move there
   - List which files to delete permanently (with justification)

---

## Task 3 — Create INDEX.md

1. **Write `ai/INDEX.md`** with:
   - Project overview (2-3 sentences, from `scope.md` or `IDENTITY.md`)
   - Directory table:
     | Directory | Purpose | Key files | Status |
     |-----------|---------|-----------|--------|
     | 01_refactor | ... | ... | ... |
   - Instructions for an agent:
     - "If you need to work on X, read first: ..."
     - "Files in `output/` are generated and may be overwritten"
     - "Files in `references/` are stable and should be updated carefully"

2. **Update ROUTING.md:**
   - Verify all mentioned paths exist
   - Fix any errors
   - Add references to new files (e.g., `INDEX.md`, `STRUCTURE_MAP.md`)

---

## Task 4 — Review Report

1. **Write `ai/_config/review-report.md`** with:
   - What you found (main problems)
   - What you did (concrete actions)
   - What remains to be done (pending tasks)
   - Recommendations for the future (e.g., "every new file must follow X convention")

2. **List unverified assertions** that require human validation:
   - E.g., "The notebook recovers 90% of artifacts" → to test
   - E.g., "TSK is the best tool for ext4" → to justify with benchmarks

---

## Expected Outputs

After completing this task, you should have produced:

- `ai/STRUCTURE_MAP.md` — structure map
- `ai/INDEX.md` — navigable index for agents
- `ai/_config/review-report.md` — review report
- Simplified CONTEXT.md files (5 files updated)
- Updated ROUTING.md
- List of files to archive/delete (to confirm with user)

---

## Quality Criteria

- **Clarity:** An agent reading `INDEX.md` immediately understands where it is and what to read
- **Minimality:** No redundant files, no concepts repeated in multiple places
- **Consistency:** Paths in files match the actual structure
- **Maintainability:** It's clear how to add new files without breaking the structure

---

## Important Notes

- **Do not delete anything without confirmation.** Flag what should be archived/deleted, but ask the user before acting.
- **Keep the tone technical but accessible.** This document will be read by humans and agents.
- **Cite files** when making assertions (e.g., "According to `phase-a-inspect.md`, ...").

---

**Start by reading the files listed in Task 1 and producing the map (Task 1, point 4). Then proceed with the other tasks in order.**