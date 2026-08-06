# Investigation guidelines

Read this file before performing an investigation or creating or editing a
Runme investigation notebook.

## Scope and method

- Produce a concise educational investigation, not an exhaustive examination.
- Select the most useful observations and stop when the investigation question
  is answered.
- Prefer source-aware DFIR tools over generic byte or text processing. For
  filesystem work, use TSK commands such as `mmls`, `fsstat`, `ifind`, `ffind`,
  `fls`, `istat`, `icat`, `blkls`, `blkcalc`, and `blkcat` when they directly
  answer the question.
- Use `grep`, `sed`, `awk`, `xxd`, regular expressions, and shell pipelines only
  for small display or validation tasks that a forensic tool cannot answer
  directly.
- Apply KISS: use short sequential steps and do not add speculative analysis,
  helpers, abstractions, or automation.

## Runme style

- Use ordinary, readable Bash. Avoid functions, arrays, complex loops, and
  dense pipelines when a direct command is sufficient.
- Use descriptive uppercase `SNAKE_CASE` variable names. Reuse `RUN_ID`,
  `RUN_DIR`, and `INV_DIR` for the same common paths across notebooks; use
  source-specific names for different concepts.
- Follow each command block with the heading `**Output**`, then a brief
  interpretation or limitation. Do not qualify the heading as selected,
  reviewed, complete, or similar.
- Save broad output in derived files and show only the bounded portion useful
  to the educational point in the notebook.
- Keep observations, interpretations, and scenario-fact validation distinct.

## Cross-cell variable propagation

If a Bash variable assigned in one Runme cell is needed by a later cell, export
it from the producer cell with an explicit self-assignment:

```bash
PRELOAD_INODE="..."
export PRELOAD_INODE="$PRELOAD_INODE"
```

Use one explicit `export NAME="$NAME"` statement per cross-cell variable. Keep
cell-local variables as ordinary assignments.
