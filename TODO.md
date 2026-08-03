# Thesis delivery queue

Updated 2026-08-03. This file contains mutable priorities only.

## Immediate sequence

1. Complete the final hybrid human/ChatGPT review of the Father-cleanup
   disk-forensics phase. Treat this as an acceptance and correction pass, not a
   second investigation: do not rerun tools or alter accepted evidence, raw
   exports, worklogs, or comparative results. Limit edits to report corrections
   approved by the human.
2. Complete the Father-cleanup RAM analysis.
3. Complete the Father-cleanup Plaso analysis.
4. Finish the cross-source interpretation and thesis-ready Father-cleanup
   conclusion only after the source phases are accepted.

Existing draft reports and comparative material are review inputs, not standing
instructions. Use `METHODOLOGY.md` for the current method and cite the exact
immutable run in every evidence-facing task.

## Delivery milestones

- By `2026-08-19`: experimental work substantially complete.
- By `2026-09-21`: final project, LaTeX integration, and slides complete.

## After the minimum deliverable

- Integrate accepted Father results into the thesis, figures, limitations, and
  presentation material.
- Perform only targeted Ubuntu 24.04 or Debian 13 replication that strengthens a
  specific thesis claim without threatening the milestones.
- Add another scenario or security-profile comparison only if the minimum
  Ubuntu 22.04 deliverables are already secure.

## Deferred unless explicitly reopened

- automatic detection, matching, scoring, or reconstruction;
- Fedora/SELinux and broad platform expansion;
- Timesketch, Velociraptor, AIDE/NSRL, graph/ontology, or broad Sigma/YARA work;
- a large test rewrite, architecture refactor, new framework, or major
  dependency; and
- optional scenarios that do not directly protect a thesis research question or
  delivery milestone.
