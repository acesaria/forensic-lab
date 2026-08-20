# Phase B — Father Implementation Prompt

Start a new Claude session at the repository root after reviewing the Phase A result.

Read only:

- `ai/ai/IDENTITY.md`
- `ai/ai/ROUTING.md`
- `ai/01_refactor/CONTEXT.md`
- `ai/father-refactor-plan.md`
- the Phase A result supplied by the user

Implement only the approved local integration changes.

Hard boundary:

Do not modify, patch, reformat, vendor-edit, or otherwise change the original Father rootkit `rk` source. The upstream hook is fixed input for this task.

Allowed changes are limited to the exact local files identified and approved in Phase A, such as:

- the local scenario runner;
- local scenario command/presentation helpers;
- a narrowly focused local validation script or existing test, only if required.

Required behavior:

1. Keep `id`, `uname -a`, and `/etc/os-release` visible in the reconnaissance output.
2. Do not print the complete account database in normal output. Retain account enumeration in the existing reconnaissance artifact and emit only a concise marker if appropriate.
3. Do not claim to fix the upstream adjacent-hidden-file bug. If it can be demonstrated locally, add only the approved focused validation or record the limitation in the stage output. If a different hiding path is proposed, prove that it does not alter the original rootkit and that it is necessary before implementing it.
4. For the default forensic experiment, retain shell-history cleanup if approved, but do not truncate `/var/log/auth.log` or `/var/log/syslog` unless the approved Phase A plan proves that this is required. Prefer preserving those logs for investigation.
5. Do not add a broad test suite or redesign the scenario.
6. Do not modify README, thesis, general documentation, unrelated scenarios, or the upstream rootkit source.

Before editing, state:

- the exact approved files to change;
- the exact upstream files that will remain untouched;
- the behavior-preserving rationale.

After editing:

- run only the approved focused validation;
- run `git diff --check`;
- show `git diff --stat`;
- report exact commands and results;
- write `ai/ai/01_refactor/output/father-rootkit-integration.md`.

The output note must include:

- files changed;
- upstream files intentionally untouched;
- reconnaissance output change;
- cleanup change and forensic rationale;
- adjacent-hidden-file limitation and validation result;
- focused validation result;
- known limitations;
- next step: final scenario run.

Do not commit.
