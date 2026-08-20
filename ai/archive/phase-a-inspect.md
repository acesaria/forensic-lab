# Phase A — Father Inspection Prompt

Start a fresh Claude session at the repository root.

Read only:

- `ai/ai/IDENTITY.md`
- `ai/ai/ROUTING.md`
- `ai/01_refactor/CONTEXT.md`
- `ai/father-refactor-plan.md`

Task:

Inspect the local Father scenario integration and prepare an implementation plan for three bounded issues. Do not edit files in this phase.

Likely targets, to verify rather than assume:

- the local Father scenario runner;
- the local scenario command/build integration;
- directly related local tests or validation scripts.

Important boundary:

The Father rootkit implementation is external/upstream. Do not modify, patch, vendor-edit, or reformat the original Father `rk` source. Treat its current behavior as fixed input.

Issues to inspect:

1. Reconnaissance currently prints the complete `/etc/passwd` output. Keep `id`, `uname -a`, and `/etc/os-release` visible for educational value, but propose how to retain account enumeration as an artifact without making normal run output unnecessarily verbose.
2. The upstream file-hiding hook may fail when two matching hidden files occur in the same directory. Do not fix the hook. Determine whether a local validation can demonstrate the limitation, or whether the scenario can safely use two different hiding paths without changing the upstream code. Do not claim a fix unless the upstream source is unchanged and behavior is actually corrected by the integration.
3. Cleanup currently removes shell history and truncates local logs. Evaluate the default experiment goal: preserve enough evidence for the DF investigation while retaining a realistic anti-forensic action. Propose whether the default should keep history cleanup but omit auth/syslog truncation, with any stronger cleanup represented as a separate explicit profile.

Inspect only the local runner, directly connected command/build helpers, and directly connected tests or validation scripts. Do not inspect or modify unrelated scenarios, README, thesis files, or the general testing framework.

Return only:

1. exact files inspected;
2. exact command blocks responsible for reconnaissance and cleanup;
3. whether the upstream hook limitation can be handled without modifying upstream code;
4. proposed minimal local integration changes;
5. proposed focused validation method;
6. exact files that would be modified;
7. exact files that will not be modified;
8. focused validation commands.

Constraints:

- preserve scenario behavior except for the explicitly approved presentation/cleanup changes;
- do not modify the upstream Father `rk` implementation;
- do not add broad tests;
- do not redesign the scenario architecture;
- do not modify README, thesis, or general documentation;
- do not commit.
