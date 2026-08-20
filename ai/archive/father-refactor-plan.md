# Father Scenario Refactor Plan

## Decision

Do not modify the original Father rootkit repository or its imported `rk` implementation.

Make changes only in the local scenario integration layer and the experiment presentation/cleanup commands. The original rootkit behavior remains an external dependency and is tested as-is.

## Scope

1. Reduce reconnaissance noise without removing useful evidence.
2. Document and validate the adjacent-hidden-file limitation of the upstream hook.
3. Decide cleanup behavior deliberately for forensic recoverability.
4. Avoid broad tests, architecture changes, and unrelated documentation.

## Recommended behavior

### Reconnaissance

Keep visible:

- `id`
- `uname -a`
- `/etc/os-release`

Collect account enumeration into `/tmp/__malicious_recon` without printing the whole database:

```bash
getent passwd >> /tmp/__malicious_recon
printf '[recon] account database collected\n'
```

Whether the account command is `cat /etc/passwd` or `getent passwd` must follow the existing scenario design; do not change it solely for style.

### Upstream hook limitation

Do not patch the upstream Father `rk` code.

Create a focused validation in the local scenario workflow that places two files matching the hide rule in the same directory, adjacent in creation/listing order, and compares:

- the compromised/preloaded view;
- an independent view that bypasses the hook.

Record the result as a known upstream limitation if both files are not hidden consistently. Do not call the scenario successful if the validation contradicts its stated behavior.

### Cleanup

Keep shell-history cleanup if it is part of the intended anti-forensic behavior:

```bash
history -c
rm -f -- "${HISTFILE:-$HOME/.bash_history}"
unset HISTFILE
```

For the current pedagogical/forensic objective, do not truncate `/var/log/auth.log` or `/var/log/syslog` in the default run. Preserving local logs makes the investigation more recoverable and provides useful evidence.

If a stronger-evasion variant is desired later, represent it as a separate explicit profile or option, not as an implicit change to the default scenario.

## Phase A: inspection prompt

Use the companion prompt `phase-a-inspect.md` in a fresh Claude session.

## Phase B: implementation prompt

Use `phase-b-implement.md` only after reviewing Phase A. The implementation target must exclude the upstream `rk` source.

## Review gate

Before proceeding to experiments, confirm:

- no upstream Father repository file changed;
- no rootkit source was patched;
- reconnaissance output is concise but evidence is retained;
- default cleanup leaves auth/syslog available;
- the adjacent-file limitation is either demonstrated and documented locally or the scenario remains unchanged until a safe integration workaround exists;
- `git diff --check` passes;
- no broad tests were added.

## Evidence rationale

Local log truncation is a real anti-forensic action, but it removes evidence from the default investigation. Local-only logs can be modified by a root-level attacker, while missing/truncated logs are themselves forensic indicators. Keep the default profile more recoverable and reserve destructive log cleanup for a clearly labeled evasion variant.
