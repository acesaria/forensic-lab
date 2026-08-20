# Father rootkit integration — Phase B result

## Files changed

- `scenarios/userland_father_ldpreload/runner.py`
- `scenarios/userland_father_ldpreload/README.md`
- `tests/test_scenario_runtime.py`

## Upstream files intentionally untouched

- `scenarios/userland_father_ldpreload/files/father-upstream-4eb2712.tar`
- `scenarios/userland_father_ldpreload/files/build.sh`
- no other file under `scenarios/userland_father_ldpreload/files/`

No upstream Father `rk` source was read, patched, reformatted, or vendor-edited.

## Reconnaissance output change

`id`, `uname -a`, and `cat /etc/os-release` are unchanged: each still tees to both
the console and `/tmp/__malicious_recon`. `cat /etc/passwd` no longer tees to the
console; it is appended to the stage file only (`cat /etc/passwd >> ...`), followed
by a `printf '[recon] account database collected\n'` marker. The full account
database is still collected as evidence in the recon stage file — it is only the
terminal transcript/console echo that is suppressed. The account-source command
itself (`cat /etc/passwd`, not `getent passwd`) was left unchanged, per the
approved plan's instruction not to change it for style.

## Cleanup change and forensic rationale

`sudo -n truncate -s 0 -- /var/log/auth.log /var/log/syslog` was removed from the
default `CLEANUP_COMMANDS`. The default cleanup now only removes the staged
artifact (`rm -f -- /tmp/rk.so`, T1070.004) and clears shell history (`history -c`,
history-file removal, `unset HISTFILE`, T1070.003). Rationale (per
`ai/father-refactor-plan.md`): log truncation is a real anti-forensic action, but
it destroys evidence the default pedagogical/forensic run is meant to preserve.
Local-only logs can also be altered by a root-level attacker regardless, while a
missing/truncated log is itself a forensic indicator. A stronger-evasion variant
that truncates these logs was not implemented — it is left as a separate,
explicitly opted-in profile for future work, not folded into the default path.

## Adjacent-hidden-file limitation and validation result

Not modified in this pass; already present in the working tree prior to Phase B
and unchanged by these edits. `_validate` in `runner.py` re-lists `/tmp` after
activation and hard-fails only if `HARVEST_FILE_NAME` is visible; it separately
records `recon_stage_hidden` (with an `error` note when the recon-stage file
also leaked through) as a non-fatal, local demonstration of the upstream
readdir-hook flaw (it skips one matching entry by fetching exactly one more,
so two hidden names returned consecutively can leak the second). This is a
single-view (post-activation, hooked-listing) inference from which name is
absent, not a two-view comparison against an independent bypass listing. The
approved Phase A plan accepted this as a reasonable minimal reading of "locally
demonstrate the limitation" and did not require the two-view comparison to be
implemented in this pass. No upstream code was touched to produce this
demonstration.

## Focused validation result

```
$ .venv/bin/python -m pytest tests/test_scenario_runtime.py -k father -q
.......                                                                  [100%]
7 passed, 23 deselected in 0.33s

$ git diff --check
(no output, exit 0)
```

## Known limitations

- The adjacent-hidden-file demonstration remains single-view (inferred from
  the hooked listing only), not a two-view hooked-vs-bypass comparison.
- No stronger-evasion cleanup profile (log truncation) exists yet; if needed
  later it must be added as an explicit, separate opt-in, not a change to the
  default `CLEANUP_COMMANDS`.
- These changes were validated at the command-string/unit-test level only; no
  VM/integration run was performed as part of Phase B.

## Next step

Final scenario run (stage `02_experiments`): execute the updated
`userland_father_ldpreload` scenario end-to-end against a real target VM to
confirm the recon staging, quieter console output, and evidence-preserving
cleanup behave as intended outside the mocked unit test.
