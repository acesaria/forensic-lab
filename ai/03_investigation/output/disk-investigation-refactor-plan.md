# Father disk investigation — bounded refactor plan (Sections 8–12, +9 sanity)

Planning-only handoff. No notebook, `investigation_utils.py`, `runner.py`,
report, metric, thesis, or root-README changes are made by this document.
Scope: `investigations/father/disk_investigation.ipynb` Sections 8, 10, 11,
12, plus a sanity check of Section 9. Reference run: `father-u22-20260819-03`.

## 1. Verified repository facts

Confirmed only from the named files.

**Notebook structure & state**

- `investigations/father/disk_investigation.ipynb` is the single canonical
  disk workflow: 15 sections, TSK/ext4 tools invoked via `run_command`
  (list-args `subprocess`, never `shell=True`), one `findings` dict, metrics
  from `findings`, report from `findings`.
- Current default run is `RUN_ID = father-u22-20260819-03` (cell
  `b43b4782380bcf2f`), overridable by env var.
- The on-disk `report/disk.md` and `findings.json` for
  `father-u22-20260819-03` were generated **before** the latest manual edits
  (they still contain a fully-populated `recovery_precondition` /
  `recovery_precondition_reason`, evidence path `14-recovery-precondition.json`,
  and journal corroboration = confirmed).

**Confirmed dangling references (the notebook as currently edited will not
run top-to-bottom):**

1. Cell 2 imports `check_command_log_precondition` from
   `investigation_utils` — this function **no longer exists** in
   `investigation_utils.py` (defined functions: `resolve_run_paths`,
   `ensure_output_dirs`, `save_raw`, `log_command`, `run_command`,
   `write_json`, `safe_sha256`, `parse_label_lines`, `parse_mmls_root_offset`,
   `parse_ewfverify`, `parse_fsstat`, `parse_istat`, `parse_istat_timestamp`,
   `detect_timestomp`, `parse_fls_regular_files`, `_render_kv_section`,
   `write_report`). → **ImportError on next run.**
2. Section 12 cell (`7cd9cb9f`) reads `precondition["status"]` and
   `precondition["reason"]`, but `precondition` is **never defined** in any
   current cell (Section 9 was simplified and no longer builds it). →
   **NameError on next run.**
3. Section 9 cell (`a1004d31`) `fls` args are `[..., "-r", "d", "-p", ...]` —
   `"-r","d"` passes `-r` plus a stray positional `d`, not the intended single
   option `-rd`.
4. The Section 15 findings-table and the report reference
   `derived/disk/raw/14-recovery-precondition.json` as an evidence path, but
   Section 9 no longer writes that file. → **dangling evidence path.**
5. Metrics (Section 13) `deleted_file_precondition_status` reads
   `findings["deleted_rk_so"]["recovery_precondition"]`, downstream of the
   removed precondition logic.

**Settled Section-9 intent (do not reverse):** the removed
`command_log`/"explicit sync before rm" precondition check must **not** be
restored; a short comment about the absence of an explicit `sync` is
sufficient.

**Doc drift (minor, outside write scope):** `README.md` mentions
`save_raw_output`; the actual helper is `save_raw`.

**Scenario ground truth (from `runner.py` + scenario README):**

- Deleted: `/tmp/rk.so` (`rm -f -- /tmp/rk.so`, T1070.004), and
  `.bash_history` (`history -c` + `rm -f -- "$HISTFILE"`, T1070.003).
- **Not** deleted (surviving compromise): `/tmp/__malicious_recon`,
  `/tmp/__malicious_harvest`, `/etc/ld.so.preload`, `/lib/selinux.so.3`.
- `auth.log` and `syslog` are **intentionally left untouched** (runner lines
  108–111; scenario README lines 53–60) — log truncation is deliberately
  excluded from the default profile.
- Persistence mechanism = `/etc/ld.so.preload` only (no cron, no systemd
  unit, no authorized_keys, no apt/dpkg install).
- Timestomp = `touch -r /lib/x86_64-linux-gnu/libc.so.6 /lib/selinux.so.3`
  (T1070.006); `ctime` cannot be reset this way and records the true install
  time.
- No genuine SSH login occurs: Father's `accept()` hook intercepts the
  connection from source port 54321 before SSH auth — so wtmp/btmp/lastlog
  carry no scenario-specific login.

**Key run facts for `father-u22-20260819-03`:**

- ext4, block size 4096, journal inode 8, journal size 64 MiB, root offset
  sector 227328.
- Installed `/usr/lib/selinux.so.3` sha256 **matches the manifest input**
  `rk.so` byte-for-byte → **the deleted `/tmp/rk.so`'s content is
  byte-identical to the still-allocated installed library.** (This materially
  changes the stakes of "content recovery" — see §4.)
- Timestomp suspected (mtime 2026-01-30 much earlier than crtime 2026-08-19).
- `/tmp/rk.so`: no live or deleted directory entry at acquisition.
- Journal marker search: `rk.so` (+ other `/tmp` names) found as
  directory-entry strings in 13 journal blocks; **zero ELF headers** in the
  journal.
- `extundelete` 0.2.4 and `ext4magic` 0.3.2 present but not invoked.
- **Timezone gotcha:** manifest `platform.timezone = Etc/UTC`, scenario
  window in `Z`, but TSK `istat` renders timestamps in the analysis host TZ
  (`CEST`/`CET`). Cross-run/cross-timezone comparison must normalize.

## 2. External methodology findings

Source categories: **[TSK-Official]** Sleuth Kit wiki/manpages; **[ext4-doc]**
ext4/journal documentation & peer-reviewed ext4-forensics papers;
**[tool-manpage]** ext4magic/extundelete manpages & project sites;
**[DFIR-ref]** established DFIR reference material. Rule applied: no single
blog treated as authoritative; every command sequence carries its limitation
and, where the flag spelling matters, a "verify locally" flag.

### A. TSK layered model — [TSK-Official]

- *"What names (allocated + deleted) exist in this directory?"* →
  `fls -o <off> [-r] <img> <inode>`. `fls` lists **both allocated and
  deleted** names by default; `-d` = deleted only, `-r` = recurse. **Can**
  establish presence/absence of a (possibly deleted) directory entry.
  **Cannot** establish content or that a deleted inode still points to
  recoverable data.
- *"Which inode owns this name/data-unit?"* → `ifind -n <path>` (name→inode)
  or `ifind -d <block>` (data-unit→inode). **Can** map a recovered block back
  to an owning inode. **Cannot** recover overwritten mappings.
- *"What deleted/orphaned inodes exist?"* → `ils -r` (removed inodes, link
  count 0). **Can** surface an orphaned inode that may still reference
  `rk.so`'s old blocks. **Cannot** guarantee the blocks are intact.
- *"Inode metadata / content"* → `istat` / `icat`.
- *"Extract unallocated space for carving"* → `blkls` (unallocated by
  default; `-e` = every block). *"Is this block allocated?"* → `blkstat`.
  *"Dump one block"* → `blkcat`.
- *"Recover all/unallocated files to a directory"* → `tsk_recover` (default:
  unallocated; `-e` = every file).
- **Crucial for this scenario:** TSK reads the **E01 directly via libewf** —
  `fls/ils/icat/blkls/blkcat/tsk_recover` all work against the `.E01` with
  `-o <offset>`, **no raw conversion required.** This is the KISS lever for
  §4 Option A.
- *Flag-spelling caveat:* exact combined-flag behavior (`-rd`, `blkls -e`,
  `tsk_recover -e`) should be **verified against the installed TSK version**
  before relying on it. Appropriate for this scenario: yes (E01-native,
  standard).

### B. ext4 journal (jbd2) recovery scope — [ext4-doc]

- Tools: `jls` (enumerate journal blocks), `jcat <journal_inode> <block>`
  (dump one journal block).
- **Can** establish: directory-entry / inode-metadata corroboration that a
  name existed; jbd2 commits on its own ~5 s timer independent of application
  `sync`.
- **Cannot** establish (in default `data=ordered`): recovery of file **data
  content** — ordered mode journals metadata only, not data blocks.
  `jls`/`jcat` interpret file-system-level journal structures, not arbitrary
  file data.
- Limitations: journal is circular and small (64 MiB here); recycles in
  minutes on a busy host. Data mode is **not reported by `fsstat`** —
  confirming `data=ordered` vs `journal`/`writeback` needs
  `dumpe2fs`/`tune2fs` against a raw device/image. Appropriate: yes (already
  the core of Section 10).

### C. ext4magic / extundelete — [tool-manpage]

- How they work: both search the journal for an **older copy of the inode**
  (whose extent map may still point to intact data blocks), then copy those
  blocks out. `ext4magic` adds carving, multiple versions, journal
  directory-history.
- Prerequisites/limits:
  - **Input:** `ext4magic` accepts a block device **or an uncompressed raw
    image** — **not** an `.E01`. `extundelete` runs on an unmounted partition
    / raw device / `dd` backup. → **Both require converting the E01 to raw**
    (`ewfexport`/`qemu-img`), a heavyweight step, and must run against a
    **copy**, never acquired evidence.
  - Must be unmounted (or read-only). Direct journal reads on a live rw
    filesystem produce bad-block reads.
  - **No guarantee** any given file is recoverable; reused data blocks yield
    corrupt output ("you should check such reports"); hardlinks/symlinks and
    extended attributes are **not** recovered.
- Appropriate here: **low marginal value** — journal shows no `rk.so`
  content, its inode number is not established, and its bytes already exist in
  the allocated installed library. High overclaim risk from a blind carve.

### D. Standard Linux post-mortem artifacts — [DFIR-ref]

- `/var/log/auth.log` (Debian/Ubuntu; `/var/log/secure` on RHEL):
  ssh/sudo/su/PAM — **timeline phase** parser territory.
- `/var/log/syslog`, systemd-journald (`/var/log/journal/`): system/service
  events — timeline phase.
- `wtmp`/`btmp`/`lastlog` (binary; `last`/`lastb`/`lastlog`):
  successful/failed logins, last-login — **not** in the current timeline
  parser set; low Father relevance (no genuine login).
- `~/.bash_history`: shell commands — first thing an attacker wipes (wiped
  here); memory (`linux.bash`) and timeline carry it.
- cron (`/etc/cron.d`, `/var/spool/cron/crontabs`), systemd units/timers,
  `~/.ssh/authorized_keys`, package-manager logs (`/var/log/dpkg.log`, apt):
  **persistence locations Father does not use** — negative controls only.
- `/etc/ld.so.preload`: the Father persistence mechanism — **already the disk
  phase's core finding.**
- Cross-distro caveat: log paths/formats differ (`auth.log` vs `secure`;
  rsyslog vs journald-only); parser list is Ubuntu/systemd-specific and must
  be treated as a per-distro variable.

## 3. Section-by-section plan

### Section 8 — `/tmp` artifact investigation

- **Current purpose:** resolve `/tmp` inode (`ifind -n /tmp`), list it
  (`fls -r -p … tmp_inode`), `istat` each regular file, compare against
  `EXPECTED_TMP_ARTIFACTS`.
- **Current weakness:** the long markdown caveat describes a *whole-disk*
  `fls -r -p` crash/non-descent that the current code **no longer performs** —
  it over-explains a path not taken. `parse_fls_regular_files` silently drops
  deleted entries (fine, but undocumented at the call site).
- **Proposed minimal change:** trim the caveat to one sentence ("`/tmp` is
  examined by resolving its own inode and listing it directly — the standard
  TSK approach for a known directory"); keep the code. Keep existing technique
  comments (`# Path Resolution`, `# File Listing`, `# Metadata Extraction`).
- **Retain:** `ifind -n /tmp`, `fls -o <off> -r -p <img> <tmp_inode>`,
  per-file `istat`.
- **Add only if justified (proposal):** nothing. Do **not** add a whole-disk
  walk.
- **Expected outputs:** unchanged — `10-ifind-tmp.txt`, `11-fls-tmp.txt`,
  `12-istat-tmp-<inode>.txt`; both `__malicious_*` present.
- **Limitations:** `parse_fls_regular_files` excludes deleted entries by
  design; descent bounded to `/tmp`.
- **Implementation risk:** very low (prose-only trim).

### Section 9 — Deleted `/tmp/rk.so` investigation (sanity check)

- **Current purpose:** show `/tmp/rk.so` has no live/deleted directory entry;
  note the absence of an explicit `sync` before `rm`.
- **Current weakness:** (a) the `fls` `-r","d"` argument bug (§1.3); (b) it
  depends on the removed `precondition` concept elsewhere; (c) the print label
  says "deleted/live directory entries (fls -rd)" but `-d` restricts to
  **deleted-only** — a plain `fls -r` already lists both, so label and flag
  disagree.
- **Proposed minimal change:**
  - Fix the argument to the intended single option — **`-rd`** (or
    `-r","-d`); **verify against installed `fls`** that `-d` = deleted-only
    and confirm the desired semantics.
  - Decide intended listing (Open decision §8.5): "any live-or-deleted `rk.so`
    entry?" → plain `fls -r`; "deleted only" → `fls -rd` and fix the print
    label to say "deleted".
  - Keep the settled short comment about the lack of an explicit `sync`; do
    **not** reintroduce a precondition dict.
- **Retain:** the `tmp_inode`-scoped `fls`, the `rk.so` presence regex.
- **Add only if justified (proposal):** nothing here (unallocated analysis is
  its own step — §7.4 / §4-A).
- **Expected outputs:** `13-fls-deleted-tmp.txt` (empty),
  `rk_so_deleted_dir_entry_present = False`.
- **Limitations:** absence of a directory entry != absence of recoverable
  content; deleted-inode reuse is common.
- **Implementation risk:** low; only behavioral change is the corrected flag.

### Section 10 — ext4 journal investigation

- **Current purpose:** enumerate journal (`jls`), read journal inode content
  once (`icat`), string-search markers, ELF-header check, per-hit `jcat`,
  cross-reference `jls` block status.
- **Current weakness:** methodologically strong already; the one soft spot is
  that it reads the raw journal-inode bytes in Python and byte-searches them,
  at the edge of the "invoke standard tools, don't reimplement" convention. It
  is defensible (one bounded `icat`, `jcat` per hit), but the report should
  frame the Python search as *string extraction over `icat` output*, not a
  bespoke parser.
- **Proposed minimal change:** keep the mechanism; name the technique
  (`# Keyword Search over journal-inode content`) and keep the existing
  `data=ordered`/ELF caveat verbatim. Optionally record per-hit `jls`/`blkstat`
  allocation status already captured — no new tool.
- **Retain:** `jls`, `istat` (journal size), one bounded `icat`, marker
  search, ELF check, per-block `jcat`, `jls` status cross-ref.
- **Add only if justified (proposal):** no `dumpe2fs` here (needs raw image);
  keep the data-mode caveat as-is.
- **Expected outputs:** unchanged (`15-jls.txt`, `16-istat-journal.txt`,
  `17-jcat-block-*.txt`); `rk.so` corroborated, 0 ELF headers.
- **Limitations:** journal circular/small; corroboration is metadata not
  content; data mode not independently confirmed (kept explicit).
- **Implementation risk:** low (mostly narrative).

### Section 11 — Optional recovery-tool investigation

- **Current purpose:** confirm `extundelete`/`ext4magic` availability; explain
  (honestly) why they were not run.
- **Current weakness:** the "not run" reasoning is sound but reads as a
  permanent stop. It omits the strongest honest point: **`rk.so`'s content is
  byte-identical to the still-allocated installed library** (hash match), so
  "content recovery" is largely moot — and it omits the cheaper, in-container
  TSK unallocated-layer step that *can* run against the E01 (§4-A) before
  reaching for raw-image tools.
- **Proposed minimal change:** keep availability check + reasoned
  non-invocation, but (a) add the "deleted object ≡ installed library bytes"
  observation, and (b) reframe extundelete/ext4magic as a **labeled optional
  methodology demonstration on a raw copy**, explicitly downstream of the
  bounded TSK unallocated step, not the primary recovery path.
- **Retain:** `extundelete -v`, `ext4magic -V`, `recovery_tooling`
  status/reason.
- **Add only if justified (proposal, only if §8 approves):** a clearly-labeled
  "not performed in this pass" pointer to the raw-conversion + tool procedure —
  as documentation, not execution.
- **Expected outputs:** `18-extundelete-version.txt`, `18-ext4magic-version.txt`;
  `recovery_status = available_but_not_run` with the enriched reason.
- **Limitations:** tools need raw (non-E01) input, unmounted, no guarantee,
  corrupt-on-reuse, no xattr/hardlink recovery.
- **Implementation risk:** low (narrative + one new observation already
  provable from the existing hash finding).

### Section 12 — Findings table / `findings` dict

- **Current purpose:** build the one canonical `findings` dict, then (Section
  15) append the findings table and write once.
- **Current weakness:** reads the now-undefined `precondition["status"]` /
  `["reason"]` (§1.2), and the table cites `14-recovery-precondition.json`,
  no longer produced (§1.4).
- **Proposed minimal change:**
  - Remove both `precondition[...]` reads. Replace `deleted_rk_so` fields with
    values that don't depend on a precondition gate:
    `directory_entry_present_live_or_deleted`, `directory_entry_status`, and a
    single `content_recovery_status` derived from what actually happened
    (journal shows no content; TSK unallocated step result once added; tools
    not run) with a short static reason string mentioning the absence of an
    explicit `sync` **as narrative, not a computed precondition**.
  - Fix the findings-table evidence path for the "content recovery" row to a
    file that exists (e.g. the journal / unallocated raw output), removing the
    `14-recovery-precondition.json` reference.
  - Keep the `confirmed/observed/not_observed/not_tested/inconclusive` status
    vocabulary; drop `precondition_not_met` as a status.
- **Retain:** the single-write discipline (findings.json written once in
  Section 15), the status vocabulary, the limitations list (edit the sync
  bullet to match the new narrative).
- **Add only if justified (proposal):** if §4-A adopted, one
  `unallocated_analysis` sub-block in `findings`.
- **Expected outputs:** a `findings.json` / `report/disk.md` that regenerate
  cleanly with no dangling keys or missing evidence files.
- **Limitations:** unchanged set, minus the precondition bullet, plus (if
  added) an unallocated-carve negative-result bullet.
- **Implementation risk:** medium — the change most likely to ripple into
  Section 13 metrics and the report; sequence after Sections 8–11 settle.

## 4. Recovery decision (single deleted target `/tmp/rk.so`)

Overriding fact: **the deleted `/tmp/rk.so` is byte-for-byte identical to the
still-allocated `/usr/lib/selinux.so.3`** (hash match, already in evidence).
Its content is therefore *not lost*; "recovery" here is about demonstrating
deleted-inode/unallocated reconstruction as **method**, not retrieving
otherwise-unavailable bytes.

| Option | Forensic value | Implementation cost | Overclaim risk | Thesis value | Recommendation |
|---|---|---|---|---|---|
| **A. Keep journal/TSK + bounded unallocated analysis** (`ils -r`, `ifind -d`, `blkls`/`blkcat`, `blkstat`, optional `tsk_recover` — all against the E01, no conversion) | High: turns "not attempted" into a real bounded **negative** at the data-unit layer using standard tools | **Low** — in-container, minutes, no raw copy | Low if framed as a bounded negative | High — demonstrates the full TSK layer stack and rigorous negatives | **Adopt now.** |
| **B. One read-only/copy `ext4magic` attempt** | Low marginal — journal already shows no content; inode unknown | **High** — `ewfexport` ~10 GB raw copy, unmount discipline | Medium — blind carve can surface a false "recovered" object | Medium — shows tool breadth | **Optional, clearly labeled; only after A; on a copy.** |
| **C. `extundelete` as comparison** | Low — same mechanism/limits as B, restore paths relative to fs root | **High** — same raw-copy requirement | Medium | Low–Medium — a second data point next to B | **Skip, or fold into B as a one-line comparison only.** |
| **D. Modify scenario for additional recoverable deleted artifacts** (explicit `sync` before `rm`, or delete a *unique* file whose content isn't elsewhere) | High — only path to a genuine *positive* recovery demonstration | **High** — changes ground truth, full re-run | Low (honest positive) but changes the case | High **if** a positive recovery chapter is wanted | **Human decision only. Do NOT auto-change `runner.py`.** |

**Recommendation:** Adopt **A** in the disk notebook now (cheap, defensible,
E01-native, converts the recovery gap into a documented bounded negative).
Treat **B/C** as an explicitly-labeled optional methodology appendix on a
copy, never the primary claim. Defer **D** to the human — and note it may be
unnecessary given the hash-identity observation.

## 5. Log and artifact scope

| Artifact | Classification | Reason |
|---|---|---|
| `/etc/ld.so.preload` | **Required (disk)** | Father persistence mechanism; already Section 6. |
| `__malicious_recon` / `__malicious_harvest` | **Required (disk)** | Surviving compromise; already Section 8. |
| `.bash_history` | **Optional (disk) / already covered** | Deleted by cleanup; primary coverage is memory (`linux.bash`) + timeline (bash_history parser). Could serve as a *second deleted-recovery target* if §4-A wants a non-identical demo (Open decision §8.3). |
| `auth.log` | **Already covered (timeline)** | Left untouched by design; timeline syslog/auth parser owns it. |
| `syslog` | **Already covered (timeline)** | Same. |
| systemd journal | **Already covered (timeline)** | `systemd_journal` parser. |
| `wtmp` | **Defer** | Not in timeline parser set; no genuine login in Father → no scenario-specific record. |
| `btmp` | **Defer** | Same (no failed-login activity). |
| `lastlog` | **Defer** | Same. |
| cron / crontab | **Defer (negative control)** | Father uses no cron persistence. |
| systemd units/timers | **Defer (negative control)** | Not used. |
| `authorized_keys` | **Defer (negative control)** | Not used. |
| package-manager logs | **Defer (negative control)** | Implant installed via `install`, not apt/dpkg. |
| temporary malicious files | **Required (disk)** | = the `__malicious_*` pair above. |

Principle honored: Father's evidence surface is narrow and already covered;
nothing added purely for the appearance of comprehensiveness.

## 6. Metrics proposal (candidates — not final)

**Framing (the denominator problem).** Keep four notions distinct; never
collapse into one "completeness %":

- **Scenario ground truth** — what the runner deterministically produced (2
  surviving `/tmp` files; 1 deleted `rk.so`; 1 preload edit; 1 timestomp; 1
  deleted `.bash_history`).
- **Observed forensic artifacts** — what TSK actually enumerates.
- **Recovery success** — content actually reconstructed for a *deleted*
  target.
- **Tool coverage** — which forensic layers/techniques were exercised.

Only ground-truth-anchored ratios have a meaningful denominator; "observed"
counts are descriptive, not fractions of an unknown universe.

| # | Metric | Numerator / observation | Denominator | Source | Across runs? | Across distros? | Unknown/N-A | Ground-truth dependent? |
|---|---|---|---|---|---|---|---|---|
| 1 | `acquisition_integrity_verified` | ewfverify SUCCESS **and** hash == sidecar | — (bool) | `01-ewfverify.txt` + acquisition.json | Yes | Yes | N-A if sidecar missing | No |
| 2 | `preload_persistence_present` | `/etc/ld.so.preload` resolves + names a lib | — (bool) | Section 6 | Yes | Yes (standard path) | false if absent | Partly |
| 3 | `installed_library_identity_match` | icat sha256 == manifest input sha256 | — (bool) | Section 7 | Yes | Only same-implant scenarios | N-A if lib absent | Yes (manifest) |
| 4 | `timestomp_mtime_minus_crtime_seconds` (+ `suspected` bool) | signed seconds mtime−crtime | — (numeric; distribution) | Section 7 istat | Yes | Yes | None if either ts invalid | Partly |
| 5 | `expected_tmp_artifacts_recovered_ratio` | # expected staged files observed offline | **scenario expected count (2)** | Section 8 | Yes | Same-scenario only | 0/2 if none | **Yes** |
| 6 | `journal_directory_entry_corroboration` (bool) + `journal_marker_block_count` | `rk.so` in journal / #unique marker blocks | — (bool + count) | Section 10 | bool: yes; count: as distribution w/ caveats | ext4 only | not_observed if none | No (marker set scenario-defined) |
| 7 | `deleted_target_content_recovered` | content reconstructed by any method | — (bool; **recovery-success**) | Sections 9–11 (+A) | Yes | Yes | false/not_observed honest value here | Yes |
| 8 | `forensic_layer_coverage` | # TSK layers exercised (filename/metadata/data-unit/journal/recovery) | fixed layer set | notebook execution | Yes | Yes | — | No (**tool-coverage, not success**) |

Metrics 5, 7, 8 deliberately separate ground-truth ratio, recovery success,
and tool coverage. Cross-run comparability is real for 1–4, 7, 8; metric 6's
count is journal-churn- and time-sensitive (comparable mainly as a
distribution). Timezone normalization (istat host-TZ vs manifest UTC) is a
prerequisite for comparing metric 4 across runs. **These are candidates;
finalize only after the procedure (Sections 8–12) is reviewed.**

## 7. Implementation sequence (small, separately reviewable)

1. **Repair dangling references + arg bug** (Sections 2/9/12): drop the
   `check_command_log_precondition` import; remove `precondition[...]` reads;
   fix `fls` to `-rd` (verified) or `-r`; fix/remove the
   `14-recovery-precondition.json` evidence path. Re-run to green.
   *(No methodology change.)*
2. **Decide Section 8 parser/caveat:** trim the stale whole-disk caveat; keep
   the direct-inode listing. *(Prose + confirm.)*
3. **Simplify/clarify Section 9 + Section 10 narrative:** settle deleted-entry
   listing semantics; keep the journal mechanism, name the technique, keep the
   data-mode caveat.
4. **Decide & plan unallocated recovery (§4-A):** add bounded E01-native
   `ils -r` / `ifind -d` / `blkls`+`blkstat` (optional `tsk_recover`) as a
   documented negative; leave ext4magic/extundelete as labeled
   optional-on-copy.
5. **Redesign findings/metrics** (Sections 12–13) **only after 1–4 settle:**
   apply the §6 candidate set; remove `precondition` status; add
   `unallocated_analysis` block if step 4 adopted.
6. **Fresh-kernel validation:**
   `RUN_ID=father-u22-20260819-03 jupyter nbconvert --to notebook --execute …`;
   scan for `output_type == error`; confirm no `shared/experiments/` writes
   and no repo-root artifacts; confirm findings.json/metrics.json/report
   mutually consistent.

## 8. Open decisions for the human

1. **Recovery scope:** adopt **Option A only** in the disk notebook
   (recommended), or also produce the **B/C** raw-copy tool demonstration as a
   labeled optional appendix?
2. **Scenario change (Option D):** given `rk.so` ≡ installed library bytes, do
   you still want a *positive* recovery demo that would require changing
   `runner.py` (explicit `sync`, or a unique deleted file) and a full re-run?
   (Default: **no**, do not touch the scenario.)
3. **`.bash_history`:** add it as a second deleted-recovery target in the disk
   phase, or leave it entirely to memory/timeline? (Default: leave to
   memory/timeline.)
4. **Metrics set:** approve the 8 candidates? Is metric 5's denominator the
   **2** surviving staged files only, or **3** including the deleted `rk.so`?
5. **Section 9 listing semantics:** intended output = "any live-or-deleted
   `rk.so` entry" (→ plain `fls -r`) or "deleted entries only" (→ `fls -rd`,
   and fix the print label)?
6. **Negative controls:** should wtmp/btmp/cron/authorized_keys/pkg-logs be
   explicitly documented as *checked-and-absent* negative controls, or simply
   deferred? (Default: deferred, not enumerated.)

## Source links used

Categories per §2.

- [Sleuth Kit — TSK_Tool_Overview wiki](https://github.com/sleuthkit/sleuthkit/wiki/TSK_Tool_Overview) [TSK-Official]
- [Sleuth Kit — The_Sleuth_Kit_commands wiki](https://github.com/sleuthkit/sleuthkit/wiki/The_Sleuth_Kit_commands) [TSK-Official]
- [ext4magic — Ubuntu manpage](https://manpages.ubuntu.com/manpages/bionic/man8/ext4magic.8.html) [tool-manpage]
- [ext4magic — project site](https://ext4magic.sourceforge.net/ext4magic_en.html) [tool-manpage]
- [extundelete — project site](https://extundelete.sourceforge.net/) [tool-manpage]
- [Ext4 Log Tracker (ScienceDirect)](https://www.sciencedirect.com/science/article/abs/pii/S2666281726001022) [ext4-doc]
- [Ext4/XFS TSK forensic framework (PDF)](https://pdfs.semanticscholar.org/5f4f/2a0469f341bb46bddfa11308c69157295835.pdf) [ext4-doc]
- [Reconstructing File Activity from Ext4/XFS Journals — CODE BLUE (PDF)](https://archive.codeblue.jp/2025/files/cb25_Uncovering_the_Past_Reconstructing_File_Activity_from_Ext4_and_XFS_Journals-Minoru_Kobayashi.pdf) [ext4-doc]
- [Magnet Forensics — Linux forensics artifacts](https://www.magnetforensics.com/blog/linux-forensics-artifacts-every-investigator-should-know/) [DFIR-ref]

## Uncertain / verify-locally items

- Exact combined-flag spellings (`fls -rd`, `blkls -e`, `tsk_recover -e`,
  `ils -r`, `ifind -d`) — verify against the installed TSK version before
  relying on them.
- Section 9 deleted-listing semantics (Open decision §8.5) — unresolved.
- Whether ext4magic/extundelete are worth running at all (Open decisions
  §8.1/§8.2) — unresolved; recommendation is to prefer Option A.
