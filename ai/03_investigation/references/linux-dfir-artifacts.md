# Linux post-mortem DFIR artifact sources (reusable reference)

Reusable, scenario-independent reference for Linux post-mortem artifact
sources. **No run-specific findings belong here** — see per-run reports under
`shared/investigations/<RUN_ID>/`.

Phase legend: **disk** = offline filesystem/image examination (TSK/ext4);
**timeline** = event-ordering / log parsing (Plaso); **memory** = volatile
capture (Volatility). "Tool / parser" names the standard extractor; verify
exact flags against the installed tool version.

| Source path / artifact | Forensic value | Tool / parser | Distro / format caveat | Phase |
|---|---|---|---|---|
| `/etc/ld.so.preload` | Userland `LD_PRELOAD` persistence: lists shared objects force-loaded into every dynamically-linked process | `icat`/`ifind` (offline); plain read | Present on glibc systems; musl (Alpine) uses `/etc/ld-musl-*.path` and no `ld.so.preload` | disk |
| `/lib`, `/usr/lib` shared objects | Implant identity by hash; usr-merge means `/lib` → `/usr/lib` symlink | `ifind`/`icat` + sha256 | usr-merge layout varies by distro/release | disk |
| `/tmp`, `/var/tmp` files | Staging, dropped payloads, recon output | `ifind -n`/`fls`/`istat` | `/tmp` may be tmpfs (RAM-only, absent from disk image) | disk |
| Deleted files (directory entries) | Prior existence of removed objects | `fls` (allocated+deleted; `-d` deleted-only), `ils -r` (orphaned inodes) | ext4 zeroes block pointers on delete → content often unrecoverable from inode alone | disk |
| Deleted-file content recovery | Reconstruct removed file bytes | `blkls`+carving, `tsk_recover`, `ext4magic`/`extundelete` (journal-aware) | ext4magic/extundelete need a **raw** (non-E01) unmounted image; no guarantee; reused blocks corrupt output; no xattr/hardlink recovery | disk |
| ext4 journal (jbd2, inode 8) | Directory-entry/metadata corroboration of recent operations; commits on ~5 s timer independent of `sync` | `jls`, `jcat`, ext4magic (journal history) | `data=ordered` (default) journals metadata, **not** file data; circular & small, recycles in minutes; data mode not shown by `fsstat` (needs `dumpe2fs`/`tune2fs`) | disk |
| File MAC times (mtime/atime/ctime/crtime) | Activity timing; timestomp detection (`touch -r` cannot reset `ctime`) | `istat`, `mactime`, Plaso `filestat` | TSK renders in analysis-host TZ, not guest TZ — normalize before comparing | disk / timeline |
| `/var/log/auth.log` | ssh/sudo/su/PAM authentication events | Plaso `syslog`/`syslog_traditional` | Debian/Ubuntu path; RHEL/CentOS use `/var/log/secure`; journald-only hosts may lack it | timeline |
| `/var/log/syslog` | General system/service events | Plaso `syslog` | Debian/Ubuntu; RHEL uses `/var/log/messages` | timeline |
| systemd journal (`/var/log/journal/`) | Structured system/service/auth events; survives when text logs are wiped | Plaso `systemd_journal`, `journalctl` | Binary format; may be volatile (`/run/log/journal`) if persistence off | timeline |
| `~/.bash_history` (and other shell history) | User command history | Plaso `bash_history`; memory `linux.bash` | No timestamps unless `HISTTIMEFORMAT` set; first artifact wiped by attackers; per-shell (zsh/fish differ) | timeline / memory |
| `/var/log/wtmp` | Successful login/logout sessions (user, tty, source IP, duration) | `last` | Binary; rotates; absent/empty when no genuine login occurred | timeline |
| `/var/log/btmp` | Failed login attempts | `lastb` (root) | Binary; often disabled/empty | timeline |
| `/var/log/lastlog` | Last login per user | `lastlog` | Binary; sparse file | timeline |
| cron (`/etc/cron.d`, `/etc/cron.*`, `/var/spool/cron/crontabs`) | Scheduled-task persistence | file read; Plaso `filestat` | Paths differ (Debian `crontabs` vs RHEL `cron`); user vs system crontabs | disk / timeline |
| systemd units/timers (`/etc/systemd/system`, `/lib/systemd/system`, `~/.config/systemd/user`) | Service/timer persistence | file read | System vs user units; enablement via symlink in `*.wants/` | disk / timeline |
| `~/.ssh/authorized_keys` | SSH key persistence / backdoor access | file read; `istat` | Per-user home; also `AuthorizedKeysFile` overrides in `sshd_config` | disk |
| Package-manager logs (`/var/log/dpkg.log`, `/var/log/apt/`, `/var/log/yum.log`, `dnf`) | Installed/removed packages; tainted-install evidence | file read | dpkg/apt (Debian) vs yum/dnf/rpm (RHEL) vs apk (Alpine) | timeline |
| Process/execution evidence (from RAM) | Live process tree, maps, sockets, argv, in-memory history | Volatility 3 (`linux.pslist`, `linux.pstree`, `linux.psaux`, `linux.proc.Maps`, `linux.sockstat`, `linux.bash`) | Needs matching ISF symbol table for the exact kernel; a failed plugin = unknown, not absent | memory |

## Cross-distro / format caveats (summary)

- **Log paths differ:** `auth.log`/`syslog` (Debian/Ubuntu) vs
  `secure`/`messages` (RHEL/CentOS); Alpine/musl and journald-only hosts
  differ again.
- **Logging stack matters:** rsyslog text logs vs systemd-journald binary
  journal change which Plaso parsers apply; treat the parser list as a
  per-distro variable.
- **Binary artifacts** (wtmp/btmp/lastlog, journald) need format-aware tools,
  not `strings`/grep.
- **Timezone:** TSK/istat renders timestamps in the analysis host's TZ;
  acquisition manifests may record guest TZ (often UTC). Normalize before any
  cross-run comparison.
- **tmpfs:** `/tmp` may be RAM-backed and therefore absent from a disk image —
  its artifacts then live only in the memory capture.
- **ext4 specifics:** journal is metadata-only in default `data=ordered`;
  journal-aware recovery tools (ext4magic/extundelete) require a raw,
  unmounted image and offer no recovery guarantee.

## Sources

- [Sleuth Kit — TSK_Tool_Overview wiki](https://github.com/sleuthkit/sleuthkit/wiki/TSK_Tool_Overview)
- [ext4magic — Ubuntu manpage](https://manpages.ubuntu.com/manpages/bionic/man8/ext4magic.8.html)
- [extundelete — project site](https://extundelete.sourceforge.net/)
- [Ext4 Log Tracker (ScienceDirect)](https://www.sciencedirect.com/science/article/abs/pii/S2666281726001022)
- [Magnet Forensics — Linux forensics artifacts](https://www.magnetforensics.com/blog/linux-forensics-artifacts-every-investigator-should-know/)
