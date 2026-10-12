# cronwatcher

A cron daemon that only runs job scripts it has verified.

Every script in the job table is hashed (SHA-256) and pinned. Before each run,
cronwatcher reads the script once, checks the hash against the approved
version, and executes **exactly those bytes** from a sealed in-memory copy.
If someone edits a job script, the edited version never runs. The job is
blocked, the diff is logged, an optional alert hook fires, and the job stays
blocked until an admin reviews and approves the change.

Why: a writable cron script that runs as root is a classic way to escalate
privileges or persist on a host. cronwatcher closes that path without making
you give up cron-style scheduling.

## How it works

- **Trust on first sight.** When the daemon starts, every script it has never
  seen before is recorded as trusted (`TRUSTED-NEW`). To review scripts before
  that happens, run `cronwatcher approve` before the first start.
- **Verify on every run.** At each scheduled run the script is read and hashed
  again, then compared with the trust store, which is re-read every time. An
  approval therefore takes effect without a restart.
- **No swap window.** The verified bytes are copied into a sealed `memfd` and
  executed from there. Replacing the file on disk between the check and the
  exec has no effect.
- **Changes need approval.** A changed script is refused (`REFUSED`/`CHANGED`)
  until `cronwatcher approve` shows you the diff against the last approved
  version and you accept it. A script that was missing when the daemon started
  is recorded as *pending*, so whatever appears at that path later must be
  approved too.
- **Tamper hook.** A `@tamper` job, itself verified, runs whenever a job is
  refused. Use it to send alerts.
- **Per-user jobs, pinned by root.** A job can name an account. The root
  daemon verifies the script and then runs it as that user. Users cannot
  change what their own job runs without an admin's approval.

## Requirements

- Linux (uses `memfd_create` with sealing, kernel 3.17 or later)
- Rust 1.88 or later to build
- GNU `diff` (diffutils) to show diffs, and `logger` (util-linux) for the
  approval audit log
- Root, if jobs should run as other users. systemd is optional.

## Install

```sh
cargo build --release
sudo install -o root -g root -m 0755 target/release/cronwatcher /usr/local/bin/
sudo install -o root -g root -m 0644 cronwatcher.tab /etc/cronwatcher.tab
sudo install -o root -g root -m 0644 cronwatcher.service /etc/systemd/system/
```

The `cronwatcher.tab` in this repository is an example: edit
`/etc/cronwatcher.tab` to list your real jobs. Then review the scripts and
start the service:

```sh
sudo cronwatcher status            # what would be trusted
sudo cronwatcher approve --all     # optional: review every script now
sudo systemctl daemon-reload
sudo systemctl enable --now cronwatcher
journalctl -u cronwatcher -f
```

The tab file, the state directory and the trust store must be owned by root
(or by the daemon's own user) and must not be writable by group or others.
Otherwise cronwatcher refuses to use them: whoever can write those files
decides what runs.

Without systemd, run `cronwatcher` in the foreground under any supervisor. It
logs to stderr. It also runs unprivileged with its own files, for example
`cronwatcher -c ~/cronwatcher.tab -s ~/.local/state/cronwatcher`; jobs can
then only run as that same user.

## Usage

```
cronwatcher [-c TAB] [-s STATEDIR]                 run the scheduler
cronwatcher [-c TAB] [-s STATEDIR] status          show trust state of every job script
cronwatcher [-c TAB] [-s STATEDIR] approve [-y] (--all | SCRIPT...)
                                                   review diff, trust current version
defaults: TAB=/etc/cronwatcher.tab STATEDIR=/var/lib/cronwatcher
```

- `status` prints `OK`, `NEW`, `CHANGED` (with diff) or `MISSING` for each
  script. It exits with 1 if any script is not `OK`, so it works as a
  monitoring check.
- `approve` shows the diff against the last approved version (or the whole
  file if none is approved), asks `[y/N]`, and trusts **the bytes it showed
  you**, even if the file changes while you read. `-y` skips the question.
  Scripts must be listed in the tab. Each approval goes to syslog
  (`auth.notice`, tag `cronwatcher`) with the old and new hash and the
  approving uid/`SUDO_USER`.

### Typical workflows

**A script was changed on purpose.** Its next run is refused and logged. Run
`sudo cronwatcher approve /opt/jobs/backup.sh`, check the diff, answer `y`.
The following run goes ahead. No restart is needed.

**Adding a job.** Write the script, add the line to the tab, review it with
`sudo cronwatcher approve /path/to/script`, then
`sudo systemctl restart cronwatcher`. Restarting does not interrupt running
jobs. If you skip the approval, the restart trusts the script on first sight
and logs `TRUSTED-NEW`.

## Job table

```
# m  h  dom mon dow  [user]  command [args...]
*/5  *  *   *   *            /opt/jobs/backup.sh --full
30   2  *   *   1-5          /opt/jobs/report.sh
5    5  *   *   *    alice   /home/alice/jobs/daily.sh
@daily                       /usr/local/bin/rotate-logs
@reboot                      /opt/jobs/warmup.sh
@tamper                      /opt/jobs/alert.sh
```

**Time fields:** minute `0-59`, hour `0-23`, day of month `1-31`,
month `1-12`, day of week `0-7` (0 and 7 are Sunday). Each field accepts `*`,
`N`, `A-B`, comma lists, and steps on `*` or ranges (`*/15`, `1-30/2`).
- Numbers only: month and day names are not supported.
- `N/S` means just `N`.
- As in classic cron, if both day of month and day of week are restricted
  (neither starts with `*`), a job runs when *either* one matches.

**Shortcuts:**

| Shortcut | Meaning |
|---|---|
| `@hourly` | `0 * * * *` |
| `@daily`, `@midnight` | `0 0 * * *` |
| `@weekly` | `0 0 * * 0` |
| `@monthly` | `0 0 1 * *` |
| `@yearly`, `@annually` | `0 0 1 1 *` |
| `@reboot` | once per boot, when the daemon starts. A restart in the same boot skips it (`REBOOT-SKIPPED`), and a `@reboot` job added later first runs at the next boot. |
| `@tamper` | the alert hook (see below). Only the first `@tamper` line is used. |

**User (optional):** a lowercase account name before the command runs the job
as that account. If it is omitted, the job runs as the daemon (root). All
accounts must exist when the daemon starts; they are looked up again at every
run.

**Command:** must be an absolute path. Arguments are split on whitespace.
There is no shell, so quoting, pipes, redirects, variables and `%` do not
work. Put that logic inside the (verified) script.

Lines starting with `#` and blank lines are ignored. The tab is read once at
startup, so restart the daemon after editing it.

## What a job sees

- The script runs from an anonymous memory file, so it needs no `+x` bit, but
  it does need a `#!` line (otherwise: `SPAWN-FAILED … hint="missing #! line?"`).
  Compiled binaries work too.
- **`$0` is `/proc/self/fd/N`, not the script path.** The real path is in
  `$CRONWATCHER_SCRIPT`. Scripts that use `$(dirname "$0")` to find sibling
  files must use `$CRONWATCHER_SCRIPT` instead. Python's `sys.path[0]` does
  not point at the script's directory either.
- stdin is `/dev/null`. stdout and stderr are logged line by line as
  `[script pid] …`.
- User jobs get `HOME`, `USER`, `LOGNAME`, all the account's groups, and the
  home directory as working directory (`/` if it does not exist). Other
  variables are inherited from the daemon.
- There is no timeout and no overlap protection: if a run takes longer than
  its interval, the next one starts anyway, as with cron.

## Tamper hook

A `@tamper` job runs whenever a job is refused, whether its script changed,
is pending, is missing or unreadable, or the trust store can't be loaded. It
gets these variables:

| Variable | Content |
|---|---|
| `CRONWATCHER_TAMPERED` | path of the refused script |
| `CRONWATCHER_REASON` | e.g. `REFUSED trusted=<sha> current=<sha>` |

The hook fires (and the diff is logged) once for each distinct bad version of
a script, not every minute, and resets once the job is allowed to run again. The
hook is verified like any other job and is trusted first at startup. If the
hook itself has been changed, it does not run; that refusal is logged but
not alerted.

```sh
#!/bin/sh
# /opt/jobs/alert.sh
printf '%s\n' "$CRONWATCHER_REASON" |
    mail -s "cronwatcher on $(hostname): refused $CRONWATCHER_TAMPERED" root
```

## Logs

Under systemd each line carries a syslog priority, so
`journalctl -u cronwatcher -p err` shows only integrity problems.

| Event | Priority | Meaning |
|---|---|---|
| `STARTING` / `STARTED` | notice | daemon start, with counts of ok/new/blocked scripts |
| `TRUSTED-NEW` | notice | script seen for the first time and pinned |
| `OK` | info | script matches its approved version (at startup) |
| `CHANGED` | err | script differs from its approved version, blocked (at startup) |
| `PENDING` | err | script exists but was never approved, blocked (at startup) |
| `MISSING` | err | script missing, unreadable, not a regular file, or over 64 MiB |
| `REFUSED` | err | a scheduled run was blocked (hash mismatch, not approved, or trust store unusable) |
| `  \| …` | err | diff of a blocked script (first 50 lines) |
| `REBOOT-SKIPPED` | notice | `@reboot` jobs already ran during this boot |
| `RUN` | info | job started (pid, user, hash) |
| `[script pid] …` | info | job output |
| `DONE` / `FAIL` | info / warning | job finished (exit status or signal, duration) |
| `SPAWN-FAILED`, `WAIT-FAILED` | err | the job could not be started or reaped |
| `FATAL` | err | bad tab, unsafe permissions or unknown user: the daemon exits |
| `APPROVED` | auth.notice | written by `cronwatcher approve` |

## State directory

`/var/lib/cronwatcher` (mode `0700`) contains:

- `trusted`: one `sha256  path` line per script (`sha256sum` format). `-`
  marks a pending path.
- `blobs/<sha256>`: a copy of every approved version, used for diffs. These
  are never pruned.
- `boot_id`: the kernel boot ID of the last `@reboot` run.

## Security model and limits

**Protected:** the bytes of every job script. A script modified after
approval never runs, even if it is swapped between the check and the exec.
Users cannot change what their own jobs run without an admin.

**Not protected:**
- The interpreter named in `#!`, and anything the script sources, imports,
  reads or executes (libraries, config files, other binaries). Keep those
  root-owned, or verify them inside the script.
- The tab, the cronwatcher binary and the state directory. Anyone who can
  write those, or who is root, controls what runs.
- First sight. A script trusted at its first start is only as good as its
  content at that moment, so review new scripts with `approve`.
- Availability. Deleting or replacing a script stops its job (and alerts
  you), but cannot make anything else run.

**Scheduling behaviour:**
- Minutes missed while the daemon is down, the machine is suspended, or the
  clock jumps forward are not caught up.
- If the clock steps back, the replayed minutes run again.
- Schedules use local time. When the clock falls back at the end of daylight
  saving time, jobs in the repeated hour run twice; when it springs forward,
  jobs in the skipped hour don't run.
- Changes to the time zone or the tab need a restart.
- With the sysctl `vm.memfd_noexec=2`, nothing can be executed (`SPAWN-FAILED`).

## Development

```sh
cargo test
cargo clippy --all-targets
```

Tests use temporary directories and need no setup. When run as root,
`user_job` also exercises the real uid/gid switch, running a job as `nobody`.

## License

MIT, see [LICENSE](LICENSE).
