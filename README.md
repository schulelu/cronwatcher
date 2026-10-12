# cronwatcher

A cron daemon that only runs job scripts it has verified.

Every script in the job table is hashed (SHA-256) and pinned. Before each run,
cronwatcher reads the script once, checks the hash against the approved
version, and executes **exactly those bytes** from a sealed in-memory copy.
If someone edits a job script, the edited version never runs. The job is
blocked, the diff is logged, an optional alert hook fires or a mail goes out,
and the job stays blocked until the change is reviewed and approved.

Why: a writable cron script that runs as root is a classic way to escalate
privileges or persist on a host. cronwatcher closes that path without making
you give up cron-style scheduling.

## How it works

- **Trust on first sight.** When the daemon starts, every script in the
  system tab that it has never seen before is recorded as trusted
  (`TRUSTED-NEW`). To review scripts before that happens, run
  `cronwatcher approve` before the first start.
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
- **Tamper hook and mail.** A `@tamper` job, itself verified, runs whenever a
  job is refused. `MAILTO=` in a tab mails failed or refused runs (or every
  run) to an address of your choice.
- **Per-user jobs, pinned by root.** A job in the system tab can name an
  account. The root daemon verifies the script and then runs it as that user.
  Users cannot change what these jobs run without an admin's approval. The
  script is read with that user's permissions, so it must be readable by them
  (as with cron), and a symlink cannot make root read a file for them.
- **Users' own jobs.** Users the admin has enabled keep their own tab, add,
  change and delete their jobs, and approve their own scripts, like with
  `crontab -e`. The root daemon runs these jobs as them.
- **Tabs reload by themselves.** As in cron, every tab is checked once a
  minute and reloaded when it has changed. No restart needed.
- **A hung filesystem stalls only its own jobs.** Every tab and every script
  is handled in a thread of its own. A script on a hung NFS or FUSE mount
  blocks only the jobs that use it (`BUSY`), never the scheduler or other
  users.

## Requirements

- Linux (uses `memfd_create` with sealing, kernel 3.17 or later)
- Rust 1.88 or later to build
- GNU `diff` (diffutils) to show diffs, and `logger` (util-linux) for the
  approval audit log
- For mail: an MTA that provides `/usr/sbin/sendmail` (postfix, exim,
  msmtp-mta, nullmailer, ...)
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
decides what runs. Only one daemon can use a state directory at a time.

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
cronwatcher [-c TAB] [-s STATEDIR] edit            edit TAB in $VISUAL/$EDITOR, check, approve
defaults: root:   TAB=/etc/cronwatcher.tab STATEDIR=/var/lib/cronwatcher
          others: STATEDIR=/var/lib/cronwatcher/users/$USER TAB=STATEDIR/tab
```

- `status` prints `OK`, `NEW`, `CHANGED` (with diff) or `MISSING` for each
  script. It exits with 1 if any script is not `OK`, so it works as a
  monitoring check.
- `approve` shows the diff against the last approved version (or the whole
  file if none is approved), asks `[y/N]`, and trusts **the bytes it showed
  you**, even if the file changes while you read. `-y` skips the question.
  Scripts must be listed in the tab. Each approval goes to syslog
  (`auth.notice`, tag `cronwatcher`) with the old and new hash and the
  approving uid/`SUDO_USER`. It exits with 1 if a script was skipped or
  missing.
- `edit` works like `crontab -e`: it opens a copy of the tab in
  `$VISUAL`/`$EDITOR` (default `vi`), installs it only once it is valid
  (otherwise it offers to edit again), and then runs `approve --all` for the
  scripts that are not trusted yet. If the tab is not installed, the error
  names the temporary file that still holds your version.

### Typical workflows

**A script was changed on purpose.** Its next run is refused and logged. Run
`sudo cronwatcher approve /opt/jobs/backup.sh`, check the diff, answer `y`.
The following run goes ahead. No restart is needed.

**Adding a job.** Write the script, then `sudo cronwatcher edit` and add the
line. `edit` asks you to approve the new script. The daemon picks up the
changed tab within a minute. If you edit the tab some other way and skip the
approval, the daemon trusts the new script on first sight and logs
`TRUSTED-NEW`.

## Users' own jobs

The admin enables a user by creating a directory for them, which is
cronwatcher's `cron.allow`:

```sh
sudo install -d -o alice -m 0700 /var/lib/cronwatcher/users/alice
```

From then on, alice manages her own jobs without root:

```sh
cronwatcher edit       # add, change or delete jobs; approve their scripts
cronwatcher status     # what is trusted, what is blocked
cronwatcher approve /home/alice/jobs/daily.sh   # after changing a script
```

Her tab (`users/alice/tab`) uses the same format as the system tab. Her jobs
always run as alice, so the user column must be empty or `alice`. She can set
`MAILTO=` and her own `@tamper` hook. Her approvals live in her own trust
store next to the tab.

The daemon (it must run as root) treats these tabs differently from the
system tab:

- **Nothing is trusted on first sight.** A script alice has not approved is
  refused (`PENDING`) until she runs `approve` or `edit`.
- **Everything of hers is read with her permissions.** The tab, her trust
  store and her scripts are opened with her file permissions, and diffs of her
  scripts run as her. A symlink or a job path therefore cannot make root read
  a file alice cannot read, such as `/etc/shadow`. The daemon never writes to
  her directory.
- Removing her directory removes her jobs (`DROPPED`). Deleting her tab does
  the same.

Jobs that an admin puts in the system tab with `alice` in the user column are
not affected: those stay pinned by root.

## Job table

```
# m  h  dom mon dow  [user]  command [args...]
*/5  *  *   *   *            /opt/jobs/backup.sh --full
30   2  *   *   1-5          /opt/jobs/report.sh
5    5  *   *   *    alice   /home/alice/jobs/daily.sh
MAILTO=ops@example.com
@daily                       /usr/local/bin/rotate-logs
@reboot                      /opt/jobs/warmup.sh
@tamper                      /opt/jobs/alert.sh
```

**Time fields:** minute `0-59`, hour `0-23`, day of month `1-31`,
month `1-12`, day of week `0-7` (0 and 7 are Sunday). Each field accepts `*`,
`N`, `A-B`, comma lists, and steps on `*` or ranges (`*/15`, `1-30/2`).
- Numbers only: month and day names are not supported.
- As in cronie, a step needs `*` or a range: `0/15` is an error; write `*/15`
  or `0-59/15`.
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
| `@tamper` | the alert hook (see below). Only the first `@tamper` line of a tab is used. |

**User (optional):** a lowercase account name before the command runs the job
as that account. If it is omitted, the job runs as the daemon (root). All
accounts must exist when the tab is loaded; they are looked up again at every
run.

**Command:** must be an absolute path. Arguments are split on whitespace.
There is no shell, so quoting, pipes, redirects, variables and `%` do not
work. Put that logic inside the (verified) script.

**Mail settings:** `MAILTO=` and `MAILON=` lines apply to the jobs below them,
as in cron, until the next such line (see [Mail](#mail)). No other variables
are allowed: a variable such as `BASH_ENV` or `LD_PRELOAD` would change what a
verified script does without changing its hash.

Lines starting with `#` and blank lines are ignored. Tabs are checked once a
minute and reloaded when they change. If a changed tab is invalid (or an
account lookup fails, e.g. while LDAP is down), the error is logged
(`RELOAD-FAILED`), its previous jobs keep running, and the reload is tried
again every minute until it succeeds. At startup an invalid system tab is
fatal.

## What a job sees

- The script runs from an anonymous memory file, so it needs no `+x` bit, but
  it does need a `#!` line (otherwise: `SPAWN-FAILED … hint="missing #! line?"`).
  Compiled binaries work too.
- **`$0` is `/proc/self/fd/N`, not the script path.** The real path is in
  `$CRONWATCHER_SCRIPT`. Scripts that use `$(dirname "$0")` to find sibling
  files must use `$CRONWATCHER_SCRIPT` instead. Python's `sys.path[0]` does
  not point at the script's directory either.
- stdin is `/dev/null`. stdout and stderr are logged line by line as
  `[script pid] …`. Lines longer than 4 KiB are split.
- The environment is cron's, nothing is inherited from the daemon:
  `PATH=/usr/bin:/bin`, `SHELL=/bin/sh`, `HOME`, `USER`, `LOGNAME`, plus
  `CRONWATCHER_SCRIPT`. The working directory is the account's home (`/` if it
  does not exist).
- Every job runs in its own session (`setsid`), so a Ctrl-C or a signal to the
  daemon's process group does not reach it. User jobs get all the account's
  groups and none of root's.
- There is no timeout and no overlap protection: if a run takes longer than
  its interval, the next one starts anyway, as with cron.

## Mail

Mail is opt-in, per job, set in the tab:

```
MAILTO=alice@example.com     # jobs below this line mail this address
MAILON=fail                  # fail (default): only failed or refused runs; always: every run
* * * * *  /home/alice/jobs/sync.sh
MAILTO=                      # jobs below this line send no mail
```

A mail is sent when a job exits with a non-zero status or is killed by a
signal, cannot be started (`SPAWN-FAILED`), or is refused because its script
changed, is not approved or is missing. With `MAILON=always`, a mail is also
sent after every successful run. Refusals are mailed once for each distinct
bad version of a script, with the diff. A run's mail contains the exit status,
the duration and the first 200 lines of output.

As in cron, the mail goes through `/usr/sbin/sendmail -i -t`, which runs as
the job's account, so the user's own MTA setup applies (such as `~/.msmtprc`).
The address may only contain letters, digits and `@!:%-.,_+`, and must start
with a letter or digit (cron's rule). If sending fails, `MAIL-FAILED` is
logged.

## Tamper hook

A `@tamper` job runs whenever a job of the same tab is refused, whether its
script changed, is pending, is missing or unreadable, or the trust store
can't be loaded. It gets these variables:

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
`journalctl -u cronwatcher -p err` shows only integrity problems. Events from
a user's own tab carry `user=NAME`.

| Event | Priority | Meaning |
|---|---|---|
| `STARTING` | notice | daemon start |
| `LOADED` | notice | a tab was (re)loaded, with counts of ok/new/blocked scripts, and `slow` ones not read within 10 s (checked once they are) |
| `RELOAD-FAILED` | err | a changed tab is invalid; its previous jobs keep running, retried every minute |
| `BUSY` | warning | a script (`job=`) or a whole tab is still being read since an earlier minute (hung filesystem?); this run is skipped |
| `DROPPED` | notice | a user's directory was removed, their jobs are gone |
| `TRUSTED-NEW` | notice | script seen for the first time and pinned (system tab only) |
| `OK` | info | script matches its approved version (at load) |
| `CHANGED` | err | script differs from its approved version, blocked (at load) |
| `PENDING` | err | script exists but was never approved, blocked (at load) |
| `MISSING` | err | script missing, unreadable, not a regular file, or over 64 MiB |
| `REFUSED` | err | a scheduled run was blocked (hash mismatch, not approved, or trust store unusable) |
| `  \| …` | err | diff of a blocked script (first 50 lines) |
| `REBOOT-SKIPPED` | notice | `@reboot` jobs already ran during this boot |
| `RUN` | info | job started (pid, user, hash) |
| `[script pid] …` | info | job output |
| `DONE` / `FAIL` | info / warning | job finished (exit status or signal, duration) |
| `SPAWN-FAILED`, `WAIT-FAILED` | err | the job could not be started or reaped |
| `MAIL-FAILED` | err | sendmail could not be run or failed |
| `FATAL` | err | bad tab, unsafe permissions, unknown user, or another daemon already running: the daemon exits |
| `APPROVED` | auth.notice | written by `cronwatcher approve` |

## State directory

`/var/lib/cronwatcher` (mode `0711`, so users can reach their own directory)
contains:

- `trusted`: one `sha256  path` line per script (`sha256sum` format). `-`
  marks a pending path.
- `blobs/<sha256>`: a copy of every approved version, used for diffs. These
  are never pruned.
- `boot_id`: the kernel boot ID of the last `@reboot` run.
- `lock`: held by the running daemon.
- `users/NAME/`: a user's own `tab`, `trusted` and `blobs/`, owned by that
  user.

## Security model and limits

**Protected:** the bytes of every job script. A script modified after
approval never runs, even if it is swapped between the check and the exec.
Users cannot change what their jobs in the system tab run without an admin.

**Users' own tabs:** their scripts are pinned by the user, not by an admin.
This stops other people and tools from changing what the user's jobs run. It
does not help if the user's account itself is compromised, because whoever
controls the account can run `cronwatcher approve`. The root daemon reads
everything in a user's tab with that user's permissions and never writes
there, so a user tab cannot be used to read or change root's files.

**Not protected:**
- The interpreter named in `#!`, and anything the script sources, imports,
  reads or executes (libraries, config files, other binaries). Keep those
  root-owned, or verify them inside the script.
- The system tab, the cronwatcher binary and the state directory. Anyone who
  can write those, or who is root, controls what runs.
- First sight. A script trusted at its first load is only as good as its
  content at that moment, so review new scripts with `approve` or `edit`.
- Availability. Deleting or replacing a script stops its job (and alerts
  you), but cannot make anything else run. A script on a hung filesystem
  only stops the jobs that use it.
- Account checks. There is no PAM: jobs of expired or locked accounts still
  run. Remove their lines or their `users/` directory.

**Scheduling behaviour** (the same as cronie):
- Woken up to 5 minutes late: every missed minute is run.
- Clock forward by up to 3 hours (start of daylight saving time, a short
  suspend): jobs with `*` in the minute or hour field run once; jobs with a
  fixed time run for every skipped minute, so a `30 2 * * *` job still runs
  on the night the clock skips 02:30.
- Clock back by up to 3 hours (end of daylight saving time): only jobs with
  `*` in the minute or hour field run until the clock has caught up, so fixed
  time jobs don't run twice.
- Bigger jumps (or a long suspend or downtime): nothing is caught up,
  scheduling carries on from the new time.
- Changes to the time zone need a restart.
- With the sysctl `vm.memfd_noexec=2`, nothing can be executed (`SPAWN-FAILED`).

**Restarts:** under systemd (`KillMode=process`) a restart does not kill
running jobs. Their output is read by the daemon, though, so a job that
writes output after the restart gets `SIGPIPE`. Editing a tab needs no
restart.

## Development

```sh
cargo test
cargo clippy --all-targets
```

Tests use temporary directories and need no setup. When run as root
(`sudo -E cargo test`), `user_job` also exercises the real uid/gid switch,
running a job as `nobody`, and `user_tab` checks that a user's files, and the
scripts of system-tab jobs that run as a user, are read with that user's
permissions.

## License

MIT, see [LICENSE](LICENSE).
