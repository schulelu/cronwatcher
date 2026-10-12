//! cronwatcher: cron that only runs scripts it has verified.
//!
//! Every job script is hashed when the daemon starts and recorded in a trust
//! store (`<state>/trusted`, sha256sum format). Before each run the script is
//! read once, hashed, compared with the trusted hash and executed from a sealed
//! in-memory copy of exactly those bytes, so swapping the file on disk between
//! check and exec has no effect. Changed scripts stay blocked until an admin
//! reviews the diff with `cronwatcher approve`. A script missing at startup is
//! recorded as pending, so whatever appears there later needs approval too.
//! `@reboot` jobs run once per kernel boot, not on every daemon restart.
//!
//! A job may name an account before its command (`m h dom mon dow [user] /cmd`):
//! the root daemon verifies the script itself (read with that user's
//! permissions), then runs it as that user (all of its groups,
//! HOME/USER/LOGNAME, cwd = home). So a user's own script is pinned by root
//! without root ever running it.
//!
//! Users the admin has enabled (`<state>/users/NAME`, owned by NAME) keep their
//! own tab and trust store there, edit and approve them themselves, and the
//! root daemon runs those jobs as them. It reads their files with their file
//! permissions only and never writes there.
//!
//! As in cron: tabs are reloaded when they change, DST and clock jumps are
//! handled like cronie does, jobs get a clean environment and their own
//! session, and `MAILTO=` mails failures (or every run) as the job's user.
//! Every tab and every script is worked on in a thread of its own, so a script
//! on a hung filesystem stalls only itself, never the scheduler.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio, exit};
use std::sync::{Arc, LazyLock, Mutex, TryLockError, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{env, thread};

const USAGE: &str = "\
usage: cronwatcher [-c TAB] [-s STATEDIR]                 run the scheduler
       cronwatcher [-c TAB] [-s STATEDIR] status          show trust state of every job script
       cronwatcher [-c TAB] [-s STATEDIR] approve [-y] (--all | SCRIPT...)
                                                          review diff, trust current version
       cronwatcher [-c TAB] [-s STATEDIR] edit            edit TAB in $VISUAL/$EDITOR, check, approve
defaults: root:   TAB=/etc/cronwatcher.tab STATEDIR=/var/lib/cronwatcher
          others: STATEDIR=/var/lib/cronwatcher/users/$USER TAB=STATEDIR/tab";

// syslog priorities, handed to journald as a "<N>" line prefix
const ERR: u8 = 3;
const WARN: u8 = 4;
const NOTICE: u8 = 5;
const INFO: u8 = 6;

static JOURNAL: LazyLock<bool> = LazyLock::new(|| {
    // systemd sets JOURNAL_STREAM=dev:inode; it can be inherited, so only
    // trust it if stderr really is that stream
    let Ok(want) = env::var("JOURNAL_STREAM") else { return false };
    let Ok(fd) = io::stderr().as_fd().try_clone_to_owned() else { return false };
    File::from(fd).metadata().is_ok_and(|m| want == format!("{}:{}", m.dev(), m.ino()))
});

fn log(level: u8, msg: &str) {
    // one lock per message keeps the threads' lines apart; a lost stderr (journald gone) drops
    // the line instead of panicking like eprintln! would
    let journal = *JOURNAL;
    let mut err = io::stderr().lock();
    for line in msg.lines() {
        let _ = if journal { writeln!(err, "<{level}>{line}") } else { writeln!(err, "{line}") };
    }
}

fn ctx<T>(p: impl AsRef<Path>, r: io::Result<T>) -> Result<T, String> {
    r.map_err(|e| format!("{}: {e}", p.as_ref().display()))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn euid() -> libc::uid_t {
    unsafe { libc::geteuid() }
}

// ---------- schedule ----------

#[derive(Clone)]
enum When {
    Cron(Cron),
    Reboot,
    Tamper,
}

#[derive(Clone)]
struct Cron {
    mask: [u64; 5], // minute, hour, day of month, month, day of week
    dom_star: bool,
    dow_star: bool,
    wild: bool, // minute or hour is '*'-based: runs once across a clock jump, fixed-time jobs catch up
}

#[derive(Clone)]
struct Job {
    when: When,
    user: Option<String>, // run as this account; None = as the daemon
    cmd: Vec<String>,
    mailto: Option<String>, // MAILTO= above this job; None = no mail
    mail_always: bool,      // MAILON=always: mail every run, not only failures
}

impl Job {
    fn path(&self) -> &str {
        &self.cmd[0]
    }
}

const RANGES: [(u32, u32); 5] = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)];

fn parse_field(s: &str, lo: u32, hi: u32) -> Result<u64, String> {
    let bad = || format!("bad field '{s}' (allowed {lo}-{hi})");
    let num = |v: &str| v.parse::<u32>().map_err(|_| bad());
    let mut mask = 0;
    for part in s.split(',') {
        let (range, step) = match part.split_once('/') {
            Some((r, st)) => (r, num(st)?),
            None => (part, 1),
        };
        let (a, b) = match range.split_once('-') {
            _ if range == "*" => (lo, hi),
            Some((a, b)) => (num(a)?, num(b)?),
            None if part.contains('/') => return Err(bad()), // as cronie: a step needs '*' or a range
            None => (num(range)?, num(range)?), // ponytail: numbers only, no month/day names
        };
        if step == 0 || a < lo || b > hi || a > b {
            return Err(bad());
        }
        for v in (a..=b).step_by(step as usize) {
            mask |= 1u64 << v;
        }
    }
    Ok(mask)
}

fn parse_cron(fields: &[&str]) -> Result<Cron, String> {
    let mut mask = [0; 5];
    for (i, f) in fields.iter().enumerate() {
        mask[i] = parse_field(f, RANGES[i].0, RANGES[i].1)?;
    }
    if mask[4] & 1 << 7 != 0 {
        mask[4] |= 1; // 7 = Sunday
    }
    let star = |i: usize| fields[i].starts_with('*');
    Ok(Cron { mask, dom_star: star(2), dow_star: star(4), wild: star(0) || star(1) })
}

impl Cron {
    /// `t` = [minute, hour, day of month, month 1-12, day of week 0-6]
    fn due(&self, t: [u32; 5]) -> bool {
        let hit = |i: usize| self.mask[i] >> t[i] & 1 == 1;
        // classic cron: if both day fields are restricted, either one matching is enough
        let day = if self.dom_star || self.dow_star { hit(2) && hit(4) } else { hit(2) || hit(4) };
        hit(0) && hit(1) && hit(3) && day
    }
}

fn parse_tab(text: &str) -> Result<Vec<Job>, String> {
    let mut jobs = vec![];
    let (mut mailto, mut mail_always) = (None, false);
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let err = |e: String| format!("line {}: {e}", n + 1);
        // settings apply to the jobs below them, as in cron. No other variables: they would change
        // what a verified script does (BASH_ENV, LD_PRELOAD, ...) without changing its hash
        if let Some((k, v)) = line.split_once('=')
            && k.trim_end().chars().all(|c| c.is_ascii_uppercase() || c == '_')
        {
            let v = v.trim().trim_matches(['"', '\'']);
            match k.trim_end() {
                "MAILTO" if v.is_empty() => mailto = None,
                "MAILTO" if safe_mail(v) => mailto = Some(v.to_string()),
                "MAILTO" => return Err(err(format!("unsafe MAILTO '{v}'"))),
                "MAILON" if v == "fail" || v == "always" => mail_always = v == "always",
                "MAILON" => return Err(err(format!("MAILON must be 'fail' or 'always', not '{v}'"))),
                k => return Err(err(format!("unknown setting '{k}' (only MAILTO and MAILON)"))),
            }
            continue;
        }
        let w: Vec<&str> = line.split_whitespace().collect();
        let (when, rest) = match w[0] {
            "@reboot" => (When::Reboot, &w[1..]),
            "@tamper" => (When::Tamper, &w[1..]),
            m if m.starts_with('@') => {
                let spec = match m {
                    "@hourly" => "0 * * * *",
                    "@daily" | "@midnight" => "0 0 * * *",
                    "@weekly" => "0 0 * * 0",
                    "@monthly" => "0 0 1 * *",
                    "@yearly" | "@annually" => "0 0 1 1 *",
                    _ => return Err(err(format!("unknown schedule {m}"))),
                };
                let fields: Vec<&str> = spec.split(' ').collect();
                (When::Cron(parse_cron(&fields).map_err(err)?), &w[1..])
            }
            _ if w.len() > 5 => (When::Cron(parse_cron(&w[..5]).map_err(err)?), &w[5..]),
            _ => return Err(err("need 5 time fields and a command".into())),
        };
        // optional account before the command: a user name, never a path
        let (user, cmd) = match rest {
            [u, cmd @ ..] if !u.starts_with('/') && !cmd.is_empty() => {
                if !valid_user(u) {
                    return Err(err(format!("bad user name '{u}'")));
                }
                (Some(u.to_string()), cmd)
            }
            _ => (None, rest),
        };
        // ponytail: args split on whitespace, no shell; pipes/quoting go into the (verified) script
        match cmd.first() {
            Some(p) if p.starts_with('/') => jobs.push(Job {
                when,
                user,
                cmd: cmd.iter().map(|s| s.to_string()).collect(),
                mailto: mailto.clone(),
                mail_always,
            }),
            _ => return Err(err("command must be an absolute path".into())),
        }
    }
    Ok(jobs)
}

/// cronie's safe_p(): the address goes into a mail header and to sendmail, so alphanumerics
/// plus "@!:%-.,_+" only, and never a leading '-'.
fn safe_mail(s: &str) -> bool {
    s.chars().enumerate().all(|(i, c)| c.is_ascii_alphanumeric() || i > 0 && "@!:%-.,_+".contains(c))
}

/// POSIX-portable account names (what useradd accepts by default).
fn valid_user(u: &str) -> bool {
    u.len() <= 32
        && u.starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
        && u.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

struct Account {
    name: String,
    uid: libc::uid_t,
    gid: libc::gid_t,
    home: PathBuf,
    groups: Vec<libc::gid_t>,
}

/// Look the account up now (not at tab load), so a changed uid or group list applies on the next run.
/// `None` = the account cronwatcher itself runs as.
fn account(name: Option<&str>) -> Result<Account, String> {
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16384];
    let mut res: *mut libc::passwd = std::ptr::null_mut();
    let rc = match name {
        Some(n) => {
            let c = CString::new(n).map_err(|_| format!("bad user name '{n}'"))?;
            unsafe { libc::getpwnam_r(c.as_ptr(), &mut pw, buf.as_mut_ptr(), buf.len(), &mut res) }
        }
        None => unsafe { libc::getpwuid_r(euid(), &mut pw, buf.as_mut_ptr(), buf.len(), &mut res) },
    };
    if rc != 0 || res.is_null() {
        return Err(name.map_or(format!("no account for uid {}", euid()), |n| format!("unknown user '{n}'")));
    }
    let cname = unsafe { CStr::from_ptr(pw.pw_name) }.to_owned();
    let home = PathBuf::from(unsafe { CStr::from_ptr(pw.pw_dir) }.to_string_lossy().into_owned());
    let mut n: libc::c_int = 64;
    let groups = loop {
        let mut g = vec![0 as libc::gid_t; n as usize];
        let mut m = n;
        if unsafe { libc::getgrouplist(cname.as_ptr(), pw.pw_gid, g.as_mut_ptr(), &mut m) } >= 0 {
            g.truncate(m as usize);
            break g;
        }
        n = m.max(n * 2);
    };
    let name = cname.to_string_lossy().into_owned();
    Ok(Account { name, uid: pw.pw_uid, gid: pw.pw_gid, home, groups })
}

/// Set `cmd` up the way cron starts a job: cron's clean environment, the home directory as cwd,
/// its own session (a Ctrl-C or signal to the daemon's process group doesn't hit it) and, if we
/// are root, the account's groups, gid and uid.
fn as_account(cmd: &mut Command, a: &Account) {
    let cwd = if a.home.is_dir() { a.home.clone() } else { PathBuf::from("/") };
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("SHELL", "/bin/sh")
        .env("HOME", &a.home)
        .env("USER", &a.name)
        .env("LOGNAME", &a.name)
        .current_dir(cwd);
    let (uid, gid, groups, root) = (a.uid, a.gid, a.groups.clone(), euid() == 0);
    // groups, then gid, then uid: after setuid there is no way back. Only
    // async-signal-safe syscalls here (this runs between fork and exec).
    unsafe {
        cmd.pre_exec(move || {
            if libc::setsid() < 0
                || root
                    && (libc::setgroups(groups.len(), groups.as_ptr()) != 0
                        || libc::setgid(gid) != 0
                        || libc::setuid(uid) != 0)
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// The first job of every distinct script, `@tamper` first so the hook is trusted before it can fire.
fn unique_jobs(jobs: &[Job]) -> Vec<&Job> {
    let mut first: Vec<&Job> = vec![];
    for j in jobs.iter().filter(|j| matches!(j.when, When::Tamper)).chain(jobs) {
        if !first.iter().any(|f| f.path() == j.path()) {
            first.push(j);
        }
    }
    first
}

// ---------- trust ----------

/// Whoever can write the tab or the trust store decides what runs, so refuse
/// anything not owned by root/`owner` or writable by group/others.
fn check_owner(path: &Path, meta: &fs::Metadata, owner: libc::uid_t) -> Result<(), String> {
    if meta.uid() != 0 && meta.uid() != owner {
        return Err(format!("{}: owned by uid {}, must be root or uid {owner}", path.display(), meta.uid()));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!("{}: writable by group/others (mode {:o})", path.display(), meta.mode() & 0o7777));
    }
    Ok(())
}

/// Open read-only and non-blocking. With `user` (a root daemon reading a user's tab, store or
/// scripts) the open runs in a throwaway thread with that user's fsuid, fsgid and groups, so a
/// symlink or a job path can't make root read what the user can't (e.g. /etc/shadow).
/// Credentials are per thread in Linux; glibc's setgroups() would change all threads, hence the
/// raw syscall. A fsuid other than 0 also drops CAP_DAC_OVERRIDE.
fn open_as(user: Option<&str>, path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    let Some(name) = user.filter(|_| euid() == 0) else { return opts.open(path) };
    let a = account(Some(name)).map_err(io::Error::other)?;
    let path = path.to_owned();
    thread::spawn(move || {
        unsafe {
            // ponytail: SYS_setgroups takes 32-bit gids on 64-bit targets; 32-bit x86/arm would need setgroups32
            if libc::syscall(libc::SYS_setgroups, a.groups.len(), a.groups.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            libc::setfsgid(a.gid);
            libc::setfsuid(a.uid);
            // setfs*id() can't report errors: read the values back (an invalid id only queries)
            if libc::setfsuid(u32::MAX) as u32 != a.uid || libc::setfsgid(u32::MAX) as u32 != a.gid {
                return Err(io::Error::other("setfsuid failed"));
            }
        }
        opts.open(&path)
    })
    .join()
    .map_err(|_| io::Error::other("open thread panicked"))?
}

/// Read a whole regular file of at most `max` bytes. Whoever can write it could swap in a FIFO or
/// /dev/zero: that must not hang or exhaust the daemon.
fn read_file(user: Option<&str>, path: &Path, max: u64) -> io::Result<(Vec<u8>, fs::Metadata)> {
    let f = open_as(user, path)?;
    let meta = f.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    let mut bytes = vec![];
    f.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(io::Error::other(format!("larger than {} MiB", max >> 20)));
    }
    Ok((bytes, meta))
}

/// Read and check a tab. With `user` it is that user's own tab: read with their permissions, and
/// every job runs as them.
fn load_tab(path: &Path, user: Option<&str>) -> Result<Vec<Job>, String> {
    let (bytes, meta) = ctx(path, read_file(user, path, MAX_SCRIPT))?;
    let owner = match user {
        Some(u) => account(Some(u))?.uid,
        None => euid(),
    };
    check_owner(path, &meta, owner)?;
    let text = String::from_utf8(bytes).map_err(|_| format!("{}: not UTF-8", path.display()))?;
    let mut jobs = check_tab(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    if let Some(u) = user {
        for j in &mut jobs {
            if j.user.as_ref().is_some_and(|x| x != u) {
                return Err(format!("{}: {} runs as '{}', but {u}'s jobs can only run as {u}", path.display(), j.path(), j.user.as_deref().unwrap_or_default()));
            }
            j.user = Some(u.to_string());
        }
    }
    Ok(jobs)
}

/// Parse a tab and fail at start, not at 3am: every account must exist, and only root can switch to it.
fn check_tab(text: &str) -> Result<Vec<Job>, String> {
    let jobs = parse_tab(text)?;
    for u in jobs.iter().filter_map(|j| j.user.as_deref()) {
        let a = account(Some(u))?;
        if euid() != 0 && a.uid != euid() {
            return Err(format!("job runs as '{u}', which needs cronwatcher running as root"));
        }
    }
    Ok(jobs)
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    let mut f = ctx(&tmp, OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp))?;
    ctx(&tmp, f.write_all(data).and_then(|_| f.sync_all()))?;
    ctx(path, fs::rename(&tmp, path))
}

type Db = BTreeMap<String, String>; // script path -> trusted sha256

/// Trust store value for a path that is known but has no approved version yet.
const PENDING: &str = "-";

struct Store {
    dir: PathBuf,
    /// A user's own store (`<state>/users/NAME`) as the root daemon sees it: read with that
    /// user's permissions, never written. None: our own store.
    user: Option<String>,
}

impl Store {
    fn owner(&self) -> Result<libc::uid_t, String> {
        match &self.user {
            Some(u) => Ok(account(Some(u))?.uid),
            None => Ok(euid()),
        }
    }

    fn mkdir(&self) -> Result<(), String> {
        // 0711: users must be able to reach their own store under users/
        ctx(&self.dir, DirBuilder::new().recursive(true).mode(0o711).create(&self.dir))
    }

    fn load(&self) -> Result<Db, String> {
        let owner = self.owner()?;
        match fs::metadata(&self.dir) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Db::new()),
            r => check_owner(&self.dir, &ctx(&self.dir, r)?, owner)?,
        }
        let path = self.dir.join("trusted");
        let (bytes, meta) = match read_file(self.user.as_deref(), &path, MAX_SCRIPT) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Db::new()),
            r => ctx(&path, r)?,
        };
        check_owner(&path, &meta, owner)?;
        let text = String::from_utf8_lossy(&bytes);
        Ok(text.lines().filter_map(|l| l.split_once("  ")).map(|(sha, p)| (p.into(), sha.into())).collect())
    }

    fn blob(&self, sha: &str) -> PathBuf {
        self.dir.join("blobs").join(sha)
    }

    /// Record `bytes` as the trusted version of `path`, keeping a copy for later diffs.
    fn trust(&self, path: &str, bytes: &[u8]) -> Result<String, String> {
        let sha = sha256(bytes);
        self.record(path, &sha, Some(bytes))?;
        Ok(sha)
    }

    fn record(&self, path: &str, sha: &str, blob: Option<&[u8]>) -> Result<(), String> {
        self.mkdir()?;
        // `approve` and the daemon's threads all update the store: one writer at a time
        let lock = ctx(&self.dir, File::open(&self.dir))?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(format!("{}: lock: {}", self.dir.display(), io::Error::last_os_error()));
        }
        if let Some(bytes) = blob {
            let blobs = self.dir.join("blobs");
            ctx(&blobs, DirBuilder::new().recursive(true).mode(0o700).create(&blobs))?;
            write_atomic(&blobs.join(sha), bytes)?; // ponytail: blobs never pruned, one small file per approved version
        }
        let mut db = self.load()?;
        db.insert(path.into(), sha.into());
        let text: String = db.iter().map(|(p, h)| format!("{h}  {p}\n")).collect();
        write_atomic(&self.dir.join("trusted"), text.as_bytes())
    }

    /// True once per kernel boot, so `@reboot` jobs don't re-run on every service restart.
    fn new_boot(&self) -> bool {
        let Ok(id) = fs::read_to_string("/proc/sys/kernel/random/boot_id") else { return true };
        let mark = self.dir.join("boot_id");
        if fs::read_to_string(&mark).is_ok_and(|old| old == id) {
            return false;
        }
        if let Err(e) = self.mkdir().and_then(|_| write_atomic(&mark, id.as_bytes())) {
            log(WARN, &format!("boot marker not saved, @reboot jobs will run again on restart: {e}"));
        }
        true
    }

    /// One read of a job's script, with the store user's permissions, else the job user's: a
    /// symlink must not make root read for a user what the user can't (e.g. /etc/shadow).
    fn inspect(&self, db: &Db, job: &Job) -> Result<Seen, String> {
        let (path, user) = (job.path(), self.user.as_deref().or(job.user.as_deref()));
        let (bytes, _) = ctx(path, read_file(user, Path::new(path), MAX_SCRIPT))?;
        let trusted = db.get(path).filter(|t| *t != PENDING).cloned();
        Ok(Seen { sha: sha256(&bytes), trusted, bytes })
    }

    /// " user=NAME" for log lines about a user's own tab.
    fn tag(&self) -> String {
        self.user.as_deref().map_or(String::new(), |u| format!(" user={u}"))
    }
}

/// One read of a script: the exact bytes that get hashed, shown and executed.
struct Seen {
    bytes: Vec<u8>,
    sha: String,
    trusted: Option<String>,
}

impl Seen {
    fn ok(&self) -> bool {
        self.trusted.as_ref().is_some_and(|t| t.eq_ignore_ascii_case(&self.sha))
    }

    fn hashes(&self) -> String {
        format!("trusted={} current={}", self.trusted.as_deref().unwrap_or("none"), self.sha)
    }
}

const MAX_SCRIPT: u64 = 64 << 20; // ponytail: 64 MiB, raise if a job binary is bigger

/// `diff -u` of the trusted copy against what was read (whole file if nothing is trusted yet).
fn diff(store: &Store, path: &str, seen: &Seen) -> String {
    let old = seen.trusted.as_deref().map(|t| store.blob(t)).filter(|b| b.exists());
    let mut cmd = Command::new("diff");
    if let Some(u) = &store.user {
        // the user controls their blobs dir: read it with their permissions, never root's
        match account(Some(u)) {
            Ok(a) => as_account(&mut cmd, &a),
            Err(e) => return format!("(diff unavailable: {e})\n"),
        }
    }
    let child = cmd
        .args(["-u", "--label", &format!("{path} (trusted)"), "--label", &format!("{path} (current)")])
        .arg(old.unwrap_or("/dev/null".into()))
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return format!("(diff unavailable: {e})\n"),
    };
    // diff reads both inputs fully before printing, so writing stdin first can't deadlock
    let _ = child.stdin.take().unwrap().write_all(&seen.bytes);
    match child.wait_with_output() {
        Ok(o) => String::from_utf8_lossy(&[o.stdout, o.stderr].concat()).into(),
        Err(e) => format!("(diff failed: {e})\n"),
    }
}

// ---------- exec ----------

/// Copy `bytes` into an anonymous memory file and seal it read-only forever.
fn sealed_memfd(bytes: &[u8]) -> io::Result<OwnedFd> {
    let name = c"cronwatcher";
    // close-on-exec: other threads start processes too, those must not inherit it. spawn() keeps
    // it open across exec in its own child only.
    let flags = libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING;
    let mut fd = unsafe { libc::memfd_create(name.as_ptr(), flags | libc::MFD_EXEC) };
    if fd < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
        // kernel < 6.3 has no MFD_EXEC; memfds are executable there anyway
        fd = unsafe { libc::memfd_create(name.as_ptr(), flags) };
    }
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut f = unsafe { File::from_raw_fd(fd) };
    f.write_all(bytes)?;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if unsafe { libc::fcntl(f.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(f.into())
}

const MAIL_LINES: usize = 200; // ponytail: job output lines per mail, the full output is in the log

/// Run the verified snapshot. Output and exit status go to the log, and to MAILTO.
fn spawn(job: &Job, seen: &Seen, env: &[(&str, &str)]) {
    let path = job.path().to_string();
    let started = (|| -> io::Result<_> {
        let fd = sealed_memfd(&seen.bytes)?;
        let raw = fd.as_raw_fd();
        let (out, w) = io::pipe()?;
        let mut cmd = Command::new(format!("/proc/self/fd/{raw}"));
        as_account(&mut cmd, &account(job.user.as_deref()).map_err(io::Error::other)?);
        // only this child keeps the memfd across exec: a #! interpreter re-opens /proc/self/fd/N
        unsafe {
            cmd.pre_exec(move || match libc::fcntl(raw, libc::F_SETFD, 0) {
                -1 => Err(io::Error::last_os_error()),
                _ => Ok(()),
            });
        }
        cmd.arg0(&path)
            .args(&job.cmd[1..])
            .env("CRONWATCHER_SCRIPT", &path) // scripts see $0 = /proc/self/fd/N
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .stdout(w.try_clone()?)
            .stderr(w);
        Ok((cmd.spawn()?, out))
    })(); // our memfd and pipe write end close here, the child keeps its copies
    let (mut child, out) = match started {
        Ok(v) => v,
        Err(e) => {
            let hint = if e.raw_os_error() == Some(libc::ENOEXEC) { " hint=\"missing #! line?\"" } else { "" };
            let msg = format!("SPAWN-FAILED job={path} error=\"{e}\"{hint}");
            mail(job, "SPAWN-FAILED", &msg);
            return log(ERR, &msg);
        }
    };
    let pid = child.id();
    let user = job.user.as_deref().map_or(String::new(), |u| format!(" user={u}"));
    log(INFO, &format!("RUN job={path}{user} pid={pid} sha={}", seen.sha));
    let name = Path::new(&path).file_name().map_or(path.clone(), |n| n.to_string_lossy().into());
    let t0 = Instant::now();
    let job = job.clone();
    thread::spawn(move || {
        let (mut r, mut line, mut kept) = (BufReader::new(out), vec![], vec![]);
        // ponytail: lines over 4 KiB are split, so one endless line can't exhaust the daemon
        while matches!((&mut r).take(4096).read_until(b'\n', &mut line), Ok(n) if n > 0) {
            let text = String::from_utf8_lossy(line.strip_suffix(b"\n").unwrap_or(&line)).into_owned();
            log(INFO, &format!("[{name} {pid}] {text}"));
            if job.mailto.is_some() && kept.len() < MAIL_LINES {
                kept.push(text);
            }
            line.clear();
        }
        let status = child.wait();
        let dur = t0.elapsed();
        let (level, msg) = match status {
            Ok(s) if s.success() => (INFO, format!("DONE job={path} pid={pid} status=0 dur={dur:.1?}")),
            Ok(s) => {
                let how = s.code().map_or(format!("signal={}", s.signal().unwrap_or(0)), |c| format!("status={c}"));
                (WARN, format!("FAIL job={path} pid={pid} {how} dur={dur:.1?}"))
            }
            Err(e) => (ERR, format!("WAIT-FAILED job={path} pid={pid} error=\"{e}\"")),
        };
        log(level, &msg);
        if level != INFO || job.mail_always {
            let event = msg.split(' ').next().unwrap_or_default();
            mail(&job, event, &format!("{msg}\n\n{}", kept.join("\n")));
        }
    });
}

/// Mail like cron: `sendmail -t` as the job's account (so its own MTA setup applies), only if the
/// tab set MAILTO for the job. In its own thread so a slow MTA can't stall the scheduler.
fn mail(job: &Job, event: &str, body: &str) {
    let Some(to) = job.mailto.clone() else { return };
    let (user, path, event, body) = (job.user.clone(), job.path().to_string(), event.to_string(), body.to_string());
    thread::spawn(move || {
        let sent = (|| -> Result<(), String> {
            let a = account(user.as_deref())?;
            let host = fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
            let msg = format!(
                "To: {to}\nSubject: cronwatcher <{}@{}> {event} {path}\nAuto-Submitted: auto-generated\n\
                 Precedence: bulk\nContent-Type: text/plain; charset=utf-8\n\n{body}\n",
                a.name,
                host.trim()
            );
            let mut cmd = Command::new("/usr/sbin/sendmail");
            as_account(&mut cmd, &a);
            cmd.args(["-i", "-t"]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
            let mut child = cmd.spawn().map_err(|e| e.to_string())?;
            let _ = child.stdin.take().unwrap().write_all(msg.as_bytes());
            let o = child.wait_with_output().map_err(|e| e.to_string())?;
            if !o.status.success() {
                return Err(format!("{}: {}", o.status, String::from_utf8_lossy(&[o.stdout, o.stderr].concat()).trim()));
            }
            Ok(())
        })();
        if let Err(e) = sent {
            log(ERR, &format!("MAIL-FAILED job={path} to={to} error=\"{e}\""));
        }
    });
}

/// An integrity failure: the job did not run.
struct Refused {
    event: &'static str,
    detail: String,
    seen: Option<Seen>,
}

fn verify_and_spawn(store: &Store, job: &Job, env: &[(&str, &str)]) -> Result<(), Refused> {
    let refused = |event: &'static str, detail: String| Refused { event, detail, seen: None };
    // re-read every run so `cronwatcher approve` takes effect without a restart
    let db = store.load().map_err(|e| refused("REFUSED", format!("error=\"trust store: {e}\"")))?;
    let seen = store.inspect(&db, job).map_err(|e| refused("MISSING", format!("error=\"{e}\"")))?;
    if !seen.ok() {
        return Err(Refused { event: "REFUSED", detail: seen.hashes(), seen: Some(seen) });
    }
    spawn(job, &seen, env);
    Ok(())
}

// ---------- daemon ----------

type Stamp = (u64, i64, i64, u64); // inode, mtime, mtime ns, size of a tab: reload when it changes

/// One job table with its trust store: the system tab, or a user's own tab under `<state>/users`.
struct Tab {
    file: PathBuf,
    stamp: Option<Stamp>,
    jobs: Arc<Vec<Job>>,
    shared: Arc<Shared>,
}

/// What a tab shares with the threads that check and run its scripts.
struct Shared {
    store: Store,
    alerted: Mutex<HashMap<String, String>>, // path -> content already reported
    busy: Mutex<HashSet<String>>,            // scripts a thread is reading or starting right now
}

/// How long a (re)load waits for its scripts before it carries on without the slow ones.
const CHECK_WAIT: Duration = Duration::from_secs(10);

impl Shared {
    fn run(&self, jobs: &[Job], job: &Job) {
        match verify_and_spawn(&self.store, job, &[]) {
            Ok(()) => {
                self.alerted.lock().unwrap().remove(job.path());
            }
            Err(r) => self.refused(jobs, job.path(), r),
        }
    }

    fn refused(&self, jobs: &[Job], path: &str, r: Refused) {
        let user = self.store.tag();
        let hint = match (&r.seen, &self.store.user) {
            (None, _) => String::new(),
            (Some(_), None) => format!(" hint=\"review and trust with: cronwatcher approve {path}\""),
            (Some(_), Some(u)) => format!(" hint=\"{u} reviews and trusts it with: cronwatcher approve {path}\""),
        };
        let line = format!("{} job={path}{user} {}", r.event, r.detail);
        // diff, mail and @tamper hook once per distinct bad content, not every minute
        let key = r.seen.as_ref().map_or("-".to_string(), |s| s.sha.clone());
        if self.alerted.lock().unwrap().insert(path.into(), key.clone()) == Some(key) {
            return log(ERR, &format!("{line}{hint}"));
        }
        let mut report = format!("{line}\n");
        let mut shown = format!("{line}{hint}\n");
        if let Some(seen) = &r.seen {
            let d = diff(&self.store, path, seen);
            let n = d.lines().count();
            let more = format!("... {} more lines, see: cronwatcher status", n.saturating_sub(50));
            for l in d.lines().take(50).chain((n > 50).then_some(more.as_str())) {
                shown += &format!("  | {l}\n");
                report += &format!("{l}\n");
            }
        }
        log(ERR, &shown);
        // ponytail: the first job with this script and a MAILTO gets the mail
        if let Some(job) = jobs.iter().find(|j| j.path() == path && j.mailto.is_some()) {
            mail(job, r.event, &report);
        }
        let Some(hook) = jobs.iter().find(|j| matches!(j.when, When::Tamper)) else { return };
        if hook.path() == path {
            return; // a broken hook can't report itself
        }
        let reason = format!("{} {}", r.event, r.detail);
        let env = [("CRONWATCHER_TAMPERED", path), ("CRONWATCHER_REASON", &reason)];
        if let Err(h) = verify_and_spawn(&self.store, hook, &env) {
            log(ERR, &format!("{} job={}{user} (tamper hook) {}", h.event, hook.path(), h.detail));
        }
    }

    /// Check one script at load: trust it on first sight (own store only), or report why it is
    /// blocked. Ok(0): trusted already, Ok(1): trusted now, Ok(2): blocked.
    fn check(&self, db: &Db, jobs: &[Job], job: &Job) -> Result<usize, String> {
        let (own, path) = (self.store.user.is_none(), job.path());
        match self.store.inspect(db, job) {
            Ok(s) if own && !db.contains_key(path) => {
                self.store.trust(path, &s.bytes)?;
                log(NOTICE, &format!("TRUSTED-NEW job={path} sha={}", s.sha));
                Ok(1)
            }
            Ok(s) if s.ok() => {
                log(INFO, &format!("OK job={path}{} sha={}", self.store.tag(), s.sha));
                Ok(0)
            }
            Ok(s) => {
                let event = if s.trusted.is_none() { "PENDING" } else { "CHANGED" };
                self.refused(jobs, path, Refused { event, detail: s.hashes(), seen: Some(s) });
                Ok(2)
            }
            Err(e) => {
                // otherwise whatever shows up here later would be trusted unseen on the next start
                if own && !db.contains_key(path) {
                    self.store.record(path, PENDING, None)?;
                }
                self.refused(jobs, path, Refused { event: "MISSING", detail: format!("error=\"{e}\""), seen: None });
                Ok(2)
            }
        }
    }
}

impl Tab {
    fn new(file: PathBuf, store: Store, jobs: Vec<Job>, stamp: Option<Stamp>) -> Tab {
        let shared = Shared { store, alerted: Mutex::default(), busy: Mutex::default() };
        Tab { file, stamp, jobs: Arc::new(jobs), shared: Arc::new(shared) }
    }

    /// Work on one script in a thread of its own, so a script on a hung filesystem (NFS, FUSE)
    /// stalls only itself. Until that thread is done, more work on the script is skipped.
    fn on_script(&self, path: &str, f: impl FnOnce(&Shared, &[Job]) + Send + 'static) {
        if !self.shared.busy.lock().unwrap().insert(path.into()) {
            let why = "still at it since an earlier minute (hung filesystem?)";
            return log(WARN, &format!("BUSY job={path}{} reason=\"{why}\"", self.shared.store.tag()));
        }
        let (shared, jobs, path) = (self.shared.clone(), self.jobs.clone(), path.to_string());
        thread::spawn(move || {
            f(&shared, &jobs);
            shared.busy.lock().unwrap().remove(&path);
        });
    }

    /// Start `due` jobs, one thread per script (several due jobs of one script run in order).
    fn run(&self, due: Vec<Job>) {
        let mut by_script: BTreeMap<String, Vec<Job>> = BTreeMap::new();
        for j in due {
            by_script.entry(j.path().into()).or_default().push(j);
        }
        for (path, group) in by_script {
            self.on_script(&path, move |s, jobs| group.iter().for_each(|j| s.run(jobs, j)));
        }
    }

    /// Trust scripts never seen before, block changed ones, pin missing ones as pending.
    /// A user's tab is only checked: its scripts need that user's own approval.
    fn check(&self) -> Result<(), String> {
        let db = Arc::new(self.shared.store.load()?);
        let scripts = unique_jobs(&self.jobs);
        let (tx, rx) = mpsc::channel();
        for &script in &scripts {
            let (tx, db, job) = (tx.clone(), db.clone(), script.clone());
            self.on_script(script.path(), move |s, jobs| {
                let _ = tx.send(s.check(&db, jobs, &job));
            });
        }
        drop(tx);
        // the scripts this tab's jobs run before the wait is over have been checked; a slow one
        // stays busy, so its jobs are skipped until its check is done
        let until = Instant::now() + CHECK_WAIT;
        let (mut n, mut failed) = ([0; 3], Ok(())); // ok, new, blocked
        while let Ok(r) = rx.recv_timeout(until.saturating_duration_since(Instant::now())) {
            match r {
                Ok(i) => n[i] += 1,
                Err(e) => {
                    n[2] += 1;
                    failed = Err(e);
                }
            }
        }
        let slow = scripts.len() - n.iter().sum::<usize>();
        let [ok, new, blocked] = n;
        let (file, user, jobs) = (self.file.display(), self.shared.store.tag(), self.jobs.len());
        log(NOTICE, &format!("LOADED tab={file}{user} jobs={jobs} ok={ok} new={new} blocked={blocked} slow={slow}"));
        failed
    }

    /// Reread the tab if it changed and check its scripts. A deleted tab has no jobs; a broken one
    /// keeps the old jobs and is tried again next minute.
    fn reload(&mut self) {
        let st = stamp(&self.file);
        if st == self.stamp {
            return;
        }
        let res = match load_tab(&self.file, self.shared.store.user.as_deref()) {
            Err(_) if st.is_none() => Ok(vec![]),
            r => r,
        };
        let res = res.and_then(|jobs| {
            self.jobs = Arc::new(jobs);
            self.check()
        });
        match res {
            Ok(()) => self.stamp = st, // only now: a failed load (LDAP down, ...) is retried
            Err(e) => log(ERR, &format!("RELOAD-FAILED tab={} error=\"{e}\"", self.file.display())),
        }
    }

    /// Daemon start: load the tab, then run its `@reboot` jobs if this is a new boot.
    fn start(&mut self, new_boot: bool) {
        self.reload();
        let reboot: Vec<Job> = self.jobs.iter().filter(|j| matches!(j.when, When::Reboot)).cloned().collect();
        if new_boot {
            self.run(reboot);
        } else if !reboot.is_empty() {
            let (n, user) = (reboot.len(), self.shared.store.tag());
            log(NOTICE, &format!("REBOOT-SKIPPED jobs={n}{user} reason=\"already ran this boot\""));
        }
    }

    /// One scheduler wake-up: reload the tab if it changed, then start what is due in `todo`.
    fn tick(&mut self, todo: &[(i64, bool, bool)]) {
        self.reload();
        let mut due = vec![];
        for &(minute, wild, fixed) in todo {
            let t = fields(minute);
            let hit = |j: &&Job| matches!(&j.when, When::Cron(c) if c.due(t) && (if c.wild { wild } else { fixed }));
            due.extend(self.jobs.iter().filter(hit).cloned());
        }
        self.run(due);
    }
}

fn stamp(path: &Path) -> Option<Stamp> {
    fs::metadata(path).ok().map(|m| (m.ino(), m.mtime(), m.mtime_nsec(), m.size()))
}

type Tabs = BTreeMap<String, Arc<Mutex<Tab>>>; // "" = system tab, else a user's own

/// As cron does, look for users' tabs every minute. Users get a tab once the admin creates
/// `<state>/users/NAME` for them (cronwatcher's `cron.allow`); only a root daemon can run their jobs.
fn scan_users(tabs: &mut Tabs, state: &Path) {
    if euid() != 0 {
        return;
    }
    let users = state.join("users");
    let names: Vec<String> = fs::read_dir(&users)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| valid_user(n))
        .collect();
    tabs.retain(|k, _| {
        let keep = k.is_empty() || names.contains(k);
        if !keep {
            log(NOTICE, &format!("DROPPED user={k} reason=\"{} is gone\"", users.join(k).display()));
        }
        keep
    });
    for name in names {
        let dir = users.join(&name);
        tabs.entry(name.clone()).or_insert_with(|| {
            let store = Store { dir: dir.clone(), user: Some(name) };
            Arc::new(Mutex::new(Tab::new(dir.join("tab"), store, vec![], None)))
        });
    }
}

/// Run `f` on every tab, each in a thread of its own: a user's tab on a hung filesystem stalls only
/// that user. A tab still busy since an earlier minute skips this one.
fn each_tab(tabs: &Tabs, f: impl Fn(&mut Tab) + Clone + Send + 'static) {
    for (name, tab) in tabs {
        let (name, tab, f) = (name.clone(), tab.clone(), f.clone());
        thread::spawn(move || {
            let mut t = match tab.try_lock() {
                Ok(t) => t,
                Err(TryLockError::Poisoned(p)) => p.into_inner(), // a minute that panicked: carry on
                Err(TryLockError::WouldBlock) => {
                    let who = if name.is_empty() { String::new() } else { format!(" user={name}") };
                    let why = "tab still at work since an earlier minute (hung filesystem?)";
                    return log(WARN, &format!("BUSY{who} reason=\"{why}\""));
                }
            };
            f(&mut t);
        });
    }
}

/// Local wall-clock minute (epoch shifted by the UTC offset), the clock cron schedules on:
/// DST shows up as this clock jumping.
fn wall_minute(epoch: u64) -> i64 {
    let t = epoch as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t, &mut tm) };
    (t + tm.tm_gmtoff).div_euclid(60)
}

/// [minute, hour, day of month, month 1-12, day of week 0-6] of a wall-clock minute.
fn fields(wall: i64) -> [u32; 5] {
    let t = (wall * 60) as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::gmtime_r(&t, &mut tm) };
    [tm.tm_min, tm.tm_hour, tm.tm_mday, tm.tm_mon + 1, tm.tm_wday].map(|v| v as u32)
}

/// cronie's handling of a wake-up at wall minute `cur` when `last` is done:
/// (new last, [(minute, run wildcard jobs, run fixed-time jobs)]).
fn steps(last: i64, cur: i64) -> (i64, Vec<(i64, bool, bool)>) {
    match cur - last {
        // woke up late: every missed minute
        1..=5 => (cur, (last + 1..=cur).map(|m| (m, true, true)).collect()),
        // DST began (or a short suspend): wildcard jobs once, fixed-time jobs for each skipped minute
        6..=180 => (cur, std::iter::once((cur, true, false)).chain((last + 1..=cur).map(|m| (m, false, true))).collect()),
        // DST ended: fixed-time jobs already ran at this wall time, so only wildcard ones,
        // and `last` waits until the clock has caught up
        -180..=0 => (last, vec![(cur, true, false)]),
        // the clock was set: carry on from now
        _ => (cur, vec![(cur, true, true)]),
    }
}

fn now() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default()
}

fn daemon(file: &Path, store: Store) -> Result<i32, String> {
    log(NOTICE, &format!("STARTING tab={} state={}", file.display(), store.dir.display()));
    // like cron's pid file: a second daemon on the same state would run every job twice
    store.mkdir()?;
    let lock_path = store.dir.join("lock");
    let lock = OpenOptions::new().write(true).create(true).truncate(false).mode(0o600).open(&lock_path);
    let lock = ctx(&lock_path, lock)?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(format!("{}: another cronwatcher runs with this state directory", lock_path.display()));
    }
    let state = store.dir.clone();
    let st = stamp(file);
    let jobs = load_tab(file, None)?; // a bad tab is fatal at startup, later it keeps the old jobs
    let system = Tab::new(file.into(), store, jobs, st);
    system.check()?;
    // always: also when no @reboot job exists yet, so one added later waits for the next boot
    let new_boot = system.shared.store.new_boot();
    let mut tabs = Tabs::from([(String::new(), Arc::new(Mutex::new(system)))]);
    scan_users(&mut tabs, &state);
    each_tab(&tabs, move |t| t.start(new_boot));

    let mut last = wall_minute(now().as_secs());
    let mut prev = last;
    loop {
        let t = now();
        thread::sleep(Duration::from_secs(60 - t.as_secs() % 60) - Duration::from_nanos(t.subsec_nanos().into()));
        let cur = wall_minute(now().as_secs());
        if cur == prev {
            continue; // woke up early in the same minute
        }
        prev = cur;
        scan_users(&mut tabs, &state);
        let (next, todo) = steps(last, cur);
        last = next;
        let todo = Arc::new(todo);
        each_tab(&tabs, move |t| t.tick(&todo));
    }
}

// ---------- admin commands ----------

fn status(tab: &Path, store: &Store) -> Result<i32, String> {
    let jobs = load_tab(tab, None)?;
    let db = store.load()?;
    let mut bad = 0;
    for job in unique_jobs(&jobs) {
        let path = job.path();
        match store.inspect(&db, job) {
            Ok(s) if s.ok() => println!("OK       {path}  {}", s.sha),
            Ok(s) if s.trusted.is_none() => {
                bad += 1;
                println!("NEW      {path}  {}", s.sha);
            }
            Ok(s) => {
                bad += 1;
                println!("CHANGED  {path}  {}", s.hashes());
                print!("{}", diff(store, path, &s));
            }
            Err(e) => {
                bad += 1;
                println!("MISSING  {e}");
            }
        }
    }
    Ok((bad > 0) as i32)
}

fn confirm(question: &str) -> bool {
    print!("{question}");
    let _ = io::stdout().flush();
    let mut answer = String::new();
    io::stdin().read_line(&mut answer).is_ok() && matches!(answer.trim(), "y" | "Y" | "yes")
}

/// Approvals happen in an admin shell, not in the daemon: send them to syslog/journald too.
fn audit(msg: &str) {
    if let Err(e) = Command::new("logger").args(["-t", "cronwatcher", "-p", "auth.notice", "--", msg]).status() {
        eprintln!("warning: audit log via logger failed: {e}");
    }
}

fn approve(tab: &Path, store: &Store, scripts: &[String], all: bool, yes: bool) -> Result<i32, String> {
    let jobs = load_tab(tab, None)?;
    let known = unique_jobs(&jobs);
    let targets: Vec<&Job> = if all {
        known
    } else {
        let find = |p: &String| known.iter().find(|j| j.path() == p).copied().ok_or(format!("{p}: not a job in {}", tab.display()));
        scripts.iter().map(find).collect::<Result<_, _>>()?
    };
    let db = store.load()?;
    let mut bad = 0; // missing or skipped: exit 1, like status
    for job in targets {
        let path = job.path();
        let seen = match store.inspect(&db, job) {
            Ok(s) => s,
            Err(e) => {
                bad += 1;
                println!("MISSING  {e}");
                continue;
            }
        };
        if seen.ok() {
            println!("OK       {path} (already trusted)");
            continue;
        }
        let what = if seen.trusted.is_some() { "CHANGED" } else { "NEW    " };
        println!("{what}  {path}  {}", seen.hashes());
        print!("{}", diff(store, path, &seen));
        if !yes && !confirm(&format!("Trust this version of {path}? [y/N] ")) {
            bad += 1;
            println!("skipped");
            continue;
        }
        // trust the bytes that were just shown, not whatever the file holds by now
        store.trust(path, &seen.bytes)?;
        let who = format!("uid={} sudo_user={}", unsafe { libc::getuid() }, env::var("SUDO_USER").unwrap_or("-".into()));
        audit(&format!("APPROVED job={path} {} {who}", seen.hashes()));
        println!("APPROVED {path}");
    }
    Ok((bad > 0) as i32)
}

/// `crontab -e`: edit a copy, install it only once it parses, then review its scripts.
fn edit(tab: &Path, store: &Store) -> Result<i32, String> {
    store.load()?; // a store we may not use: stop before touching anything
    let old = match fs::read(tab) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => vec![],
        r => ctx(tab, r)?,
    };
    let tmp = env::temp_dir().join(format!("cronwatcher-{}.tab", std::process::id()));
    let copied = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).and_then(|mut f| f.write_all(&old));
    ctx(&tmp, copied)?;
    let text = loop {
        let edited = Command::new("sh").args(["-c", "exec ${VISUAL:-${EDITOR:-vi}} \"$1\"", "sh"]).arg(&tmp).status();
        if !edited.is_ok_and(|s| s.success()) {
            break Err(format!("editor failed, {} not changed", tab.display()));
        }
        let text = fs::read(&tmp).unwrap_or_default();
        if text == old {
            break Ok(None);
        }
        match String::from_utf8(text).map_err(|_| "not UTF-8".to_string()).and_then(|t| check_tab(&t).map(|_| t)) {
            Ok(t) => break Ok(Some(t)),
            Err(e) => {
                println!("{}: {e}", tab.display());
                if !confirm("Edit again? [y/N] ") {
                    break Err(format!("{} not changed", tab.display()));
                }
            }
        }
    };
    // on any error the edited copy stays, as with crontab -e: an edit is never lost
    let kept = |e: String| format!("{e}; your version is in {}", tmp.display());
    let Some(text) = text.map_err(kept)? else {
        let _ = fs::remove_file(&tmp);
        println!("no changes");
        return Ok(0);
    };
    write_atomic(tab, text.as_bytes()).map_err(kept)?;
    let _ = fs::remove_file(&tmp);
    println!("installed {}", tab.display());
    approve(tab, store, &[], true, false)
}

fn usage(code: i32) -> ! {
    eprintln!("{USAGE}");
    exit(code)
}

fn main() {
    let (mut tab, mut state): (Option<PathBuf>, Option<PathBuf>) = (None, None);
    let (mut cmd, mut scripts, mut yes, mut all) = (None, vec![], false, false);
    let mut args = env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" => tab = Some(args.next().unwrap_or_else(|| usage(2)).into()),
            "-s" => state = Some(args.next().unwrap_or_else(|| usage(2)).into()),
            "-y" => yes = true,
            "--all" => all = true,
            "-h" | "--help" => usage(0),
            "status" | "approve" | "edit" if cmd.is_none() => cmd = Some(a.clone()),
            _ if a.starts_with('-') || cmd.is_none() => usage(2),
            _ => scripts.push(a),
        }
    }
    // users get their own tab and store by default, like `crontab`
    let root = euid() == 0;
    let state = match state {
        Some(s) => s,
        None if root => "/var/lib/cronwatcher".into(),
        None => match account(None) {
            Ok(a) => Path::new("/var/lib/cronwatcher/users").join(a.name),
            Err(e) => {
                log(ERR, &format!("FATAL {e}"));
                exit(1)
            }
        },
    };
    let tab = tab.unwrap_or_else(|| if root { "/etc/cronwatcher.tab".into() } else { state.join("tab") });
    // absolute: a user's diff runs in their home directory
    let abs = |p: PathBuf| std::path::absolute(&p).unwrap_or(p);
    let (tab, store) = (abs(tab), Store { dir: abs(state), user: None });
    let res = match cmd.as_deref() {
        None if !yes && !all => daemon(&tab, store),
        Some("status") if !yes && !all && scripts.is_empty() => status(&tab, &store),
        Some("approve") if all == scripts.is_empty() => approve(&tab, &store, &scripts, all, yes),
        Some("edit") if !yes && !all && scripts.is_empty() => edit(&tab, &store),
        _ => usage(2),
    };
    match res {
        Ok(code) => exit(code),
        Err(e) => {
            log(ERR, &format!("FATAL {e}"));
            exit(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(user: Option<String>, cmd: Vec<String>) -> Job {
        Job { when: When::Reboot, user, cmd, mailto: None, mail_always: false }
    }

    #[test]
    fn schedule() {
        assert_eq!(parse_field("*/15", 0, 59).unwrap(), 1 | 1 << 15 | 1 << 30 | 1 << 45);
        assert_eq!(parse_field("1-5,9", 0, 23).unwrap(), 0b10_0011_1110);
        assert!(parse_field("60", 0, 59).is_err() && parse_field("*/0", 0, 59).is_err() && parse_field("x", 0, 59).is_err());
        assert!(parse_field("0/15", 0, 59).is_err() && parse_field("5/1", 0, 59).is_err()); // as cronie
        let cron = |s: &str| match &parse_tab(&format!("{s} /bin/true")).unwrap()[0].when {
            When::Cron(c) => c.clone(),
            _ => panic!("not a cron line"),
        };
        let sunday = [0, 0, 11, 10, 0]; // [min, hour, mday, month, wday]
        assert!(cron("0 0 * * 7").due(sunday)); // 7 = Sunday
        assert!(!cron("0 0 * * 1").due(sunday));
        assert!(cron("0 0 1 * 0").due(sunday)); // both day fields set: either matches
        assert!(!cron("0 0 1 * *").due(sunday));
        assert!(cron("@daily").due([0, 0, 5, 3, 2]) && !cron("@daily").due([1, 0, 5, 3, 2]));
        assert!(cron("*/5 3 * * *").wild && cron("@hourly").wild && !cron("30 2 * * *").wild && !cron("@daily").wild);
        assert!(parse_tab("* * * * * relative.sh").is_err() && parse_tab("@often /bin/true").is_err());

        let job = |s: &str| parse_tab(s).map(|j| j.into_iter().next().unwrap());
        let j = job("5 5 * * * ageiger /home/a/run.sh --x").unwrap();
        assert_eq!(j.user.as_deref(), Some("ageiger"));
        assert_eq!(j.cmd, ["/home/a/run.sh", "--x"]);
        assert_eq!(job("@tamper www-data /bin/true").unwrap().user.as_deref(), Some("www-data"));
        assert!(job("* * * * * /bin/true").unwrap().user.is_none());
        assert!(job("* * * * * bob relative.sh").is_err()); // still an absolute command
        assert!(job("* * * * * Bob /bin/true").is_err()); // bad user name
        assert!(job("* * * * * bob").is_err()); // user without command
        assert!(job("* * * * * /bin/x --opt=1").is_ok()); // '=' in args is no setting

        // MAILTO/MAILON apply to the jobs below them
        let tab = "@daily /bin/a\nMAILTO=ops@example.com\nMAILON = always\n@daily /bin/b\nMAILTO=\"\"\n@daily /bin/c";
        let mail: Vec<_> = parse_tab(tab).unwrap().into_iter().map(|j| (j.mailto, j.mail_always)).collect();
        assert_eq!(mail, [(None, false), (Some("ops@example.com".into()), true), (None, true)]);
        assert!(parse_tab("MAILTO=-oQ/tmp/x").is_err() && parse_tab("MAILTO=a;b").is_err()); // cronie's safe_p
        assert!(parse_tab("MAILON=sometimes").is_err() && parse_tab("BASH_ENV=/tmp/x").is_err());
    }

    #[test]
    fn time_jumps() {
        assert_eq!(fields(0), [0, 0, 1, 1, 4]); // 1970-01-01 00:00, a Thursday
        assert_eq!(steps(10, 11), (11, vec![(11, true, true)]));
        assert_eq!(steps(10, 13), (13, vec![(11, true, true), (12, true, true), (13, true, true)])); // woke late
        // DST begins, 01:59 -> 03:00: wildcard jobs once, every skipped fixed-time minute runs
        let (last, todo) = steps(119, 180);
        assert_eq!(last, 180);
        assert_eq!(todo.iter().filter(|s| s.1).map(|s| s.0).collect::<Vec<_>>(), [180]);
        assert_eq!(todo.iter().filter(|s| s.2).map(|s| s.0).collect::<Vec<_>>(), (120..=180).collect::<Vec<_>>());
        // DST ends, 02:59 -> 02:00: wildcard only, until the clock passes 02:59 again
        assert_eq!(steps(179, 120), (179, vec![(120, true, false)]));
        assert_eq!(steps(179, 179), (179, vec![(179, true, false)]));
        assert_eq!(steps(179, 180), (180, vec![(180, true, true)]));
        assert_eq!(steps(10, 100_000), (100_000, vec![(100_000, true, true)])); // clock set
        assert_eq!(steps(100_000, 10), (10, vec![(10, true, true)]));
    }

    #[test]
    fn user_tab() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = env::temp_dir().join(format!("cronwatcher-tab-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let me = account(None).unwrap().name;
        let (tab, script) = (tmp.join("tab"), tmp.join("job.sh"));
        fs::write(&script, "#!/bin/sh\n").unwrap();
        fs::write(&tab, format!("@reboot {me} {}\n@daily {}\n", script.display(), script.display())).unwrap();
        fs::set_permissions(&tab, fs::Permissions::from_mode(0o644)).unwrap();
        let jobs = load_tab(&tab, Some(&me)).unwrap();
        assert!(jobs.iter().all(|j| j.user.as_deref() == Some(me.as_str()))); // runs as the owner

        // the daemon only checks a user's tab: nothing trusted on first sight, nothing written
        let store = Store { dir: tmp.join("state"), user: Some(me.clone()) };
        let t = Tab::new(tab.clone(), store, jobs, None);
        t.check().unwrap();
        assert!(!tmp.join("state").exists());
        assert_eq!(t.shared.alerted.lock().unwrap().len(), 1); // reported as pending

        fs::write(&tab, "@daily nobody /bin/true\n").unwrap();
        assert!(load_tab(&tab, Some(&me)).is_err()); // can't run as someone else
        if euid() == 0 {
            // the root daemon reads a user's files with that user's rights only
            let secret = tmp.join("secret");
            fs::write(&secret, "x").unwrap();
            fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(read_file(Some("nobody"), &secret, 10).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
            assert!(read_file(None, &secret, 10).is_ok());
            // so does root's own store for a job in the system tab that runs as a user
            let pinned = job(Some("nobody".into()), vec![secret.to_str().unwrap().into()]);
            let system = Store { dir: tmp.join("system"), user: None };
            assert!(system.inspect(&Db::new(), &pinned).err().unwrap().contains("Permission denied"));
        }
        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn user_job() {
        use std::os::unix::fs::PermissionsExt;
        // as root: really switch to nobody; otherwise the own account (no switch possible)
        let root = euid() == 0;
        let name = if root { "nobody".to_string() } else { account(None).unwrap().name };
        let a = account(Some(&name)).unwrap();
        let tmp = env::temp_dir().join(format!("cronwatcher-user-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o777)).unwrap();
        let (script, out) = (tmp.join("job.sh"), tmp.join("out"));
        fs::write(&script, "#!/bin/sh\necho \"$(id -u) $USER $HOME $PWD $PATH $(id -G)\" > \"$1\"\n").unwrap();
        let path = script.to_str().unwrap().to_string();
        let job = job(Some(name.clone()), vec![path.clone(), out.to_str().unwrap().into()]);
        let store = Store { dir: tmp.join("state"), user: None };
        store.trust(&path, &fs::read(&script).unwrap()).unwrap();
        assert!(verify_and_spawn(&store, &job, &[]).is_ok());
        let ran = (0..50)
            .find_map(|_| {
                thread::sleep(Duration::from_millis(100));
                fs::read_to_string(&out).ok().filter(|s| !s.is_empty())
            })
            .unwrap();
        let f: Vec<&str> = ran.split_whitespace().collect();
        let cwd = if a.home.is_dir() { a.home.to_str().unwrap() } else { "/" };
        // cron's clean environment, home as cwd
        assert_eq!(f[..5], [a.uid.to_string().as_str(), &name, a.home.to_str().unwrap(), cwd, "/usr/bin:/bin"]);
        if root {
            let mut got: Vec<u32> = f[5..].iter().map(|g| g.parse().unwrap()).collect();
            let mut want = a.groups.clone();
            got.sort_unstable();
            want.sort_unstable();
            want.dedup();
            assert_eq!(got, want); // exactly the account's groups, none of root's
        }
        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn verified_run() {
        let tmp = env::temp_dir().join(format!("cronwatcher-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let (script, out) = (tmp.join("job.sh"), tmp.join("out"));
        // no +x needed: the sealed memfd copy is what gets executed
        fs::write(&script, "#!/bin/sh\necho \"ran $CRONWATCHER_SCRIPT\" > \"$1\"\n").unwrap();
        let path = script.to_str().unwrap().to_string();
        let job = job(None, vec![path.clone(), out.to_str().unwrap().into()]);
        let store = Store { dir: tmp.join("state"), user: None };

        assert_eq!(verify_and_spawn(&store, &job, &[]).err().unwrap().event, "REFUSED"); // nothing trusted yet
        store.trust(&path, &fs::read(&script).unwrap()).unwrap();
        assert!(verify_and_spawn(&store, &job, &[]).is_ok());
        let ran = (0..50).find_map(|_| {
            thread::sleep(Duration::from_millis(100));
            fs::read_to_string(&out).ok().filter(|s| !s.is_empty())
        });
        assert_eq!(ran.unwrap(), format!("ran {path}\n"));
        // close-on-exec, so only the job's own child gets it (spawn clears the flag there)
        let fd = sealed_memfd(b"#!/bin/sh\n").unwrap();
        assert_ne!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC, 0);

        fs::write(&script, "#!/bin/sh\necho pwned > \"$1\"\n").unwrap();
        let r = verify_and_spawn(&store, &job, &[]).err().unwrap();
        assert_eq!(r.event, "REFUSED");
        assert!(diff(&store, &path, r.seen.as_ref().unwrap()).contains("+echo pwned"));

        // a FIFO in place of the script must be refused, not block the daemon
        fs::remove_file(&script).unwrap();
        assert_eq!(unsafe { libc::mkfifo(CString::new(path.clone()).unwrap().as_ptr(), 0o600) }, 0);
        let r = verify_and_spawn(&store, &job, &[]).err().unwrap();
        assert_eq!((r.event, r.detail.contains("not a regular file")), ("MISSING", true));
        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn pending() {
        let tmp = env::temp_dir().join(format!("cronwatcher-pending-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let script = tmp.join("later.sh");
        let path = script.to_str().unwrap().to_string();
        let job = job(None, vec![path.clone()]);
        let tab = || Tab::new(tmp.join("tab"), Store { dir: tmp.join("state"), user: None }, vec![job.clone()], None);

        tab().check().unwrap(); // missing: pinned, not trusted
        fs::write(&script, "#!/bin/sh\necho planted\n").unwrap();
        let t = tab();
        t.check().unwrap(); // appeared later: still not trusted
        let store = &t.shared.store;
        assert_eq!(store.load().unwrap()[&path], PENDING);
        let r = verify_and_spawn(store, &job, &[]).err().unwrap();
        assert_eq!((r.event, r.seen.unwrap().trusted), ("REFUSED", None));

        store.trust(&path, &fs::read(&script).unwrap()).unwrap(); // what `approve` does
        assert!(store.inspect(&store.load().unwrap(), &job).unwrap().ok());
        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn parallel_check() {
        let tmp = env::temp_dir().join(format!("cronwatcher-parallel-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        // same content: two threads trust the same blob at once
        let paths: Vec<String> = (0..8).map(|i| tmp.join(format!("{i}.sh")).to_str().unwrap().into()).collect();
        paths.iter().for_each(|p| fs::write(p, "#!/bin/sh\n").unwrap());
        let jobs = paths.iter().map(|p| job(None, vec![p.clone()])).collect();
        let t = Tab::new(tmp.join("tab"), Store { dir: tmp.join("state"), user: None }, jobs, None);
        t.check().unwrap();
        assert_eq!(t.shared.store.load().unwrap().len(), 8);

        // a script whose earlier read still hangs is skipped, not waited for
        t.shared.busy.lock().unwrap().insert(paths[0].clone());
        let t0 = Instant::now();
        t.check().unwrap();
        t.run(vec![job(None, vec![paths[0].clone()])]);
        assert!(t0.elapsed() < CHECK_WAIT);
        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn reboot_once() {
        let tmp = env::temp_dir().join(format!("cronwatcher-boot-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let store = Store { dir: tmp.join("state"), user: None };
        assert!(store.new_boot() && !store.new_boot());
        fs::write(store.dir.join("boot_id"), "an earlier boot\n").unwrap();
        assert!(store.new_boot() && !store.new_boot());
        fs::remove_dir_all(&tmp).unwrap();
    }
}
