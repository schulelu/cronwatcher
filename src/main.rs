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
//! the root daemon verifies the script itself, then runs it as that user (all
//! of its groups, HOME/USER/LOGNAME, cwd = home). So a user's own script is
//! pinned by root without root ever running it.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::ffi::{CStr, CString};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio, exit};
use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{env, thread};

const USAGE: &str = "\
usage: cronwatcher [-c TAB] [-s STATEDIR]                 run the scheduler
       cronwatcher [-c TAB] [-s STATEDIR] status          show trust state of every job script
       cronwatcher [-c TAB] [-s STATEDIR] approve [-y] (--all | SCRIPT...)
                                                          review diff, trust current version
defaults: TAB=/etc/cronwatcher.tab STATEDIR=/var/lib/cronwatcher";

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
    for line in msg.lines() {
        if *JOURNAL {
            eprintln!("<{level}>{line}");
        } else {
            eprintln!("{line}");
        }
    }
}

fn ctx<T>(p: impl AsRef<Path>, r: io::Result<T>) -> Result<T, String> {
    r.map_err(|e| format!("{}: {e}", p.as_ref().display()))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
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
}

#[derive(Clone)]
struct Job {
    when: When,
    user: Option<String>, // run as this account; None = as the daemon
    cmd: Vec<String>,
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
            None => (num(range)?, num(range)?), // ponytail: "5/15" means just 5, no month/day names
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
    Ok(Cron { mask, dom_star: fields[2].starts_with('*'), dow_star: fields[4].starts_with('*') })
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
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let err = |e: String| format!("line {}: {e}", n + 1);
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
            Some(p) if p.starts_with('/') => jobs.push(Job { when, user, cmd: cmd.iter().map(|s| s.to_string()).collect() }),
            _ => return Err(err("command must be an absolute path".into())),
        }
    }
    Ok(jobs)
}

/// POSIX-portable account names (what useradd accepts by default).
fn valid_user(u: &str) -> bool {
    u.len() <= 32
        && u.starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
        && u.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

struct Account {
    uid: libc::uid_t,
    gid: libc::gid_t,
    home: PathBuf,
    groups: Vec<libc::gid_t>,
}

/// Look the account up now (not at tab load), so a changed uid or group list applies on the next run.
fn account(name: &str) -> Result<Account, String> {
    let cname = CString::new(name).map_err(|_| format!("bad user name '{name}'"))?;
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16384];
    let mut res: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwnam_r(cname.as_ptr(), &mut pw, buf.as_mut_ptr(), buf.len(), &mut res) };
    if rc != 0 || res.is_null() {
        return Err(format!("unknown user '{name}'"));
    }
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
    Ok(Account { uid: pw.pw_uid, gid: pw.pw_gid, home, groups })
}

/// Every distinct script, `@tamper` first so the hook is trusted before it can fire.
fn unique_paths(jobs: &[Job]) -> Vec<&str> {
    let mut paths: Vec<&str> = vec![];
    for j in jobs.iter().filter(|j| matches!(j.when, When::Tamper)).chain(jobs) {
        if !paths.contains(&j.path()) {
            paths.push(j.path());
        }
    }
    paths
}

// ---------- trust ----------

/// Whoever can write the tab or the trust store decides what runs, so refuse
/// anything not owned by root/us or writable by group/others.
fn check_owner(path: &Path, meta: &fs::Metadata) -> Result<(), String> {
    let me = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != me {
        return Err(format!("{}: owned by uid {}, must be root or uid {me}", path.display(), meta.uid()));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!("{}: writable by group/others (mode {:o})", path.display(), meta.mode() & 0o7777));
    }
    Ok(())
}

fn load_tab(path: &Path) -> Result<Vec<Job>, String> {
    let mut f = ctx(path, File::open(path))?;
    check_owner(path, &ctx(path, f.metadata())?)?; // fstat of the opened file, no swap window
    let mut text = String::new();
    ctx(path, f.read_to_string(&mut text))?;
    let jobs = parse_tab(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    // fail at start, not at 3am: every account must exist, and only root can switch to it
    let me = unsafe { libc::geteuid() };
    for u in jobs.iter().filter_map(|j| j.user.as_deref()) {
        let a = account(u).map_err(|e| format!("{}: {e}", path.display()))?;
        if me != 0 && a.uid != me {
            return Err(format!("{}: job runs as '{u}', which needs cronwatcher running as root", path.display()));
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
}

impl Store {
    fn load(&self) -> Result<Db, String> {
        match fs::metadata(&self.dir) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Db::new()),
            r => check_owner(&self.dir, &ctx(&self.dir, r)?)?,
        }
        let path = self.dir.join("trusted");
        let mut f = match File::open(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Db::new()),
            r => ctx(&path, r)?,
        };
        check_owner(&path, &ctx(&path, f.metadata())?)?;
        let mut text = String::new();
        ctx(&path, f.read_to_string(&mut text))?;
        Ok(text.lines().filter_map(|l| l.split_once("  ")).map(|(sha, p)| (p.into(), sha.into())).collect())
    }

    fn blob(&self, sha: &str) -> PathBuf {
        self.dir.join("blobs").join(sha)
    }

    /// Record `bytes` as the trusted version of `path`, keeping a copy for later diffs.
    fn trust(&self, path: &str, bytes: &[u8]) -> Result<String, String> {
        let sha = sha256(bytes);
        let blobs = self.dir.join("blobs");
        ctx(&blobs, DirBuilder::new().recursive(true).mode(0o700).create(&blobs))?;
        write_atomic(&blobs.join(&sha), bytes)?; // ponytail: blobs never pruned, one small file per approved version
        self.record(path, &sha)?;
        Ok(sha)
    }

    fn record(&self, path: &str, sha: &str) -> Result<(), String> {
        ctx(&self.dir, DirBuilder::new().recursive(true).mode(0o700).create(&self.dir))?;
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
        let saved = ctx(&self.dir, DirBuilder::new().recursive(true).mode(0o700).create(&self.dir))
            .and_then(|_| write_atomic(&mark, id.as_bytes()));
        if let Err(e) = saved {
            log(WARN, &format!("boot marker not saved, @reboot jobs will run again on restart: {e}"));
        }
        true
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

fn inspect(db: &Db, path: &str) -> Result<Seen, String> {
    // whoever can write the script could swap in a FIFO or /dev/zero: that must not
    // hang or exhaust the daemon, so open non-blocking and take regular files only
    let f = OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY).open(path);
    let f = ctx(path, f)?;
    if !ctx(path, f.metadata())?.is_file() {
        return Err(format!("{path}: not a regular file"));
    }
    let mut bytes = vec![];
    ctx(path, f.take(MAX_SCRIPT + 1).read_to_end(&mut bytes))?;
    if bytes.len() as u64 > MAX_SCRIPT {
        return Err(format!("{path}: larger than {} MiB", MAX_SCRIPT >> 20));
    }
    let trusted = db.get(path).filter(|t| *t != PENDING).cloned();
    Ok(Seen { sha: sha256(&bytes), trusted, bytes })
}

/// `diff -u` of the trusted copy against what was read (whole file if nothing is trusted yet).
fn diff(store: &Store, path: &str, seen: &Seen) -> String {
    let old = seen.trusted.as_deref().map(|t| store.blob(t)).filter(|b| b.exists());
    let child = Command::new("diff")
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
    // no MFD_CLOEXEC: a #! interpreter re-opens /proc/self/fd/N after exec
    let mut fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING | libc::MFD_EXEC) };
    if fd < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
        // kernel < 6.3 has no MFD_EXEC; memfds are executable there anyway
        fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING) };
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

/// Run the verified snapshot. Output and exit status go to the log.
fn spawn(job: &Job, seen: &Seen, env: &[(&str, &str)]) {
    let path = job.path().to_string();
    let started = (|| -> io::Result<_> {
        let fd = sealed_memfd(&seen.bytes)?;
        let (out, w) = io::pipe()?;
        let mut cmd = Command::new(format!("/proc/self/fd/{}", fd.as_raw_fd()));
        cmd.arg0(&path)
            .args(&job.cmd[1..])
            .env("CRONWATCHER_SCRIPT", &path) // scripts see $0 = /proc/self/fd/N
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .stdout(w.try_clone()?)
            .stderr(w);
        if let Some(name) = &job.user {
            let a = account(name).map_err(io::Error::other)?;
            let cwd = if a.home.is_dir() { a.home.clone() } else { PathBuf::from("/") };
            cmd.env("HOME", &a.home).env("USER", name).env("LOGNAME", name).current_dir(cwd);
            if unsafe { libc::geteuid() } == 0 {
                let (uid, gid, groups) = (a.uid, a.gid, a.groups);
                // groups, then gid, then uid: after setuid there is no way back. Only
                // async-signal-safe syscalls here (this runs between fork and exec).
                unsafe {
                    cmd.pre_exec(move || {
                        if libc::setgroups(groups.len(), groups.as_ptr()) != 0
                            || libc::setgid(gid) != 0
                            || libc::setuid(uid) != 0
                        {
                            return Err(io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
            }
        }
        Ok((cmd.spawn()?, out))
    })(); // our memfd and pipe write end close here, the child keeps its copies
    let (mut child, out) = match started {
        Ok(v) => v,
        Err(e) => {
            let hint = if e.raw_os_error() == Some(libc::ENOEXEC) { " hint=\"missing #! line?\"" } else { "" };
            return log(ERR, &format!("SPAWN-FAILED job={path} error=\"{e}\"{hint}"));
        }
    };
    let pid = child.id();
    let user = job.user.as_deref().map_or(String::new(), |u| format!(" user={u}"));
    log(INFO, &format!("RUN job={path}{user} pid={pid} sha={}", seen.sha));
    let name = Path::new(&path).file_name().map_or(path.clone(), |n| n.to_string_lossy().into());
    let t0 = Instant::now();
    thread::spawn(move || {
        for line in BufReader::new(out).split(b'\n').map_while(Result::ok) {
            log(INFO, &format!("[{name} {pid}] {}", String::from_utf8_lossy(&line)));
        }
        let status = child.wait();
        let dur = t0.elapsed();
        match status {
            Ok(s) if s.success() => log(INFO, &format!("DONE job={path} pid={pid} status=0 dur={dur:.1?}")),
            Ok(s) => {
                let how = s.code().map_or(format!("signal={}", s.signal().unwrap_or(0)), |c| format!("status={c}"));
                log(WARN, &format!("FAIL job={path} pid={pid} {how} dur={dur:.1?}"));
            }
            Err(e) => log(ERR, &format!("WAIT-FAILED job={path} pid={pid} error=\"{e}\"")),
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
    let seen = inspect(&db, job.path()).map_err(|e| refused("MISSING", format!("error=\"{e}\"")))?;
    if !seen.ok() {
        return Err(Refused { event: "REFUSED", detail: seen.hashes(), seen: Some(seen) });
    }
    spawn(job, &seen, env);
    Ok(())
}

// ---------- daemon ----------

struct Daemon {
    store: Store,
    tamper: Option<Job>,
    alerted: HashMap<String, String>, // path -> content already reported
}

impl Daemon {
    fn run(&mut self, job: &Job) {
        match verify_and_spawn(&self.store, job, &[]) {
            Ok(()) => {
                self.alerted.remove(job.path());
            }
            Err(r) => self.refused(job.path(), r),
        }
    }

    fn refused(&mut self, path: &str, r: Refused) {
        let hint = match r.seen {
            Some(_) => format!(" hint=\"review and trust with: cronwatcher approve {path}\""),
            None => String::new(),
        };
        log(ERR, &format!("{} job={path} {}{hint}", r.event, r.detail));
        // diff and @tamper hook once per distinct bad content, not every minute
        let key = r.seen.as_ref().map_or("-".to_string(), |s| s.sha.clone());
        if self.alerted.get(path) == Some(&key) {
            return;
        }
        self.alerted.insert(path.into(), key);
        if let Some(seen) = &r.seen {
            let d = diff(&self.store, path, seen);
            for line in d.lines().take(50) {
                log(ERR, &format!("  | {line}"));
            }
            if d.lines().count() > 50 {
                log(ERR, &format!("  | ... {} more lines, see: cronwatcher status", d.lines().count() - 50));
            }
        }
        let Some(hook) = &self.tamper else { return };
        if hook.path() == path {
            return; // a broken hook can't report itself
        }
        let reason = format!("{} {}", r.event, r.detail);
        let env = [("CRONWATCHER_TAMPERED", path), ("CRONWATCHER_REASON", &reason)];
        if let Err(h) = verify_and_spawn(&self.store, hook, &env) {
            log(ERR, &format!("{} job={} (tamper hook) {}", h.event, hook.path(), h.detail));
        }
    }

    /// Trust scripts never seen before, block changed ones, pin missing ones as pending.
    fn startup(&mut self, jobs: &[Job]) -> Result<(), String> {
        let db = self.store.load()?;
        let (mut ok, mut new, mut blocked) = (0, 0, 0);
        for path in unique_paths(jobs) {
            match inspect(&db, path) {
                Ok(s) if !db.contains_key(path) => {
                    self.store.trust(path, &s.bytes)?;
                    log(NOTICE, &format!("TRUSTED-NEW job={path} sha={}", s.sha));
                    new += 1;
                }
                Ok(s) if s.ok() => {
                    log(INFO, &format!("OK job={path} sha={}", s.sha));
                    ok += 1;
                }
                Ok(s) => {
                    blocked += 1;
                    let event = if s.trusted.is_none() { "PENDING" } else { "CHANGED" };
                    self.refused(path, Refused { event, detail: s.hashes(), seen: Some(s) });
                }
                Err(e) => {
                    blocked += 1;
                    // otherwise whatever shows up here later would be trusted unseen on the next start
                    if !db.contains_key(path) {
                        self.store.record(path, PENDING)?;
                    }
                    self.refused(path, Refused { event: "MISSING", detail: format!("error=\"{e}\""), seen: None });
                }
            }
        }
        log(NOTICE, &format!("STARTED jobs={} ok={ok} new={new} blocked={blocked}", jobs.len()));
        Ok(())
    }
}

fn local_time(epoch: u64) -> [u32; 5] {
    let t = epoch as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t, &mut tm) };
    [tm.tm_min, tm.tm_hour, tm.tm_mday, tm.tm_mon + 1, tm.tm_wday].map(|v| v as u32)
}

fn now() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default()
}

fn daemon(tab: &Path, store: Store) -> Result<i32, String> {
    let jobs = load_tab(tab)?;
    log(NOTICE, &format!("STARTING tab={} state={} jobs={}", tab.display(), store.dir.display(), jobs.len()));
    let tamper = jobs.iter().find(|j| matches!(j.when, When::Tamper)).cloned();
    let mut d = Daemon { store, tamper, alerted: HashMap::new() };
    d.startup(&jobs)?;

    let reboot: Vec<&Job> = jobs.iter().filter(|j| matches!(j.when, When::Reboot)).collect();
    if reboot.is_empty() || d.store.new_boot() {
        for job in reboot {
            d.run(job);
        }
    } else {
        log(NOTICE, &format!("REBOOT-SKIPPED jobs={} reason=\"already ran this boot\"", reboot.len()));
    }
    let mut last = 0;
    loop {
        let t = now();
        thread::sleep(Duration::from_secs(60 - t.as_secs() % 60) - Duration::from_nanos(t.subsec_nanos().into()));
        let minute = now().as_secs() / 60;
        if minute == last {
            continue; // ponytail: clock stepped back replays minutes, stepped forward skips them; no catch-up
        }
        last = minute;
        let t = local_time(minute * 60);
        for job in &jobs {
            if let When::Cron(c) = &job.when
                && c.due(t)
            {
                d.run(job);
            }
        }
    }
}

// ---------- admin commands ----------

fn status(tab: &Path, store: &Store) -> Result<i32, String> {
    let jobs = load_tab(tab)?;
    let db = store.load()?;
    let mut bad = 0;
    for path in unique_paths(&jobs) {
        match inspect(&db, path) {
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
    let jobs = load_tab(tab)?;
    let known = unique_paths(&jobs);
    let targets: Vec<&str> = if all { known.clone() } else { scripts.iter().map(String::as_str).collect() };
    if let Some(p) = targets.iter().find(|p| !known.contains(p)) {
        return Err(format!("{p}: not a job in {}", tab.display()));
    }
    let db = store.load()?;
    for path in targets {
        let seen = match inspect(&db, path) {
            Ok(s) => s,
            Err(e) => {
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
            println!("skipped");
            continue;
        }
        // trust the bytes that were just shown, not whatever the file holds by now
        store.trust(path, &seen.bytes)?;
        let who = format!("uid={} sudo_user={}", unsafe { libc::getuid() }, env::var("SUDO_USER").unwrap_or("-".into()));
        audit(&format!("APPROVED job={path} {} {who}", seen.hashes()));
        println!("APPROVED {path}");
    }
    Ok(0)
}

fn usage(code: i32) -> ! {
    eprintln!("{USAGE}");
    exit(code)
}

fn main() {
    let mut tab = PathBuf::from("/etc/cronwatcher.tab");
    let mut state = PathBuf::from("/var/lib/cronwatcher");
    let (mut cmd, mut scripts, mut yes, mut all) = (None, vec![], false, false);
    let mut args = env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" => tab = args.next().unwrap_or_else(|| usage(2)).into(),
            "-s" => state = args.next().unwrap_or_else(|| usage(2)).into(),
            "-y" => yes = true,
            "--all" => all = true,
            "-h" | "--help" => usage(0),
            "status" | "approve" if cmd.is_none() => cmd = Some(a.clone()),
            _ if a.starts_with('-') || cmd.is_none() => usage(2),
            _ => scripts.push(a),
        }
    }
    let store = Store { dir: state };
    let res = match cmd.as_deref() {
        None if !yes && !all => daemon(&tab, store),
        Some("status") if !yes && !all && scripts.is_empty() => status(&tab, &store),
        Some("approve") if all == scripts.is_empty() => approve(&tab, &store, &scripts, all, yes),
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

    #[test]
    fn schedule() {
        assert_eq!(parse_field("*/15", 0, 59).unwrap(), 1 | 1 << 15 | 1 << 30 | 1 << 45);
        assert_eq!(parse_field("1-5,9", 0, 23).unwrap(), 0b10_0011_1110);
        assert!(parse_field("60", 0, 59).is_err() && parse_field("*/0", 0, 59).is_err() && parse_field("x", 0, 59).is_err());
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
    }

    #[test]
    fn user_job() {
        use std::os::unix::fs::PermissionsExt;
        // as root: really switch to nobody; otherwise the own account (no switch possible)
        let root = unsafe { libc::geteuid() } == 0;
        let name = if root {
            "nobody".to_string()
        } else {
            String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout).unwrap().trim().to_string()
        };
        let a = account(&name).unwrap();
        let tmp = env::temp_dir().join(format!("cronwatcher-user-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o777)).unwrap();
        let (script, out) = (tmp.join("job.sh"), tmp.join("out"));
        fs::write(&script, "#!/bin/sh\necho \"$(id -u) $USER $HOME $PWD $(id -G)\" > \"$1\"\n").unwrap();
        let path = script.to_str().unwrap().to_string();
        let job = Job { when: When::Reboot, user: Some(name.clone()), cmd: vec![path.clone(), out.to_str().unwrap().into()] };
        let store = Store { dir: tmp.join("state") };
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
        assert_eq!(f[..4], [a.uid.to_string().as_str(), &name, a.home.to_str().unwrap(), cwd]);
        if root {
            let mut got: Vec<u32> = f[4..].iter().map(|g| g.parse().unwrap()).collect();
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
        let job = Job { when: When::Reboot, user: None, cmd: vec![path.clone(), out.to_str().unwrap().into()] };
        let store = Store { dir: tmp.join("state") };

        assert_eq!(verify_and_spawn(&store, &job, &[]).err().unwrap().event, "REFUSED"); // nothing trusted yet
        store.trust(&path, &fs::read(&script).unwrap()).unwrap();
        assert!(verify_and_spawn(&store, &job, &[]).is_ok());
        let ran = (0..50).find_map(|_| {
            thread::sleep(Duration::from_millis(100));
            fs::read_to_string(&out).ok().filter(|s| !s.is_empty())
        });
        assert_eq!(ran.unwrap(), format!("ran {path}\n"));

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
        let job = Job { when: When::Reboot, user: None, cmd: vec![path.clone()] };
        let daemon = || Daemon { store: Store { dir: tmp.join("state") }, tamper: None, alerted: HashMap::new() };

        daemon().startup(std::slice::from_ref(&job)).unwrap(); // missing: pinned, not trusted
        fs::write(&script, "#!/bin/sh\necho planted\n").unwrap();
        let mut d = daemon();
        d.startup(std::slice::from_ref(&job)).unwrap(); // appeared later: still not trusted
        assert_eq!(d.store.load().unwrap()[&path], PENDING);
        let r = verify_and_spawn(&d.store, &job, &[]).err().unwrap();
        assert_eq!((r.event, r.seen.unwrap().trusted), ("REFUSED", None));

        d.store.trust(&path, &fs::read(&script).unwrap()).unwrap(); // what `approve` does
        assert!(inspect(&d.store.load().unwrap(), &path).unwrap().ok());
        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn reboot_once() {
        let tmp = env::temp_dir().join(format!("cronwatcher-boot-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let store = Store { dir: tmp.join("state") };
        assert!(store.new_boot() && !store.new_boot());
        fs::write(store.dir.join("boot_id"), "an earlier boot\n").unwrap();
        assert!(store.new_boot() && !store.new_boot());
        fs::remove_dir_all(&tmp).unwrap();
    }
}
