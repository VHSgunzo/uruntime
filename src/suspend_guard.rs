//! Suspend guard.
//!
//! Suspend freezes every user process at once. An app caught waiting for its
//! FUSE driver, itself already frozen, sits in an uninterruptible wait and
//! cannot be frozen, so the suspend fails. An app freezes fine while its driver
//! still runs. So the app gets a systemd scope of its own, away from the driver,
//! and that scope is frozen under a logind delay lock before the suspend
//! freezes the rest.
//!
//! Best effort throughout: without a systemd user manager or logind the app
//! runs as it did before, unguarded. The guard never prints.

use std::{
    collections::VecDeque,
    env,
    fmt::Write as _,
    fs::{metadata, read_dir, read_link, read_to_string, File},
    io::{Error, ErrorKind, Read, Result},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{fs::MetadataExt, net::UnixStream},
    },
    path::{Path, PathBuf},
    thread::{sleep, Builder, JoinHandle},
    time::{Duration, Instant},
};

use nix::libc;

use crate::dbus::{
    Connection, Message, Reader, Writer, BUS, BUS_PATH, ERROR, METHOD_RETURN, SIGNAL,
};

const SYSTEMD: &str = "org.freedesktop.systemd1";
const SYSTEMD_PATH: &str = "/org/freedesktop/systemd1";
const SYSTEMD_MANAGER: &str = "org.freedesktop.systemd1.Manager";
const LOGIND: &str = "org.freedesktop.login1";
const LOGIND_PATH: &str = "/org/freedesktop/login1";
const LOGIND_MANAGER: &str = "org.freedesktop.login1.Manager";
const PROPERTIES: &str = "org.freedesktop.DBus.Properties";
const BUSY: &str = "org.freedesktop.login1.OperationInProgress";
const SYSTEM_BUS: &str = "unix:path=/run/dbus/system_bus_socket";
const SLEEP_SIGNAL: &str = "type='signal',sender='org.freedesktop.login1',\
    interface='org.freedesktop.login1.Manager',member='PrepareForSleep',\
    path='/org/freedesktop/login1'";

/// Inode of the initial PID namespace (`PROC_PID_INIT_INO`).
const INIT_PID_NAMESPACE: u64 = 0xEFFF_FFFC;
/// The app waits this long at the gate, whatever the guard thread does.
const GATE_TIMEOUT_MS: libc::c_int = 2000;
/// Time for the bus logins and for the move into the scope. The app may wait
/// at the gate for both, so together they stay below the gate's own limit.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(1000);
const SCOPE_TIMEOUT: Duration = Duration::from_millis(900);
const CALL_TIMEOUT: Duration = Duration::from_secs(2);
const FREEZE_TIMEOUT: Duration = Duration::from_millis(900);
/// Kept back from logind's delay limit for the freeze itself. An app needed up
/// to 212 ms to settle with a cold DwarFS cache.
const FREEZE_MARGIN: Duration = Duration::from_secs(1);
const LOCK_POLL: Duration = Duration::from_millis(50);
const SCOPE_POLL: Duration = Duration::from_millis(1);
const MAX_ESCAPED_NAME: usize = 180;
/// Scopes of this name hold a FUSE driver. No guard ever freezes one.
const DRIVER_SCOPE_PREFIX: &str = "uruntime-fuse-";

/// The child's side of the launch gate.
#[derive(Clone, Copy)]
pub(crate) struct Gate {
    pid_writer: RawFd,
    reader: RawFd,
    writer: RawFd,
}

impl Gate {
    /// Runs in the forked child before exec, so async-signal-safe calls only.
    /// Reports the PID, then waits until the guard has moved the child into its
    /// scope. Everything the app forks later is born there.
    pub(crate) fn hold(self) -> Result<()> {
        unsafe {
            // Our own copy of the write end would keep the gate shut.
            libc::close(self.writer);
            let pid = libc::getpid();
            libc::write(
                self.pid_writer,
                (&raw const pid).cast(),
                size_of::<libc::pid_t>(),
            );
            let mut gate = libc::pollfd {
                fd: self.reader,
                events: libc::POLLIN,
                revents: 0,
            };
            while libc::poll(&mut gate, 1, GATE_TIMEOUT_MS) < 0
                && Error::last_os_error().kind() == ErrorKind::Interrupted
            {}
        }
        Ok(())
    }
}

pub(crate) struct SuspendGuard {
    /// Returns the cgroup of the app's scope, if the guard got that far.
    thread: JoinHandle<Option<String>>,
    stop: OwnedFd,
    /// The gate and the child's pipe ends, kept open until the child has been
    /// forked with them. `None` for a guard that took over a running app.
    child: Option<(Gate, OwnedFd, OwnedFd)>,
}

struct Setup {
    session: String,
    system: String,
    uid: u32,
    name: String,
    /// Where the image is mounted.
    mount: PathBuf,
    /// The FUSE driver, when this launch started it.
    driver: Option<u32>,
}

/// What a guard needs to know before it starts. `None` when there is nothing
/// to guard with, or the guard was switched off.
fn setup(runtime_name: &str, mount: &Path, driver: Option<u32>) -> Option<Setup> {
    if env::var("NO_SUSPEND_GUARD").is_ok_and(|value| value == "1") {
        return None;
    }
    // cgroup v2 only, and only where a PID means the same to systemd as here.
    if !read_to_string("/proc/self/cgroup")
        .ok()?
        .starts_with("0::/")
        || metadata("/proc/self/ns/pid").ok()?.ino() != INIT_PID_NAMESPACE
    {
        return None;
    }
    let variable = |name| {
        env::var(name)
            .ok()
            .filter(|value: &String| !value.is_empty())
    };
    Some(Setup {
        session: variable("DBUS_SESSION_BUS_ADDRESS")
            .or_else(|| Some(format!("unix:path={}/bus", variable("XDG_RUNTIME_DIR")?)))?,
        system: variable("DBUS_SYSTEM_BUS_ADDRESS").unwrap_or_else(|| SYSTEM_BUS.into()),
        uid: unsafe { libc::getuid() },
        name: Path::new(runtime_name)
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        mount: mount.to_path_buf(),
        driver,
    })
}

/// Starts the guard for the app about to be spawned from `mount`. `driver` is
/// the FUSE driver when this launch started one.
pub(crate) fn start(runtime_name: &str, mount: &Path, driver: Option<u32>) -> Option<SuspendGuard> {
    spawn(setup(runtime_name, mount, driver)?)
}

/// Takes the guard over in the detached cleanup process. The main process of
/// the app has exited, and the first guard with it, but other processes of the
/// app may run on for hours. `scope` is what `stop` returned.
pub(crate) fn keep(runtime_name: &str, mount: &Path, scope: String) -> Option<SuspendGuard> {
    let setup = setup(runtime_name, mount, None)?;
    let (stop_reader, stop) = crate::create_lifetime_pipe().ok()?;
    let thread = Builder::new()
        .name("suspend-guard".into())
        .spawn(move || {
            let (system, session, max_delay) = connect(&setup, Instant::now() + CONNECT_TIMEOUT)?;
            let mut guard = Guard {
                system,
                session,
                app: None,
                scope,
                mount: setup.mount,
                max_delay,
                lock: None,
                frozen: Vec::new(),
                stop: stop_reader,
            };
            guard.run();
            Some(guard.scope)
        })
        .ok()?;
    Some(SuspendGuard {
        thread,
        stop,
        child: None,
    })
}

fn spawn(setup: Setup) -> Option<SuspendGuard> {
    let (pid_reader, pid_writer) = crate::create_lifetime_pipe().ok()?;
    let (gate_reader, gate_writer) = crate::create_lifetime_pipe().ok()?;
    let (stop_reader, stop) = crate::create_lifetime_pipe().ok()?;
    let gate = Gate {
        pid_writer: pid_writer.as_raw_fd(),
        reader: gate_reader.as_raw_fd(),
        writer: gate_writer.as_raw_fd(),
    };
    let thread = Builder::new()
        .name("suspend-guard".into())
        .spawn(move || run(&setup, pid_reader, gate_writer, stop_reader))
        .ok()?;
    Some(SuspendGuard {
        thread,
        stop,
        child: Some((gate, pid_writer, gate_reader)),
    })
}

impl SuspendGuard {
    pub(crate) fn gate(&self) -> Option<Gate> {
        self.child.as_ref().map(|(gate, ..)| *gate)
    }

    /// Ends the guard once the app's main process has exited, or was never
    /// started. The thread owns the delay lock and both bus sockets, so none
    /// of them outlives this. Returns the cgroup of the app's scope when there
    /// is one, for `keep`.
    pub(crate) fn stop(self) -> Option<String> {
        // The PID pipe goes first as well: when no child was ever forked, the
        // thread is still waiting on it and would never be joined.
        drop((self.stop, self.child));
        self.thread.join().ok().flatten()
    }
}

fn run(setup: &Setup, pid_reader: OwnedFd, gate_writer: OwnedFd, stop: OwnedFd) -> Option<String> {
    let buses = connect(setup, Instant::now() + CONNECT_TIMEOUT);
    // Read in every case: until then the child may not have been forked, and
    // it closes its copy of the gate by number.
    let pid = read_pid(pid_reader);
    let deadline = Instant::now() + SCOPE_TIMEOUT;
    let guard = buses
        .zip(pid)
        .and_then(|((system, session, max_delay), pid)| {
            Guard::new(system, session, max_delay, pid, setup, deadline, stop)
        });
    // The app starts now, guarded or not.
    drop(gate_writer);
    let mut guard = guard?;
    if let Some(driver) = setup.driver {
        guard.shelter_driver(driver, &setup.name);
    }
    guard.run();
    Some(guard.scope)
}

/// Both buses, and logind's delay limit as proof that logind is there.
fn connect(setup: &Setup, deadline: Instant) -> Option<(Connection, Connection, Duration)> {
    let mut system = Connection::open(&setup.system, setup.uid, receive, deadline).ok()?;
    let mut body = Writer::default();
    body.string(LOGIND_MANAGER);
    body.string("InhibitDelayMaxUSec");
    let reply = system
        .call(
            Message::call(LOGIND, LOGIND_PATH, PROPERTIES, "Get").with_body("ss", body),
            deadline,
        )
        .ok()
        .filter(|reply| reply.kind == METHOD_RETURN)?;
    let mut value = reply.reader();
    if value.signature()? != "t" {
        return None;
    }
    let max_delay = Duration::from_micros(value.u64()?);
    let session = Connection::open(&setup.session, setup.uid, receive, deadline).ok()?;
    Some((system, session, max_delay))
}

fn read_pid(reader: OwnedFd) -> Option<u32> {
    let mut pid = [0; size_of::<libc::pid_t>()];
    File::from(reader).read_exact(&mut pid).ok()?;
    u32::try_from(libc::pid_t::from_ne_bytes(pid))
        .ok()
        .filter(|pid| *pid != 0)
}

/// `recvmsg` that keeps descriptors passed with `SCM_RIGHTS`, close-on-exec.
fn receive(stream: &UnixStream, buffer: &mut [u8], fds: &mut VecDeque<OwnedFd>) -> Result<usize> {
    let mut control = [0u64; 16];
    let mut iov = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen = size_of_val(&control) as _;
    let read = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut header, libc::MSG_CMSG_CLOEXEC) };
    if read < 0 {
        return Err(Error::last_os_error());
    }
    unsafe {
        let mut entry = libc::CMSG_FIRSTHDR(&header);
        while !entry.is_null() {
            if (*entry).cmsg_level == libc::SOL_SOCKET && (*entry).cmsg_type == libc::SCM_RIGHTS {
                let length =
                    ((*entry).cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize);
                let data = libc::CMSG_DATA(entry).cast::<RawFd>();
                for index in 0..length / size_of::<RawFd>() {
                    fds.push_back(OwnedFd::from_raw_fd(data.add(index).read_unaligned()));
                }
            }
            entry = libc::CMSG_NXTHDR(&header, entry);
        }
    }
    Ok(read as usize)
}

/// Waits for `stop` to close, for `bus` to become readable, or for `timeout`.
/// True when it was `stop`: the runtime wants the guard to end.
fn stopped(stop: &OwnedFd, bus: Option<RawFd>, timeout: Option<Duration>) -> bool {
    let mut fds = [
        libc::pollfd {
            fd: stop.as_raw_fd(),
            events: 0,
            revents: 0,
        },
        libc::pollfd {
            fd: bus.unwrap_or(-1),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let timeout = timeout.map_or(-1, |timeout| timeout.as_millis() as libc::c_int);
    loop {
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout) };
        if ready >= 0 || Error::last_os_error().kind() != ErrorKind::Interrupted {
            let [stop, _] = fds;
            return ready < 0 || stop.revents != 0;
        }
    }
}

/// The unit a `/proc/<pid>/cgroup` line of cgroup v2 ends in.
fn unit_of(cgroup: &str) -> &str {
    cgroup.trim_end().rsplit('/').next().unwrap_or_default()
}

fn cgroup_in_scope(cgroup: &str, scope: &str) -> bool {
    cgroup
        .trim_end()
        .strip_suffix(scope)
        .is_some_and(|parent| parent.ends_with('/'))
}

fn in_scope(pid: u32, scope: &str) -> bool {
    read_to_string(format!("/proc/{pid}/cgroup"))
        .is_ok_and(|cgroup| cgroup_in_scope(&cgroup, scope))
}

/// The cgroup of a process, as a path below the cgroup root.
fn cgroup_of_pid(pid: u32) -> Option<String> {
    let line = read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    Some(line.trim_end().strip_prefix("0::")?.to_string())
}

/// The image's file name as part of a unit name, escaped as systemd does.
fn escaped(name: &str) -> String {
    let mut escaped = String::new();
    for byte in name.bytes() {
        if escaped.len() > MAX_ESCAPED_NAME {
            break;
        }
        if byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'.') {
            escaped.push(char::from(byte));
        } else {
            let _ = write!(escaped, "\\x{byte:02x}");
        }
    }
    escaped
}

/// Desktops name app scopes `app-<launcher>-<id>-<pid>.scope`, and portals read
/// the app id back from that. So the id of the runtime's own launch scope is
/// carried over. Anything else gets a name built from the image's file name.
/// That includes a runtime started by another guarded app: the scope it sits
/// in then carries that app's file name, not a launcher's id.
fn scope_name(own_unit: &str, name: &str, pid: u32) -> String {
    let launch_id = own_unit
        .strip_prefix("app-")
        .and_then(|unit| unit.strip_suffix(".scope"))
        .and_then(|unit| unit.rsplit_once('-'))
        .filter(|(id, number)| {
            !id.is_empty()
                && !id.starts_with("uruntime-")
                && !number.is_empty()
                && number.bytes().all(|byte| byte.is_ascii_digit())
        });
    match launch_id {
        Some((id, _)) => format!("app-{id}-{pid}.scope"),
        None => format!("app-uruntime-{}-{pid}.scope", escaped(name)),
    }
}

/// Parent PID from the text of `/proc/<pid>/stat`. The command name in it may
/// itself hold spaces and brackets.
fn parent_of(stat: &str) -> Option<u32> {
    stat.rsplit_once(')')?
        .1
        .split_ascii_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// `root` and every process descended from it, given (pid, parent) pairs.
fn descendants(root: u32, parents: &[(u32, u32)]) -> Vec<u32> {
    let mut found = vec![root];
    let mut next = 0;
    while let Some(&parent) = found.get(next) {
        let children: Vec<u32> = parents
            .iter()
            .filter(|(pid, of)| *of == parent && !found.contains(pid))
            .map(|(pid, _)| *pid)
            .collect();
        found.extend(children);
        next += 1;
    }
    found
}

/// Every process in procfs that `select` has an answer for.
fn processes<T>(select: impl Fn(&Path) -> Option<T>) -> Vec<(u32, T)> {
    read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let pid = entry.file_name().to_str()?.parse().ok()?;
            Some((pid, select(&entry.path())?))
        })
        .collect()
}

/// `root` and its live descendants.
fn process_tree(root: u32) -> Vec<u32> {
    let parents = processes(|process| parent_of(&read_to_string(process.join("stat")).ok()?));
    descendants(root, &parents)
}

/// The processes whose executable lies in `mount`. This finds what a process
/// tree no longer shows: a process whose parent has exited.
fn running_from(mount: &Path) -> Vec<u32> {
    processes(|process| {
        read_link(process.join("exe"))
            .ok()?
            .starts_with(mount)
            .then_some(())
    })
    .into_iter()
    .map(|(pid, ())| pid)
    .collect()
}

/// True when a process in this cgroup has `/dev/fuse` open: it serves a mount.
fn serves_fuse(cgroup: &str) -> bool {
    read_to_string(format!("/sys/fs/cgroup{cgroup}/cgroup.procs")).is_ok_and(|members| {
        members.lines().any(|pid| {
            read_dir(format!("/proc/{pid}/fd"))
                .into_iter()
                .flatten()
                .flatten()
                .any(|fd| read_link(fd.path()).is_ok_and(|target| target == Path::new("/dev/fuse")))
        })
    })
}

/// What to freeze, as cgroups: the scope made for the app, and every other
/// scope a process of the app now lives in. Chromium moves its main process
/// into a scope of its own, for one. Never the cgroup the runtime itself is
/// in, never one that is not a scope, and never a scope made for a FUSE driver.
fn units_to_freeze(
    scope: &str,
    own: &str,
    app_cgroups: impl IntoIterator<Item = String>,
) -> Vec<String> {
    let mut freeze = vec![scope.to_string()];
    for cgroup in app_cgroups {
        let unit = unit_of(&cgroup);
        if unit.ends_with(".scope")
            && cgroup != own
            && !unit.starts_with(DRIVER_SCOPE_PREFIX)
            && !freeze.contains(&cgroup)
        {
            freeze.push(cgroup);
        }
    }
    freeze
}

/// Asks the user manager for a scope in `app.slice` that holds `pids`. The
/// call only queues the job; the move itself follows.
fn start_scope(session: &mut Connection, scope: &str, pids: &[u32], deadline: Instant) -> bool {
    let mut body = Writer::default();
    body.string(scope);
    body.string("fail");
    body.array(8, |properties| {
        properties.align(8);
        properties.string("PIDs");
        properties.signature("au");
        properties.array(4, |list| pids.iter().for_each(|pid| list.u32(*pid)));
        // A failed scope would otherwise keep its name taken.
        properties.align(8);
        properties.string("CollectMode");
        properties.signature("s");
        properties.string("inactive-or-failed");
        properties.align(8);
        properties.string("Slice");
        properties.signature("s");
        properties.string("app.slice");
    });
    body.array(8, |_| {});
    let call = Message::call(SYSTEMD, SYSTEMD_PATH, SYSTEMD_MANAGER, "StartTransientUnit")
        .with_body("ssa(sv)a(sa(sv))", body);
    session
        .call(call, deadline)
        .is_ok_and(|reply| reply.kind == METHOD_RETURN)
}

/// PIDs that hold a delay lock on sleep, from a `ListInhibitors` reply.
fn delay_lock_pids(body: &mut Reader) -> Option<Vec<u32>> {
    let length = body.u32()? as usize;
    body.align(8)?;
    let end = body.position().checked_add(length)?;
    let mut pids = Vec::new();
    while body.position() < end {
        body.align(8)?;
        let what = body.string()?;
        body.string()?;
        body.string()?;
        let mode = body.string()?;
        body.u32()?;
        let pid = body.u32()?;
        if mode == "delay" && what.split(':').any(|what| what == "sleep") {
            pids.push(pid);
        }
    }
    Some(pids)
}

#[derive(Eq, PartialEq)]
enum Lock {
    Taken,
    /// logind is in the middle of a suspend and hands out no locks.
    Busy,
    Failed,
}

struct Guard {
    system: Connection,
    session: Connection,
    /// The app's main process, while this guard lives beside it.
    app: Option<u32>,
    /// The cgroup of the scope made for the app.
    scope: String,
    /// Where the image is mounted.
    mount: PathBuf,
    max_delay: Duration,
    lock: Option<OwnedFd>,
    /// The cgroups this guard has frozen, in that order.
    frozen: Vec<String>,
    stop: OwnedFd,
}

impl Guard {
    /// Moves `pid` into a scope of its own. The caller holds `pid` back from
    /// exec meanwhile, so nothing it forks is left behind.
    fn new(
        system: Connection,
        mut session: Connection,
        max_delay: Duration,
        pid: u32,
        setup: &Setup,
        deadline: Instant,
        stop: OwnedFd,
    ) -> Option<Self> {
        // Read as late as possible: a desktop launcher moves the runtime into
        // its launch scope a moment after starting it.
        let scope = scope_name(
            unit_of(&read_to_string("/proc/self/cgroup").ok()?),
            &setup.name,
            pid,
        );
        if !start_scope(&mut session, &scope, &[pid], deadline) {
            return None;
        }
        while !in_scope(pid, &scope) {
            if Instant::now() >= deadline {
                return None;
            }
            sleep(SCOPE_POLL);
        }
        Some(Self {
            system,
            session,
            app: Some(pid),
            scope: cgroup_of_pid(pid)?,
            mount: setup.mount.clone(),
            max_delay,
            lock: None,
            frozen: Vec::new(),
            stop,
        })
    }

    /// Moves this launch's FUSE driver into a scope of its own. Left where it
    /// was started, it can sit inside the app scope of another guarded app that
    /// launched this one, and that app's guard would freeze it under clients
    /// that still run. The app is not held back for this.
    fn shelter_driver(&mut self, driver: u32, name: &str) {
        let scope = format!("{DRIVER_SCOPE_PREFIX}{}-{driver}.scope", escaped(name));
        start_scope(
            &mut self.session,
            &scope,
            &process_tree(driver),
            Instant::now() + CALL_TIMEOUT,
        );
    }

    /// The cgroups to freeze right now: those of `units_to_freeze` for the
    /// app's process tree and for everything that runs from the mount, less
    /// any that holds a FUSE server. Freezing a server under clients that
    /// still run is the very deadlock this guard is there to prevent.
    fn freeze_set(&self) -> Vec<String> {
        let mut app = self.app.map(process_tree).unwrap_or_default();
        app.extend(running_from(&self.mount));
        let own = cgroup_of_pid(std::process::id()).unwrap_or_default();
        let mut freeze =
            units_to_freeze(&self.scope, &own, app.into_iter().filter_map(cgroup_of_pid));
        freeze.retain(|cgroup| !serves_fuse(cgroup));
        freeze
    }

    fn run(&mut self) {
        // Subscribed before the lock is taken, so no suspend slips between.
        let mut rule = Writer::default();
        rule.string(SLEEP_SIGNAL);
        let subscribed = self.system.call(
            Message::call(BUS, BUS_PATH, BUS, "AddMatch").with_body("s", rule),
            Instant::now() + CALL_TIMEOUT,
        );
        if subscribed.is_ok_and(|reply| reply.kind == METHOD_RETURN)
            && self.take_lock() != Lock::Failed
        {
            while let Some(sleeping) = self.next_sleep_signal() {
                if sleeping {
                    self.on_sleep();
                } else {
                    self.on_resume();
                }
            }
        }
        // The app is never left frozen.
        self.thaw();
    }

    fn thaw(&mut self) {
        for cgroup in std::mem::take(&mut self.frozen).iter().rev() {
            self.unit_call("ThawUnit", unit_of(cgroup));
        }
    }

    /// Blocks until logind announces a suspend (`true`) or a resume (`false`).
    /// `None` when the guard has to end.
    fn next_sleep_signal(&mut self) -> Option<bool> {
        loop {
            if let Some(message) = self.system.pending.pop_front() {
                if let Some(sleeping) = self.sleep_signal(&message) {
                    return Some(sleeping);
                }
                continue;
            }
            // What is buffered already comes first: poll would not see it.
            if let Some(message) = self.system.read(Instant::now()).ok()? {
                self.system.pending.push_back(message);
                continue;
            }
            if stopped(&self.stop, Some(self.system.stream().as_raw_fd()), None) {
                return None;
            }
            if let Some(message) = self.system.read(Instant::now() + CALL_TIMEOUT).ok()? {
                self.system.pending.push_back(message);
            }
        }
    }

    fn sleep_signal(&mut self, message: &Message) -> Option<bool> {
        if message.kind != SIGNAL
            || message.member != "PrepareForSleep"
            || message.interface != LOGIND_MANAGER
            || message.path != LOGIND_PATH
        {
            return None;
        }
        // Any client of the system bus may send this signal straight to us.
        // Only the one from logind itself counts.
        let mut name = Writer::default();
        name.string(LOGIND);
        let owner = self
            .system
            .call(
                Message::call(BUS, BUS_PATH, BUS, "GetNameOwner").with_body("s", name),
                Instant::now() + CALL_TIMEOUT,
            )
            .ok()
            .filter(|reply| reply.kind == METHOD_RETURN)?;
        if owner.reader().string()? != message.sender {
            return None;
        }
        Some(message.reader().u32()? != 0)
    }

    fn on_sleep(&mut self) {
        if self.frozen.is_empty() {
            // An app may handle the suspend itself under a delay lock of its
            // own, as Electron does. Freezing sooner would cut that short and
            // leave its lock held until logind's limit.
            let deadline = Instant::now() + self.max_delay.saturating_sub(FREEZE_MARGIN);
            let units = self.freeze_set();
            while self.app_holds_delay_lock(&units, deadline) {
                if stopped(&self.stop, None, Some(LOCK_POLL)) {
                    self.release_lock();
                    return;
                }
            }
            // Looked up again: the app may have forked or moved meanwhile.
            for cgroup in self.freeze_set() {
                if self.unit_call("FreezeUnit", unit_of(&cgroup)) {
                    self.frozen.push(cgroup);
                }
            }
        }
        // Only now may the suspend go on and freeze the driver.
        self.release_lock();
    }

    fn on_resume(&mut self) {
        // A failed suspend is retried at once while the lid stays closed, and
        // logind hands out no delay locks meanwhile. Staying frozen lets that
        // retry succeed. The resume that follows it thaws.
        if self.take_lock() == Lock::Busy {
            return;
        }
        self.thaw();
    }

    fn take_lock(&mut self) -> Lock {
        self.release_lock();
        let mut body = Writer::default();
        for text in [
            "sleep",
            "uruntime",
            "Freeze the app ahead of its FUSE mount",
            "delay",
        ] {
            body.string(text);
        }
        let call =
            Message::call(LOGIND, LOGIND_PATH, LOGIND_MANAGER, "Inhibit").with_body("ssss", body);
        let Ok(reply) = self.system.call(call, Instant::now() + CALL_TIMEOUT) else {
            return Lock::Failed;
        };
        if reply.kind == ERROR && reply.error_name == BUSY {
            return Lock::Busy;
        }
        // The newest descriptor is the lock. An older one would be a lock whose
        // reply came too late, and holding it would delay every suspend.
        self.lock = self.system.fds.pop_back();
        self.system.fds.clear();
        if self.lock.is_some() {
            Lock::Taken
        } else {
            Lock::Failed
        }
    }

    fn release_lock(&mut self) {
        self.lock = None;
        self.system.fds.clear();
    }

    /// True while a process in one of the cgroups `units` holds a delay lock and
    /// `deadline` has not passed. That is the app itself, or the guard of an app it
    /// launched: the inner app is then frozen before the outer one.
    fn app_holds_delay_lock(&mut self, units: &[String], deadline: Instant) -> bool {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        let call = Message::call(LOGIND, LOGIND_PATH, LOGIND_MANAGER, "ListInhibitors");
        let Ok(reply) = self.system.call(call, deadline.min(now + CALL_TIMEOUT)) else {
            return false;
        };
        reply.kind == METHOD_RETURN
            && delay_lock_pids(&mut reply.reader()).is_some_and(|pids| {
                pids.into_iter()
                    .filter_map(cgroup_of_pid)
                    .any(|cgroup| units.contains(&cgroup))
            })
    }

    /// `FreezeUnit` or `ThawUnit` on a unit. True on success and on a timeout:
    /// a freeze still under way has to be undone on resume all the same.
    fn unit_call(&mut self, method: &str, unit: &str) -> bool {
        let mut body = Writer::default();
        body.string(unit);
        let call =
            Message::call(SYSTEMD, SYSTEMD_PATH, SYSTEMD_MANAGER, method).with_body("s", body);
        match self.session.call(call, Instant::now() + FREEZE_TIMEOUT) {
            Ok(reply) => reply.kind == METHOD_RETURN,
            Err(error) => error.kind() == ErrorKind::TimedOut,
        }
    }
}
