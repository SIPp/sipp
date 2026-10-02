//! Linux and the other Unix: the C library itself, with an eventfd and an
//! epoll set on Linux, a pipe and a kqueue on macOS and the BSDs.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::time::Duration;

pub use libc::{
    c_short, AF_INET, AF_INET6, getsockopt, nfds_t, poll, pollfd, setsockopt, socklen_t, EADDRINUSE, EAGAIN, ECONNREFUSED, ECONNRESET, EINPROGRESS, EINTR, EINVAL, ENOBUFS,
    ENOTCONN, EPIPE, POLLERR, POLLHUP, POLLIN, POLLOUT, SOL_SOCKET, SO_ERROR,
};
/// What socket2::SockRef takes.
pub use std::os::fd::AsFd as AsSock;
pub use std::os::fd::{AsRawFd, RawFd};

/// What wakes a media thread up: an eventfd.
#[cfg(target_os = "linux")]
pub struct Wake(OwnedFd);

#[cfg(target_os = "linux")]
impl Wake {
    pub fn new() -> Wake {
        // SAFETY: a new eventfd, which the OwnedFd then owns.
        let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        assert!(fd >= 0, "eventfd: {}", io::Error::last_os_error());
        // SAFETY: fd is ours alone.
        Wake(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    pub fn wake(&self) {
        let one = 1u64;
        // SAFETY: 8 bytes into our own eventfd; a full count (never
        // reached) means the thread is awake anyway.
        unsafe { libc::write(self.0.as_raw_fd(), (&one as *const u64).cast(), 8) };
    }

    /// Once the thread is up.
    pub fn clear(&self) {
        let mut count = 0u64;
        // SAFETY: 8 bytes into a u64 of ours.
        unsafe { libc::read(self.0.as_raw_fd(), (&mut count as *mut u64).cast(), 8) };
    }

    pub fn fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// The sockets a media thread waits on, each with a key for its events:
/// an epoll set.
#[cfg(target_os = "linux")]
pub struct MediaPoll {
    epfd: OwnedFd,
    events: Vec<libc::epoll_event>,
    pwait2: bool,
}

#[cfg(target_os = "linux")]
impl MediaPoll {
    pub fn new() -> MediaPoll {
        // SAFETY: a new epoll set, which the OwnedFd then owns.
        let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        assert!(epfd >= 0, "epoll_create1: {}", io::Error::last_os_error());
        // SAFETY: epfd is ours alone.
        let epfd = unsafe { OwnedFd::from_raw_fd(epfd) };
        MediaPoll { epfd, events: vec![libc::epoll_event { events: 0, u64: 0 }; 64], pwait2: true }
    }

    /// Wait on `fd` for `key`'s events, or no longer.
    pub fn watch(&mut self, fd: RawFd, key: u64, on: bool) {
        let mut ev = libc::epoll_event { events: libc::EPOLLIN as u32, u64: key };
        let op = if on { libc::EPOLL_CTL_ADD } else { libc::EPOLL_CTL_DEL };
        // SAFETY: our own epoll set and socket.
        unsafe { libc::epoll_ctl(self.epfd.as_raw_fd(), op, fd, &mut ev) };
    }

    /// The keys of what is readable, once something is or `wait` is over
    /// (None: until then): epoll_pwait2() for its timeout in nanoseconds,
    /// else (before Linux 5.11) epoll_wait() rounded up to the millisecond.
    pub fn wait(&mut self, wait: Option<Duration>, mut each: impl FnMut(u64)) {
        let (epfd, max) = (self.epfd.as_raw_fd(), self.events.len() as libc::c_int);
        let n = if self.pwait2 {
            let ts = wait.map(|d| libc::timespec { tv_sec: d.as_secs() as libc::time_t, tv_nsec: d.subsec_nanos() as libc::c_long });
            let tp = ts.as_ref().map_or(std::ptr::null(), |t| t as *const libc::timespec);
            // SAFETY: events is a live array of max events.
            let n = unsafe { libc::epoll_pwait2(epfd, self.events.as_mut_ptr(), max, tp, std::ptr::null()) };
            if n < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ENOSYS) {
                self.pwait2 = false;
                return;
            }
            n
        } else {
            let ms = wait.map_or(-1, |d| d.as_micros().div_ceil(1000).min(i32::MAX as u128) as libc::c_int);
            // SAFETY: as above.
            unsafe { libc::epoll_wait(epfd, self.events.as_mut_ptr(), max, ms) }
        };
        for ev in &self.events[..n.max(0) as usize] {
            each(ev.u64);
        }
    }
}

/// What wakes a media thread up where there is no eventfd: a pipe, whose
/// read end the thread waits on.
#[cfg(not(target_os = "linux"))]
pub struct Wake {
    read: OwnedFd,
    write: OwnedFd,
}

#[cfg(not(target_os = "linux"))]
impl Wake {
    pub fn new() -> Wake {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: pipe() fills the two fds it is given.
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert!(ret == 0, "pipe: {}", io::Error::last_os_error());
        for fd in fds {
            // SAFETY: fcntl() on our own new pipe.
            unsafe {
                libc::fcntl(fd, libc::F_SETFL, libc::fcntl(fd, libc::F_GETFL) | libc::O_NONBLOCK);
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            }
        }
        // SAFETY: both fds are ours alone.
        unsafe { Wake { read: OwnedFd::from_raw_fd(fds[0]), write: OwnedFd::from_raw_fd(fds[1]) } }
    }

    pub fn wake(&self) {
        // SAFETY: one byte into our own pipe; a full one means the thread
        // has wake-ups waiting already.
        unsafe { libc::write(self.write.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
    }

    /// Once the thread is up.
    pub fn clear(&self) {
        let mut buf = [0u8; 64];
        // SAFETY: into a buffer of ours, of its length.
        while unsafe { libc::read(self.read.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
    }

    pub fn fd(&self) -> RawFd {
        self.read.as_raw_fd()
    }
}

/// The sockets a media thread waits on, each with a key for its events:
/// a kqueue.
#[cfg(not(target_os = "linux"))]
pub struct MediaPoll {
    kq: OwnedFd,
    events: Vec<libc::kevent>,
}

#[cfg(not(target_os = "linux"))]
impl MediaPoll {
    pub fn new() -> MediaPoll {
        // SAFETY: a new kqueue, which the OwnedFd then owns.
        let kq = unsafe { libc::kqueue() };
        assert!(kq >= 0, "kqueue: {}", io::Error::last_os_error());
        // SAFETY: as above; a zeroed kevent is an empty one.
        let (kq, empty) = unsafe {
            libc::fcntl(kq, libc::F_SETFD, libc::FD_CLOEXEC);
            (OwnedFd::from_raw_fd(kq), std::mem::zeroed::<libc::kevent>())
        };
        MediaPoll { kq, events: vec![empty; 64] }
    }

    /// Wait on `fd` for `key`'s events, or no longer.
    pub fn watch(&mut self, fd: RawFd, key: u64, on: bool) {
        // SAFETY: a zeroed kevent is an empty one.
        let mut ev: libc::kevent = unsafe { std::mem::zeroed() };
        ev.ident = fd as _;
        ev.filter = libc::EVFILT_READ;
        ev.flags = if on { libc::EV_ADD } else { libc::EV_DELETE };
        ev.udata = key as usize as _;
        // SAFETY: our own kqueue and socket, one change and no events.
        unsafe { libc::kevent(self.kq.as_raw_fd(), &ev, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
    }

    /// The keys of what is readable, once something is or `wait` is over
    /// (None: until then), to the nanosecond.
    pub fn wait(&mut self, wait: Option<Duration>, mut each: impl FnMut(u64)) {
        let ts = wait.map(|d| libc::timespec { tv_sec: d.as_secs() as libc::time_t, tv_nsec: d.subsec_nanos() as libc::c_long });
        let tp = ts.as_ref().map_or(std::ptr::null(), |t| t as *const libc::timespec);
        // SAFETY: events is a live array of its length.
        let n = unsafe { libc::kevent(self.kq.as_raw_fd(), std::ptr::null(), 0, self.events.as_mut_ptr(), self.events.len() as libc::c_int, tp) };
        for ev in &self.events[..n.max(0) as usize] {
            each(ev.udata as usize as u64);
        }
    }
}

/// A media thread's: no signal for it, which the main thread takes.
pub fn block_signals() {
    // SAFETY: a signal set of ours, for this thread only.
    unsafe {
        let mut all: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut all);
        libc::pthread_sigmask(libc::SIG_BLOCK, &all, std::ptr::null_mut());
    }
}

/// WTERMSIG(): the signal that killed a child with no exit code.
pub fn exit_signal(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status.signal().unwrap_or(0)
}

/// localtime_r(), and the UTC offset in seconds.
pub fn localtime(t: i64) -> (libc::tm, i64) {
    // SAFETY: localtime_r() fills the zeroed tm it is given.
    let tm = unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&(t as libc::time_t), &mut tm);
        tm
    };
    let off = tm.tm_gmtoff as i64;
    (tm, off)
}

/// The home directory of a user, from getpwnam_r(): None if there is no
/// such user, or the error.
pub fn user_home(name: &str) -> Option<Result<String, std::io::Error>> {
    let name = std::ffi::CString::new(name).ok()?;
    // -1 is no limit, as on musl: as much as glibc suggests.
    // SAFETY: sysconf() takes any name.
    let size = usize::try_from(unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) }).ok().filter(|&n| n > 0).unwrap_or(16384);
    let mut buf = vec![0 as libc::c_char; size];
    // SAFETY: a zeroed passwd is valid; getpwnam_r() gets a
    // NUL-terminated name and a buffer of its length, which the passwd it
    // fills points into, and pw_dir is read while buf lives.
    unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut result = std::ptr::null_mut();
        let ret = libc::getpwnam_r(name.as_ptr(), &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result);
        if result.is_null() {
            return (ret != 0).then(|| Err(std::io::Error::from_raw_os_error(ret)));
        }
        Some(Ok(std::ffi::CStr::from_ptr(pwd.pw_dir).to_string_lossy().into_owned()))
    }
}

/// Random bytes from getrandom(): false if it gave none.
#[cfg(target_os = "linux")]
pub fn random_bytes(buf: &mut [u8]) -> bool {
    // SAFETY: getrandom() writes at most buf.len() bytes into buf.
    unsafe { libc::getrandom(buf.as_mut_ptr().cast(), buf.len(), 0) == buf.len() as isize }
}

/// Random bytes from getentropy(), 256 at most a call: false if it gave
/// none.
#[cfg(not(target_os = "linux"))]
pub fn random_bytes(buf: &mut [u8]) -> bool {
    // SAFETY: getentropy() fills each chunk, of its length.
    buf.chunks_mut(256).all(|c| unsafe { libc::getentropy(c.as_mut_ptr().cast(), c.len()) } == 0)
}

/// The size of stdio's buffer for a file, as glibc's _IO_file_doallocate():
/// its st_blksize, up to BUFSIZ.
pub fn stdio_buffer_size(file: &std::fs::File) -> usize {
    use std::os::unix::fs::MetadataExt;
    match file.metadata().map(|m| m.blksize()) {
        Ok(n) if n > 0 && n < 8192 => n as usize,
        _ => 8192,
    }
}

/// A plugin library, and its symbols: dlopen() and dlsym().
pub struct Library(*mut libc::c_void);

// SAFETY: a library handle, which dlsym() may use from any thread.
unsafe impl Send for Library {}
unsafe impl Sync for Library {}

impl Library {
    pub fn open(path: &str) -> Result<Library, String> {
        let p = std::ffi::CString::new(path).map_err(|e| e.to_string())?;
        // SAFETY: a NUL-terminated path.
        let h = unsafe { libc::dlopen(p.as_ptr(), libc::RTLD_NOW) };
        if h.is_null() { Err(dlerror()) } else { Ok(Library(h)) }
    }

    pub fn symbol(&self, name: &str) -> Result<*mut libc::c_void, String> {
        let n = std::ffi::CString::new(name).map_err(|e| e.to_string())?;
        // SAFETY: our library's handle and a NUL-terminated name.
        let f = unsafe { libc::dlsym(self.0, n.as_ptr()) };
        if f.is_null() { Err(dlerror()) } else { Ok(f) }
    }
}

fn dlerror() -> String {
    // SAFETY: dlerror() returns a NUL-terminated message, or null.
    let e = unsafe { libc::dlerror() };
    if e.is_null() {
        return "not found".into();
    }
    // SAFETY: as above.
    unsafe { std::ffi::CStr::from_ptr(e) }.to_string_lossy().into_owned()
}

/// The soft limit on open files, raised to the hard limit (macOS takes
/// at most OPEN_MAX, 10240, which libc doesn't export).
pub fn raise_nofile_limit() -> Option<u64> {
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit() fills our rlimit.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } < 0 {
        return None;
    }
    #[cfg(target_os = "macos")]
    let max = lim.rlim_max.min(10240);
    #[cfg(not(target_os = "macos"))]
    let max = lim.rlim_max;
    let raised = libc::rlimit { rlim_cur: max, rlim_max: lim.rlim_max };
    // SAFETY: setrlimit() reads our rlimit.
    if max > lim.rlim_cur && unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } == 0 {
        lim.rlim_cur = max;
    }
    Some(lim.rlim_cur)
}

/// What a run needs first: nothing, on Unix.
pub fn init() {}

/// stdin in SIPp's cbreak mode: non-blocking, and a terminal also without
/// line buffering or echo; restored on drop.
pub struct Terminal {
    /// The terminal's settings, when stdin is one.
    saved: Option<libc::termios>,
    flags: libc::c_int,
}

impl Terminal {
    pub fn open() -> Option<Terminal> {
        let fd = libc::STDIN_FILENO;
        // SAFETY: termios and fcntl calls on our own stdin.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags == -1 {
                return None;
            }
            let mut saved: libc::termios = std::mem::zeroed();
            let saved = (libc::isatty(fd) != 0 && libc::tcgetattr(fd, &mut saved) == 0).then_some(saved);
            if let Some(saved) = saved {
                let mut raw = saved;
                raw.c_lflag &= !(libc::ICANON | libc::ECHO);
                raw.c_cc[libc::VMIN] = 0;
                raw.c_cc[libc::VTIME] = 0;
                libc::tcsetattr(fd, libc::TCSANOW, &raw);
            }
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            Some(Terminal { saved, flags })
        }
    }

    /// What was typed since the last call, into `buf`.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        // Not std::io::stdin(): its buffer stays allocated until exit.
        // SAFETY: reading into our own buffer.
        let n = unsafe { libc::read(libc::STDIN_FILENO, buf.as_mut_ptr().cast(), buf.len()) };
        usize::try_from(n).unwrap_or(0)
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let fd = libc::STDIN_FILENO;
        // SAFETY: restoring what open() changed.
        unsafe {
            if let Some(saved) = &self.saved {
                libc::tcsetattr(fd, libc::TCSANOW, saved);
            }
            libc::fcntl(fd, libc::F_SETFL, self.flags);
        }
    }
}
