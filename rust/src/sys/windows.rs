//! Windows: Winsock and Win32 under the Unix names.

use std::io;
use std::net::UdpSocket;
use std::time::Duration;
use windows_sys::Win32::Networking::WinSock as ws;

/// A socket's handle.
pub type RawFd = ws::SOCKET;

/// What socket2::SockRef takes.
pub use std::os::windows::io::AsSocket as AsSock;

/// as_raw_fd(): a socket's handle, which Unix calls a file descriptor.
pub trait AsRawFd {
    fn as_raw_fd(&self) -> RawFd;
}

impl<T: std::os::windows::io::AsRawSocket> AsRawFd for T {
    fn as_raw_fd(&self) -> RawFd {
        self.as_raw_socket() as RawFd
    }
}

#[allow(non_camel_case_types)]
pub type c_short = i16;
#[allow(non_camel_case_types)]
pub type nfds_t = u32;
#[allow(non_camel_case_types)]
pub type socklen_t = i32;
pub use ws::WSAPOLLFD as pollfd;

pub const POLLIN: c_short = ws::POLLRDNORM as c_short;
pub const POLLOUT: c_short = ws::POLLWRNORM as c_short;
pub const POLLERR: c_short = ws::POLLERR as c_short;
pub const POLLHUP: c_short = ws::POLLHUP as c_short;
pub const SOL_SOCKET: i32 = ws::SOL_SOCKET;
pub const SO_ERROR: i32 = ws::SO_ERROR;
pub const AF_INET: i32 = ws::AF_INET as i32;
pub const AF_INET6: i32 = ws::AF_INET6 as i32;

/// The Winsock errors for Unix's errno values: a closed connection's
/// write (EPIPE) is WSAECONNABORTED, and a connect in progress
/// (EINPROGRESS) WSAEWOULDBLOCK.
pub const EADDRINUSE: i32 = ws::WSAEADDRINUSE;
pub const EAGAIN: i32 = ws::WSAEWOULDBLOCK;
pub const ECONNREFUSED: i32 = ws::WSAECONNREFUSED;
pub const ECONNRESET: i32 = ws::WSAECONNRESET;
pub const EINPROGRESS: i32 = ws::WSAEWOULDBLOCK;
pub const EINTR: i32 = ws::WSAEINTR;
pub const EINVAL: i32 = ws::WSAEINVAL;
pub const ENOBUFS: i32 = ws::WSAENOBUFS;
pub const ENOTCONN: i32 = ws::WSAENOTCONN;
pub const EPIPE: i32 = ws::WSAECONNABORTED;

/// poll(): WSAPoll().
///
/// # Safety
/// `fds` points at `n` pollfds.
pub unsafe fn poll(fds: *mut pollfd, n: nfds_t, timeout: i32) -> i32 {
    // SAFETY: as the caller promises.
    unsafe { ws::WSAPoll(fds, n, timeout) }
}

/// # Safety
/// `value` and `len` describe a buffer of `*len` bytes.
pub unsafe fn getsockopt(fd: RawFd, level: i32, name: i32, value: *mut std::ffi::c_void, len: *mut socklen_t) -> i32 {
    // SAFETY: as the caller promises.
    unsafe { ws::getsockopt(fd, level, name, value.cast(), len) }
}

/// # Safety
/// `value` is valid for `len` bytes.
pub unsafe fn setsockopt(fd: RawFd, level: i32, name: i32, value: *const std::ffi::c_void, len: socklen_t) -> i32 {
    // SAFETY: as the caller promises.
    unsafe { ws::setsockopt(fd, level, name, value.cast(), len) }
}

/// What wakes a media thread up, which it polls with its sockets: a
/// datagram from one loopback socket to another.
pub struct Wake {
    rx: UdpSocket,
    tx: UdpSocket,
}

impl Wake {
    pub fn new() -> Wake {
        let pair = || -> io::Result<Wake> {
            let rx = UdpSocket::bind("127.0.0.1:0")?;
            let tx = UdpSocket::bind("127.0.0.1:0")?;
            tx.connect(rx.local_addr()?)?;
            rx.set_nonblocking(true)?;
            tx.set_nonblocking(true)?;
            Ok(Wake { rx, tx })
        };
        pair().unwrap_or_else(|e| panic!("a media thread's wake-up sockets: {e}"))
    }

    pub fn wake(&self) {
        // A datagram already waiting wakes the thread as well.
        let _ = self.tx.send(&[1]);
    }

    pub fn clear(&self) {
        let mut b = [0u8; 16];
        while self.rx.recv(&mut b).is_ok() {}
    }

    pub fn fd(&self) -> RawFd {
        self.rx.as_raw_fd()
    }
}

/// The sockets a media thread waits on, each with a key for its events,
/// in one WSAPoll().
pub struct MediaPoll {
    fds: Vec<pollfd>,
    keys: Vec<u64>,
}

impl MediaPoll {
    pub fn new() -> MediaPoll {
        MediaPoll { fds: Vec::new(), keys: Vec::new() }
    }

    pub fn watch(&mut self, fd: RawFd, key: u64, on: bool) {
        let at = self.fds.iter().position(|p| p.fd == fd);
        match (on, at) {
            (true, None) => {
                self.fds.push(pollfd { fd, events: POLLIN, revents: 0 });
                self.keys.push(key);
            }
            (true, Some(i)) => self.keys[i] = key,
            (false, Some(i)) => {
                self.fds.swap_remove(i);
                self.keys.swap_remove(i);
            }
            (false, None) => {}
        }
    }

    /// The keys of what is readable, once something is or `wait` is over
    /// (None: until then), to the millisecond.
    pub fn wait(&mut self, wait: Option<Duration>, mut each: impl FnMut(u64)) {
        let ms = wait.map_or(-1, |d| d.as_micros().div_ceil(1000).min(i32::MAX as u128) as i32);
        for p in &mut self.fds {
            p.revents = 0;
        }
        // SAFETY: fds is a live array of its length.
        let n = unsafe { ws::WSAPoll(self.fds.as_mut_ptr(), self.fds.len() as u32, ms) };
        if n <= 0 {
            return;
        }
        for (p, &key) in self.fds.iter().zip(&self.keys) {
            if p.revents != 0 {
                each(key);
            }
        }
    }
}

/// Unix's signal masks: Windows has none.
pub fn block_signals() {}

/// A child killed on Windows has an exit code: none ends by a signal.
pub fn exit_signal(_status: &std::process::ExitStatus) -> i32 {
    0
}

extern "C" {
    fn _localtime64_s(tm: *mut libc::tm, t: *const i64) -> i32;
    fn _mkgmtime64(tm: *mut libc::tm) -> i64;
}

/// localtime(), and the UTC offset in seconds, which the UCRT's tm lacks:
/// the local time read as UTC, less the time.
pub fn localtime(t: i64) -> (libc::tm, i64) {
    // SAFETY: _localtime64_s() fills the zeroed tm it is given, and
    // _mkgmtime64() reads a copy of it.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        _localtime64_s(&mut tm, &t);
        let mut as_utc = tm;
        (tm, _mkgmtime64(&mut as_utc) - t)
    }
}

/// No user database to find a ~user's home in.
pub fn user_home(_name: &str) -> Option<Result<String, std::io::Error>> {
    None
}

/// Random bytes from the system's generator: false if it gave none.
pub fn random_bytes(buf: &mut [u8]) -> bool {
    use windows_sys::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
    // SAFETY: BCryptGenRandom() writes buf.len() bytes into buf.
    unsafe { BCryptGenRandom(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 }
}

/// The size of stdio's buffer for a file: the UCRT's, 4096.
pub fn stdio_buffer_size(_file: &std::fs::File) -> usize {
    4096
}

/// A plugin library, and its symbols: LoadLibraryW() and GetProcAddress().
pub struct Library(windows_sys::Win32::Foundation::HMODULE);

// SAFETY: a module handle, which GetProcAddress() may use from any thread.
unsafe impl Send for Library {}
unsafe impl Sync for Library {}

impl Library {
    pub fn open(path: &str) -> Result<Library, String> {
        use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;
        let wide: Vec<u16> = path.encode_utf16().chain([0]).collect();
        // SAFETY: a NUL-terminated wide path.
        let h = unsafe { LoadLibraryW(wide.as_ptr()) };
        if h.is_null() { Err(io::Error::last_os_error().to_string()) } else { Ok(Library(h)) }
    }

    pub fn symbol(&self, name: &str) -> Result<*mut std::ffi::c_void, String> {
        use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
        let n = std::ffi::CString::new(name).map_err(|e| e.to_string())?;
        // SAFETY: our module's handle and a NUL-terminated name.
        match unsafe { GetProcAddress(self.0, n.as_ptr().cast()) } {
            Some(f) => Ok(f as *mut std::ffi::c_void),
            None => Err("not found".into()),
        }
    }
}

/// Windows has no limit on open files to raise.
pub fn raise_nofile_limit() -> Option<u64> {
    None
}

/// What a Windows run needs first: a 1 ms timer tick, for the media
/// threads' waits (the default is 15.6 ms), and escape sequences in the
/// console, for the screens.
pub fn init() {
    use windows_sys::Win32::System::Console::{GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};
    // SAFETY: plain calls on our own process and console.
    unsafe {
        windows_sys::Win32::Media::timeBeginPeriod(1);
        for h in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            let h = GetStdHandle(h);
            let mut mode = 0;
            if GetConsoleMode(h, &mut mode) != 0 {
                SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
    }
}

/// stdin as SIPp's cbreak mode has it: a console without line input or
/// echo, read by key events that wait; a pipe read only when it has
/// bytes. Restored on drop.
pub struct Terminal {
    handle: windows_sys::Win32::Foundation::HANDLE,
    /// The console's mode, when stdin is one.
    saved: Option<u32>,
}

impl Terminal {
    pub fn open() -> Option<Terminal> {
        use windows_sys::Win32::System::Console::{GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, STD_INPUT_HANDLE};
        // SAFETY: plain calls on our own stdin.
        unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                return None;
            }
            let mut mode = 0;
            let saved = (GetConsoleMode(handle, &mut mode) != 0).then_some(mode);
            if let Some(mode) = saved {
                // Ctrl-C stays processed: the SIGINT of the C runtime.
                SetConsoleMode(handle, mode & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT));
            }
            Some(Terminal { handle, saved })
        }
    }

    /// What was typed since the last call, into `buf`: the characters of
    /// the key presses, UTF-8.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        use windows_sys::Win32::System::Console::{GetNumberOfConsoleInputEvents, ReadConsoleInputW, INPUT_RECORD, KEY_EVENT};
        // SAFETY: calls on our own stdin, into buffers of ours.
        unsafe {
            if self.saved.is_none() {
                return self.read_pipe(buf);
            }
            let mut waiting = 0;
            if GetNumberOfConsoleInputEvents(self.handle, &mut waiting) == 0 || waiting == 0 {
                return 0;
            }
            let mut records: [INPUT_RECORD; 16] = std::mem::zeroed();
            let mut got = 0;
            if ReadConsoleInputW(self.handle, records.as_mut_ptr(), waiting.min(16), &mut got) == 0 {
                return 0;
            }
            let mut n = 0;
            for r in &records[..got as usize] {
                if u32::from(r.EventType) != KEY_EVENT || r.Event.KeyEvent.bKeyDown == 0 {
                    continue;
                }
                let Some(c) = char::from_u32(u32::from(r.Event.KeyEvent.uChar.UnicodeChar)).filter(|&c| c != '\0') else { continue };
                let mut utf8 = [0u8; 4];
                let bytes = c.encode_utf8(&mut utf8).as_bytes();
                if n + bytes.len() > buf.len() {
                    break;
                }
                buf[n..n + bytes.len()].copy_from_slice(bytes);
                n += bytes.len();
            }
            n
        }
    }

    /// A pipe (or file) for stdin: only what waits in it.
    unsafe fn read_pipe(&mut self, buf: &mut [u8]) -> usize {
        use windows_sys::Win32::Storage::FileSystem::{GetFileType, ReadFile, FILE_TYPE_PIPE};
        use windows_sys::Win32::System::Pipes::PeekNamedPipe;
        // SAFETY: calls on our own stdin, into buf.
        unsafe {
            if GetFileType(self.handle) == FILE_TYPE_PIPE {
                let mut avail = 0;
                if PeekNamedPipe(self.handle, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut avail, std::ptr::null_mut()) == 0 || avail == 0 {
                    return 0;
                }
            }
            let mut n = 0;
            if ReadFile(self.handle, buf.as_mut_ptr(), buf.len() as u32, &mut n, std::ptr::null_mut()) == 0 {
                return 0;
            }
            n as usize
        }
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        if let Some(mode) = self.saved {
            // SAFETY: restoring what open() changed.
            unsafe { windows_sys::Win32::System::Console::SetConsoleMode(self.handle, mode) };
        }
    }
}
