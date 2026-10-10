//! What Linux and Windows do differently, under the names of the Unix
//! calls sipp-rs was written with: a socket's handle (Unix's file
//! descriptor), poll(), the errno values of socket errors, the media
//! threads' wait for their sockets, and a few C library calls.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;
