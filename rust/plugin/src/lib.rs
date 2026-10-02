//! Plugins for sipp-rs: shared objects, loaded with `-plugin file.so`, that
//! add [keywords] to its messages, as SIPp's plugins do with
//! registerKeyword().
//!
//! A plugin is a `cdylib` crate:
//!
//! ```ignore
//! fn init(p: &mut sipp_plugin::Registrar) -> Result<(), String> {
//!     // [shout text]: the text, rendered for the call, in capitals.
//!     p.keyword("shout", |call| call.render(call.args()).unwrap_or_default().to_uppercase())
//! }
//! sipp_plugin::plugin!(init);
//! ```
//!
//! Plugins talk to sipp-rs through the C ABI in [`abi`], so a plugin keeps
//! working with a sipp-rs built by another compiler, and can be written in
//! C too. A plugin built for another [`abi::VERSION`] is refused.

use std::ffi::{c_int, c_void};
use std::marker::PhantomData;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// What sipp-rs and a plugin share.
pub mod abi {
    use std::ffi::{c_int, c_void};

    /// Changes whenever anything here does.
    pub const VERSION: u32 = 1;
    /// The `u32` a plugin exports, set to the VERSION it was built with.
    pub const VERSION_SYMBOL: &str = "sipp_plugin_abi";
    /// The `InitFn` sipp-rs calls once the plugin is loaded.
    pub const INIT_SYMBOL: &str = "sipp_plugin_init";

    /// UTF-8 text, not NUL-terminated.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Str {
        pub ptr: *const u8,
        pub len: usize,
    }

    impl Str {
        pub fn new(s: &str) -> Str {
            Str { ptr: s.as_ptr(), len: s.len() }
        }

        /// # Safety
        /// `ptr` and `len` must describe UTF-8 text that outlives `'a`.
        pub unsafe fn as_str<'a>(self) -> &'a str {
            if self.len == 0 {
                return "";
            }
            std::str::from_utf8_unchecked(std::slice::from_raw_parts(self.ptr, self.len))
        }
    }

    /// Expands a keyword: `data` as registered, `kw` for this use of it.
    /// Returns 0, or anything else to drop what it wrote.
    pub type KeywordFn = unsafe extern "C" fn(data: *mut c_void, kw: *mut Keyword) -> c_int;

    /// Given to the plugin's `InitFn`, valid while it runs.
    #[repr(C)]
    pub struct Host {
        pub version: u32,
        /// As [sipp_version] prints it.
        pub sipp_version: Str,
        /// Adds [name ...]; it replaces a keyword of sipp-rs's own of that
        /// name. Returns 0, or -1 when the name is taken or not a word, and
        /// sipp-rs then fails to start.
        pub register_keyword: unsafe extern "C" fn(name: Str, f: KeywordFn, data: *mut c_void) -> c_int,
    }

    /// One use of a keyword in a message being sent, valid while its
    /// `KeywordFn` runs.
    #[repr(C)]
    pub struct Keyword {
        /// What follows the name inside the brackets, blanks trimmed.
        pub args: Str,
        /// Appends to the keyword's value.
        pub write: unsafe extern "C" fn(kw: *mut Keyword, text: Str),
        /// Renders scenario text such as "[call_id]" or "[$var]" for the
        /// call. Sets `out` to the result, or to the reason it could not
        /// be parsed and returns -1; `out` lives as long as `kw`.
        pub render: unsafe extern "C" fn(kw: *mut Keyword, text: Str, out: *mut Str) -> c_int,
        /// sipp-rs's own.
        pub host: *mut c_void,
    }

    pub type InitFn = unsafe extern "C" fn(host: *const Host) -> c_int;
}

/// What a plugin's init function registers its keywords with.
pub struct Registrar<'a> {
    host: &'a abi::Host,
}

type Expand = dyn Fn(&Call) -> String + Send + Sync;

unsafe extern "C" fn expand(data: *mut c_void, kw: *mut abi::Keyword) -> c_int {
    // SAFETY: data is the Box<Expand> keyword() leaked for this function.
    let f = unsafe { &*(data as *const Box<Expand>) };
    let call = Call { kw, _life: PhantomData };
    match catch_unwind(AssertUnwindSafe(|| f(&call))) {
        Ok(value) => {
            // SAFETY: kw is valid while we run.
            unsafe { ((*kw).write)(kw, abi::Str::new(&value)) };
            0
        }
        Err(_) => -1,
    }
}

impl Registrar<'_> {
    /// The sipp-rs version, as [sipp_version] prints it.
    pub fn sipp_version(&self) -> &str {
        // SAFETY: the host keeps it for as long as it runs.
        unsafe { self.host.sipp_version.as_str() }
    }

    /// Adds [name ...], valued by `f` each time a message uses it.
    pub fn keyword<F>(&mut self, name: &str, f: F) -> Result<(), String>
    where
        F: Fn(&Call) -> String + Send + Sync + 'static,
    {
        // Plugins stay loaded, so the closure lives as long as sipp-rs.
        let data = Box::into_raw(Box::new(Box::new(f) as Box<Expand>));
        // SAFETY: a host function called as documented.
        match unsafe { (self.host.register_keyword)(abi::Str::new(name), expand, data.cast()) } {
            0 => Ok(()),
            _ => {
                // SAFETY: the host refused it, so nothing else holds it.
                drop(unsafe { Box::from_raw(data) });
                Err(format!("Can not register keyword '{name}'"))
            }
        }
    }
}

/// A keyword being expanded, for one call's message.
pub struct Call<'a> {
    kw: *mut abi::Keyword,
    _life: PhantomData<&'a ()>,
}

impl Call<'_> {
    /// What follows the keyword's name, as in "text" for [shout text].
    pub fn args(&self) -> &str {
        // SAFETY: valid while the keyword is expanded.
        unsafe { (*self.kw).args.as_str() }
    }

    /// Scenario text rendered for this call: "[call_id]", "[$var]",
    /// "[last_From:]", "sip:[service]@[remote_ip]"...
    pub fn render(&self, text: &str) -> Result<String, String> {
        let mut out = abi::Str::new("");
        // SAFETY: a host function called as documented; out stays valid
        // while the keyword is expanded, and we copy it at once.
        unsafe {
            let rc = ((*self.kw).render)(self.kw, abi::Str::new(text), &mut out);
            let s = out.as_str().to_string();
            if rc == 0 {
                Ok(s)
            } else {
                Err(s)
            }
        }
    }
}

/// Glue for [`plugin!`].
///
/// # Safety
/// `host` must be the Host sipp-rs passed to the plugin's init.
#[doc(hidden)]
pub unsafe fn init(host: *const abi::Host, f: fn(&mut Registrar) -> Result<(), String>) -> c_int {
    // SAFETY: sipp-rs passes a Host valid while init runs.
    let host = unsafe { &*host };
    let mut r = Registrar { host };
    match catch_unwind(AssertUnwindSafe(|| f(&mut r))) {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => {
            eprintln!("{e}");
            -1
        }
        Err(_) => -1,
    }
}

/// Exports `init`, a `fn(&mut Registrar) -> Result<(), String>`, as the
/// plugin's entry point.
#[macro_export]
macro_rules! plugin {
    ($init:path) => {
        #[no_mangle]
        pub static sipp_plugin_abi: u32 = $crate::abi::VERSION;

        /// # Safety
        /// Called by sipp-rs with a valid Host.
        #[no_mangle]
        pub unsafe extern "C" fn sipp_plugin_init(host: *const $crate::abi::Host) -> ::std::ffi::c_int {
            unsafe { $crate::init(host, $init) }
        }
    };
}
