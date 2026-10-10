//! -plugin file.so: shared objects that add [keywords], through the C ABI
//! of the sipp-plugin crate. SIPp's own plugins call into its C++ internals,
//! so they don't load here.

use crate::template::{Ctx, Template};
use sipp_plugin::abi::{self, Str};
use std::collections::HashMap;
use std::ffi::{c_int, c_void};
use std::sync::Mutex;

struct Entry {
    name: String,
    f: abi::KeywordFn,
    data: *mut c_void,
}

// SAFETY: data is the plugin's, handed back to its own function only.
unsafe impl Send for Entry {}

static KEYWORDS: Mutex<Vec<Entry>> = Mutex::new(Vec::new());
/// Why the last registration was refused.
static REFUSED: Mutex<Option<String>> = Mutex::new(None);

/// Plugin text, which we don't trust to be UTF-8.
unsafe fn text<'a>(s: Str) -> Result<&'a str, String> {
    if s.len == 0 {
        return Ok("");
    }
    // SAFETY: the plugin passes a buffer of s.len bytes.
    std::str::from_utf8(unsafe { std::slice::from_raw_parts(s.ptr, s.len) }).map_err(|e| e.to_string())
}

unsafe extern "C" fn register_keyword(name: Str, f: abi::KeywordFn, data: *mut c_void) -> c_int {
    // SAFETY: as documented for register_keyword.
    let name = match unsafe { text(name) } {
        Ok(n) if !n.is_empty() && !n.contains(|c: char| c.is_whitespace() || c == '[' || c == ']') => n,
        Ok(n) => {
            *REFUSED.lock().unwrap() = Some(format!("Can not register keyword '{n}', not a word!"));
            return -1;
        }
        Err(e) => {
            *REFUSED.lock().unwrap() = Some(format!("Can not register keyword: {e}"));
            return -1;
        }
    };
    let mut keywords = KEYWORDS.lock().unwrap();
    if keywords.iter().any(|k| k.name == name) {
        *REFUSED.lock().unwrap() = Some(format!("Can not register keyword '{name}', already registered!"));
        return -1;
    }
    keywords.push(Entry { name: name.to_string(), f, data });
    0
}

/// Loads the plugin at `path` and lets it register its keywords; it stays
/// loaded.
pub fn load(path: &str) -> Result<(), String> {
    // Never closed: its keywords stay.
    let lib = crate::sys::Library::open(path).map_err(|e| format!("Could not open plugin {path}: {e}"))?;
    let lib = Box::leak(Box::new(lib));
    let symbol = |name: &str| lib.symbol(name).map_err(|e| format!("Could not locate {name} in {path}: {e}"));
    // SAFETY: the plugin! macro exports it as a u32.
    let version = unsafe { *(symbol(abi::VERSION_SYMBOL)? as *const u32) };
    if version != abi::VERSION {
        return Err(format!("Plugin {path} is for plugin ABI {version}, this sipp-rs has {}.", abi::VERSION));
    }
    // SAFETY: and this as an InitFn.
    let init: abi::InitFn = unsafe { std::mem::transmute(symbol(abi::INIT_SYMBOL)?) };
    static VERSION: &str = concat!(env!("SIPP_VERSION_BARE"), "-rs");
    let host = abi::Host { version: abi::VERSION, sipp_version: Str::new(VERSION), register_keyword };
    // SAFETY: host is valid for the call.
    let rc = unsafe { init(&host) };
    if let Some(e) = REFUSED.lock().unwrap().take() {
        return Err(e);
    }
    if rc != 0 {
        return Err(format!("Plugin {path} initialization failed."));
    }
    Ok(())
}

/// The keyword a plugin registered by this name.
pub fn lookup(name: &str) -> Option<usize> {
    KEYWORDS.lock().unwrap().iter().position(|k| k.name == name)
}

/// What the plugin's Keyword.host points to while it runs.
struct Use {
    ctx: *const c_void,
    value: String,
    /// What render() handed out; each String's text stays put.
    rendered: Vec<String>,
}

unsafe extern "C" fn write(kw: *mut abi::Keyword, s: Str) {
    // SAFETY: kw is the Keyword expand() passed, its host our Use.
    let u = unsafe { &mut *((*kw).host as *mut Use) };
    // SAFETY: as documented for write.
    if let Ok(s) = unsafe { text(s) } {
        u.value += s;
    }
}

unsafe extern "C" fn render(kw: *mut abi::Keyword, s: Str, out: *mut Str) -> c_int {
    // SAFETY: as in write(); ctx is the Ctx expand() was given.
    let u = unsafe { &mut *((*kw).host as *mut Use) };
    let ctx = unsafe { &*(u.ctx as *const Ctx) };
    // SAFETY: as documented for render.
    let (rc, value) = match unsafe { text(s) }.and_then(|t| Template::parse_line(t, &HashMap::new())) {
        Ok(t) => (0, t.render_line(ctx)),
        Err(e) => (-1, e),
    };
    u.rendered.push(value);
    // SAFETY: out is the plugin's.
    unsafe { *out = Str::new(u.rendered.last().unwrap()) };
    rc
}

/// A plugin keyword's value in a message for the call `c`.
pub fn expand(id: usize, args: &str, c: &Ctx) -> String {
    // Unlocked while it runs: its render() may expand plugin keywords too.
    let (f, data) = {
        let k = KEYWORDS.lock().unwrap();
        (k[id].f, k[id].data)
    };
    let mut u = Use { ctx: (c as *const Ctx).cast(), value: String::new(), rendered: Vec::new() };
    let mut kw = abi::Keyword { args: Str::new(args), write, render, host: (&mut u as *mut Use).cast() };
    // SAFETY: the plugin's function with its own data, and a Keyword valid
    // for the call.
    match unsafe { f(data, &mut kw) } {
        0 => u.value,
        _ => String::new(),
    }
}
