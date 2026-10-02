//! The version, as C SIPp's CMakeLists.txt gets it, and on Windows, which has
//! no POSIX regex, musl's (vendor/musl-regex).

use std::process::Command;

/// `git describe --tags --always --first-parent` of the checkout, like C
/// SIPp's; else the SIPP_VERSION of a release tarball's include/version.h
/// (not the stub of a checkout, which has an #error); else the crate's.
fn version() -> String {
    let git = |args: &[&str]| {
        let out = Command::new("git").args(args).current_dir(env!("CARGO_MANIFEST_DIR")).output().ok()?;
        let text = String::from_utf8(out.stdout).ok()?.trim().to_string();
        (out.status.success() && !text.is_empty()).then_some(text)
    };
    // A commit, or a checkout of another branch, changes it.
    for path in ["HEAD", "logs/HEAD", "packed-refs"] {
        if let Some(p) = git(&["rev-parse", "--git-path", path]) {
            println!("cargo:rerun-if-changed={p}");
        }
    }
    if let Some(v) = git(&["describe", "--tags", "--always", "--first-parent"]) {
        return v;
    }
    let header = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../include/version.h")).unwrap_or_default();
    if !header.contains("#error") {
        if let Some(v) = header.lines().find_map(|l| l.strip_prefix("#define SIPP_VERSION \"")?.strip_suffix('"')) {
            return v.to_string();
        }
    }
    format!("v{}", env!("CARGO_PKG_VERSION"))
}

fn main() {
    let version = version();
    // [sipp_version] and plugins drop the "v", as C does.
    println!("cargo:rustc-env=SIPP_VERSION={version}");
    println!("cargo:rustc-env=SIPP_VERSION_BARE={}", version.strip_prefix('v').unwrap_or(&version));
    println!("cargo:rerun-if-changed=vendor/musl-regex");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let dir = "vendor/musl-regex";
    let mut build = cc::Build::new();
    for f in ["regcomp.c", "regexec.c", "tre-mem.c", "regerror.c"] {
        build.file(format!("{dir}/{f}"));
    }
    build.include(dir).flag_if_supported("-std=c99").warnings(false).compile("musl_regex");
}
