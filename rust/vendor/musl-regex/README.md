The POSIX regex of musl 1.2.5 (src/regex, MIT: see COPYRIGHT), which
sipp-rs builds on Windows only: glibc's regcomp()/regexec() on Linux,
this there, both POSIX extended regular expressions.

Changes from musl: regex.h stands alone, with the functions renamed
sipp_* and regoff_t a ptrdiff_t; regerror.c has glibc's messages and no
locale; tre.h defines musl's `hidden` away, CHARCLASS_NAME_MAX and
RE_DUP_MAX (glibc's 0x7fff) where Windows has none, and ALIGN() aligns
to a pointer's size.

For glibc's syntax, regcomp.c has only glibc's \w, \W, \s and \S of TRE's
escape macros (\t, \d and the rest are the letters), no \xHH, glibc's \`
and \' anchors, and back references in extended expressions too.
