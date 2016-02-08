<a href="https://scan.coverity.com/projects/5988">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/5988/badge.svg"/>
</a>

SIPp - a SIP protocol test tool
Copyright (C) 2003-2015 - The Authors

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program.  If not, see
[http://www.gnu.org/licenses/](http://www.gnu.org/licenses/).

# Building

This is the SIPp package. Please refer to the
[webpage](http://sipp.sourceforge.net/) for details and documentation.

Normally, you should be able to build SIPp by using the provided build
script: `build.sh`. This:
* checks out the gtest submodule
* generates autotools files
* runs configure
* builds and runs the test suite
* builds SIPp

`build.sh` passes its arguments through to the configure script, so you
can enable SSL, PCAP and SCTP support by calling `./build.sh
--with-pcap --with-sctp --with-openssl` or `./build.sh --full` to enable
all optional features.

# Support

I try and be responsive to issues raised on Github, and there's [a
reasonably active mailing
list](https://lists.sourceforge.net/lists/listinfo/sipp-users).

# Making a release

* Update CHANGES.md and configure.ac. Tag release.
* Download zip, `autoreconf -vif`, copy sipp.1, copy include/version.h.
* Create tgz. Upload to github as "binary".

# Contributing

SIPp is free software, under the terms of the GPL licence (see the
LICENCE.txt file for details). You can contribute to the development of
SIPp and use the standard Github fork/pull request method to integrate
your changes integrate your changes. If you make changes in SIPp,
*PLEASE* follow a few coding rules:

  - SIPp uses GNU autotools, so changes to the build process should be
    done by editing configure.ac and Makefile.am. Then regenerate the
    files with `autoreconf -ivf`. (You will need your distribution's
    `autotools` and `autoconf-archive` packages installed for this.)

  - Please stay conformant with the current indentation style (4 spaces
    indent, standard Emacs-like indentation). Examples:

```
if (condition) {        /* "{" even if only one instruction */
    f();                /* 4 space indents */
} else {
    char* p = ptr;      /* C++-style pointer declaration placement */
    g(p);
}
```

  - If possible, check your changes can be compiled on:
      - Linux,
      - Cygwin,
      - Mac OS X,
      - FreeBSD.

Thanks,

  Rob Day <rkd@rkd.me.uk>
