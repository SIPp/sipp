#   SIPp - a SIP protocol test tool
#   Copyright (C) 2003-2013 - The Authors
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

BUILDING
********

This is the SIPp package. Please refer to the
http://sipp.sourceforge.net/ webpage for details and download of the
last version.

Normally, you should be able to build SIPp by just typing "./configure
--with-pcap --with-sctp; make" in the current directory. Then "sipp
-h" will give you access to the online help.

If you checked out the source through a VCS, you may need to "touch
configure.ac aclocal.m4 configure Makefile.am Makefile.in" before
running configure and make.

CONTRIBUTING
************

SIPp is free software, under the terms of the GPL licence (see the
LICENCE.txt file for details). You can contribute to the development
of SIPp and contact us via Sourceforge to integrate your changes. If
you make changes in SIPp, *PLEASE* follow a few coding rules:

  - Use 80 columns code,

  - Do *NOT* use tabulations for indentation. Use spaces.

  - Please stay conform with the current indentation style (2 spaces
    indent, standard Emacs-like indentation). Examples:

    if (condition) {
      f();
    } else {
      g();
    }

  - Use "{" in if conditions even if there is only one instruction
    (see example above).

  - If possible, check your changes can be compiled on:
      - Linux,
      - Cygwin,
      - FreeBSD.

    (We can provide help on these portability points).

Thanks,

  Rob Day <rkd@rkd.me.uk>
