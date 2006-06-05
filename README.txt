#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#  Copyright (C) 2003,2004,2005,2006 - The Authors
#

BUILDING
********

This is the Sipp package. Please refer to the http://sipp.sourceforge.net/
WEB page for details and download of the last version.

Normally, you should be able to build Sipp by just typing "make" in the
current diractory. Then "sipp -h" will give you access to the online help.

CONTRIBUTING
************

Sipp is free software, under the terms of the GPL licence (please the the
LICENCE.txt file for details). You can contribute to the development 
of Sipp and contact us via Sourceforge to integrate your changes. If you 
make changes in Sipp, *PLEASE* follow a few coding rules:

  - Use 80 columns code,

  - Do *NOT* use tabulations for indentation. Use spaces,

  - Please stay conform with the current indentation style (2 spaces
    indent, standard Emacs-like indentation). Examples:

    if (condition) {
      f();
    } else {
      g();
    }

  - Use "{" in if conditions even if there is only one instruction
    (see example above).

  - Do not use std C++ libs if something euivalent exists in libc
    (better portability). (e.g. prefer "printf" to "cout <<" ).

  - Check your changes can be compiled on:
 
      - Linux,
      - HPUX,
      - Tru64,

    (We can provide help on these portability points).

Thanks,

  ojacques@users.sourceforge.net
  richard_gayraud@users.sourceforge.net

******************************************************************
