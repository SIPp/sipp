Features added in 3.7.0~rc1
===========================

* B2BUA Media Gateway RTP/SRTP bit pattern testing -- see
  `docs/rtpcheck_xml_syntax_reference.pdf`. Command line examples:
    ```
    # UAS (RTP)
    ./sipp -m 1 -sf sipp_scenarios/pfca_uas.xml \
      -i 127.0.0.3 -t u1 -p 5060 -rtp_echo

    # UAC (RTP)
    ./sipp -m 1 -sf sipp_scenarios/pfca_uac_apattern.xml \
      -t u1 -i 127.0.0.2 -p 5060 127.0.0.3:5060
    ```
    ```
    # UAS (audio SRTP)
    ./sipp -m 1 -sf sipp_scenarios/pfca_uas_audio_crypto_simple.xml \
      -t u1 -i 127.0.0.3 -p 5060 -srtpcheck_debug

    # UAC (audio SRTP)
    ./sipp -m 1 -sf sipp_scenarios/pfca_uac_apattern_crypto_simple.xml \
      -t u1 -i 127.0.0.2 -p 5060 -rtpcheck_debug -srtpcheck_debug \
      127.0.0.3:5060
    ```
  By Jeannot Langlois.
* Removed `-mp` in favor of `-min_rtp_port` and `-max_rtp_port`. Also
  removed `[auto_media_port]`. There are way too many (conflicting)
  options to specify ports here.
* URL encode/decode `<action>` for scenarios (by Jérôme Poulin).
* Variables in the rtpstream/pcap filenames (by Orgad Shaneh).
* WolfSSL/WolfCrypt library support (as alternative to OpenSSL, by
  Thomas Uhle).


Bugs fixed in 3.7.0~rc1
=======================

* Documentation updates. Code cleanups. Build fixes. (By Walter Doekes,
  Thomas Uhle, ChanderG, Lin Sun, Markus Goetzl, Rob Day, Stefan
  Mititelu, Orgad Shaneh, Karn Saheb).
* Fix socket/tcp refcount/order issue (by Orgad Shaneh).
* Fix timezone in [date] on FreeBSD (by kadabusha).
* Track auto-answered messages as a visible counter rather than an error
  log (by Rob Day).
* Unconditionally show index in scenario screen (by Rob Day).


Bugs fixed in 3.6.2
===================

* Fix crash when abusing authentication method (#503, by Markus).
* Fix crash when trying to change an unset ooc scenario (#463, by
  @jquinn60137).
* Fix various build issues with CMake and/or missing version.h and/or
  compiler warnings. By Walter Doekes, by Silver Chan, Thomas Uhle,
  Orgad Shaneh.
* Remove RTP\_STREAM define. The code is always included. (By Orgad Shaneh.)
* Various minor documentation fixes. By Walter Doekes, kadabusha, Thomas
  Uhle, Alexander Traud.


BREAKING(!) changes in 3.6.1
============================

* CMake is now used as build environment: autoconf and friends are gone
  (#430, by Rob Day (@rkday)). See `build.sh` for CMake invocations.
  For a full build, do:
    ```
    cmake . -DUSE_GSL=1 -DUSE_PCAP=1 -DUSE_SSL=1 -DUSE_SCTP=1
    make -j4
    ```


Bugs fixed in 3.6.1
===================

* Consistently unescape XML attributes when loading scenario (#458, by
  Steve Frécinaux (@nud)).
* Fix buffer overflow in screen output (#479, reported by @brettowe).
* Fix nonce count in auth headers (#421, by Cody Herzog (@codyherzog)).
* Fix parser warning when trying to access 0-byte SDP body (by Lin Sun
  (@sunlin7)).
* Fix pcapplay on FreeBSD (#434, by Rob Day (@rkday)).
* Improve build validation (#424, by Stanislav Litvinenko (@dolk13)), a
  few compiler fixes, a few ncurses fixes (including #436, reported by
  @TamerL), build cleanup after CMake (#443, #442, by Orgad Shaneh
  (@orgads)) and libtinfo linker issues (Jeannot Langlois
  (@jeannotlanglois)).
* Improve provided sipp.dtd file (#425, by David M. Lee (@leedm777)),
  and XML fixes by Rob Day.
* Make it easier to deal with large SIP packets by adding an optional
  `-DSIPP_MAX_MSG_SIZE=262144` to the `cmake` command (#422, by Cody Herzog
  (@codyherzog)).


BREAKING(!) changes in 3.6.0
============================

* Automatic filenames (trace files, error files, etc..) are now created in
  the current working directory instead of in the directory of the scenario
  file. (Issue #399, reported by @sergey-safarov.)
* Only validates SSL certficate if CA-file is separately specified!
  (PR #335, by Patrick Wildt @bluerise.)
* Angle brackets `<` and `>` need to be escaped inside XML attributes.
  See #414. So, not `regexp="<(sip:.*)>"` but `regexp="&lt;(sip:.*)&gt;"`.


Bugs fixed in 3.6.0
===================

* Fix `[routes]` header in UAS scenario's. (Issue #262, reported by
  Stefan Mititelu (@smititelu).)
* last\_Keyword does not search in SIP body anymore (#207, reported by Zoltan).


Changes in 3.6.0
================

* Added PAGER by default to the extremely large sipp help output.
* Removed unused RTPStream code concerning video streams. Also
  consolidated the rtpstream audio port usage to reuse the global
  `[media_port]` instead of the `[rtpstream_audio_port]`.
  Also the `-min_rtp_port` and `-max_rtp_port` options have been
  removed. Advantages: cleaner code, fewer scenario variables.
  Drawbacks: possible ICMP port unreachable messages for RCTP and video.
  Also, no easy way to discern different streams if you want to bombard
  a single UAS with multiple RTP streams. (Issue #192, reported by
  @atsakiridis.)


Features added in 3.6.0
=======================

* Add `play_dtmf` code originally from
  https://sourceforge.net/p/sipp/patches/50/ (Dmitry Kunilov), then
  pull #82 (@horacimacias) and then #141 (@vodik). Compile with
  pcap-play support, and use it by adding `<exec play_dtmf="1234*#"/>`
  similar to how you use `play_pcap_audio`.
  - Add RTP payload 96 in your SDP:
    m=audio [media_port] RTP/AVP 0 96 97
    a=rtpmap:0 PCMU/8000
    a=rtpmap:96 telephone-event/8000
    a=fmtp:96 0-15
    a=rtpmap:97 no-op/8000
  - Exec syntax is `<exec play_dtmf="digits[,length]"/>` where digits
    can be one or more of "0123456789#*ABCD" and length defaults to 200
    and must be between 50 and 2000.
  - Instead of digits a `[field...]` keyword is also accepted.
  - Make sure you add enough `<pause/>` after `play_dtmf`.
* Add `rtp_echo` action (pull #259 by Snom Technology). Compile with
  `--with-rtpstream` and use it by adding `<rtp_echo value="0">` to stop
  the RTP echo enabled via `-rtp_echo`. RTP echo can be restarted via
  `<rtp_echo value="1">` action. Usage example in `regress/github-#0259/uas.xml`
* Added the required constants for G722 (payload 9) and iLBC at 30ms per frame
  to rtp\_stream media actions. (PR #366, by Jasper Hafkenscheid @hafkensite.)
* Add quick and dirty detection of invalid XML (issue #322).
* Clarify that `-infindex` should takes a basename only (issue #395, reported
  by @sergey-safarov).


Bugs fixed in 3.5.3
===================

* Fix `[routes]` header in UAS scenario's. (Issue #262, reported by
  Stefan Mititelu (@smititelu).)
  (Backported from b6c7b209 from 3.6.)
* Fix bad Content-Length calculation when whitespace was between the CRLF
  pairs that separate the body. (Issue #337, fixed by Serg Stetsuk
  (@sergstetsuk)).
* Fix crash in pcap play on send failure because of pthread\_cleanup macros.
  (Issue #74, #370, reported by various people.)


Bugs fixed in 3.5.2
===================

Build issues:

* Improve ncurses/gsl detection and linkage on various platforms.
  (Issue #205, #271, #275, reported by Paul Malpass, AlexB, Leon Roy,
  Victor Seva.)
* Fix compile issues on old CentOS and Solaris. (Issue #211, #245, #252,
  reported by sjthomason, mscdex.)
* Fix newer openssl detection. (Issue #302, #304, #315, #328.)
* Recompile entire source after a reconfigure.
* Reduce confusion when someone downloads a tag from git instead of the tar.gz
  with the autogenerated files and valid version.h (#270, reported by AlexB).
* Remove hardcoded build datetime from binary, for "reproducible builds".
  (#286, by Victor Seva.)
* Replace underscore in tag-name with tilde, for debian-style "~rc1" version
  suffix.

Bugs:

* Handle Contact header with extra angle brackets ('<...>') outside of the
  uri-parameters (in the contact-params). The contact params should not be
  used in the `next_url`. (Issue #234, reported by Justin Zimmer.)
* Fix TLS issues for during high load. (Issue #241, #243, reported by sgel83,
  and fixes by Rob Day.)
* Fix problem with `get_inet_address` on FreeBSD (#331, reported by tsgan.)
* Retry video RTP bind if port is taken (#276, thanks Corey Farrell).

Tests:

* Document `search_in="hdr"` test.
* Also test without `HAVE_EPOLL`.


Bugs fixed in 3.5.1
===================

* Fix qop-value in authorization Digest. It can only hold a single value
  (auth, auth-int, ...) and does not take double quotes, in contrast to
  the challenge. Some servers returned a 400 upon receiving this.
  (Issue #191, reported by @artlov.)
* Fix compile error on Cygwin. (Issue #193, reported by @Gankarloo.)


Features added in 3.5.0
=======================

* Clean up source code, fix typo's, alter warning and error messages,
  fix pedantic coding style. Add gtest framework and tests. Add regression
  tests. Fix and improve build scripts (see also: `build.sh`).
* Use better timing with `clock_gettime` (or `clock_get_time` on OSX).
* Don't complain about the dummy variable `_` being used only once.
* Ignore 4x NUL keepalive (next to ignoring the CRLF CRLF keepalive).
* Add `[date]` keyword.
* Add `-trace_screen` option to log screen output in a file.
* Add `-rate_increase` option to increase load periodically.
* Add `-callid_slash_ign` to disable the magic triple slash behaviour.a
* Alter `-aa` to also reply to OPTIONS.
* Allow replaying pcaps with `LINUX_SLL`, `EN10MB` and 802.11 (and ratiotap)
  link layer types. Handle 802.1Q tagged frames.
* Allow starting SIPp without a TERM setting (a "working" terminal).
* Allow m=image in SDP to pcapplay faxes/images.
* `<exec play_pcap_audio="..."/>` and friends:
  - If the argument is not an absolute path, the pcap is searched next
    to the scenario, before falling back to checking the current
    working directory.
  - The argument may be enclosed in brackets, in which case it is
    interpreted as a keyword value; set through the `-key` command line
    option. Example: `<exec play_pcap_audio="[file1]"/>` with option
    `-key file1 /path/to/pcap`.


Bugs fixed in 3.5.0
===================

* Start SDP search in body instead of in header. Fix IPv6 media address in SDP.
* Allow single CR and single LF in SDP.
* Don't confuse cnonce with nonce, improve other auth parsing.
* Don't abort SIPp if the To header is missing.
* Fixes to XML parser; improve `get_peer_tag` behaviour.
* Fix jump recursion crashes.
* Fix a few (potential) memory leaks and dangerous code.
* Remove a few autogenerated files from tree (configure, manpage).
* Fix digest calculation when `qop` is given.


3.4.1
=====

* Not documented here.
