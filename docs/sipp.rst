Main features
=============

SIPp allows to generate one or many SIP calls to one remote system.
The tool is started from the command line. In this example, two SIPp
are started in front of each other to demonstrate SIPp capabilities.

Run sipp with embedded server (uas) scenario:

::

    # ./sipp -sn uas


On the same host, run sipp with embedded client (uac) scenario

::

    # ./sipp -sn uac 127.0.0.1





Running SIPp in background
``````````````````````````

SIPp can be launched in background mode (-bg command line option).

By doing so, SIPp will be detached from the current terminal and run
in the background. The PID of the SIPp process is provided. If you
didn't specify a number of calls to execute with the -m option, SIPp
will run forever.

There is a mechanism implemented to stop SIPp smoothly. The command
kill -SIGUSR1 [SIPp_PID] will instruct SIPp to stop placing any new
calls and finish all ongoing calls before exiting.

When using the background mode, the main sipp instance stops and a
child process will continue the job. Therefore, the log files names
will contain another PID than the actual sipp instance PID.



Screens
```````

Several screens are available to monitor SIP traffic. You can change
the screen view by pressing 1 to 9 keys on the keyboard.


+ Key '1': Scenario screen. It displays a call flow of the scenario as
  well as some important informations.
+ Key '2': Statistics screen. It displays the main statistics
  counters. The "Cumulative" column gather all statistics, since SIPp
  has been launched. The "Periodic" column gives the statistic value for
  the period considered (specified by -f frequency command line
  parameter).
+ Key '3': Repartition screen. It displays the distribution of
  response time and call length, as specified in the scenario.
+ Key '4': Variables screen. It displays informations on actions in
  scenario as well as scenario variable informations.





Exit codes
``````````

To ease automation of testing, upon exit (on fatal error or when the
number of asked calls (-m command line option) is reached, sipp exits
with one of the following exit codes:


+ 0: All calls were successful
+ 1: At least one call failed
+ 97: exit on internal command. Calls may have been processed. Also
  exit on global timeout (see -timeout_global option)
+ 99: Normal exit without calls processed
+ -1: Fatal error


Depending on the system that SIPp is running on, you can echo this
exit code by using "echo ?" command.













Contributing to SIPp
~~~~~~~~~~~~~~~~~~~~

Of course, we welcome contributions, and many of SIPp's features
(including epoll support for better Linux performance, RTP streaming,
and Cygwin support) have come from external contributions. See `here`_
for how to get started.

byRichard GAYRAUD [initial code],Olivier JACQUES
[code/documentation],Robert Day [code/documentation],Charles P. Wright
[code],Many contributors [code]
Copyright 2004-2013 The authors All rights reserved.
Send feedback about the website to: `Rob Day`_
.. _SIPp
.. _OpenSSL library: http://www.openssl.org/
.. _original XML file: http://sipp.sourceforge.net/doc/3pcc-C-B.xml
.. _3pcc-C-B.xml: http://sipp.sourceforge.net/doc/3pcc-C-B.xml.html
.. _original XML file: http://sipp.sourceforge.net/doc/regexp.xml
.. _Documentation [pdf]: http://sipp.sourceforge.net/doc/../doc/reference.pdf
.. _original XML file: http://sipp.sourceforge.net/doc/3pcc-C-A.xml
.. _uas.xml: http://sipp.sourceforge.net/doc/uas.xml.html
.. _original XML file: http://sipp.sourceforge.net/doc/branchs.xml
.. _Negative Binomial on Wikipedia: http://en.wikipedia.org/wiki/Negative_binomial_distribution
.. _GNU GPL license: http://www.gnu.org/copyleft/gpl.html
.. _License: http://sipp.sourceforge.net/doc/../doc/license.html
.. _original XML file: http://sipp.sourceforge.net/doc/ooc_default.xml
.. _Documentation (3.3): http://sipp.sourceforge.net/doc/../doc3.3/reference.html
.. _Documentation - Chinese translation [pdf]: http://sipp.sourceforge.net/doc/../doc/cn-reference.pdf
.. _original XML file: http://sipp.sourceforge.net/doc/3pcc-A.xml
.. _original XML file: http://sipp.sourceforge.net/doc/3pcc-B.xml
.. _Documentation [html]: http://sipp.sourceforge.net/doc/../doc/reference.html
.. _Weibull on Wikipedia: http://en.wikipedia.org/wiki/Weibull
.. _Home: http://sipp.sourceforge.net/doc/../index.html
.. _Gnu Scientific Libraries: http://www.gnu.org/software/gsl/
.. _Pareto on Wikipedia: http://en.wikipedia.org/wiki/Pareto_distribution
.. _
                  Posix Extended standard (POSIX 1003.2): http://www.opengroup.org/onlinepubs/007908799/xbd/re.html
.. _
        PDF: http://sipp.sourceforge.net/doc/reference.pdf
.. _sipp-01.wmv: http://sipp.sourceforge.net/doc/images/sipp-01.wmv
.. _Rob Day: mailto:rkd@rkd.me.uk?subject=SIPp Feedback%C2%A0doc/reference.html
.. _original XML file: http://sipp.sourceforge.net/doc/uac.xml
.. _here: https://github.com/SIPp/sipp/wiki/New-Developers'-Guide
.. _original XML file: http://sipp.sourceforge.net/doc/uac_pcap.xml
.. _
        XML: http://sipp.sourceforge.net/doc/reference.xml
.. _http://win6.jp/Cygwin/: http://win6.jp/Cygwin/
.. _
                  regexp tutorial: http://analyser.oli.tudelft.nl/regex/index.html.en
.. _FAQ: http://sipp.sourceforge.net/doc/../doc/faq.html
.. _http://www.jedit.org/: http://www.jedit.org/
.. _WinPcap developer package: http://www.winpcap.org/devel.htm
.. _branchs.xml: http://sipp.sourceforge.net/doc/branchs.xml.html
.. _3pcc-C-A.xml: http://sipp.sourceforge.net/doc/3pcc-C-A.xml.html
.. _tcpdump: http://www.tcpdump.org/
.. _RFC 3725: http://www.ietf.org/rfc/rfc3725.txt
.. _http://www.iptel.org/~sipsc/: http://www.iptel.org/~sipsc/
.. _PCAP library: http://www.tcpdump.org/pcap3_man.html
.. _ooc_default.xml: http://sipp.sourceforge.net/doc/ooc_default.xml.html
.. _sipp-users@lists.sourceforge.net: mailto:sipp-users.at.lists.sourceforge.net
.. _SIPp's
            SVN: http://sipp.svn.sourceforge.net/viewvc/sipp/sipp/trunk/
.. _branchc.xml: http://sipp.sourceforge.net/doc/branchc.xml.html
.. _sipp.dtd: http://sipp.sourceforge.net/doc/sipp.dtd
.. _uac.xml: http://sipp.sourceforge.net/doc/uac.xml.html
.. _Hewlett-Packard: http://www.hp.com
.. _sipp-02.wmv: http://sipp.sourceforge.net/doc/images/sipp-02.wmv
.. _original XML file: http://sipp.sourceforge.net/doc/uas.xml
.. _3pcc-A.xml: http://sipp.sourceforge.net/doc/3pcc-A.xml.html
.. _http://lists.sourceforge.net/lists/listinfo/sipp-users: http://lists.sourceforge.net/lists/listinfo/sipp-users
.. _http://callflow.sourceforge.net/: http://callflow.sourceforge.net/
.. _SIPp v3.4 (current): http://sipp.sourceforge.net/doc/../doc/
.. _Documentation (3.2): http://sipp.sourceforge.net/doc/../doc3.2/reference.html
.. _3pcc-B.xml: http://sipp.sourceforge.net/doc/3pcc-B.xml.html
.. _http://www.wireshark.org/: http://www.wireshark.org/
.. _regexp.xml: http://sipp.sourceforge.net/doc/regexp.xml.html
.. _Gamma on Wikipedia: http://en.wikipedia.org/wiki/Gamma_distribution
.. _uac_pcap.xml: http://sipp.sourceforge.net/doc/uac_pcap.xml.html
.. _original XML file: http://sipp.sourceforge.net/doc/branchc.xml


