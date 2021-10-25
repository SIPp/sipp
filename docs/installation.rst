Installation
~~~~~~~~~~~~



Getting SIPp
````````````

SIPp is released under the `GNU GPL license`_. All the terms of the
license apply. It was originally created and provided to the SIP
community by `Hewlett-Packard`_ engineers in hope it can be useful,
but HP does not provide any support nor warranty concerning SIPp.



SIPp releases
`````````````

Like many other "open source" projects, there are two versions of
SIPp: a stable and unstable release. Stable release: before being
labelled as "stable", a SIPp release is thoroughly tested. So you can
be confident that all mentioned features will work :)

.. note::
  Use the stable release for your everyday use and if you are not
  blocked by a specific feature present in the "unstable release" (see
  below).

`SIPp stable download page <https://github.com/SIPp/sipp/releases>`_



Unstable release
````````````````

Unstable release: all new features and bug fixes are checked in
`SIPp's master tree`_ repository as soon as they are available.

.. note::
  Use the unstable release if you absolutely need a bug fix or a feature
  that is not in the stable release.


Available platforms
```````````````````

SIPp is available on Linux and Cygwin. Other Unix distributions are
likely to work, but are not tested every release cycle.

.. note::
  SIPp on Cygwin works only on Windows XP and later versions and will
  not work on Win2000. This is because of IPv6 support.


Installing SIPp
```````````````


+ On Linux, SIPp is provided in the form of source code. You will need
  to compile SIPp to actually use it.

+ Pre-requisites to compile SIPp are:

    + C++ Compiler
    + curses or ncurses library
    + For TLS support: OpenSSL >= 0.9.8 or WolfSSL >= 3.15.0
    + For pcap play support: libpcap and libnet
    + For SCTP support: lksctp-tools
    + For distributed pauses: `Gnu Scientific Libraries`_

+ You have four options to compile SIPp:

    + Without TLS (Transport Layer Security), SCTP or PCAP support --
      this is the recommended setup if you don't need to handle SCTP, TLS or
      PCAP::

        tar -xvzf sipp-xxx.tar
        cd sipp
        cmake .
        make

    + With TLS support, you must have installed `OpenSSL library`_
      (>=0.9.8) (which may come with your system) or `WolfSSL library`_
      (>=3.15.0). Building SIPp consists only of adding the
      ``-DUSE_SSL=1`` option to the cmake command::

        tar -xvzf sipp-xxx.tar.gz
        cd sipp
        cmake . -DUSE_SSL=1
        make

    + With PCAP play support::

        tar -xvzf sipp-xxx.tar.gz
        cd sipp
        cmake . -DUSE_PCAP=1
        make

    + With SCTP support::

        tar -xvzf sipp-xxx.tar.gz
        cd sipp
        cmake . -DUSE_SCTP=1
        make

    + With support for statistically distributed pauses::

        tar -xvzf sipp-xxx.tar.gz
        cd sipp
        cmake . -DUSE_GSL=1
        make

    + You can also combine these various options, e.g.::

        tar -xvzf sipp-xxx.tar.gz
        cd sipp
        cmake . -DUSE_GSL=1 -DUSE_PCAP=1 -DUSE_SSL=1 -DUSE_SCTP=1
        make


.. warning::
  SIPp compiles under CYGWIN on Windows, provided that you
  installed IPv6 extension for `CYGWIN <http://win6.jp/Cygwin/>`_, as
  well as libncurses and (optionally OpenSSL and WinPcap). SCTP is not
  currently supported.

+ To compile SIPp on Windows with pcap (media support), you must:

    + Copy the `WinPcap developer package`_ to "C:\cygwin\lib\WpdPack"
    + Remove or rename "pthread.h" in "C:\cygwin\lib\WpdPack\Include", as
      it interfers with pthread.h from cygwin
    + Compile according to the instructions above.

.. _GNU GPL license: https://www.gnu.org/copyleft/gpl.html
.. _Gnu Scientific Libraries: https://www.gnu.org/software/gsl/
.. _WinPcap developer package: https://www.winpcap.org/devel.htm
.. _hewlett-packard: https://www.hp.com/
.. _SIPp's master tree: https://github.com/SIPp/sipp/tree/master
.. _OpenSSL library: https://www.openssl.org/
.. _WolfSSL library: https://www.wolfssl.com/
