Media impairment proxy
======================

``tools/sipp_impair.py`` is a dependency-free UDP proxy for reproducible RTP
impairment tests.  It is useful when a scenario must validate behavior under
loss, delay, jitter, duplication, reordering or burst loss without requiring
root privileges or Linux ``tc netem``.

Basic use
---------

Listen on a port that is advertised to SIPp or to the system under test, and
forward the packets to the real RTP destination::

   python3 tools/sipp_impair.py \
       --listen 127.0.0.1:40000 \
       --upstream 192.0.2.50:40000 \
       --delay-ms 80 \
       --jitter-ms 15 \
       --loss-percent 1.5 \
       --seed 42

The first peer sending to the listen socket is learned as the return path, so
the proxy impairs both directions after the flow starts.

Profiles
--------

The supported controls are:

* ``--loss-percent`` - independent packet loss.
* ``--delay-ms`` - base one-way delay.
* ``--jitter-ms`` - uniform positive or negative delay variation.
* ``--duplicate-percent`` - probability of forwarding a second copy.
* ``--reorder-percent`` - probability of delaying a packet by the extra
  ``--reorder-delay-ms`` interval so later packets may pass it.
* ``--burst-start-percent`` and ``--burst-length`` - deterministic consecutive
  packet-loss bursts.
* ``--seed`` - make all probabilistic choices reproducible.

Examples
--------

Two percent random loss with 30 ms jitter::

   python3 tools/sipp_impair.py --listen 127.0.0.1:40000 \
       --upstream 192.0.2.50:40000 --loss-percent 2 --jitter-ms 30 --seed 7

A severe mobile-network style profile with occasional 5-packet bursts::

   python3 tools/sipp_impair.py --listen 127.0.0.1:40000 \
       --upstream 192.0.2.50:40000 --delay-ms 120 --jitter-ms 40 \
       --reorder-percent 1 --duplicate-percent .2 \
       --burst-start-percent .5 --burst-length 5 --seed 100

Tests
-----

The scheduler and deterministic impairment behavior can be tested with::

   python3 -m unittest tests/test_sipp_impair.py
