Media impairment proxy
======================

``tools/sipp_impair.py`` is a dependency-free UDP proxy for seedable RTP
impairment tests. It is useful when a scenario must validate behavior under
loss, delay, jitter, duplication, reordering or burst loss.

Linux ``tc netem`` is the better choice for shaping a whole interface. This
proxy is meant for the cases where netem is awkward:

* it needs no root privileges or ``CAP_NET_ADMIN``, so it runs in CI
  containers and as an unprivileged user;
* it impairs exactly one UDP flow and leaves SIP signalling and other
  traffic on the same host untouched, without writing filters;
* it is plain Python, so it works the same on Linux, macOS and BSD;
* with ``--seed`` the loss, duplication and reorder decisions of each
  direction are the same from run to run.

Basic use
---------

Listen on a port that is advertised to SIPp or to the system under test, and
forward the packets to the real RTP destination:

.. code-block:: bash

   python3 tools/sipp_impair.py \
       --listen 127.0.0.1:40000 \
       --upstream 192.0.2.50:40000 \
       --delay-ms 80 \
       --jitter-ms 15 \
       --loss-percent 1.5 \
       --seed 42

IPv6 endpoints use bracket notation, for example ``[2001:db8::10]:40000``;
an unbracketed IPv6 literal such as ``::1:3478`` is rejected. Hostnames are
resolved as IPv4 or IPv6 UDP endpoints.

On exit (``SIGINT`` or ``SIGTERM``) the proxy prints its counters for each
direction to standard error; ``SIGUSR1`` prints them without stopping:

.. code-block:: text

   sipp_impair: client->upstream received=500 forwarded=493 dropped=7 ...
   sipp_impair: upstream->client received=500 forwarded=495 dropped=5 ...

``rejected`` counts datagrams discarded because they came from an unexpected
source, ``overflow`` counts packets dropped because more than ``--max-queue``
(default 4096) were waiting, and ``send_errors`` counts failed sends.

Topology
--------

One instance proxies one UDP flow: datagrams from the client to ``--listen``
go to ``--upstream``, and datagrams from ``--upstream`` back to the proxy go
to the client:

.. code-block:: text

   client  <-->  --listen [sipp_impair] (ephemeral port)  <-->  --upstream

* The upstream socket is ``connect()``\ ed to ``--upstream``, so the kernel
  chooses its local address and only datagrams from the upstream peer are
  accepted on it.
* The client is fixed with ``--client HOST:PORT``; without it the proxy locks
  to the first sender. Datagrams to ``--listen`` from any other source are
  discarded, so a third party cannot take over the return path. With an
  IPv6 ``--listen`` such as ``[::]``, an IPv4 ``--client`` matches the
  IPv4-mapped address (``::ffff:a.b.c.d``) the client arrives from.
* The return direction is only impaired if the upstream peer uses symmetric
  RTP (RFC 4961), i.e. it sends its media back to the address the media came
  from. Most user agents send to the address in the SDP instead, which
  bypasses the proxy; for those, only the client-to-upstream direction is
  impaired, or a second instance is needed with the SDP of the other side
  pointing at it.
* RTCP uses its own port (normally RTP port + 1), and every extra media
  stream has its own ports, so each needs its own instance.

For example, SIPp in ``-rtp_echo`` mode echoes RTP back to its sender, so it
is symmetric. To impair both directions of RTP between a system under test
and a SIPp UAS whose media port is ``127.0.0.1:6000``, advertise
``192.0.2.10`` port ``40000`` in the SDP of the UAS scenario (instead of
``[media_ip]`` and ``[media_port]``) and run:

.. code-block:: bash

   python3 tools/sipp_impair.py --listen 192.0.2.10:40000 \
       --upstream 127.0.0.1:6000 --loss-percent 2 --seed 1 &
   sipp -sf uas.xml -mi 127.0.0.1 -mp 6000 -rtp_echo

The system under test sends RTP to ``192.0.2.10:40000``, the proxy locks to
it, and both the RTP and the echo returned by SIPp are impaired. When the
upstream peer also exchanges RTCP (SIPp's echo does not), start a second
instance for the RTCP ports, with its own seed:

.. code-block:: bash

   python3 tools/sipp_impair.py --listen 192.0.2.10:40001 \
       --upstream 198.51.100.20:6001 --loss-percent 2 --seed 2 &

Profiles
--------

The supported controls are:

* ``--loss-percent`` - independent packet loss.
* ``--delay-ms`` - base one-way delay.
* ``--jitter-ms`` - uniform positive or negative delay variation.
* ``--duplicate-percent`` - probability of forwarding a second copy.
* ``--reorder-percent`` - probability of holding one packet and sending it
  just after the next packet of the same direction, so the two adjacent
  packets are swapped. If no further packet arrives within
  ``--reorder-delay-ms``, the held packet is sent then, so reordering never
  silently becomes packet loss. The packet that a held one waits for is
  never held itself, even when the held packet has already been sent at its
  deadline.
* ``--burst-start-percent`` and ``--burst-length`` - probability that a
  packet starts a loss burst, and the number of consecutive packets (that
  one included) dropped by each burst.
* ``--seed`` - seed the random choices; without it every run differs.

Each direction has its own random generator, burst state, reorder slot and
counters, and every random choice for a packet (loss, burst, jitter,
duplication, reordering) is drawn when the packet arrives. With ``--seed``,
whether the Nth packet of a direction is lost, duplicated or held for
reordering, and the jitter it gets, depend only on the seed and N, not on
traffic in the other direction or on packet timing. Timing still decides the
rest: send times follow arrival times plus the configured delay and jitter, a
held packet whose successor arrives after ``--reorder-delay-ms`` is sent
without being swapped, and packets that find ``--max-queue`` packets waiting
are dropped as ``overflow``.

Examples
--------

Two percent random loss with 30 ms jitter:

.. code-block:: bash

   python3 tools/sipp_impair.py --listen 127.0.0.1:40000 \
       --upstream 192.0.2.50:40000 --loss-percent 2 --jitter-ms 30 --seed 7

A severe mobile-network style profile with occasional 5-packet bursts:

.. code-block:: bash

   python3 tools/sipp_impair.py --listen 127.0.0.1:40000 \
       --upstream 192.0.2.50:40000 --delay-ms 120 --jitter-ms 40 \
       --reorder-percent 1 --duplicate-percent .2 \
       --burst-start-percent .5 --burst-length 5 --seed 100

Tests
-----

The scheduler, the impairment decisions and the proxy itself (over loopback
sockets, including IPv6 when available) can be tested with:

.. code-block:: bash

   python3 -m unittest tests/test_sipp_impair.py
